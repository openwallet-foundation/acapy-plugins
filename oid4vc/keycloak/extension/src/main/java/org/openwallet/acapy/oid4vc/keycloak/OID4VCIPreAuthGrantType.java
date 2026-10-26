package org.openwallet.acapy.oid4vc.keycloak;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator;
import org.keycloak.common.util.Time;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase;
import org.keycloak.protocol.oidc.rar.AuthorizationDetailsProcessorManager;
import org.keycloak.protocol.oidc.rar.InvalidAuthorizationDetailsException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AuthorizationDetailsJSONRepresentation;
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.services.util.DPoPUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import org.jboss.logging.Logger;

/**
 * OID4VCI pre-authorized code grant backed by the ACA-Py OID4VC plugin.
 * <p>
 * The plugin owns the pre-authorized code, the tx_code and the exchange. This
 * grant does what the plugin should not have to: authenticate the wallet
 * (attestation-based client authentication) and bind the token to a DPoP key.
 * It then redeems the code at the plugin and issues a short-lived, DPoP-bound
 * access token for a generic holder user, carrying the exchange's refresh_id,
 * and a long-lived refresh token ({@link OID4VCIPreAuthRefreshTokenProvider}) bound to
 * the same wallet key.
 * <p>
 * {@code authorization_details} in the request (RFC 9396, OID4VCI 1.0 §5.1.1)
 * go through Keycloak's RAR processing with
 * {@link OID4VCIAuthorizationDetailsProcessor}; the response and the tokens
 * carry them with {@code credential_identifiers} (§6.2).
 * <p>
 * Order matters: the client, the DPoP proof and {@code authorization_details}
 * are checked before the code is redeemed (the plugin checks the requested
 * credential configurations against the offer before redeeming), so an
 * invalid request cannot burn a code or a tx_code attempt.
 */
public class OID4VCIPreAuthGrantType extends OAuth2GrantTypeBase {

    static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    static final String CODE_PARAM = "pre-authorized_code";
    static final String TX_CODE_PARAM = "tx_code";
    static final String CREDENTIAL_CONFIGURATION_IDS_CLAIM = "credential_configuration_ids";
    static final String AUTH_METHOD = "oid4vci-pre-authorized-code";
    /** RFC 9396 §5 error code (Keycloak has no constant for it). */
    static final String INVALID_AUTHORIZATION_DETAILS = "invalid_authorization_details";

    private static final Logger LOGGER = Logger.getLogger(OID4VCIPreAuthGrantType.class);

    /** A client_id the realm doesn't know, sent by a wallet that got the anonymous client. */
    private String unregisteredWalletClientId;

    @Override
    public Response process(Context context) {
        setContext(context);
        unregisteredWalletClientId = null;
        OID4VCIPreAuthConfig config = OID4VCIPreAuthConfig.of(realm);
        if (!config.isComplete()) {
            LOGGER.errorf("Realm '%s' is missing %s / %s", realm.getName(),
                    OID4VCIPreAuthConfig.REDEEM_URL, OID4VCIPreAuthConfig.CREDENTIAL_ISSUER);
            event.error(Errors.INVALID_REQUEST);
            throw error(OAuthErrorException.SERVER_ERROR, "pre-authorized code grant is not configured",
                    Response.Status.INTERNAL_SERVER_ERROR);
        }

        String code = formParams.getFirst(CODE_PARAM);
        if (code == null || code.isBlank()) {
            event.detail(Details.REASON, "missing " + CODE_PARAM).error(Errors.INVALID_CODE);
            throw error(OAuthErrorException.INVALID_REQUEST, "Missing parameter: " + CODE_PARAM,
                    Response.Status.BAD_REQUEST);
        }
        String txCode = formParams.getFirst(TX_CODE_PARAM);

        // 1. Client authentication (TokenEndpoint skips checkClient() for this grant type).
        authenticateClient(config);

        // 2. DPoP: TokenEndpoint already validated a proof if one was sent.
        DPoP dpop = session.getAttribute(DPoPUtil.DPOP_SESSION_ATTRIBUTE, DPoP.class);
        if (config.requireDpop && dpop == null) {
            event.detail(Details.REASON, "DPoP proof required").error(Errors.INVALID_DPOP_PROOF);
            throw error(OAuthErrorException.INVALID_DPOP_PROOF, "DPoP proof is required",
                    Response.Status.BAD_REQUEST);
        }

        // 3. authorization_details: entries the realm can't process are
        // rejected here; the requested credential configurations go to the
        // plugin, which checks them against the offer before redeeming.
        List<String> requestedConfigurationIds = requestedConfigurationIds();

        // 4. Redeem the code at the plugin.
        RedeemClient.Redemption redemption;
        try {
            String walletClientId = formParams.getFirst(OAuth2Constants.CLIENT_ID);
            redemption = RedeemClient.redeem(session, realm, config, code, txCode,
                    walletClientId != null ? walletClientId : client.getClientId(), requestedConfigurationIds);
        } catch (RedeemClient.RedeemException e) {
            boolean details = INVALID_AUTHORIZATION_DETAILS.equals(e.error);
            event.detail(Details.REASON, e.getMessage())
                    .error(details ? INVALID_AUTHORIZATION_DETAILS : Errors.INVALID_CODE);
            if (e.unavailable) {
                throw error(OAuthErrorException.TEMPORARILY_UNAVAILABLE, "Credential issuer unavailable",
                        Response.Status.SERVICE_UNAVAILABLE);
            }
            String description = details
                    ? "authorization_details names a credential configuration the offer does not include"
                    : OAuthErrorException.INVALID_REQUEST.equals(e.error)
                            ? "Invalid token request" : "Invalid pre-authorized code or tx_code";
            throw error(e.error, description, Response.Status.BAD_REQUEST);
        }

        // 5. Generic holder user and a transient session: Keycloak does not know the holder.
        UserModel holder = session.users().getUserByUsername(realm, config.holderUsername);
        if (holder == null || !holder.isEnabled()) {
            LOGGER.errorf("Realm '%s' has no enabled holder user '%s'", realm.getName(), config.holderUsername);
            event.error(Errors.USER_NOT_FOUND);
            throw error(OAuthErrorException.SERVER_ERROR, "pre-authorized code grant is not configured",
                    Response.Status.INTERNAL_SERVER_ERROR);
        }
        event.user(holder).detail(Details.USERNAME, holder.getUsername());

        String scope = getRequestedScopes();
        RootAuthenticationSessionModel rootAuthSession =
                new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(holder);
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.ISSUER,
                Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);

        UserSessionModel userSession = new UserSessionManager(session).createUserSession(
                authSession.getParentSession().getId(), realm, holder, holder.getUsername(),
                clientConnection.getRemoteHost(), AUTH_METHOD, false, null, null,
                UserSessionModel.SessionPersistenceState.TRANSIENT);
        event.session(userSession);

        AuthenticationManager.setClientScopesInSession(session, authSession);
        ClientSessionContext clientSessionCtx =
                TokenManager.attachAuthenticationSession(session, userSession, authSession);
        if (clientAuthAttributes != null) {
            updateUserSessionFromClientAuth(userSession);
        }
        if (unregisteredWalletClientId != null) {
            // Recorded in the refresh token, so the wallet can refresh with the
            // same client_id (OID4VCIRefreshClientHintAuthenticator).
            clientSessionCtx.setAttribute(OID4VCIPreAuthRefreshTokenProvider.WALLET_CLIENT_ID_ATTR,
                    unregisteredWalletClientId);
        }

        // authorization_details for the response (OID4VCI §6.2): each entry
        // with credential_identifiers for the configurations the code grants.
        List<AuthorizationDetailsJSONRepresentation> authorizationDetails = null;
        if (requestedConfigurationIds != null) {
            clientSessionCtx.setAttribute(OID4VCIAuthorizationDetailsProcessor.GRANTED_CONFIGURATION_IDS,
                    redemption.credentialConfigurationIds());
            authorizationDetails = processAuthorizationDetails(userSession, clientSessionCtx);
            clientSessionCtx.setAttribute(Constants.AUTHORIZATION_DETAILS_RESPONSE, authorizationDetails);
        }

        // 6./7. Short-lived access token. The DPoP protocol mapper binds cnf.jkt
        // because a validated proof is in the session.
        TokenManager.AccessTokenResponseBuilder responseBuilder =
                createTokenResponseBuilder(holder, userSession, clientSessionCtx, scope, null);
        AccessToken token = responseBuilder.getAccessToken();
        token.setOtherClaims(config.refreshIdClaim, redemption.refreshId());
        token.setOtherClaims(CREDENTIAL_CONFIGURATION_IDS_CLAIM, redemption.credentialConfigurationIds());
        token.addAudience(config.credentialIssuer);
        if (authorizationDetails != null) {
            // Also copied into the refresh token, and from it into refreshed tokens.
            token.setAuthorizationDetails(authorizationDetails);
        }
        if (redemption.expiresIn() != null && redemption.expiresIn() > 0) {
            long cap = (long) Time.currentTime() + redemption.expiresIn();
            if (token.getExp() == null || token.getExp() > cap) {
                token.exp(cap);
            }
        }
        // Long-lived refresh token (OID4VCIPreAuthRefreshTokenProvider). A public
        // client's refresh token must be bound to its DPoP key (RFC 9449 §5);
        // confidential clients (e.g. attestation-based) are bound by Keycloak to
        // their attested key.
        if (config.refreshTokens) {
            if (token.getConfirmation() != null || !client.isPublicClient()) {
                responseBuilder.generateRefreshToken();
            } else {
                LOGGER.debugf("No refresh token for public client '%s' without a DPoP proof", client.getClientId());
            }
        }
        return createTokenResponse(responseBuilder, clientSessionCtx, false);
    }

    /**
     * The credential configuration ids requested in {@code authorization_details},
     * or null without it. Entries are validated by Keycloak's RAR processing
     * (an unknown type, or an {@code openid_credential} entry without a
     * configuration id or for another issuer, is rejected).
     */
    private List<String> requestedConfigurationIds() {
        String raw = formParams.getFirst(OAuth2Constants.AUTHORIZATION_DETAILS);
        if (raw == null) {
            return null;
        }
        String reason;
        try {
            new AuthorizationDetailsProcessorManager(session).validateAuthorizationDetail(raw);
            OID4VCIAuthorizationDetail[] details = JsonSerialization.readValue(raw, OID4VCIAuthorizationDetail[].class);
            return Arrays.stream(details).map(OID4VCIAuthorizationDetail::getCredentialConfigurationId)
                    .distinct().toList();
        } catch (InvalidAuthorizationDetailsException e) {
            reason = e.getMessage();
        } catch (IOException | RuntimeException e) {
            reason = "authorization_details is not a valid JSON array";
        }
        event.detail(Details.REASON, reason).error(INVALID_AUTHORIZATION_DETAILS);
        throw error(INVALID_AUTHORIZATION_DETAILS, reason, Response.Status.BAD_REQUEST);
    }

    private void authenticateClient(OID4VCIPreAuthConfig config) {
        // A client "presents credentials" when it sends a wallet attestation or
        // any other client authentication the realm understands. A bare
        // client_id is not a credential.
        boolean presentsCredentials =
                headers.getHeaderString(AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_HEADER) != null
                || headers.getHeaderString(HttpHeaders.AUTHORIZATION) != null
                || formParams.getFirst(OAuth2Constants.CLIENT_ASSERTION) != null
                || formParams.getFirst(OAuth2Constants.CLIENT_SECRET) != null;

        // A client_id naming an enabled public client of this realm identifies
        // the wallet; it will send the same client_id when refreshing.
        String requestedClientId = formParams.getFirst(OAuth2Constants.CLIENT_ID);
        ClientModel requested = requestedClientId == null ? null : realm.getClientByClientId(requestedClientId);
        boolean knownPublicClient = requested != null && requested.isEnabled() && requested.isPublicClient();

        if (!presentsCredentials && !knownPublicClient && !config.requireClientAttestation
                && config.anonymousClientId != null) {
            // No client authentication: use the public anonymous client. The
            // wallet's own client_id (if any) is unauthenticated: it is passed to
            // the plugin for logging and, if the realm doesn't know it, recorded
            // in the refresh token.
            client = realm.getClientByClientId(config.anonymousClientId);
            if (client == null || !client.isEnabled() || !client.isPublicClient()) {
                event.error(Errors.CLIENT_NOT_FOUND);
                throw error(OAuthErrorException.INVALID_CLIENT, "Anonymous client is not available",
                        Response.Status.UNAUTHORIZED);
            }
            if (requestedClientId != null && !requestedClientId.isBlank() && requested == null) {
                unregisteredWalletClientId = requestedClientId;
                event.detail(OID4VCIRefreshClientHintAuthenticator.WALLET_CLIENT_ID_DETAIL, requestedClientId);
            }
            clientConfig = OIDCAdvancedConfigWrapper.fromClientModel(client);
            clientAuthAttributes = Map.of();
        } else {
            // Runs the realm client authentication flow (ABCA authenticator
            // included); a public client authenticates with its client_id alone.
            checkClient();
        }

        session.getContext().setClient(client);
        context.setClient(client);
        event.client(client);

        if (config.requireClientAttestation) {
            AttestationBasedClientAuthenticator.ABCAResult abca = session.getAttribute(
                    AttestationBasedClientAuthenticator.ABCAResult.ABCA_RESULT,
                    AttestationBasedClientAuthenticator.ABCAResult.class);
            ClientModel attested = abca == null ? null : abca.getAttestedClient();
            if (attested == null || !attested.getId().equals(client.getId())) {
                event.detail(Details.REASON, "client attestation required").error(Errors.INVALID_CLIENT);
                throw error(OAuthErrorException.INVALID_CLIENT, "Client attestation is required",
                        Response.Status.UNAUTHORIZED);
            }
        }
    }

    private CorsErrorResponseException error(String error, String description, Response.Status status) {
        return new CorsErrorResponseException(cors, error, description, status);
    }

    @Override
    protected boolean useRefreshToken() {
        return false;
    }

    @Override
    public EventType getEventType() {
        return EventType.VERIFIABLE_CREDENTIAL_PRE_AUTHORIZED_GRANT;
    }

    @Override
    public Set<String> getTokenParameterNames() {
        return Collections.emptySet();
    }
}
