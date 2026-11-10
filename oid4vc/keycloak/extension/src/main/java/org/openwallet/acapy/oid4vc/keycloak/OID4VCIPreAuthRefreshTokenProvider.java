package org.openwallet.acapy.oid4vc.keycloak;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriInfo;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.util.Time;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseObjectProvider;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.protocol.oidc.refresh.AbstractRefreshTokenProvider;
import org.keycloak.protocol.oidc.refresh.InitialRefreshTokenContext;
import org.keycloak.protocol.oidc.refresh.RefreshTokenContext;
import org.keycloak.protocol.oidc.refresh.RefreshTokenException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.RefreshToken;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.UserSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import org.jboss.logging.Logger;

/**
 * Sessionless, long-lived refresh tokens for the ACA-Py OID4VCI pre-authorized
 * code grant.
 * <p>
 * Follows the design of Keycloak's own OID4VCI refresh token provider, without
 * depending on Keycloak's experimental OID4VC features:
 * <ul>
 *   <li>the refresh token is a self-contained signed JWT carrying the exchange's
 *       {@code refresh_id} and credential configuration ids; nothing is
 *       persisted per holder (no offline sessions);</li>
 *   <li>Keycloak binds it to the wallet key (DPoP for public clients, the
 *       attested instance key for attestation-based clients) and checks that
 *       binding on every refresh;</li>
 *   <li>each refresh builds a transient session and copies the claims onto the
 *       new access token, so no protocol mappers are needed;</li>
 *   <li>rotation (realm "Revoke refresh token") is tracked per token family in
 *       the single-use object store, with the family's lifetime;</li>
 *   <li>the lifetime is absolute ({@code oid4vci.refresh.token.lifespan},
 *       default one year): rotated tokens keep the first token's expiry.</li>
 * </ul>
 * Revoking a refresh token (revocation endpoint) marks its whole family revoked.
 * <p>
 * A wallet that sent a {@code client_id} the realm doesn't know got the
 * anonymous client; that {@code client_id} is recorded in the refresh token
 * ({@value #WALLET_CLIENT_ID_CLAIM}) so the wallet can refresh with it
 * ({@link OID4VCIRefreshClientHintAuthenticator}). It is not copied into access
 * tokens.
 * <p>
 * The rotation logic ({@link #validateTokenReuseForRefresh}, the rotation
 * record and its lock id) is adapted from Keycloak 26.8.0's
 * {@code org.keycloak.protocol.oid4vc.refresh.OID4VCIRefreshTokenProvider}
 * (Apache License 2.0), which in turn mirrors {@code TokenManager#validateTokenReuse}.
 * The refresh token SPI is internal to Keycloak: re-check this class against
 * those upstream classes on every Keycloak upgrade.
 */
public class OID4VCIPreAuthRefreshTokenProvider extends AbstractRefreshTokenProvider {

    /** Client session context attribute marking requests handled by this provider. */
    static final String MARKER = OID4VCIPreAuthRefreshTokenProvider.class.getName();
    /** Refresh token claim: the unregistered client_id the wallet sent in the token request. */
    static final String WALLET_CLIENT_ID_CLAIM = "wallet_client_id";
    /** Client session context attribute carrying {@link #WALLET_CLIENT_ID_CLAIM} to the new refresh token. */
    static final String WALLET_CLIENT_ID_ATTR = MARKER + ".walletClientId";
    private static final String CLAIMS_ATTR = MARKER + ".claims";
    private static final String EXPIRY_ATTR = MARKER + ".exp";
    private static final String ROTATION_KEY_PREFIX = MARKER.toLowerCase() + ".rotation.";
    private static final String NOTE_ACCEPTED_TOKEN_ID = "acceptedTokenId";
    private static final String NOTE_LATEST_GENERATED_TOKEN_ID = "latestGeneratedTokenId";
    private static final String NOTE_USE_COUNT = "useCount";
    private static final String NOTE_LAST_REFRESH = "lastRefresh";
    private static final String NOTE_REVOKED = "revoked";
    private static final int CLOCK_SKEW_SECONDS = 10;

    private static final Logger LOGGER = Logger.getLogger(OID4VCIPreAuthRefreshTokenProvider.class);

    private String pendingRotationKey;
    private Map<String, String> pendingRotationRecord;

    public OID4VCIPreAuthRefreshTokenProvider(KeycloakSession session) {
        super(session);
    }

    @Override
    public String getProviderId() {
        return OID4VCIPreAuthRefreshTokenProviderFactory.PROVIDER_ID;
    }

    // --- Initial issuance and rotation -------------------------------------------------------------------------

    @Override
    public boolean supports(InitialRefreshTokenContext ctx) {
        ClientSessionContext clientSessionCtx = ctx.clientSessionCtx();
        String grantType = clientSessionCtx.getAttribute(Constants.GRANT_TYPE, String.class);
        return OID4VCIPreAuthGrantType.GRANT_TYPE.equals(grantType)
                || Boolean.TRUE.equals(clientSessionCtx.getAttribute(MARKER, Boolean.class));
    }

    @Override
    public RefreshToken generateRefreshToken(InitialRefreshTokenContext ctx) throws RefreshTokenException {
        if (ctx.offlineTokenRequested()) {
            throw new RefreshTokenException(OAuthErrorException.INVALID_REQUEST,
                    "offline_access is not supported with the pre-authorized code grant");
        }
        ClientSessionContext clientSessionCtx = ctx.clientSessionCtx();
        AccessToken accessToken = ctx.responseBuilder().getAccessToken();
        RefreshToken refreshToken = createRefreshToken(accessToken, ctx.confirmation(), getProviderId());

        // Exchange claims: from the access token on initial issuance, from the
        // old refresh token (stashed by validateToken) on rotation.
        Map<String, Object> claims = exchangeClaims(clientSessionCtx, accessToken);
        refreshToken.getOtherClaims().putAll(claims);
        String walletClientId = clientSessionCtx.getAttribute(WALLET_CLIENT_ID_ATTR, String.class);
        if (walletClientId != null) {
            refreshToken.setOtherClaims(WALLET_CLIENT_ID_CLAIM, walletClientId);
        }

        Long expiry = clientSessionCtx.getAttribute(EXPIRY_ATTR, Long.class);
        if (expiry == null) {
            OID4VCIPreAuthConfig config = OID4VCIPreAuthConfig.of(session.getContext().getRealm());
            expiry = (long) Time.currentTime() + config.refreshTokenLifespan;
        }
        refreshToken.exp(expiry);
        return refreshToken;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> exchangeClaims(ClientSessionContext clientSessionCtx, AccessToken accessToken) {
        Map<String, Object> stashed = clientSessionCtx.getAttribute(CLAIMS_ATTR, Map.class);
        if (stashed != null) {
            return stashed;
        }
        OID4VCIPreAuthConfig config = OID4VCIPreAuthConfig.of(clientSessionCtx.getClientSession().getRealm());
        Map<String, Object> claims = new HashMap<>();
        Object refreshId = accessToken.getOtherClaims().get(config.refreshIdClaim);
        if (refreshId == null) {
            throw new RefreshTokenException(OAuthErrorException.INVALID_REQUEST, "access token has no exchange reference");
        }
        claims.put(config.refreshIdClaim, refreshId);
        Object ids = accessToken.getOtherClaims().get(OID4VCIPreAuthGrantType.CREDENTIAL_CONFIGURATION_IDS_CLAIM);
        if (ids != null) {
            claims.put(OID4VCIPreAuthGrantType.CREDENTIAL_CONFIGURATION_IDS_CLAIM, ids);
        }
        return claims;
    }

    // --- Refresh ---------------------------------------------------------------------------------------------

    @Override
    public boolean supports(RefreshTokenContext ctx) {
        return getProviderId().equals(ctx.oldRefreshToken().getProvider());
    }

    @Override
    protected TokenManager.TokenValidation validateToken(KeycloakSession session, UriInfo uriInfo, ClientConnection connection,
                                                         RealmModel realm, RefreshToken oldToken, HttpHeaders headers,
                                                         String scope, ClientModel client, TokenManager tokenManager,
                                                         EventBuilder event) throws OAuthErrorException {
        // Signature, issuer, expiry, not-before, azp and the DPoP / attestation
        // key binding were already checked by TokenManager.verifyRefreshToken.
        OID4VCIPreAuthConfig config = OID4VCIPreAuthConfig.of(realm);
        if (!config.refreshTokens) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Refresh tokens are disabled");
        }
        Object refreshId = oldToken.getOtherClaims().get(config.refreshIdClaim);
        if (refreshId == null) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token");
        }

        UserModel user = session.users().getUserById(realm, oldToken.getSubject());
        if (user == null || !user.isEnabled()) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Invalid refresh token", "Holder user missing or disabled");
        }

        RootAuthenticationSessionModel rootAuthSession =
                new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setAuthenticatedUser(user);
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setClientNote(OIDCLoginProtocol.ISSUER,
                Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scope);

        UserSessionModel userSession = new UserSessionManager(session).createUserSession(
                authSession.getParentSession().getId(), realm, user, user.getUsername(),
                connection.getRemoteHost(), OID4VCIPreAuthGrantType.AUTH_METHOD + "-refresh", false, null, null,
                UserSessionModel.SessionPersistenceState.TRANSIENT);
        event.session(userSession);

        AuthenticationManager.setClientScopesInSession(session, authSession);
        ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession, authSession);
        clientSessionCtx.setAttribute(Constants.GRANT_TYPE, OAuth2Constants.REFRESH_TOKEN);
        clientSessionCtx.setAttribute(MARKER, Boolean.TRUE);

        Map<String, Object> claims = new HashMap<>();
        claims.put(config.refreshIdClaim, refreshId);
        Object ids = oldToken.getOtherClaims().get(OID4VCIPreAuthGrantType.CREDENTIAL_CONFIGURATION_IDS_CLAIM);
        if (ids != null) {
            claims.put(OID4VCIPreAuthGrantType.CREDENTIAL_CONFIGURATION_IDS_CLAIM, ids);
        }
        clientSessionCtx.setAttribute(CLAIMS_ATTR, claims);
        clientSessionCtx.setAttribute(EXPIRY_ATTR, oldToken.getExp());
        // Kept on rotation, but not part of the claims copied onto the access token.
        if (oldToken.getOtherClaims().get(WALLET_CLIENT_ID_CLAIM) instanceof String walletClientId) {
            clientSessionCtx.setAttribute(WALLET_CLIENT_ID_ATTR, walletClientId);
        }

        return new TokenManager.TokenValidation(user, userSession, clientSessionCtx);
    }

    @Override
    @SuppressWarnings("unchecked")
    protected void afterRefreshTokenGenerated(RefreshTokenContext ctx, TokenManager.AccessTokenResponseBuilder responseBuilder) {
        flushRotationRecord(ctx, responseBuilder.getRefreshToken());

        ClientSessionContext clientSessionCtx = responseBuilder.getClientSessionCtx();
        Map<String, Object> claims = clientSessionCtx.getAttribute(CLAIMS_ATTR, Map.class);
        AccessToken accessToken = responseBuilder.getAccessToken();
        if (claims != null) {
            claims.forEach(accessToken::setOtherClaims);
        }
        OID4VCIPreAuthConfig config = OID4VCIPreAuthConfig.of(session.getContext().getRealm());
        if (config.credentialIssuer != null) {
            accessToken.addAudience(config.credentialIssuer);
        }
    }

    // --- Rotation (realm "Revoke refresh token") ---------------------------------------------------------------

    @Override
    protected String getRefreshTokenLockId(RealmModel realm, RefreshToken refreshToken, TokenManager tokenManager) {
        return "refreshLock:" + rotationKey(realm, refreshToken);
    }

    /**
     * The transient client session can't hold rotation state, so it is kept in
     * the single-use object store per token family. Mirrors
     * {@link TokenManager#validateTokenReuse}; the record is written in
     * {@link #flushRotationRecord} once the new token's id is known.
     */
    @Override
    protected void validateTokenReuseForRefresh(KeycloakSession session, RealmModel realm, RefreshToken refreshToken,
                                                TokenManager.TokenValidation validation, TokenManager tokenManager)
            throws OAuthErrorException {
        pendingRotationKey = null;
        pendingRotationRecord = null;

        String key = rotationKey(realm, refreshToken);
        Map<String, String> record = session.singleUseObjects().get(key);
        if (record != null && Boolean.parseBoolean(record.get(NOTE_REVOKED))) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Refresh token revoked");
        }
        if (!realm.isRevokeRefreshToken()) {
            return;
        }

        String acceptedTokenId = note(record, NOTE_ACCEPTED_TOKEN_ID);
        String latestGeneratedTokenId = note(record, NOTE_LATEST_GENERATED_TOKEN_ID);
        int useCount = intNote(record, NOTE_USE_COUNT);
        int lastRefresh = intNote(record, NOTE_LAST_REFRESH);

        if (acceptedTokenId != null && !refreshToken.getId().equals(acceptedTokenId)) {
            // Another token of this family was already accepted: anything issued
            // no later than the most recently generated token is a replay.
            if (latestGeneratedTokenId != null && !refreshToken.getId().equals(latestGeneratedTokenId)
                    && refreshToken.getIat() <= lastRefresh) {
                LOGGER.debugf("Rejecting replayed refresh token %s in realm %s", refreshToken.getId(), realm.getName());
                throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Stale token");
            }
            useCount = 0;
        }
        if (useCount > realm.getRefreshTokenMaxReuse()) {
            throw new OAuthErrorException(OAuthErrorException.INVALID_GRANT, "Maximum allowed refresh token reuse exceeded",
                    "Maximum allowed refresh token reuse exceeded");
        }

        Map<String, String> updated = record == null ? new HashMap<>() : new HashMap<>(record);
        updated.put(NOTE_ACCEPTED_TOKEN_ID, refreshToken.getId());
        updated.put(NOTE_USE_COUNT, String.valueOf(useCount + 1));
        pendingRotationKey = key;
        pendingRotationRecord = updated;
    }

    private void flushRotationRecord(RefreshTokenContext ctx, RefreshToken newRefreshToken) {
        String key = pendingRotationKey;
        Map<String, String> record = pendingRotationRecord;
        pendingRotationKey = null;
        pendingRotationRecord = null;
        if (key == null || record == null) {
            return;
        }
        RefreshToken lifespanSource = ctx.oldRefreshToken();
        if (newRefreshToken != null) {
            record.put(NOTE_LATEST_GENERATED_TOKEN_ID, newRefreshToken.getId());
            record.put(NOTE_LAST_REFRESH, String.valueOf(newRefreshToken.getIat()));
            lifespanSource = newRefreshToken;
        }
        store(session.singleUseObjects(), key, lifespanSource.getExp(), record);
    }

    @Override
    public void revokeToken(AccessToken token, UserModel user, ClientModel client, EventBuilder event) {
        RealmModel realm = session.getContext().getRealm();
        String key = rotationKey(realm, token);
        Map<String, String> record = session.singleUseObjects().get(key);
        Map<String, String> updated = record == null ? new HashMap<>() : new HashMap<>(record);
        updated.put(NOTE_REVOKED, Boolean.TRUE.toString());
        store(session.singleUseObjects(), key, token.getExp(), updated);
    }

    private static void store(SingleUseObjectProvider store, String key, Long expiry, Map<String, String> record) {
        long lifespan = (expiry == null ? 0 : expiry - Time.currentTime()) + CLOCK_SKEW_SECONDS;
        if (lifespan > 0) {
            store.put(key, lifespan, record);
        }
    }

    /** reuse_id identifies the token family; without it, strict single use of the one token. */
    private static String rotationKey(RealmModel realm, AccessToken refreshToken) {
        Object reuseId = refreshToken.getOtherClaims().get(Constants.REUSE_ID);
        String familyId = reuseId != null ? String.valueOf(reuseId) : refreshToken.getId();
        return ROTATION_KEY_PREFIX + HashUtils.sha256UrlEncodedHash(realm.getId() + "." + familyId, StandardCharsets.UTF_8);
    }

    private static String note(Map<String, String> record, String name) {
        return record == null ? null : record.get(name);
    }

    private static int intNote(Map<String, String> record, String name) {
        String value = note(record, name);
        return value != null ? Integer.parseInt(value) : 0;
    }
}
