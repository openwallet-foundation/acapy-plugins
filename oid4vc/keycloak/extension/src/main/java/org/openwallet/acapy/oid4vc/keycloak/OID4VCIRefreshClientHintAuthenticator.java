package org.openwallet.acapy.oid4vc.keycloak;

import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;

import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.AbstractClientAuthenticator;
import org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.RefreshToken;

/**
 * Client identification hint for refresh requests from wallets that got the
 * anonymous client.
 * <p>
 * A wallet that used the anonymous public client never learned that client's
 * id. For a {@code refresh_token} request carrying one of this extension's
 * refresh tokens issued to a <em>public</em> client, this authenticator helps
 * Keycloak's default {@code client-secret} authenticator ("Client Id and
 * Secret"), which identifies public clients, find the token's client ({@code azp}):
 * <ul>
 *   <li>no {@code client_id}: it sets the {@code client_id} session attribute,
 *       which that authenticator falls back to;</li>
 *   <li>a {@code client_id} the realm doesn't know: only if it is the one the
 *       wallet sent in its token request, recorded in the refresh token
 *       ({@link OID4VCIPreAuthRefreshTokenProvider#WALLET_CLIENT_ID_CLAIM}), it
 *       replaces the request's {@code client_id} with the token's client. Any other
 *       unknown {@code client_id} is left alone and rejected as usual, so the
 *       refresh token is only accepted with the client_id it was issued for
 *       (OAuth 2.1 §4.3.1).</li>
 * </ul>
 * It never authenticates a client itself, and a {@code client_id} naming a
 * client of the realm is left to the normal client authentication. Identifying
 * a public client from its signed, DPoP-bound refresh token is no weaker than
 * the client sending its {@code client_id}.
 * <p>
 * Add it to the realm's client authentication flow ("clients") as ALTERNATIVE,
 * before "Client Id and Secret".
 */
public class OID4VCIRefreshClientHintAuthenticator extends AbstractClientAuthenticator {

    public static final String PROVIDER_ID = "oid4vci-refresh-client-hint";
    /** Event detail: the unregistered client_id a wallet used. */
    static final String WALLET_CLIENT_ID_DETAIL = "wallet_client_id";

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        MultivaluedMap<String, String> form = context.getHttpRequest().getDecodedFormParameters();
        if (form == null || !OAuth2Constants.REFRESH_TOKEN.equals(form.getFirst(OAuth2Constants.GRANT_TYPE))) {
            return;
        }
        HttpHeaders headers = context.getHttpRequest().getHttpHeaders();
        if (headers.getHeaderString(HttpHeaders.AUTHORIZATION) != null
                || headers.getHeaderString(AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_HEADER) != null) {
            return;
        }
        RealmModel realm = context.getRealm();
        String clientId = form.getFirst(OAuth2Constants.CLIENT_ID);
        if (clientId != null && realm.getClientByClientId(clientId) != null) {
            return;
        }
        String encoded = form.getFirst(OAuth2Constants.REFRESH_TOKEN);
        if (encoded == null) {
            return;
        }
        KeycloakSession session = context.getSession();
        RefreshToken token = session.tokens().decode(encoded, RefreshToken.class);
        if (token == null || !OID4VCIPreAuthRefreshTokenProviderFactory.PROVIDER_ID.equals(token.getProvider())
                || token.getIssuedFor() == null) {
            return;
        }
        ClientModel client = realm.getClientByClientId(token.getIssuedFor());
        if (client == null || !client.isEnabled() || !client.isPublicClient()) {
            return;
        }
        if (clientId == null) {
            session.setAttribute(OAuth2Constants.CLIENT_ID, client.getClientId());
        } else if (clientId.equals(token.getOtherClaims().get(OID4VCIPreAuthRefreshTokenProvider.WALLET_CLIENT_ID_CLAIM))) {
            // "Client Id and Secret" reads client_id from the form before the
            // session attribute. The request's parsed form parameters are cached
            // for the whole request, so replacing the value here is what it sees.
            form.putSingle(OAuth2Constants.CLIENT_ID, client.getClientId());
            context.getEvent().detail(WALLET_CLIENT_ID_DETAIL, clientId);
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "OID4VCI refresh client hint";
    }

    @Override
    public String getHelpText() {
        return "Identifies the public client of an OID4VCI pre-authorized code refresh token when the wallet "
                + "sends no client_id, or the unregistered client_id it used for the token request. "
                + "Place before 'Client Id and Secret'.";
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public List<ProviderConfigProperty> getConfigPropertiesPerClient() {
        return List.of();
    }

    @Override
    public Map<String, Object> getAdapterConfiguration(KeycloakSession session, ClientModel client) {
        return Map.of();
    }

    @Override
    public Set<String> getProtocolAuthenticatorMethods(String loginProtocol) {
        return Set.of();
    }
}
