package org.openwallet.acapy.oid4vc.keycloak;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.keycloak.OAuthErrorException;
import org.keycloak.TokenCategory;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.Urls;
import org.keycloak.util.JsonSerialization;
import org.keycloak.vault.VaultStringSecret;

import org.apache.http.client.config.RequestConfig;

import org.jboss.logging.Logger;

/**
 * Back-channel call to the plugin's redeem endpoint on its admin API.
 * <p>
 * Keycloak is an OAuth client of the plugin and authenticates with the
 * method configured in {@code oid4vci.redeem.client.auth}:
 * <ul>
 *   <li>{@code private_key_jwt} (default, RFC 7523): a client assertion signed
 *       with the realm's active access-token key; the plugin verifies it against
 *       the realm JWKS, so there is no shared secret.</li>
 *   <li>{@code client_secret_jwt}: the same assertion, HMAC-signed with the
 *       configured secret.</li>
 *   <li>{@code client_secret_post}: client_id + client_secret form parameters.</li>
 * </ul>
 * Credentials are sent in the form body: on the ACA-Py admin port the
 * {@code Authorization} header is reserved for ACA-Py tenant tokens. The call
 * goes through Keycloak's HTTP client ({@link SimpleHttp}), so it honours the
 * server's outgoing proxy, trust store and connection settings.
 * <p>
 * The plugin tenant is carried in the authentication: the request names the
 * credential issuer it acts for ({@code oid4vci.credential.issuer}) as a
 * {@code credential_issuer} claim of the client assertion and as a form
 * parameter. The plugin routes on it and verifies it against that tenant's
 * configuration.
 */
final class RedeemClient {

    static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    static final String PRIVATE_KEY_JWT = "private_key_jwt";
    static final String CLIENT_SECRET_JWT = "client_secret_jwt";
    static final String CLIENT_SECRET_POST = "client_secret_post";
    static final String CREDENTIAL_ISSUER = "credential_issuer";
    /** Form parameter: JSON array of the requested credential configuration ids. */
    static final String CREDENTIAL_CONFIGURATION_IDS = "credential_configuration_ids";
    private static final int ASSERTION_TTL_SECONDS = 60;

    private static final Logger LOGGER = Logger.getLogger(RedeemClient.class);

    /** Successful redemption. */
    record Redemption(String refreshId, List<String> credentialConfigurationIds, Integer expiresIn) {
    }

    /** Redemption refused by the plugin (OAuth error code) or failed. */
    static final class RedeemException extends Exception {
        final String error;
        final boolean unavailable;

        RedeemException(String error, String message, boolean unavailable) {
            super(message);
            this.error = error;
            this.unavailable = unavailable;
        }
    }

    private RedeemClient() {
    }

    /**
     * @param requestedConfigurationIds credential configuration ids the wallet
     *        requested in authorization_details (null without); the plugin
     *        rejects a mismatch with the offer before redeeming the code
     */
    static Redemption redeem(KeycloakSession session, RealmModel realm, OID4VCIPreAuthConfig config,
                             String code, String txCode, String walletClientId,
                             List<String> requestedConfigurationIds) throws RedeemException {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("pre_authorized_code", code);
        if (txCode != null) {
            form.put("tx_code", txCode);
        }
        if (walletClientId != null) {
            form.put("wallet_client_id", walletClientId);
        }
        form.put(CREDENTIAL_ISSUER, config.credentialIssuer);

        int status;
        String body;
        try {
            if (requestedConfigurationIds != null) {
                form.put(CREDENTIAL_CONFIGURATION_IDS, JsonSerialization.writeValueAsString(requestedConfigurationIds));
            }
            addClientAuthentication(session, realm, config, form);
            RequestConfig requestConfig = RequestConfig.custom()
                    .setConnectTimeout(config.redeemTimeoutMs)
                    .setConnectionRequestTimeout(config.redeemTimeoutMs)
                    .setSocketTimeout(config.redeemTimeoutMs)
                    .setRedirectsEnabled(false)
                    .build();
            try (SimpleHttpResponse response = SimpleHttp.create(session)
                    .withRequestConfig(requestConfig)
                    .doPost(config.redeemUrl.toString())
                    .params(form)
                    .acceptJson()
                    .asResponse()) {
                status = response.getStatus();
                body = response.asString();
            }
        } catch (IOException | RuntimeException e) {
            LOGGER.warnf(e, "Pre-authorized code redeem call to %s failed", config.redeemUrl);
            throw new RedeemException(OAuthErrorException.SERVER_ERROR, "redeem call failed", true);
        }

        Map<?, ?> json;
        try {
            json = JsonSerialization.readValue(body, Map.class);
        } catch (IOException | RuntimeException e) {
            json = Map.of();
        }

        if (status == 200) {
            Object refreshId = json.get("refresh_id");
            Object ids = json.get("credential_configuration_ids");
            if (!(refreshId instanceof String) || !(ids instanceof List<?> list) || list.isEmpty()) {
                throw new RedeemException(OAuthErrorException.SERVER_ERROR, "malformed redeem response", true);
            }
            Object expiresIn = json.get("expires_in");
            return new Redemption((String) refreshId,
                    list.stream().map(String::valueOf).toList(),
                    expiresIn instanceof Number n ? n.intValue() : null);
        }
        if (status == 400) {
            Object error = json.get("error");
            String code400 = OAuthErrorException.INVALID_REQUEST.equals(error)
                    || OID4VCIPreAuthGrantType.INVALID_AUTHORIZATION_DETAILS.equals(error)
                    ? (String) error : OAuthErrorException.INVALID_GRANT;
            throw new RedeemException(code400, String.valueOf(json.get("error_description")), false);
        }
        if (status == 401) {
            LOGGER.errorf("The plugin rejected Keycloak's client authentication for %s; check "
                    + "oid4vci.redeem.client.* and the tenant's redeem_client settings", config.redeemUrl);
        } else {
            LOGGER.warnf("Pre-authorized code redeem call returned HTTP %d", status);
        }
        throw new RedeemException(OAuthErrorException.SERVER_ERROR, "redeem call returned " + status, true);
    }

    private static void addClientAuthentication(KeycloakSession session, RealmModel realm,
                                                OID4VCIPreAuthConfig config, Map<String, String> form) {
        String clientId = config.redeemClientId != null ? config.redeemClientId
                : Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        switch (config.redeemClientAuth) {
            case PRIVATE_KEY_JWT -> {
                form.put("client_assertion_type", JWT_BEARER);
                form.put("client_assertion", new JWSBuilder().type("JWT")
                        .jsonContent(assertionClaims(clientId, config)).sign(realmSigner(session)));
            }
            case CLIENT_SECRET_JWT -> {
                form.put("client_assertion_type", JWT_BEARER);
                form.put("client_assertion", new JWSBuilder().type("JWT")
                        .jsonContent(assertionClaims(clientId, config))
                        .hmac256(secret(session, config).getBytes(StandardCharsets.UTF_8)));
            }
            case CLIENT_SECRET_POST -> {
                form.put("client_id", clientId);
                form.put("client_secret", secret(session, config));
            }
            default -> throw new IllegalStateException(
                    "Unsupported " + OID4VCIPreAuthConfig.REDEEM_CLIENT_AUTH + ": " + config.redeemClientAuth);
        }
    }

    private static Map<String, Object> assertionClaims(String clientId, OID4VCIPreAuthConfig config) {
        long now = Time.currentTime();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", clientId);
        claims.put("sub", clientId);
        claims.put("aud", config.redeemUrl.toString());
        claims.put(CREDENTIAL_ISSUER, config.credentialIssuer);
        claims.put("iat", now);
        claims.put("exp", now + ASSERTION_TTL_SECONDS);
        claims.put("jti", UUID.randomUUID().toString());
        return claims;
    }

    private static SignatureSignerContext realmSigner(KeycloakSession session) {
        String algorithm = session.tokens().signatureAlgorithm(TokenCategory.ACCESS);
        try {
            return session.getProvider(SignatureProvider.class, algorithm).signer();
        } catch (Exception e) {
            throw new IllegalStateException("No active realm signing key for " + algorithm, e);
        }
    }

    /** The configured secret; a ${vault.key} reference is resolved through the Keycloak vault. */
    private static String secret(KeycloakSession session, OID4VCIPreAuthConfig config) {
        if (config.redeemClientSecret == null) {
            throw new IllegalStateException(OID4VCIPreAuthConfig.REDEEM_CLIENT_SECRET + " is not set");
        }
        try (VaultStringSecret secret = session.vault().getStringSecret(config.redeemClientSecret)) {
            return secret.get().orElseThrow(() -> new IllegalStateException(
                    OID4VCIPreAuthConfig.REDEEM_CLIENT_SECRET + " could not be resolved"));
        }
    }
}
