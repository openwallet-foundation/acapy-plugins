package org.openwallet.acapy.oid4vc.keycloak;

import java.net.URI;
import java.net.URISyntaxException;

import org.keycloak.models.RealmModel;

import org.jboss.logging.Logger;

/**
 * Per-realm configuration, read from realm attributes so each realm (one per
 * issuer tenant) can point at its own plugin instance.
 */
final class OID4VCIPreAuthConfig {

    private static final Logger LOGGER = Logger.getLogger(OID4VCIPreAuthConfig.class);

    /**
     * Plugin redeem endpoint on its admin API (required), e.g.
     * http://issuer:3001/oid4vci/pre-auth/redeem. The same endpoint serves all
     * tenants; the tenant is the credential issuer named in the request.
     */
    static final String REDEEM_URL = "oid4vci.redeem.url";
    /**
     * How Keycloak authenticates to the redeem endpoint: private_key_jwt (default,
     * realm key), client_secret_jwt or client_secret_post.
     */
    static final String REDEEM_CLIENT_AUTH = "oid4vci.redeem.client.auth";
    /** Client id presented to the plugin (default: the realm issuer URL). */
    static final String REDEEM_CLIENT_ID = "oid4vci.redeem.client.id";
    /** Secret for the client_secret_* methods; may be a ${vault.key} reference. */
    static final String REDEEM_CLIENT_SECRET = "oid4vci.redeem.client.secret";
    /**
     * Credential Issuer Identifier of the plugin tenant (required). Added to the
     * access token audience, and names the tenant in redeem requests.
     */
    static final String CREDENTIAL_ISSUER = "oid4vci.credential.issuer";
    /** Require attestation-based client authentication (default true). */
    static final String REQUIRE_CLIENT_ATTESTATION = "oid4vci.require.client.attestation";
    /** Require a DPoP proof and issue DPoP-bound tokens (default true). */
    static final String REQUIRE_DPOP = "oid4vci.require.dpop";
    /**
     * Public client used for wallets that do not present a client attestation.
     * Only honoured when client attestation is not required; unset means such
     * requests are rejected.
     */
    static final String ANONYMOUS_CLIENT_ID = "oid4vci.anonymous.client.id";
    /** Username of the generic, credential-less holder user (default oid4vci-holder). */
    static final String HOLDER_USERNAME = "oid4vci.holder.username";
    /** Access token claim carrying the plugin exchange refresh_id (default refresh_id). */
    static final String REFRESH_ID_CLAIM = "oid4vci.refresh.id.claim";
    /** Issue refresh tokens (default true). */
    static final String REFRESH_TOKENS = "oid4vci.refresh.tokens";
    /**
     * Refresh token lifetime in seconds (default one year). Absolute: rotated
     * refresh tokens keep the expiry of the first one.
     */
    static final String REFRESH_TOKEN_LIFESPAN = "oid4vci.refresh.token.lifespan";
    /** Timeout for the redeem call in milliseconds (default 5000). */
    static final String REDEEM_TIMEOUT_MS = "oid4vci.redeem.timeout.ms";

    final URI redeemUrl;
    final String redeemClientAuth;
    final String redeemClientId;
    final String redeemClientSecret;
    final String credentialIssuer;
    final boolean requireClientAttestation;
    final boolean requireDpop;
    final String anonymousClientId;
    final String holderUsername;
    final String refreshIdClaim;
    final int redeemTimeoutMs;
    final boolean refreshTokens;
    final int refreshTokenLifespan;

    private OID4VCIPreAuthConfig(RealmModel realm) {
        this.redeemUrl = httpUrl(realm, realm.getAttribute(REDEEM_URL));
        this.redeemClientAuth = orDefault(realm.getAttribute(REDEEM_CLIENT_AUTH), "private_key_jwt");
        this.redeemClientId = trimToNull(realm.getAttribute(REDEEM_CLIENT_ID));
        this.redeemClientSecret = trimToNull(realm.getAttribute(REDEEM_CLIENT_SECRET));
        this.credentialIssuer = trimToNull(realm.getAttribute(CREDENTIAL_ISSUER));
        this.requireClientAttestation = bool(realm.getAttribute(REQUIRE_CLIENT_ATTESTATION), true);
        this.requireDpop = bool(realm.getAttribute(REQUIRE_DPOP), true);
        this.anonymousClientId = trimToNull(realm.getAttribute(ANONYMOUS_CLIENT_ID));
        this.holderUsername = orDefault(realm.getAttribute(HOLDER_USERNAME), "oid4vci-holder");
        this.refreshIdClaim = orDefault(realm.getAttribute(REFRESH_ID_CLAIM), "refresh_id");
        this.redeemTimeoutMs = intOr(realm.getAttribute(REDEEM_TIMEOUT_MS), 5000);
        this.refreshTokens = bool(realm.getAttribute(REFRESH_TOKENS), true);
        this.refreshTokenLifespan = intOr(realm.getAttribute(REFRESH_TOKEN_LIFESPAN), 31_536_000);
    }

    static OID4VCIPreAuthConfig of(RealmModel realm) {
        return new OID4VCIPreAuthConfig(realm);
    }

    boolean isComplete() {
        return redeemUrl != null && credentialIssuer != null;
    }

    /** An absolute http(s) URL, or null (logged) when the attribute is unusable. */
    private static URI httpUrl(RealmModel realm, String value) {
        String trimmed = trimToNull(value);
        if (trimmed == null) {
            return null;
        }
        try {
            URI uri = new URI(trimmed);
            String scheme = uri.getScheme();
            if (uri.getHost() == null || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
                throw new URISyntaxException(trimmed, "not an absolute http(s) URL");
            }
            return uri;
        } catch (URISyntaxException e) {
            LOGGER.warnf("Realm '%s': ignoring invalid %s '%s': %s", realm.getName(), REDEEM_URL, trimmed,
                    e.getReason());
            return null;
        }
    }

    private static String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String orDefault(String value, String fallback) {
        String trimmed = trimToNull(value);
        return trimmed == null ? fallback : trimmed;
    }

    private static boolean bool(String value, boolean fallback) {
        String trimmed = trimToNull(value);
        return trimmed == null ? fallback : Boolean.parseBoolean(trimmed);
    }

    private static int intOr(String value, int fallback) {
        try {
            String trimmed = trimToNull(value);
            return trimmed == null ? fallback : Integer.parseInt(trimmed);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
