package org.openwallet.acapy.oid4vc.keycloak;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testframework.annotations.InjectHttpServer;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs the extension in a real Keycloak (test framework distribution mode,
 * extension deployed from this project) against a stub of the plugin's redeem
 * endpoint, served by the test framework's HTTP server.
 * <p>
 * Covers the anonymous (attestation off) path: DPoP requirement, redemption and
 * its client assertion, access token claims and binding, authorization_details,
 * refresh tokens (claims carried over, key binding, rotation) and the refresh
 * client hint (no client_id, or the unregistered client_id of the token request).
 * Attestation-based client authentication is covered by the end-to-end test in
 * {@code oid4vc/keycloak/e2e}.
 */
@KeycloakIntegrationTest(config = OID4VCIPreAuthGrantTypeTest.ServerConfig.class)
public class OID4VCIPreAuthGrantTypeTest {

    static final String CREDENTIAL_ISSUER = "https://issuer.example/tenant/t1";
    static final String ANONYMOUS_CLIENT = "oid4vci-wallet-public";
    static final String REDEEM_PATH = "/oid4vci/pre-auth/redeem";
    // The test framework's HttpServer listens on 127.0.0.1:8500.
    static final String REDEEM_URL = "http://127.0.0.1:8500" + REDEEM_PATH;
    static final String REFRESH_ID = "refresh-" + UUID.randomUUID();
    static final String PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    static final String OFFERED_CONFIGURATION = "MyCred";
    /** A client_id the realm doesn't know, as wallets often send. */
    static final String WALLET_APP = "some-wallet-app";

    @InjectHttpServer
    HttpServer httpServer;

    @InjectRealm(config = PreAuthRealm.class)
    ManagedRealm realm;

    private final HttpClient http = HttpClient.newHttpClient();
    private final List<Map<String, String>> redeemCalls = new CopyOnWriteArrayList<>();
    private volatile int redeemStatus = 200;

    public static class ServerConfig implements KeycloakServerConfig {
        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            return config.dependencyCurrentProject();
        }
    }

    public static class PreAuthRealm implements RealmConfig {
        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            return realm
                    .revokeRefreshToken(true)
                    .refreshTokenMaxReuse(0)
                    .attribute(OID4VCIPreAuthConfig.REDEEM_URL, REDEEM_URL)
                    .attribute(OID4VCIPreAuthConfig.CREDENTIAL_ISSUER, CREDENTIAL_ISSUER)
                    .attribute(OID4VCIPreAuthConfig.REQUIRE_CLIENT_ATTESTATION, "false")
                    .attribute(OID4VCIPreAuthConfig.ANONYMOUS_CLIENT_ID, ANONYMOUS_CLIENT)
                    .users(UserBuilder.create("oid4vci-holder").enabled(true)
                            .name("OID4VCI", "Holder").email("oid4vci-holder@invalid.example")
                            .emailVerified(true))
                    .clients(ClientBuilder.create(ANONYMOUS_CLIENT).publicClient()
                            .attribute("dpop.bound.access.tokens", "true"));
        }
    }

    @BeforeEach
    void stubRedeemEndpoint() {
        redeemCalls.clear();
        redeemStatus = 200;
        try {
            httpServer.removeContext(REDEEM_PATH);
        } catch (IllegalArgumentException ignored) {
            // not registered yet
        }
        httpServer.createContext(REDEEM_PATH, this::handleRedeem);
    }

    private void handleRedeem(HttpExchange exchange) throws IOException {
        Map<String, String> form = parseForm(new String(exchange.getRequestBody().readAllBytes(),
                StandardCharsets.UTF_8));
        redeemCalls.add(form);
        // Like the plugin: requested configurations must be the offered one.
        String requested = form.get(RedeemClient.CREDENTIAL_CONFIGURATION_IDS);
        boolean otherConfiguration = requested != null
                && !List.of(OFFERED_CONFIGURATION).equals(JsonSerialization.readValue(requested, List.class));
        int status = otherConfiguration ? 400 : redeemStatus;
        Object body = otherConfiguration
                ? Map.of("error", "invalid_authorization_details", "error_description", "not offered")
                : status == 200
                        ? Map.of("refresh_id", REFRESH_ID, "credential_configuration_ids", List.of(OFFERED_CONFIGURATION),
                                "expires_in", 300)
                        : Map.of("error", "invalid_grant", "error_description", "tx_code is invalid");
        byte[] bytes = JsonSerialization.writeValueAsBytes(body);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    @Test
    public void tokenRequestRedeemsCodeAndIssuesBoundTokens() throws Exception {
        Wallet wallet = new Wallet();
        HttpResponse<String> response = tokenRequest(wallet, true);
        assertEquals(200, response.statusCode(), response.body());
        Map<?, ?> token = json(response.body());
        assertEquals("DPoP", token.get("token_type"));
        assertNotNull(token.get("refresh_token"), "refresh token issued");

        // The redeem call: code, credential issuer, realm-signed client assertion
        assertEquals(1, redeemCalls.size());
        Map<String, String> redeem = redeemCalls.get(0);
        assertEquals("code-1", redeem.get("pre_authorized_code"));
        assertEquals(CREDENTIAL_ISSUER, redeem.get("credential_issuer"));
        assertEquals(RedeemClient.JWT_BEARER, redeem.get("client_assertion_type"));
        Map<?, ?> assertion = claims(redeem.get("client_assertion"));
        assertEquals(realm.getBaseUrl(), assertion.get("iss"));
        assertEquals(realm.getBaseUrl(), assertion.get("sub"));
        assertEquals(REDEEM_URL, assertion.get("aud"));
        assertEquals(CREDENTIAL_ISSUER, assertion.get("credential_issuer"));
        assertNotNull(assertion.get("jti"));

        // The access token: exchange reference, audience, DPoP binding
        Map<?, ?> access = claims((String) token.get("access_token"));
        assertEquals(REFRESH_ID, access.get("refresh_id"));
        assertEquals(List.of("MyCred"), access.get("credential_configuration_ids"));
        assertAudience(access, CREDENTIAL_ISSUER);
        assertEquals(wallet.thumbprint(), ((Map<?, ?>) access.get("cnf")).get("jkt"));

        // No authorization_details in the request: none in the response (OID4VCI §6.2)
        assertNull(token.get("authorization_details"));
        assertNull(access.get("authorization_details"));
        assertNull(redeem.get(RedeemClient.CREDENTIAL_CONFIGURATION_IDS));
    }

    @Test
    public void authorizationDetailsAreReturnedWithCredentialIdentifiers() throws Exception {
        Wallet wallet = new Wallet();
        String requested = "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\""
                + OFFERED_CONFIGURATION + "\",\"locations\":[\"" + CREDENTIAL_ISSUER + "\"]}]";
        HttpResponse<String> response = tokenRequest(wallet, true, requested);
        assertEquals(200, response.statusCode(), response.body());
        Map<?, ?> token = json(response.body());

        // The plugin was asked to check the requested configuration before redeeming
        assertEquals("[\"" + OFFERED_CONFIGURATION + "\"]",
                redeemCalls.get(0).get(RedeemClient.CREDENTIAL_CONFIGURATION_IDS));

        // Response and access token: the entry with credential_identifiers (OID4VCI §6.2)
        assertGrantedDetails(token.get("authorization_details"));
        assertGrantedDetails(claims((String) token.get("access_token")).get("authorization_details"));

        // Kept on refresh
        HttpResponse<String> refreshed = refreshRequest(wallet, (String) token.get("refresh_token"), ANONYMOUS_CLIENT);
        assertEquals(200, refreshed.statusCode(), refreshed.body());
        Map<?, ?> refreshedToken = json(refreshed.body());
        assertGrantedDetails(refreshedToken.get("authorization_details"));
        assertGrantedDetails(claims((String) refreshedToken.get("access_token")).get("authorization_details"));
    }

    @Test
    public void authorizationDetailsForAnotherConfigurationAreRejectedByThePlugin() throws Exception {
        String requested = "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"Other\"}]";
        HttpResponse<String> response = tokenRequest(new Wallet(), true, requested);
        assertEquals(400, response.statusCode(), response.body());
        assertEquals("invalid_authorization_details", json(response.body()).get("error"));
        assertEquals("[\"Other\"]", redeemCalls.get(0).get(RedeemClient.CREDENTIAL_CONFIGURATION_IDS));
    }

    @Test
    public void invalidAuthorizationDetailsAreRejectedBeforeRedeeming() throws Exception {
        for (String requested : List.of(
                "[{\"type\":\"payment_initiation\"}]",
                "[{\"type\":\"openid_credential\"}]",
                "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + OFFERED_CONFIGURATION
                        + "\",\"locations\":[\"https://other-issuer.example\"]}]",
                "[]",
                "not json")) {
            HttpResponse<String> response = tokenRequest(new Wallet(), true, requested);
            assertEquals(400, response.statusCode(), requested + ": " + response.body());
            assertEquals("invalid_authorization_details", json(response.body()).get("error"), requested);
        }
        assertTrue(redeemCalls.isEmpty(), "nothing is redeemed");
    }

    @Test
    public void dpopProofIsRequired() throws Exception {
        HttpResponse<String> response = tokenRequest(new Wallet(), false);
        assertEquals(400, response.statusCode(), response.body());
        assertEquals("invalid_dpop_proof", json(response.body()).get("error"));
        assertTrue(redeemCalls.isEmpty(), "the code must not be redeemed");
    }

    @Test
    public void rejectedRedemptionIsInvalidGrant() throws Exception {
        redeemStatus = 400;
        HttpResponse<String> response = tokenRequest(new Wallet(), true);
        assertEquals(400, response.statusCode(), response.body());
        assertEquals("invalid_grant", json(response.body()).get("error"));
    }

    @Test
    public void invalidRedeemUrlIsReportedAsNotConfigured() throws Exception {
        RealmRepresentation rep = realm.admin().toRepresentation();
        Map<String, String> attributes = new HashMap<>(rep.getAttributes());
        attributes.put(OID4VCIPreAuthConfig.REDEEM_URL, REDEEM_URL + " with a space");
        rep.setAttributes(attributes);
        realm.admin().update(rep);
        try {
            HttpResponse<String> response = tokenRequest(new Wallet(), true);
            assertEquals(500, response.statusCode(), response.body());
            assertEquals("server_error", json(response.body()).get("error"));
            assertTrue(redeemCalls.isEmpty(), "nothing is redeemed");
        } finally {
            attributes.put(OID4VCIPreAuthConfig.REDEEM_URL, REDEEM_URL);
            rep.setAttributes(attributes);
            realm.admin().update(rep);
        }
    }

    @Test
    public void refreshKeepsTheExchangeAndRotates() throws Exception {
        Wallet wallet = new Wallet();
        String refreshToken = (String) json(tokenRequest(wallet, true).body()).get("refresh_token");

        HttpResponse<String> refreshed = refreshRequest(wallet, refreshToken, ANONYMOUS_CLIENT);
        assertEquals(200, refreshed.statusCode(), refreshed.body());
        Map<?, ?> token = json(refreshed.body());
        Map<?, ?> access = claims((String) token.get("access_token"));
        assertEquals(REFRESH_ID, access.get("refresh_id"));
        assertAudience(access, CREDENTIAL_ISSUER);
        assertEquals(wallet.thumbprint(), ((Map<?, ?>) access.get("cnf")).get("jkt"));
        assertNotEquals(refreshToken, token.get("refresh_token"), "refresh token rotated");
        assertEquals(1, redeemCalls.size(), "refresh does not redeem again");

        // The rotated-out refresh token is rejected
        HttpResponse<String> reused = refreshRequest(wallet, refreshToken, ANONYMOUS_CLIENT);
        assertEquals(400, reused.statusCode(), reused.body());
        assertEquals("invalid_grant", json(reused.body()).get("error"));
    }

    @Test
    public void refreshTokenIsBoundToTheWalletKey() throws Exception {
        String refreshToken = (String) json(tokenRequest(new Wallet(), true).body()).get("refresh_token");
        HttpResponse<String> response = refreshRequest(new Wallet(), refreshToken, ANONYMOUS_CLIENT);
        assertEquals(400, response.statusCode(), response.body());
        assertEquals("invalid_grant", json(response.body()).get("error"));
    }

    @Test
    public void refreshClientHintIdentifiesTheAnonymousClient() throws Exception {
        installRefreshClientHint();
        Wallet wallet = new Wallet();
        String refreshToken = (String) json(tokenRequest(wallet, true).body()).get("refresh_token");

        // No client_id: the wallet never learned the anonymous client's id
        HttpResponse<String> response = refreshRequest(wallet, refreshToken, null);
        assertEquals(200, response.statusCode(), response.body());
        assertEquals(REFRESH_ID, claims((String) json(response.body()).get("access_token")).get("refresh_id"));
    }

    @Test
    public void refreshClientHintAcceptsTheUnregisteredClientIdOfTheTokenRequest() throws Exception {
        installRefreshClientHint();
        Wallet wallet = new Wallet();
        Map<?, ?> token = json(tokenRequest(wallet, true, null, WALLET_APP).body());
        Map<?, ?> access = claims((String) token.get("access_token"));
        assertEquals(ANONYMOUS_CLIENT, access.get("azp"));
        assertNull(access.get("wallet_client_id"), "not in access tokens");
        String refreshToken = (String) token.get("refresh_token");
        assertEquals(WALLET_APP, claims(refreshToken).get("wallet_client_id"));

        HttpResponse<String> refreshed = refreshRequest(wallet, refreshToken, WALLET_APP);
        assertEquals(200, refreshed.statusCode(), refreshed.body());
        Map<?, ?> refreshedToken = json(refreshed.body());
        Map<?, ?> refreshedAccess = claims((String) refreshedToken.get("access_token"));
        assertEquals(REFRESH_ID, refreshedAccess.get("refresh_id"));
        assertEquals(ANONYMOUS_CLIENT, refreshedAccess.get("azp"));
        assertNull(refreshedAccess.get("wallet_client_id"), "not in access tokens");

        // Kept on rotation
        String rotated = (String) refreshedToken.get("refresh_token");
        assertEquals(WALLET_APP, claims(rotated).get("wallet_client_id"));
        HttpResponse<String> again = refreshRequest(wallet, rotated, WALLET_APP);
        assertEquals(200, again.statusCode(), again.body());
    }

    @Test
    public void refreshWithAnotherUnregisteredClientIdIsRejected() throws Exception {
        installRefreshClientHint();
        Wallet wallet = new Wallet();
        String refreshToken = (String) json(tokenRequest(wallet, true, null, WALLET_APP).body()).get("refresh_token");
        assertInvalidClient(refreshRequest(wallet, refreshToken, "another-wallet-app"));

        // A token request without client_id records none, so no unknown client_id matches.
        Wallet other = new Wallet();
        String withoutClientId = (String) json(tokenRequest(other, true).body()).get("refresh_token");
        assertNull(claims(withoutClientId).get("wallet_client_id"));
        assertInvalidClient(refreshRequest(other, withoutClientId, WALLET_APP));
    }

    // --- Helpers ----------------------------------------------------------------------------------------------

    private static void assertInvalidClient(HttpResponse<String> response) throws IOException {
        assertEquals(401, response.statusCode(), response.body());
        assertEquals("invalid_client", json(response.body()).get("error"));
    }

    /** The hint authenticator must run first in a copy of the built-in "clients" flow. */
    private void installRefreshClientHint() {
        var flows = realm.admin().flows();
        String alias = "clients-oid4vci";
        if (flows.getFlows().stream().noneMatch(f -> alias.equals(f.getAlias()))) {
            flows.copy("clients", Map.of("newName", alias)).close();
            flows.addExecution(alias, Map.of("provider", OID4VCIRefreshClientHintAuthenticator.PROVIDER_ID));
            List<AuthenticationExecutionInfoRepresentation> executions = flows.getExecutions(alias);
            AuthenticationExecutionInfoRepresentation hint = executions.stream()
                    .filter(e -> OID4VCIRefreshClientHintAuthenticator.PROVIDER_ID.equals(e.getProviderId()))
                    .findFirst().orElseThrow();
            hint.setRequirement("ALTERNATIVE");
            flows.updateExecutions(alias, hint);
            for (int i = executions.indexOf(hint); i > 0; i--) {
                flows.raisePriority(hint.getId());
            }
        }
        RealmRepresentation rep = realm.admin().toRepresentation();
        rep.setClientAuthenticationFlow(alias);
        realm.admin().update(rep);
    }

    private String tokenEndpoint() {
        return realm.getBaseUrl() + "/protocol/openid-connect/token";
    }

    private HttpResponse<String> tokenRequest(Wallet wallet, boolean withDpop) throws Exception {
        return tokenRequest(wallet, withDpop, null);
    }

    private HttpResponse<String> tokenRequest(Wallet wallet, boolean withDpop, String authorizationDetails)
            throws Exception {
        return tokenRequest(wallet, withDpop, authorizationDetails, null);
    }

    private HttpResponse<String> tokenRequest(Wallet wallet, boolean withDpop, String authorizationDetails,
                                              String clientId) throws Exception {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", PRE_AUTH_GRANT);
        form.put("pre-authorized_code", "code-1");
        form.put("tx_code", "1234");
        if (authorizationDetails != null) {
            form.put("authorization_details", authorizationDetails);
        }
        if (clientId != null) {
            form.put("client_id", clientId);
        }
        return post(form, withDpop ? wallet.dpopProof(tokenEndpoint()) : null);
    }

    private static void assertGrantedDetails(Object details) {
        assertTrue(details instanceof List<?> list && list.size() == 1, "authorization_details " + details);
        Map<?, ?> entry = (Map<?, ?>) ((List<?>) details).get(0);
        assertEquals("openid_credential", entry.get("type"));
        assertEquals(OFFERED_CONFIGURATION, entry.get("credential_configuration_id"));
        assertEquals(List.of(OFFERED_CONFIGURATION), entry.get("credential_identifiers"));
        assertEquals(List.of(CREDENTIAL_ISSUER), entry.get("locations"));
    }

    private HttpResponse<String> refreshRequest(Wallet wallet, String refreshToken, String clientId)
            throws Exception {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", refreshToken);
        if (clientId != null) {
            form.put("client_id", clientId);
        }
        return post(form, wallet.dpopProof(tokenEndpoint()));
    }

    private HttpResponse<String> post(Map<String, String> form, String dpop) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(tokenEndpoint()))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form.entrySet().stream()
                        .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                                + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                        .collect(Collectors.joining("&"))));
        if (dpop != null) {
            request.header("DPoP", dpop);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static void assertAudience(Map<?, ?> claims, String expected) {
        Object aud = claims.get("aud");
        assertTrue(expected.equals(aud) || (aud instanceof List<?> list && list.contains(expected)),
                "aud " + aud + " should include " + expected);
    }

    private static Map<?, ?> json(String body) throws IOException {
        return JsonSerialization.readValue(body, Map.class);
    }

    private static Map<?, ?> claims(String jwt) throws IOException {
        return JsonSerialization.readValue(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), Map.class);
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> form = new LinkedHashMap<>();
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                form.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return form;
    }

    /** A wallet's DPoP key. */
    static final class Wallet {
        private final KeyWrapper key = new KeyWrapper();
        private final JWK jwk;

        Wallet() throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair pair = generator.generateKeyPair();
            key.setKid(UUID.randomUUID().toString());
            key.setAlgorithm(Algorithm.ES256);
            key.setType(KeyType.EC);
            key.setUse(KeyUse.SIG);
            key.setPrivateKey(pair.getPrivate());
            key.setPublicKey(pair.getPublic());
            jwk = JWKBuilder.create().algorithm(Algorithm.ES256).ec(pair.getPublic());
        }

        String thumbprint() {
            return JWKSUtils.computeThumbprint(jwk);
        }

        String dpopProof(String htu) throws Exception {
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("jti", UUID.randomUUID().toString());
            claims.put("htm", "POST");
            claims.put("htu", htu);
            claims.put("iat", Time.currentTime());
            return new JWSBuilder().type("dpop+jwt").jwk(jwk).jsonContent(claims)
                    .sign(new ECDSASignatureSignerContext(key));
        }
    }
}
