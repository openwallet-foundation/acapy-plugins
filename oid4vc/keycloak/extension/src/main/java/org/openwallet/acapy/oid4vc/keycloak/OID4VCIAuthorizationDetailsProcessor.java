package org.openwallet.acapy.oid4vc.keycloak;

import java.util.List;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.rar.AuthorizationDetailsProcessor;
import org.keycloak.protocol.oidc.rar.InvalidAuthorizationDetailsException;
import org.keycloak.representations.AuthorizationDetailsJSONRepresentation;

/**
 * {@code openid_credential} authorization details (RFC 9396, OID4VCI 1.0
 * §5.1.1, §6.2) for the ACA-Py pre-authorized code grant.
 * <p>
 * Keycloak's RAR processing calls this processor for each entry of a token
 * request's {@code authorization_details}. An entry must name a
 * {@code credential_configuration_id}, and its {@code locations}, if any, must
 * include this realm's credential issuer. The grant validates the entries
 * before redeeming the code, and the plugin checks the requested
 * configurations against the offer; after redemption each entry is returned
 * with {@code credential_identifiers}, the configuration itself (one
 * credential per exchange, accepted by the plugin as {@code credential_identifier}).
 * <p>
 * Keycloak's own {@code openid_credential} processor belongs to its experimental
 * OID4VC issuer (feature {@code oid4vc-vci}), which must stay disabled.
 */
public class OID4VCIAuthorizationDetailsProcessor implements AuthorizationDetailsProcessor<OID4VCIAuthorizationDetail> {

    /** Client session context attribute: credential configuration ids the redeemed code grants. */
    static final String GRANTED_CONFIGURATION_IDS = OID4VCIAuthorizationDetailsProcessor.class.getName() + ".granted";

    private final KeycloakSession session;

    public OID4VCIAuthorizationDetailsProcessor(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public boolean isSupported() {
        return true;
    }

    @Override
    public String getSupportedType() {
        return OID4VCIAuthorizationDetail.TYPE;
    }

    @Override
    public Class<OID4VCIAuthorizationDetail> getSupportedResponseJavaType() {
        return OID4VCIAuthorizationDetail.class;
    }

    @Override
    public OID4VCIAuthorizationDetail validateAuthorizationDetail(AuthorizationDetailsJSONRepresentation entry)
            throws InvalidAuthorizationDetailsException {
        OID4VCIAuthorizationDetail detail = OID4VCIAuthorizationDetail.PARSER.asSubtype(entry,
                OID4VCIAuthorizationDetail.class);
        String configurationId = detail.getCredentialConfigurationId();
        if (configurationId == null || configurationId.isBlank()) {
            throw new InvalidAuthorizationDetailsException(
                    OID4VCIAuthorizationDetail.TYPE + " entry has no credential_configuration_id");
        }
        List<String> locations = detail.getLocations();
        if (locations != null && !locations.isEmpty()) {
            String issuer = credentialIssuer();
            if (issuer == null || locations.stream().noneMatch(l -> sameUrl(l, issuer))) {
                throw new InvalidAuthorizationDetailsException(
                        OID4VCIAuthorizationDetail.TYPE + " entry locations do not include this credential issuer");
            }
        }
        return detail;
    }

    @Override
    @SuppressWarnings("unchecked")
    public OID4VCIAuthorizationDetail process(UserSessionModel userSession, ClientSessionContext clientSessionCtx,
                                              AuthorizationDetailsJSONRepresentation entry)
            throws InvalidAuthorizationDetailsException {
        OID4VCIAuthorizationDetail detail = validateAuthorizationDetail(entry);
        List<String> granted = clientSessionCtx.getAttribute(GRANTED_CONFIGURATION_IDS, List.class);
        if (granted == null) {
            throw new InvalidAuthorizationDetailsException(
                    OID4VCIAuthorizationDetail.TYPE + " is only supported with the pre-authorized code grant");
        }
        String configurationId = detail.getCredentialConfigurationId();
        if (!granted.contains(configurationId)) {
            // The plugin already checked this before redeeming the code.
            throw new InvalidAuthorizationDetailsException(
                    "credential configuration " + configurationId + " is not part of the offer");
        }
        detail.setCredentialIdentifiers(List.of(configurationId));
        return detail;
    }

    @Override
    public List<OID4VCIAuthorizationDetail> handleMissingAuthorizationDetails(UserSessionModel userSession,
                                                                              ClientSessionContext clientSessionCtx) {
        // No authorization_details in the request: none in the response (OID4VCI §6.2).
        return List.of();
    }

    @Override
    public OID4VCIAuthorizationDetail processStoredAuthorizationDetails(UserSessionModel userSession,
                                                                        ClientSessionContext clientSessionCtx,
                                                                        AuthorizationDetailsJSONRepresentation entry)
            throws InvalidAuthorizationDetailsException {
        return OID4VCIAuthorizationDetail.PARSER.asSubtype(entry, OID4VCIAuthorizationDetail.class);
    }

    @Override
    public void afterAuthorizationDetailsProcessed(UserSessionModel userSession, ClientSessionContext clientSessionCtx,
                                                   OID4VCIAuthorizationDetail detail) {
    }

    @Override
    public void close() {
    }

    private String credentialIssuer() {
        RealmModel realm = session.getContext().getRealm();
        return realm == null ? null : OID4VCIPreAuthConfig.of(realm).credentialIssuer;
    }

    private static boolean sameUrl(String a, String b) {
        return a != null && stripSlash(a).equals(stripSlash(b));
    }

    private static String stripSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
