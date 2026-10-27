package org.openwallet.acapy.oid4vc.keycloak;

import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;

import org.jboss.logging.Logger;

/**
 * Registers {@link OID4VCIPreAuthGrantType} for the OID4VCI pre-authorized code
 * grant type. Keycloak's own experimental implementation uses the same id, so
 * the {@code oid4vc-vci-preauth-code} feature must stay disabled.
 */
public class OID4VCIPreAuthGrantTypeFactory implements OAuth2GrantTypeFactory {

    private static final Logger LOGGER = Logger.getLogger(OID4VCIPreAuthGrantTypeFactory.class);

    @Override
    public String getId() {
        return OID4VCIPreAuthGrantType.GRANT_TYPE;
    }

    @Override
    public String getShortcut() {
        // Keycloak's built-in pre-authorized code grant uses "pc".
        return "pa";
    }

    @Override
    public OAuth2GrantType create(KeycloakSession session) {
        return new OID4VCIPreAuthGrantType();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        if (Profile.isFeatureEnabled(Profile.Feature.OID4VC_VCI_PREAUTH_CODE)) {
            LOGGER.warn("Feature oid4vc-vci-preauth-code is enabled; it registers a grant type with the same id "
                    + "as the ACA-Py OID4VCI extension. Disable it.");
        }
        if (!Profile.isFeatureEnabled(Profile.Feature.CLIENT_AUTH_ABCA)) {
            LOGGER.warn("Feature client-auth-abca is disabled; realms that require client attestation "
                    + "(oid4vci.require.client.attestation, default true) will reject all token requests.");
        }
    }

    @Override
    public int order() {
        return 100;
    }

    @Override
    public void close() {
    }
}
