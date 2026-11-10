package org.openwallet.acapy.oid4vc.keycloak;

import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.rar.AuthorizationDetailsProcessor;
import org.keycloak.protocol.oidc.rar.AuthorizationDetailsProcessorFactory;
import org.keycloak.util.AuthorizationDetailsParser;

import org.jboss.logging.Logger;

/**
 * Registers {@link OID4VCIAuthorizationDetailsProcessor}. Keycloak selects
 * authorization details processors by id = {@code type}, so this uses the id
 * {@code openid_credential}, like the processor of Keycloak's experimental
 * OID4VC issuer, which must stay disabled. It also registers the JSON parser
 * Keycloak needs for {@code openid_credential} entries in token responses.
 */
public class OID4VCIAuthorizationDetailsProcessorFactory implements AuthorizationDetailsProcessorFactory {

    private static final Logger LOGGER = Logger.getLogger(OID4VCIAuthorizationDetailsProcessorFactory.class);

    @Override
    public String getId() {
        return OID4VCIAuthorizationDetail.TYPE;
    }

    @Override
    public AuthorizationDetailsProcessor<?> create(KeycloakSession session) {
        return new OID4VCIAuthorizationDetailsProcessor(session);
    }

    @Override
    public void init(Config.Scope config) {
        AuthorizationDetailsParser.registerParser(OID4VCIAuthorizationDetail.TYPE, OID4VCIAuthorizationDetail.PARSER);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        if (Profile.isFeatureEnabled(Profile.Feature.OID4VC_VCI)) {
            LOGGER.warn("Feature oid4vc-vci is enabled; its openid_credential authorization details processor "
                    + "has the same id as the ACA-Py OID4VCI extension's. Disable it.");
        }
    }

    @Override
    public int order() {
        return 100;
    }
}
