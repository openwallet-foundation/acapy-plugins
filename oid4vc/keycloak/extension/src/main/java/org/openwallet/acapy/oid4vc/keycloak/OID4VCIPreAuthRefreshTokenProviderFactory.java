package org.openwallet.acapy.oid4vc.keycloak;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.refresh.RefreshTokenProvider;
import org.keycloak.protocol.oidc.refresh.RefreshTokenProviderFactory;

/** Registers {@link OID4VCIPreAuthRefreshTokenProvider}. */
public class OID4VCIPreAuthRefreshTokenProviderFactory implements RefreshTokenProviderFactory {

    static final String PROVIDER_ID = "acapy-oid4vci-pre-auth";

    @Override
    public RefreshTokenProvider create(KeycloakSession session) {
        return new OID4VCIPreAuthRefreshTokenProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public int order() {
        // Ahead of Keycloak's default (0) and OID4VCI (10) providers; supports()
        // only matches tokens from the pre-authorized code grant.
        return 100;
    }
}
