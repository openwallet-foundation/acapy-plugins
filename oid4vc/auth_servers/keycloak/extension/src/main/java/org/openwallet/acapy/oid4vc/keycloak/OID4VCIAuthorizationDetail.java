package org.openwallet.acapy.oid4vc.keycloak;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.keycloak.representations.AuthorizationDetailsJSONRepresentation;
import org.keycloak.util.AuthorizationDetailsParser;
import org.keycloak.util.JsonSerialization;

/**
 * An {@code openid_credential} authorization details entry (OID4VCI 1.0
 * §5.1.1, §6.2). Other members ({@code claims}, ...) are kept as custom data
 * and returned as received.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OID4VCIAuthorizationDetail extends AuthorizationDetailsJSONRepresentation {

    public static final String TYPE = "openid_credential";

    /** Converts generic entries of this type to this class (registered for {@link #TYPE}). */
    static final AuthorizationDetailsParser PARSER = new AuthorizationDetailsParser() {
        @Override
        public <T extends AuthorizationDetailsJSONRepresentation> T asSubtype(
                AuthorizationDetailsJSONRepresentation detail, Class<T> type) {
            return type.isInstance(detail) ? type.cast(detail) : JsonSerialization.mapper.convertValue(detail, type);
        }
    };

    @JsonProperty("credential_configuration_id")
    private String credentialConfigurationId;

    @JsonProperty("credential_identifiers")
    private List<String> credentialIdentifiers;

    public String getCredentialConfigurationId() {
        return credentialConfigurationId;
    }

    public void setCredentialConfigurationId(String credentialConfigurationId) {
        this.credentialConfigurationId = credentialConfigurationId;
    }

    public List<String> getCredentialIdentifiers() {
        return credentialIdentifiers;
    }

    public void setCredentialIdentifiers(List<String> credentialIdentifiers) {
        this.credentialIdentifiers = credentialIdentifiers;
    }
}
