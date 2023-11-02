from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields


class OID4VCICredentialSupported(BaseRecord):
    class Meta:
        schema_class = "CredSupRecordSchema"

    RECORD_ID_NAME = "oid4vci_id"
    RECORD_TYPE = "oid4vci_exchange"
    EVENT_NAMESPACE = "oid4vci"
    TAG_NAMES = {"credential_supported_id", "types", "scope"}

    def __init__(
        self,
        *,
        credential_supported_id,
        format,
        types,
        cryptographic_binding_methods_supported,
        cryptographic_suites_supported,
        display,
        credential_subject,
        scope,
        **kwargs,
    ):
        super().__init__(
            None,
            state="init",
            **kwargs,
        )
        self.credential_supported_id = credential_supported_id
        self.format = format
        self.types = types
        self.cryptographic_binding_methods_supported = (
            cryptographic_binding_methods_supported
        )
        self.cryptographic_suites_supported = cryptographic_suites_supported
        self.display = display
        self.credential_subject = credential_subject
        self.scope = scope

    def web_serialize(self) -> dict:
        return self.serialize()

    @property
    def id(self):
        return self._id


# TODO: add validation
class CredSupRecordSchema(BaseRecordSchema):
    class Meta:
        model_class = OID4VCICredentialSupported

    credential_supported_id = fields.Str(
        required=True, metadata={"example": "UniversityDegree_JWT"}
    )
    format = fields.Str(required=True, metadata={"example": "jwt_vc_json"})
    types = fields.List(
        fields.Str(),
        metadata={"example": ["VerifiableCredential", "UniversityDegreeCredential"]},
    )
    cryptographic_binding_methods_supported = fields.List(
        fields.Str(), metadata={"example": []}
    )
    cryptographic_suites_supported = fields.List(
        fields.Str(), metadata={"example": ["ES256K"]}
    )
    display = fields.List(
        fields.Dict(),
        metadata={
            "example": [
                {
                    "name": "University Credential",
                    "locale": "en-US",
                    "logo": {
                        "url": "https://exampleuniversity.com/public/logo.png",
                        "alt_text": "a square logo of a university",
                    },
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF",
                }
            ]
        },
    )
    credential_subject = fields.Dict(
        metadata={
            "given_name": {"display": [{"name": "Given Name", "locale": "en-US"}]},
            "family_name": {"display": [{"name": "Surname", "locale": "en-US"}]},
            "degree": {},
            "gpa": {"display": [{"name": "GPA"}]},
        }
    )
    scope = fields.Str(
        required=True,
    )
