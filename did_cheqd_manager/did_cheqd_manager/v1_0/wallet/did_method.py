from acapy_agent.wallet.did_method import DIDMethod, HolderDefinedDid
from acapy_agent.wallet.key_type import ED25519
from marshmallow import fields, validate
from acapy_agent.wallet.did_method import (KEY,SOV, PEER2, PEER4)
from acapy_agent.wallet.routes import DIDListQueryStringSchema

CHEQD = DIDMethod(
    name="cheqd",
    key_types=[ED25519],
    rotation=True,
    holder_defined_did=HolderDefinedDid.ALLOWED,
)

class CustomDIDListQueryStringSchema(DIDListQueryStringSchema):
    method = fields.Str(
        required=False,
        validate=validate.OneOf(
            [
                KEY.method_name,
                SOV.method_name,
                CHEQD.method_name,
                PEER2.method_name,
                PEER4.method_name,
            ]
        ),
        metadata={
            "example": KEY.method_name,
            "description": (
                "DID method to query for. e.g. sov to only fetch indy/sov DIDs"
            ),
        },
    )