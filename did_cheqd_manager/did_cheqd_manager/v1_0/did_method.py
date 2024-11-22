"""Cheqd DID Method."""

from acapy_agent.wallet.did_method import (
    KEY,
    PEER2,
    PEER4,
    SOV,
    DIDMethod,
    HolderDefinedDid,
)
from acapy_agent.wallet.key_type import ED25519
from acapy_agent.wallet.routes import DIDListQueryStringSchema
from marshmallow import fields, validate

CHEQD = DIDMethod(
    name="cheqd",
    key_types=[ED25519],
    rotation=True,
    holder_defined_did=HolderDefinedDid.ALLOWED,
)


class CustomDIDListQueryStringSchema(DIDListQueryStringSchema):
    """Class to extend DIDListQueryStringSchema."""

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
