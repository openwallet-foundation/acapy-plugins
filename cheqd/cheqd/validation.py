"""Cheqd Validation."""

import re

from marshmallow.validate import Regexp


class CheqdDID(Regexp):
    """Validate value against cheqd DID."""

    EXAMPLE = "did:cheqd:testnet:099be283-4302-40cc-9850-22016bcd1d86"

    UUID = r"([a-z,0-9,-]{36,36})"
    ID_CHAR = r"(?:[a-zA-Z0-9]{21,22}|" + UUID + ")"
    NETWORK = r"(testnet|mainnet)"
    METHOD_ID = r"(?:" + ID_CHAR + r"*:)*(" + ID_CHAR + r"+)"
    QUERY = r"([?][^#]*)?"
    PARAMS = r"((;[a-zA-Z0-9_.:%-]+=[a-zA-Z0-9_.:%-]*)*)"

    PATTERN = re.compile(
        rf"^(did:cheqd:{NETWORK}:{METHOD_ID}{PARAMS}{QUERY}|did:cheqd:{NETWORK}:{METHOD_ID}/resources/{UUID}{QUERY})$"
    )

    DIDSTATE_EXAMPLE = {
        "did": EXAMPLE,
        "state": "finished",
        "secret": {
            "signingResponse": [
                {
                    "kid": EXAMPLE + "#key-1",
                    "signature": "SHFz...",
                }
            ]
        },
        "didDocument": {
            "id": EXAMPLE,
            "controller": [EXAMPLE],
            "verificationMethod": [
                {
                    "id": EXAMPLE + "#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": EXAMPLE,
                    "publicKeyMultibase": "z6Mk...",
                }
            ],
            "authentication": [EXAMPLE + "#key-1"],
        },
    }

    RESOURCE_ID_PATTERN = re.compile(
        rf"^did:cheqd:{NETWORK}:{METHOD_ID}/resources/{UUID}"
    )

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            CheqdDID.PATTERN,
            error="Value {input} is not an cheqd decentralized identifier (DID)",
        )


class CheqdCredDefId(Regexp):
    """Validate value against cheqd credential definition identifier specification."""

    EXAMPLE = "did:cheqd:testnet:8a7e756c-d3b5-4947-af99-2dcd2e8cc5a2/resources/83f06db5-"
    PATTERN = CheqdDID.RESOURCE_ID_PATTERN.pattern

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            CheqdCredDefId.PATTERN,
            error="Value {input} is not an indy credential definition identifier",
        )


class CheqdSchemaId(Regexp):
    """Validate value against cheqd schema identifier specification."""

    EXAMPLE = "did:cheqd:testnet:8a7e756c-d3b5-4947-af99-2dcd2e8cc5a2/resources/e8cc28f2-"
    PATTERN = CheqdDID.RESOURCE_ID_PATTERN.pattern

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            CheqdSchemaId.PATTERN,
            error="Value {input} is not an indy schema identifier",
        )


CHEQD_DID_VALIDATE = CheqdDID()
CHEQD_DID_EXAMPLE = CheqdDID.EXAMPLE
CHEQD_DIDSTATE_EXAMPLE = CheqdDID.DIDSTATE_EXAMPLE

CHEQD_SCHEMA_ID_VALIDATE = CheqdSchemaId()
CHEQD_SCHEMA_ID_EXAMPLE = CheqdSchemaId.EXAMPLE

CHEQD_CRED_DEF_ID_VALIDATE = CheqdCredDefId()
CHEQD_CRED_DEF_ID_EXAMPLE = CheqdCredDefId.EXAMPLE
