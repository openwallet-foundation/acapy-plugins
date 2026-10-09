"""Validators for schema fields."""

import re

from base58 import alphabet
from marshmallow.validate import Regexp

B58 = alphabet if isinstance(alphabet, str) else alphabet.decode("ascii")

EXAMPLE_TIMESTAMP = 1640995199  # 2021-12-31 23:59:59Z


class IndyCredDefId(Regexp):
    """Validate value against indy credential definition identifier specification."""

    EXAMPLE = "WgWxqztrNooG92RXvxSTWv:3:CL:20:tag"
    PATTERN = (
        rf"^([{B58}]{{21,22}})"  # issuer DID
        f":3"  # cred def id marker
        f":CL"  # sig alg
        rf":(([1-9][0-9]*)|([{B58}]{{21,22}}:2:.+:[0-9.]+))"  # schema txn / id
        f":(.+)?$"  # tag
    )

    def __init__(self):
        """Initialize the instance."""
        super().__init__(
            IndyCredDefId.PATTERN,
            error="Value {input} is not an indy credential definition identifier",
        )


class IndyDID(Regexp):
    """Validate value against indy DID."""

    EXAMPLE = "did:indy:sovrin:WRfXPg8dantKVubE3HX8pw"
    PATTERN = re.compile(rf"^(did:(sov|indy):)?[{B58}]{{21,22}}$")

    def __init__(self):
        """Initialize the instance."""
        super().__init__(
            IndyDID.PATTERN,
            error="Value {input} is not an indy decentralized identifier (DID)",
        )


class IndyRevRegId(Regexp):
    """Validate value against indy revocation registry identifier specification."""

    EXAMPLE = "WgWxqztrNooG92RXvxSTWv:4:WgWxqztrNooG92RXvxSTWv:3:CL:20:tag:CL_ACCUM:0"
    PATTERN = (
        rf"^([{B58}]{{21,22}}):4:"
        rf"([{B58}]{{21,22}}):3:"
        rf"CL:(([1-9][0-9]*)|([{B58}]{{21,22}}:2:.+:[0-9.]+))(:.+)?:"
        rf"CL_ACCUM:(.+$)"
    )

    def __init__(self):
        """Initialize the instance."""
        super().__init__(
            IndyRevRegId.PATTERN,
            error="Value {input} is not an indy revocation registry identifier",
        )


class IndyCredRevId(Regexp):
    """Validate value against indy credential revocation identifier specification."""

    EXAMPLE = "12345"
    PATTERN = r"^[1-9][0-9]*$"

    def __init__(self):
        """Initialize the instance."""
        super().__init__(
            IndyCredRevId.PATTERN,
            error="Value {input} is not an indy credential revocation identifier",
        )


class IndySchemaId(Regexp):
    """Validate value against indy schema identifier specification."""

    EXAMPLE = "WgWxqztrNooG92RXvxSTWv:2:schema_name:1.0"
    PATTERN = rf"^[{B58}]{{21,22}}:2:.+:[0-9.]+$"

    def __init__(self):
        """Initialize the instance."""
        super().__init__(
            IndySchemaId.PATTERN,
            error="Value {input} is not an indy schema identifier",
        )


INDY_CRED_DEF_ID_VALIDATE = IndyCredDefId()
INDY_CRED_DEF_ID_EXAMPLE = IndyCredDefId.EXAMPLE

INDY_DID_VALIDATE = IndyDID()
INDY_DID_EXAMPLE = IndyDID.EXAMPLE

INDY_REV_REG_ID_VALIDATE = IndyRevRegId()
INDY_REV_REG_ID_EXAMPLE = IndyRevRegId.EXAMPLE

INDY_CRED_REV_ID_VALIDATE = IndyCredRevId()
INDY_CRED_REV_ID_EXAMPLE = IndyCredRevId.EXAMPLE

INDY_SCHEMA_ID_VALIDATE = IndySchemaId()
INDY_SCHEMA_ID_EXAMPLE = IndySchemaId.EXAMPLE
