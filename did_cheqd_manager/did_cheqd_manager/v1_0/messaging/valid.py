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

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            CheqdDID.PATTERN,
            error="Value {input} is not an cheqd decentralized identifier (DID)",
        )
CHEQD_DID_VALIDATE = CheqdDID()
CHEQD_DID_EXAMPLE = CheqdDID.EXAMPLE