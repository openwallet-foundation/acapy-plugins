"""Cheqd Validation."""

import re

from marshmallow.validate import Regexp


class WebVHDID(Regexp):
    """Validate value against webvh DID."""

    EXAMPLE = "did:webvh:scid:domain.com:099be283-4302-40cc-9850-22016bcd1d86"

    SCID = r"([a-z,0-9,A-Z]{46,46})"

    PATTERN = re.compile(r"^did:webvh:")

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
                    "type": "Multikey",
                    "controller": EXAMPLE,
                    "publicKeyMultibase": "z6Mk...",
                }
            ],
            "authentication": [EXAMPLE + "#key-1"],
        },
    }

    def __init__(self):
        """Initialize the instance."""

        super().__init__(
            WebVHDID.PATTERN,
            error="Value {input} is not an webvh decentralized identifier (DID)",
        )


WEBVH_DID_VALIDATE = WebVHDID()
WEBVH_DID_EXAMPLE = WebVHDID.EXAMPLE
WEBVH_DIDSTATE_EXAMPLE = WebVHDID.DIDSTATE_EXAMPLE
