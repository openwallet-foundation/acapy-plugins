"""Operations supporting mso_mdoc creation and verification."""

import logging
import re
from binascii import unhexlify
from typing import Any, Mapping

import cbor2
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModel, BaseModelSchema
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.error import WalletNotFoundError
from acapy_agent.wallet.util import bytes_to_b58
from cbor_diag import cbor2diag
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from marshmallow import fields

from ..mso import MsoVerifier

LOGGER = logging.getLogger(__name__)


class MdocVerifyResult(BaseModel):
    """Result from verify."""

    class Meta:
        """MdocVerifyResult metadata."""

        schema_class = "MdocVerifyResultSchema"

    def __init__(
        self,
        headers: Mapping[str, Any],
        payload: Mapping[str, Any],
        valid: bool,
        kid: str,
    ):
        """Initialize a MdocVerifyResult instance."""
        self.headers = headers
        self.payload = payload
        self.valid = valid
        self.kid = kid


class MdocVerifyResultSchema(BaseModelSchema):
    """MdocVerifyResult schema."""

    class Meta:
        """MdocVerifyResultSchema metadata."""

        model_class = MdocVerifyResult

    headers = fields.Dict(
        required=False, metadata={"description": "Headers from verified mso_mdoc."}
    )
    payload = fields.Dict(
        required=True, metadata={"description": "Payload from verified mso_mdoc"}
    )
    valid = fields.Bool(required=True)
    kid = fields.Str(required=False, metadata={"description": "kid of signer"})
    error = fields.Str(required=False, metadata={"description": "Error text"})


async def mso_mdoc_verify(profile: Profile, mdoc_str: str) -> MdocVerifyResult:
    """Verify a mso_mdoc CBOR string."""
    result = mdoc_verify(mdoc_str)
    verkey = result.kid

    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        try:
            did_info = await wallet.get_local_did_for_verkey(verkey)
        except WalletNotFoundError:
            did_info = None
        verification_method = did_info.did if did_info else ""
        result.kid = verification_method

    return result


def mdoc_verify(mdoc_str: str) -> MdocVerifyResult:
    """Verify a mso_mdoc CBOR string."""
    mdoc_bytes = unhexlify(mdoc_str)
    mso_mdoc = cbor2.loads(mdoc_bytes)
    mso_verifier = MsoVerifier(mso_mdoc["documents"][0]["issuerSigned"]["issuerAuth"])
    valid = mso_verifier.verify_signature()

    headers = {}
    mdoc_str = str(cbor2diag(mdoc_bytes)).replace("\n", "").replace("h'", "'")
    mdoc_str = re.sub(r'\s+(?=(?:[^"]*"[^"]*")*[^"]*$)', "", mdoc_str)
    payload = {"mso_mdoc": mdoc_str}

    if isinstance(mso_verifier.public_key, Ed25519PublicKey):
        public_bytes = mso_verifier.public_key.public_bytes_raw()
    elif isinstance(mso_verifier.public_key, EllipticCurvePublicKey):
        public_bytes = mso_verifier.public_key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
    verkey = bytes_to_b58(public_bytes)

    return MdocVerifyResult(headers, payload, valid, verkey)
