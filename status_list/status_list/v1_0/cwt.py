"""COSE_Sign1 (CWT) signing for IETF Token Status List.

Produces `application/statuslist+cwt` artifacts per
draft-ietf-oauth-status-list, using the same DID / wallet key material
as the JWT publication path. `wallet.sign_message` already returns
COSE-compatible signatures for the supported key types (Ed25519: raw
64-byte EdDSA; P-256: raw R||S), so no private-key extraction is
needed.
"""

from typing import Any, Dict, Mapping, Optional

import cbor2
from acapy_agent.core.profile import Profile
from acapy_agent.resolver.did_resolver import DIDUrl
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.jwt import (
    BaseVerificationKeyStrategy,
    did_lookup_name,
    nym_to_did,
)
from acapy_agent.wallet.key_type import ED25519, P256
from acapy_agent.wallet.util import b64_to_bytes

# COSE header labels (RFC 9052 section 3.1 and RFC 9596).
_HEADER_ALG = 1
_HEADER_KID = 4
_HEADER_TYP = 16

# COSE algorithm identifiers (RFC 9053). RFC 9864 deprecates these in favour of
# ESP256 (-9) and Ed25519 (-19); they are kept for interoperability, as the status
# list draft's CWT example still uses -7.
_ALG_ES256 = -7
_ALG_EDDSA = -8

# CWT registered claim keys (RFC 8392 §4, Table 1)
_CLAIM_ISS = 1
_CLAIM_SUB = 2
_CLAIM_EXP = 4
_CLAIM_NBF = 5
_CLAIM_IAT = 6
_CLAIM_CTI = 7

# draft-ietf-oauth-status-list CBOR claim registrations
_CLAIM_STATUS_LIST = 65533
_CLAIM_TTL = 65534

# StatusList map keys (draft-ietf-oauth-status-list section 4.3).
_SL_BITS = "bits"
_SL_LST = "lst"

# "typ" value for status list CWT
STATUSLIST_CWT_TYP = "application/statuslist+cwt"

# CBOR tag for COSE_Sign1 (RFC 9052 §4.2)
_COSE_SIGN1_TAG = 18


_JWT_TO_CWT_CLAIM_KEYS: Dict[str, int] = {
    "iss": _CLAIM_ISS,
    "sub": _CLAIM_SUB,
    "exp": _CLAIM_EXP,
    "nbf": _CLAIM_NBF,
    "iat": _CLAIM_IAT,
    "ttl": _CLAIM_TTL,
}


def _decode_lst(lst_value: Any) -> bytes:
    """Return the zlib-compressed list bytes for CWT encoding.

    `get_status_list()` emits `lst` as an unpadded base64url string; the
    CWT form of the draft requires a raw byte string.
    """
    if isinstance(lst_value, (bytes, bytearray)):
        return bytes(lst_value)
    if not isinstance(lst_value, str):
        raise ValueError("status_list.lst must be str or bytes")
    padding = (-len(lst_value)) % 4
    return b64_to_bytes(lst_value + ("=" * padding), urlsafe=True)


def to_cwt_claims(ietf_payload: Mapping[str, Any]) -> Dict[int, Any]:
    """Convert an IETF-form JWT status-list claims dict to CWT integer keys."""
    claims: Dict[int, Any] = {}
    for jwt_key, value in ietf_payload.items():
        if jwt_key == "jti":
            # CWT uses cti (claim 7), which is a byte string
            claims[_CLAIM_CTI] = (
                value.encode("utf-8") if isinstance(value, str) else bytes(value)
            )
        elif jwt_key == "status_list":
            claims[_CLAIM_STATUS_LIST] = {
                _SL_BITS: value["bits"],
                _SL_LST: _decode_lst(value["lst"]),
            }
        elif jwt_key in _JWT_TO_CWT_CLAIM_KEYS:
            claims[_JWT_TO_CWT_CLAIM_KEYS[jwt_key]] = value
        # unmapped keys are intentionally dropped
    return claims


async def cwt_sign(
    profile: Profile,
    payload: Mapping[str, Any],
    did: Optional[str] = None,
    verification_method: Optional[str] = None,
) -> bytes:
    """Create a signed COSE_Sign1 (CWT) for an IETF status list.

    `payload` is the JWT-form status-list dict produced by
    `status_handler.get_status_list()`. It is mapped to CWT integer
    claim keys before signing. Returns tag-18-wrapped COSE_Sign1 CBOR
    bytes ready to serve as `application/statuslist+cwt`.
    """
    if verification_method is None:
        if did is None:
            raise ValueError("did or verification_method required.")
        did = nym_to_did(did)
        verkey_strat = profile.inject(BaseVerificationKeyStrategy)
        verification_method = await verkey_strat.get_verification_method_id_for_did(
            did, profile
        )
        if not verification_method:
            raise ValueError("Could not determine verification method from DID")
    else:
        did = DIDUrl.parse(verification_method).did
        if not did:
            raise ValueError("DID URL must be absolute")

    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        did_info = await wallet.get_local_did(did_lookup_name(did))
        if did_info.key_type == ED25519:
            alg = _ALG_EDDSA
        elif did_info.key_type == P256:
            alg = _ALG_ES256
        else:
            raise ValueError("Unable to determine COSE signing alg for key type")

        protected: Dict[int, Any] = {
            _HEADER_ALG: alg,
            _HEADER_TYP: STATUSLIST_CWT_TYP,
            _HEADER_KID: verification_method.encode("utf-8"),
        }

        cwt_claims = to_cwt_claims(payload)
        payload_bstr = cbor2.dumps(cwt_claims)
        protected_bstr = cbor2.dumps(protected)

        # Sig_structure per RFC 9052 §4.4 with empty external_aad
        sig_structure = ["Signature1", protected_bstr, b"", payload_bstr]
        to_be_signed = cbor2.dumps(sig_structure)

        signature = await wallet.sign_message(to_be_signed, did_info.verkey)

    cose_sign1 = [protected_bstr, {}, payload_bstr, signature]
    return cbor2.dumps(cbor2.CBORTag(_COSE_SIGN1_TAG, cose_sign1))
