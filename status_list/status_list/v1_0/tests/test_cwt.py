"""Tests for cwt module."""

import cbor2
import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.did_method import KEY
from acapy_agent.wallet.key_type import ED25519, P256
from acapy_agent.wallet.util import b58_to_bytes

from .. import status_handler
from ..cwt import (
    cwt_sign,
    to_cwt_claims,
)


# Header labels / claim keys under test (mirror cwt.py private constants).
_HEADER_ALG = 1
_HEADER_KID = 4
_HEADER_TYP = 16
_ALG_EDDSA = -8

_CLAIM_ISS = 1
_CLAIM_SUB = 2
_CLAIM_EXP = 4
_CLAIM_NBF = 5
_CLAIM_IAT = 6
_CLAIM_CTI = 7
_CLAIM_STATUS_LIST = 65533
_CLAIM_TTL = 65534
_SL_BITS = "bits"
_SL_LST = "lst"

_COSE_SIGN1_TAG = 18


def test_to_cwt_claims_maps_registered_and_status_list_keys():
    payload = {
        "iss": "did:web:example.com",
        "sub": "https://status.example.com/1",
        "nbf": 100,
        "iat": 100,
        "exp": 200,
        "ttl": 43200,
        "jti": "urn:uuid:1",
        "status_list": {"bits": 1, "lst": "eNrbuRgAAhcBXQ"},
    }

    claims = to_cwt_claims(payload)

    assert claims[_CLAIM_ISS] == "did:web:example.com"
    assert claims[_CLAIM_SUB] == "https://status.example.com/1"
    assert claims[_CLAIM_NBF] == 100
    assert claims[_CLAIM_IAT] == 100
    assert claims[_CLAIM_EXP] == 200
    assert claims[_CLAIM_TTL] == 43200
    assert claims[_CLAIM_CTI] == b"urn:uuid:1"

    inner = claims[_CLAIM_STATUS_LIST]
    assert inner[_SL_BITS] == 1
    assert isinstance(inner[_SL_LST], bytes)
    assert cbor2.dumps(inner).hex() == "a2646269747301636c73744a78dadbb918000217015d"


def test_to_cwt_claims_drops_unknown_keys():
    claims = to_cwt_claims({"foo": "bar", "iss": "x"})
    assert claims == {_CLAIM_ISS: "x"}


@pytest.mark.asyncio
async def test_cwt_sign_structure(context: AdminRequestContext):
    payload = {
        "iss": "did:web:example.com",
        "sub": "https://status.example.com/tenants/base/status/1",
        "nbf": 1_700_000_000,
        "iat": 1_700_000_000,
        "exp": 1_700_086_400,
        "ttl": 43200,
        "jti": "urn:uuid:1",
        "status_list": {"bits": 1, "lst": "eNo"},
    }
    verification_method = (
        "did:web:example.com#3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx"
    )

    cwt = await cwt_sign(
        context.profile,
        payload=payload,
        verification_method=verification_method,
    )

    assert isinstance(cwt, (bytes, bytearray))

    tagged = cbor2.loads(cwt)
    assert isinstance(tagged, cbor2.CBORTag)
    assert tagged.tag == _COSE_SIGN1_TAG

    protected_bstr, unprotected, payload_bstr, signature = tagged.value
    assert isinstance(protected_bstr, (bytes, bytearray))
    assert dict(unprotected) == {}
    assert isinstance(payload_bstr, (bytes, bytearray))
    # Ed25519 raw signature length is 64 bytes.
    assert isinstance(signature, (bytes, bytearray)) and len(signature) == 64

    protected = cbor2.loads(protected_bstr)
    assert protected[_HEADER_ALG] == _ALG_EDDSA
    assert protected[_HEADER_TYP] == "application/statuslist+cwt"
    assert protected[_HEADER_KID] == verification_method.encode("utf-8")

    claims = cbor2.loads(payload_bstr)
    assert claims[_CLAIM_ISS] == "did:web:example.com"
    assert claims[_CLAIM_TTL] == 43200
    assert claims[_CLAIM_CTI] == b"urn:uuid:1"
    assert claims[_CLAIM_STATUS_LIST][_SL_BITS] == 1
    assert isinstance(claims[_CLAIM_STATUS_LIST][_SL_LST], bytes)


@pytest.mark.asyncio
@pytest.mark.parametrize("key_type", [ED25519, P256])
async def test_cwt_signature_verifies_with_public_key(context, key_type):
    async with context.profile.session() as session:
        wallet = session.inject(BaseWallet)
        did_info = await wallet.create_local_did(method=KEY, key_type=key_type)

    token = await cwt_sign(
        context.profile,
        {"sub": "https://example.com/statuslists/1", "iat": 1_700_000_000},
        did=did_info.did,
    )
    protected, _, payload, signature = cbor2.loads(token).value
    assert len(signature) == 64
    assert cbor2.loads(protected)[_HEADER_ALG] == (
        _ALG_EDDSA if key_type == ED25519 else -7
    )
    signing_input = cbor2.dumps(["Signature1", protected, b"", payload])
    public_bytes = b58_to_bytes(did_info.verkey)

    if key_type == ED25519:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        public_key.verify(signature, signing_input)
        with pytest.raises(InvalidSignature):
            public_key.verify(signature, signing_input + b"tampered")
    else:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), public_bytes
        )
        der_signature = utils.encode_dss_signature(
            int.from_bytes(signature[:32], "big"),
            int.from_bytes(signature[32:], "big"),
        )
        public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
        with pytest.raises(InvalidSignature):
            public_key.verify(
                der_signature, signing_input + b"tampered", ec.ECDSA(hashes.SHA256())
            )


@pytest.mark.asyncio
async def test_cwt_sign_requires_did_or_verification_method(
    context: AdminRequestContext,
):
    with pytest.raises(ValueError):
        await cwt_sign(context.profile, payload={"iss": "x"})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "token_format, is_ietf, expected_cwt",
    [
        (None, True, False),
        ("jwt", True, False),
        ("cwt", True, True),
        ("cwt", False, False),
    ],
)
async def test_get_status_list_token_format(
    context,
    seed_db,
    status_list_def,
    status_list_def_msg,
    token_format,
    is_ietf,
    expected_cwt,
):
    definition = status_list_def if is_ietf else status_list_def_msg
    options = {"token_format": token_format} if token_format is not None else {}

    token = await status_handler.get_status_list_token(
        context, definition.list_number, definition, **options
    )

    if expected_cwt:
        assert isinstance(token, bytes)
        tagged = cbor2.loads(token)
        assert isinstance(tagged, cbor2.CBORTag)
        assert tagged.tag == _COSE_SIGN1_TAG
    else:
        assert isinstance(token, str)
        assert token.count(".") == 2


@pytest.mark.asyncio
async def test_get_status_list_token_rejects_unknown_format(context):
    with pytest.raises(ValueError, match="Unsupported status list token format"):
        await status_handler.get_status_list_token(context, "1", token_format="invalid")
