"""JWT Methods."""

import base64 as _b64
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional

from acapy_agent.core.profile import Profile
from acapy_agent.resolver.did_resolver import DIDResolver, DIDUrl
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.jwt import (
    BadJWSHeaderError,
    BaseVerificationKeyStrategy,
    dict_to_b64,
    did_lookup_name,
    nym_to_did,
)
from acapy_agent.wallet.jwt import b64_to_bytes, b64_to_dict
from acapy_agent.wallet.key_type import ED25519, P256
from acapy_agent.wallet.util import b58_to_bytes, bytes_to_b64
from aries_askar import Key, KeyAlg
from cryptography import x509 as cx509
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# Algorithms supported by jwt_sign / jwt_verify.
# Entries map directly to the wallet key types handled by jwt_sign:
#   ED25519 → EdDSA (RFC 8037)
#   P256    → ES256 (RFC 7518 §3.4)
# Update this tuple whenever a new key type is added to jwt_sign.
SUPPORTED_ALGS: tuple[str, ...] = ("EdDSA", "ES256")


@dataclass
class JWTVerifyResult:
    """JWT Verification Result."""

    def __init__(
        self,
        headers: Mapping[str, Any],
        payload: Mapping[str, Any],
        verified: bool,
    ):
        """Initialize a JWTVerifyResult instance."""
        self.headers = headers
        self.payload = payload
        self.verified = verified


async def key_material_for_kid(profile: Profile, kid: str):
    """Resolve key material for a kid."""
    DIDUrl(kid)

    resolver = profile.inject(DIDResolver)
    vm = await resolver.dereference_verification_method(profile, kid)
    if vm.type == "JsonWebKey2020" and vm.public_key_jwk:
        return Key.from_jwk(vm.public_key_jwk)
    if vm.type == "Ed25519VerificationKey2018" and vm.public_key_base58:
        key_bytes = b58_to_bytes(vm.public_key_base58)
        return Key.from_public_bytes(KeyAlg.ED25519, key_bytes)
    if vm.type == "Ed25519VerificationKey2020" and vm.public_key_multibase:
        key_bytes = b58_to_bytes(vm.public_key_multibase[1:])
        if len(key_bytes) == 32:
            pass
        elif len(key_bytes) == 34:
            # Trim off the multicodec header, if present
            key_bytes = key_bytes[2:]
        return Key.from_public_bytes(KeyAlg.ED25519, key_bytes)
    if vm.type == "Multikey" and vm.public_key_multibase:
        # did:key v2+ and Credo 0.6.x use Multikey type with multicodec-prefixed keys.
        # The publicKeyMultibase value is 'z' + base58btc(varint(codec) + raw_key_bytes).
        raw_bytes = b58_to_bytes(vm.public_key_multibase[1:])  # strip 'z' prefix
        if len(raw_bytes) >= 2 and raw_bytes[0] == 0xED and raw_bytes[1] == 0x01:
            # ed25519-pub multicodec varint [0xed, 0x01]
            return Key.from_public_bytes(KeyAlg.ED25519, raw_bytes[2:])
        if len(raw_bytes) >= 2 and raw_bytes[0] == 0x80 and raw_bytes[1] == 0x24:
            # p256-pub multicodec varint [0x80, 0x24]
            return Key.from_public_bytes(KeyAlg.P256, raw_bytes[2:])
        raise ValueError(f"Unsupported Multikey multicodec prefix: {raw_bytes[:2].hex()}")

    raise ValueError("Unsupported verification method type")


def key_from_x5c(x5c: List[str]) -> Key:
    """Extract the public key from the leaf cert in an x5c array.

    x5c entries are standard (padded) base64-encoded DER certificates per
    RFC 7517 §4.7.  Returns an aries_askar Key for signature verification.
    """
    raw_b64 = x5c[0]
    padding = (4 - len(raw_b64) % 4) % 4
    cert_der = _b64.b64decode(raw_b64 + "=" * padding)
    cert = cx509.load_der_x509_certificate(cert_der)
    pub_key = cert.public_key()

    if isinstance(pub_key, EllipticCurvePublicKey):
        nums = pub_key.public_numbers()
        crv_name = pub_key.curve.name  # secp256r1, secp384r1, secp521r1
        crv_map = {
            "secp256r1": "P-256",
            "secp384r1": "P-384",
            "secp521r1": "P-521",
        }
        crv = crv_map.get(crv_name, "P-256")
        coord_bytes = (pub_key.key_size + 7) // 8
        x_bytes = nums.x.to_bytes(coord_bytes, "big")
        y_bytes = nums.y.to_bytes(coord_bytes, "big")
        x_b64 = _b64.urlsafe_b64encode(x_bytes).rstrip(b"=").decode()
        y_b64 = _b64.urlsafe_b64encode(y_bytes).rstrip(b"=").decode()
        return Key.from_jwk(json.dumps({"kty": "EC", "crv": crv, "x": x_b64, "y": y_b64}))
    elif isinstance(pub_key, Ed25519PublicKey):
        raw = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return Key.from_public_bytes(KeyAlg.ED25519, raw)
    else:
        raise ValueError(f"Unsupported public key type in x5c: {type(pub_key).__name__}")


async def jwt_sign(
    profile: Profile,
    headers: Dict[str, Any],
    payload: Mapping[str, Any],
    did: Optional[str] = None,
    verification_method: Optional[str] = None,
    x5c_chain: Optional[List[str]] = None,
) -> str:
    """Create a signed JWT given headers, payload, and signing DID or DID URL.

    If *x5c_chain* is provided (or ``x5c`` is already present in *headers*)
    the resulting JWT will carry an ``x5c`` header instead of ``kid``.  The
    private key used for signing is still resolved from the wallet via
    *did* / *verification_method* — the cert chain must correspond to that key.
    """
    if verification_method is None:
        if did is None:
            raise ValueError("did or verificationMethod required.")

        did = nym_to_did(did)

        verkey_strat = profile.inject(BaseVerificationKeyStrategy)
        verification_method = await verkey_strat.get_verification_method_id_for_did(
            did, profile
        )
        if not verification_method:
            raise ValueError("Could not determine verification method from DID")
    else:
        # We look up keys by did for now
        did = DIDUrl.parse(verification_method).did
        if not did:
            raise ValueError("DID URL must be absolute")

    encoded_payload = dict_to_b64(payload)

    if not headers.get("typ", None):
        headers["typ"] = "JWT"

    # Build key-identification header.
    # x5c (RFC 7517 §4.7) and kid (RFC 7517 §4.5) are mutually exclusive.
    if x5c_chain:
        headers = {**headers, "x5c": x5c_chain}
    elif "x5c" not in headers:
        headers = {**headers, "kid": verification_method}
    # else: caller already set x5c in headers — leave as-is, omit kid.

    async with profile.session() as session:
        wallet = session.inject(BaseWallet)
        did_info = await wallet.get_local_did(did_lookup_name(did))

        if did_info.key_type == ED25519:
            headers["alg"] = "EdDSA"
        elif did_info.key_type == P256:
            headers["alg"] = "ES256"
        else:
            raise ValueError("Unable to determine JWT signing alg")

        encoded_headers = dict_to_b64(headers)
        sig_bytes = await wallet.sign_message(
            f"{encoded_headers}.{encoded_payload}".encode(), did_info.verkey
        )

    sig = bytes_to_b64(sig_bytes, urlsafe=True, pad=False)
    return f"{encoded_headers}.{encoded_payload}.{sig}"


async def jwt_verify(
    profile: Profile, jwt: str, *, cnf: Optional[dict] = None
) -> JWTVerifyResult:
    """Verify a JWT and return the headers and payload."""
    encoded_headers, encoded_payload, encoded_signature = jwt.split(".", 3)
    headers = b64_to_dict(encoded_headers)
    payload = b64_to_dict(encoded_payload)

    # RFC 7515 §4.1.1: alg is a REQUIRED JWS header parameter.
    alg = headers.get("alg")
    if not alg:
        raise BadJWSHeaderError(
            "JWT header is missing the required 'alg' parameter (RFC 7515 §4.1.1)"
        )

    if alg not in SUPPORTED_ALGS:
        raise BadJWSHeaderError(
            f"JWT header 'alg' value '{alg}' is not supported; "
            f"expected one of: {', '.join(SUPPORTED_ALGS)}"
        )

    # kid, jwk, and x5c are mutually exclusive key-identification header parameters.
    # Exactly one must be present; having multiple is ambiguous (RFC 7515 §4.1).
    key_id_params = [p for p in ("kid", "jwk", "x5c") if p in headers]
    if len(key_id_params) > 1:
        raise BadJWSHeaderError(
            f"JWT header contains multiple mutually exclusive key-identification "
            f"parameters: {', '.join(key_id_params)}. Exactly one of 'kid', 'jwk', "
            f"or 'x5c' is permitted (RFC 7515 §4.1)."
        )

    if cnf:
        if "jwk" in cnf:
            key = Key.from_jwk(cnf["jwk"])
        elif "kid" in cnf:
            if "kid" not in headers:
                raise BadJWSHeaderError(
                    "JWT header is missing the required 'kid' parameter "
                    "when cnf contains a kid binding (RFC 7515 §4.1.4)"
                )
            key = await key_material_for_kid(profile, headers["kid"])
        else:
            raise ValueError("Unsupported cnf")
    elif "jwk" in headers:
        key = Key.from_jwk(headers["jwk"])
    elif "kid" in headers:
        key = await key_material_for_kid(profile, headers["kid"])
    elif "x5c" in headers:
        key = key_from_x5c(headers["x5c"])
    else:
        raise BadJWSHeaderError(
            "JWT header is missing a key-identification parameter. "
            "Exactly one of 'kid', 'jwk', or 'x5c' is required (RFC 7515 §4.1)."
        )

    decoded_signature = b64_to_bytes(encoded_signature, urlsafe=True)
    if alg == "EdDSA" and key.algorithm != KeyAlg.ED25519:
        raise BadJWSHeaderError(
            "JWT header 'alg' is 'EdDSA' but the resolved key is not an Ed25519 key"
        )
    elif alg == "ES256" and key.algorithm != KeyAlg.P256:
        raise BadJWSHeaderError(
            "JWT header 'alg' is 'ES256' but the resolved key is not a P-256 key"
        )

    valid = key.verify_signature(
        f"{encoded_headers}.{encoded_payload}".encode(),
        decoded_signature,
    )

    return JWTVerifyResult(headers, payload, valid)
