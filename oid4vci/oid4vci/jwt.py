"""."""

from aries_askar import Key, AskarError
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.wallet.jwt import JWTVerifyResult, BadJWSHeaderError
from aries_cloudagent.wallet.jwt import b64_to_dict, b64_to_bytes
from aries_cloudagent.resolver.did_resolver import DIDResolver
from pydid import Resource, VerificationMethod


def key_from_verification_method(vm: VerificationMethod) -> Key:
    """Create a Key instance from a DID Document Verification Method."""

    if vm.type == "JsonWebKey2020":
        jwk = vm.public_key_jwk
        if not jwk:
            raise ValueError("JWK verification method missing key")
        try:
            key = Key.from_jwk(jwk)
        except AskarError as err:
            raise ValueError("Invalid JWK") from err
        return key

    else:
        raise ValueError("Unsupported verification method type")


async def jwt_verify(profile: Profile, jwt: str) -> JWTVerifyResult:
    """Verify a JWT and return the headers and payload."""
    encoded_headers, encoded_payload, encoded_signature = jwt.split(".", 3)
    headers = b64_to_dict(encoded_headers)
    if "alg" not in headers or headers["alg"] != "EdDSA" or "kid" not in headers:
        raise BadJWSHeaderError(
            "Invalid JWS header parameters for Ed25519Signature2018."
        )

    payload = b64_to_dict(encoded_payload)
    verification_method = headers["kid"]
    decoded_signature = b64_to_bytes(encoded_signature, urlsafe=True)

    resolver = profile.inject(DIDResolver)
    vmethod: Resource = await resolver.dereference(
        profile,
        verification_method,
    )

    if not isinstance(vmethod, VerificationMethod):
        raise TypeError("Dereferenced resource is not a verification method")

    key = key_from_verification_method(vmethod)

    valid = key.verify_signature(
        f"{encoded_headers}.{encoded_payload}".encode(),
        decoded_signature,
    )

    return JWTVerifyResult(headers, payload, valid, verification_method)
