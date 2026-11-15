import base64
import json
import time
from unittest.mock import AsyncMock, call

import pytest
from acapy_agent.core.profile import Profile
from aries_askar import Key, KeyAlg
from aiohttp import ClientConnectionError

from oid4vc import key_attestation as test_module
from oid4vc.jose_util import JoseError
from oid4vc.key_attestation import (
    KeyAttestationError,
    public_jwk,
    verify_key_attestation,
)
from oid4vc.models.issuer_config import IssuerConfiguration
from oid4vc.models.wallet_provider import WalletProvider
from oid4vc.utils import get_wallet_id

ISS = "https://wallet.example.com"
KID = "provider-key-1"
METADATA = {"proof_signing_alg_values_supported": ["ES256"]}


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def make_attestation(signer: Key, headers: dict | None = None, **claims) -> str:
    holder = json.loads(Key.generate(KeyAlg.P256).get_jwk_public())
    now = int(time.time())
    payload = {
        "iss": ISS,
        "iat": now,
        "exp": now + 300,
        "attested_keys": [{**holder, "kid": "credential-1"}],
        "nonce": "nonce-1",
        **claims,
    }
    header = {"typ": "key-attestation+jwt", "alg": "ES256", "kid": KID, **(headers or {})}
    signing_input = f"{_b64(header)}.{_b64(payload)}"
    signature = signer.sign_message(signing_input.encode(), sig_type="ES256")
    return f"{signing_input}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"


@pytest.fixture
def signer() -> Key:
    return Key.generate(KeyAlg.P256)


@pytest.fixture
async def provider(profile: Profile, signer: Key):
    jwk = {**json.loads(signer.get_jwk_public()), "kid": KID}
    record = WalletProvider(iss=ISS, jwks={"keys": [jwk]})
    async with profile.session() as session:
        await record.save(session)
    return record


async def _reject(profile, token, metadata=METADATA, error="invalid_proof"):
    with pytest.raises(KeyAttestationError) as exc:
        await verify_key_attestation(profile, token, metadata)
    assert exc.value.error == error
    return exc.value


async def test_verify_success(profile, provider, signer):
    token = make_attestation(
        signer, key_storage=["iso_18045_moderate"], user_authentication=["x"]
    )
    result = await verify_key_attestation(profile, token, METADATA)
    assert result.iss == ISS
    assert result.kid == KID
    assert result.nonce == "nonce-1"
    assert set(result.attested_keys[0]) == {"kty", "crv", "x", "y"}
    assert result.key_storage == ["iso_18045_moderate"]


@pytest.mark.parametrize(
    "token",
    ["not-a-jwt", "!!!.###.$$$"],
)
async def test_malformed(profile, provider, token):
    await _reject(profile, token)


async def test_wrong_typ(profile, provider, signer):
    await _reject(profile, make_attestation(signer, {"typ": "JWT"}))


async def test_alg_not_in_metadata(profile, provider, signer):
    token = make_attestation(signer)
    await _reject(profile, token, {"proof_signing_alg_values_supported": ["EdDSA"]})
    await _reject(profile, token, {})


async def test_missing_kid_or_iss(profile, provider, signer):
    await _reject(profile, make_attestation(signer, {"kid": None, "x5c": ["MII"]}))
    await _reject(profile, make_attestation(signer, iss=None))


async def test_unknown_signer(profile, provider, signer):
    await _reject(profile, make_attestation(signer, {"kid": "other"}))
    await _reject(profile, make_attestation(signer, iss="https://other.example"))


@pytest.mark.parametrize(
    "members,trusted",
    [
        ({"use": "sig", "alg": "ES256"}, True),
        ({"use": "enc"}, False),
        ({"alg": "ES384"}, False),
    ],
)
async def test_inline_key_use_and_alg(profile, provider, signer, members, trusted):
    provider.jwks = {"keys": [{**provider.jwks["keys"][0], **members}]}
    async with profile.session() as session:
        await provider.save(session)
    token = make_attestation(signer)
    if trusted:
        await verify_key_attestation(profile, token, METADATA)
    else:
        error = await _reject(profile, token)
        assert error.description == "key attestation signer is not trusted"


async def test_inactive_provider(profile, provider, signer):
    provider.active = False
    async with profile.session() as session:
        await provider.save(session)
    await _reject(profile, make_attestation(signer))


async def test_bad_signature(profile, provider):
    await _reject(profile, make_attestation(Key.generate(KeyAlg.P256)))


async def test_time_claims(profile, provider, signer):
    now = int(time.time())
    await _reject(profile, make_attestation(signer, exp=now - 3600))
    await _reject(profile, make_attestation(signer, iat=now + 3600))
    await _reject(profile, make_attestation(signer, exp=None))
    await _reject(profile, make_attestation(signer, iat="now"))


async def test_attested_keys(profile, provider, signer):
    x25519 = json.loads(Key.generate(KeyAlg.X25519).get_jwk_public())
    await _reject(profile, make_attestation(signer, attested_keys=[]))
    await _reject(profile, make_attestation(signer, attested_keys=["jwk"]))
    await _reject(profile, make_attestation(signer, attested_keys=[x25519]))


async def test_multiple_attested_keys(profile, provider, signer):
    async with profile.session() as session:
        await IssuerConfiguration(
            configuration_id=get_wallet_id(profile),
            new_with_id=True,
            batch_credential_issuance={"batch_size": 2},
        ).save(session)
    keys = [json.loads(Key.generate(KeyAlg.P256).get_jwk_public()) for _ in range(2)]
    result = await verify_key_attestation(
        profile, make_attestation(signer, attested_keys=keys), METADATA
    )
    assert result.attested_keys == keys
    await _reject(
        profile,
        make_attestation(signer, attested_keys=[keys[0], {**keys[0], "kid": "other"}]),
    )


async def test_optional_claims(profile, provider, signer):
    await _reject(profile, make_attestation(signer, key_storage=[]))
    await _reject(profile, make_attestation(signer, user_authentication="x"))
    await _reject(profile, make_attestation(signer, certification=1))
    await _reject(profile, make_attestation(signer, status="ok"))
    await _reject(profile, make_attestation(signer, nonce=None))


async def test_key_attestations_required(profile, provider, signer):
    metadata = {
        **METADATA,
        "key_attestations_required": {"key_storage": ["iso_18045_high"]},
    }
    await _reject(
        profile, make_attestation(signer, key_storage=["iso_18045_moderate"]), metadata
    )
    await _reject(profile, make_attestation(signer), metadata)
    result = await verify_key_attestation(
        profile, make_attestation(signer, key_storage=["iso_18045_high"]), metadata
    )
    assert result.key_storage == ["iso_18045_high"]
    # An empty object means "required, no level constraints"
    await verify_key_attestation(
        profile, make_attestation(signer), {**METADATA, "key_attestations_required": {}}
    )


@pytest.mark.parametrize(
    "outcome,error",
    [
        (None, None),
        (JoseError("no matching key"), "invalid_proof"),
        (ClientConnectionError("down"), "credential_request_denied"),
        (TimeoutError("timed out"), "credential_request_denied"),
        (json.JSONDecodeError("invalid JWKS", "", 0), "credential_request_denied"),
    ],
)
async def test_signer_from_jwks_uri(profile, signer, monkeypatch, outcome, error):
    uri = "https://wallet.example.com/jwks.json"
    async with profile.session() as session:
        await WalletProvider(iss=ISS, jwks_uri=uri).save(session)
    jwk = {**json.loads(signer.get_jwk_public()), "kid": KID}
    get_key = AsyncMock(return_value=jwk, side_effect=outcome)
    monkeypatch.setattr(test_module.JWKS_CACHE, "get_key", get_key)
    token = make_attestation(signer)
    if error:
        await _reject(profile, token, error=error)
    else:
        assert (await verify_key_attestation(profile, token, METADATA)).kid == KID
    get_key.assert_awaited_once_with(uri, KID, "ES256")


async def test_signer_tries_next_jwks_uri(profile, signer, monkeypatch):
    providers = [
        WalletProvider(iss=ISS, jwks_uri="https://wallet.example.com/old.json"),
        WalletProvider(iss=ISS, jwks_uri="https://wallet.example.com/current.json"),
    ]
    monkeypatch.setattr(WalletProvider, "query", AsyncMock(return_value=providers))
    jwk = {**json.loads(signer.get_jwk_public()), "kid": KID}
    get_key = AsyncMock(side_effect=[JoseError("no matching key"), jwk])
    monkeypatch.setattr(test_module.JWKS_CACHE, "get_key", get_key)

    result = await verify_key_attestation(profile, make_attestation(signer), METADATA)

    assert result.kid == KID
    assert get_key.await_args_list == [
        call(provider.jwks_uri, KID, "ES256") for provider in providers
    ]


def test_public_jwk():
    for alg in (KeyAlg.P256, KeyAlg.P384, KeyAlg.K256, KeyAlg.ED25519):
        jwk = json.loads(Key.generate(alg).get_jwk_public())
        assert public_jwk({**jwk, "kid": "k", "use": "sig"}) == jwk
    p256 = json.loads(Key.generate(KeyAlg.P256).get_jwk_public())
    x25519 = json.loads(Key.generate(KeyAlg.X25519).get_jwk_public())
    for jwk in (
        {**p256, "d": "c"},
        {"kty": "oct", "k": "a"},
        {"kty": ["EC"]},
        {"kty": "EC", "crv": "P-256", "x": p256["x"]},
        {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"},
        {"kty": "RSA", "n": "AQAB", "e": "AQAB"},
        x25519,
    ):
        with pytest.raises(ValueError):
            public_jwk(jwk)
