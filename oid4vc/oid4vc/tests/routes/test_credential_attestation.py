import datetime
import json
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aries_askar import Key, KeyAlg
from marshmallow import ValidationError

from oid4vc.cred_processor import CredProcessorError, CredProcessors
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.issuer_config import IssuerConfiguration, IssuerConfigurationSchema
from oid4vc.models.supported_cred import (
    SupportedCredential,
    validate_proof_types_supported,
)
from oid4vc.models.wallet_provider import WalletProvider
from oid4vc.public_routes import credential as credential_module
from oid4vc.public_routes.nonce import create_nonce
from oid4vc.public_routes.credential import issue_cred
from oid4vc.tests.test_key_attestation import ISS, KID, make_attestation
from oid4vc.utils import get_wallet_id

ATTESTATION_ONLY = {"attestation": {"proof_signing_alg_values_supported": ["ES256"]}}


@pytest.fixture
def signer():
    return Key.generate(KeyAlg.P256)


@pytest.fixture
async def setup(monkeypatch, profile, signer):
    """Exchange, supported credential and processor mocks; a trusted provider."""
    jwk = {**json.loads(signer.get_jwk_public()), "kid": KID}
    async with profile.session() as session:
        await WalletProvider(iss=ISS, jwks={"keys": [jwk]}).save(session)

    token = MagicMock()
    token.payload = {"sub": "refresh_id"}
    token.exchange_key = "refresh_id"
    monkeypatch.setattr(credential_module, "check_token", AsyncMock(return_value=token))

    ex_record = MagicMock(spec=OID4VCIExchangeRecord)
    ex_record.supported_cred_id = "cred_id"
    ex_record.nonce = None
    ex_record.notification_id = None
    ex_record.save = AsyncMock()
    monkeypatch.setattr(
        OID4VCIExchangeRecord, "retrieve_by_refresh_id", AsyncMock(return_value=ex_record)
    )

    supported = MagicMock(spec=SupportedCredential)
    supported.format = "jwt_vc_json"
    supported.identifier = "cred_id"
    supported.proof_types_supported = dict(ATTESTATION_ONLY)
    monkeypatch.setattr(
        SupportedCredential, "retrieve_by_id", AsyncMock(return_value=supported)
    )

    processor = MagicMock()
    processor.issue = AsyncMock(return_value="credential")
    monkeypatch.setattr(
        CredProcessors, "issuer_for_format", MagicMock(return_value=processor)
    )
    return supported, processor


@pytest.fixture
async def batch(profile):
    """Publish batch_size 10 so attestations may carry several keys."""
    async with profile.session() as session:
        await IssuerConfiguration(
            configuration_id=get_wallet_id(profile),
            new_with_id=True,
            batch_credential_issuance={"batch_size": 10},
        ).save(session)


async def _nonce(profile) -> str:
    return (await create_nonce(profile, 16, 300)).nonce_value


async def _issue(dummy_request, proofs):
    resp = await issue_cred(
        dummy_request(
            json_data={"credential_configuration_id": "cred_id", "proofs": proofs}
        )
    )
    return resp.status, json.loads(resp.text)


async def test_attestation_issues_bound_credential(profile, setup, signer, dummy_request):
    _, processor = setup
    nonce = await _nonce(profile)
    status, body = await _issue(
        dummy_request, {"attestation": [make_attestation(signer, nonce=nonce)]}
    )
    assert status == 200
    assert body["credentials"][0]["credential"] == "credential"
    holder = processor.issue.call_args.args[3]
    assert holder.verified and holder.holder_kid is None
    assert set(holder.holder_jwk) == {"kty", "crv", "x", "y"}

    # The nonce is single-use
    status, body = await _issue(
        dummy_request, {"attestation": [make_attestation(signer, nonce=nonce)]}
    )
    assert (status, body["error"]) == (400, "invalid_nonce")


async def test_invalid_attestation_does_not_consume_nonce(
    profile, setup, signer, dummy_request
):
    nonce = await _nonce(profile)
    forged = make_attestation(Key.generate(KeyAlg.P256), nonce=nonce)
    status, body = await _issue(dummy_request, {"attestation": [forged]})
    assert (status, body["error"]) == (400, "invalid_proof")
    status, _ = await _issue(
        dummy_request, {"attestation": [make_attestation(signer, nonce=nonce)]}
    )
    assert status == 200


async def test_logs_omit_attestation_secrets(
    profile, setup, signer, dummy_request, caplog
):
    caplog.set_level(logging.INFO, logger="oid4vc")
    nonce = await _nonce(profile)
    key = json.loads(Key.generate(KeyAlg.P256).get_jwk_public())
    token = make_attestation(signer, nonce=nonce, attested_keys=[key])
    forged = make_attestation(Key.generate(KeyAlg.P256), nonce=nonce, attested_keys=[key])
    assert (await _issue(dummy_request, {"attestation": [forged]}))[0] == 400
    assert (await _issue(dummy_request, {"attestation": [token]}))[0] == 200
    assert "Key attestation verified" in caplog.text
    for secret in (token, forged, nonce, key["x"]):
        assert secret not in caplog.text


async def test_draft_proof_type_member_is_ignored(profile, setup, signer, dummy_request):
    nonce = await _nonce(profile)
    status, _ = await _issue(
        dummy_request,
        {
            "proof_type": "attestation",
            "attestation": [make_attestation(signer, nonce=nonce)],
        },
    )
    assert status == 200


@pytest.mark.parametrize(
    "proof_types_supported",
    [
        {"jwt": {"proof_signing_alg_values_supported": ["ES256"]}},
        None,
    ],
)
async def test_attestation_not_configured(
    profile, setup, signer, dummy_request, proof_types_supported
):
    supported, _ = setup
    supported.proof_types_supported = proof_types_supported
    nonce = await _nonce(profile)
    status, body = await _issue(
        dummy_request, {"attestation": [make_attestation(signer, nonce=nonce)]}
    )
    assert (status, body["error"]) == (400, "invalid_proof")


@pytest.mark.parametrize(
    "proofs,error",
    [
        ({"jwt": ["a.b.c"], "attestation": ["a.b.c"]}, "invalid_credential_request"),
        ({"jwt": ["a.b.c"]}, "invalid_proof"),
        ({"cwt": ["x"]}, "invalid_proof"),
        ({"attestation": []}, "invalid_proof"),
        ({"attestation": "a.b.c"}, "invalid_proof"),
        ({"attestation": ["a.b.c", "a.b.c"]}, "invalid_proof"),
        ({}, "invalid_proof"),
    ],
)
async def test_proofs_shape(setup, dummy_request, proofs, error):
    status, body = await _issue(dummy_request, proofs)
    assert (status, body["error"]) == (400, error)


def _attestation(algs=("ES256",), **extra):
    return {"attestation": {"proof_signing_alg_values_supported": list(algs), **extra}}


@pytest.mark.parametrize(
    "value,valid",
    [
        ({"jwt": {}}, True),
        (_attestation(["ES256", "ES384", "ES256K", "EdDSA"]), True),
        (
            _attestation(
                key_attestations_required={
                    "key_storage": ["iso_18045_high"],
                    "user_authentication": ["iso_18045_moderate"],
                }
            ),
            True,
        ),
        (_attestation(key_attestations_required={}), True),
        ({"attestation": None}, False),
        ({"attestation": {}}, False),
        (_attestation([]), False),
        (_attestation([256]), False),
        (_attestation(["none"]), False),
        (_attestation(["HS256"]), False),
        (_attestation(["ES256", "RS256"]), False),
        (_attestation(key_attestations_required={"key_storage": []}), False),
        (_attestation(key_attestations_required={"other": ["x"]}), False),
    ],
)
def test_validate_proof_types_supported(value, valid):
    if valid:
        validate_proof_types_supported(value)
    else:
        with pytest.raises(ValidationError):
            validate_proof_types_supported(value)


@pytest.mark.parametrize(
    "value,valid",
    [
        ({"batch_size": 2}, True),
        ({"batch_size": 1}, False),
        ({"batch_size": "10"}, False),
        ({"batch_size": None}, False),
        ({"batch_size": True}, False),
        ({"batch_size": 2.5}, False),
        ({}, False),
    ],
)
def test_validate_batch_credential_issuance(value, valid):
    errors = IssuerConfigurationSchema().validate({"batch_credential_issuance": value})
    assert ("batch_credential_issuance" in errors) is not valid


@pytest.mark.parametrize(
    "proof",
    [
        {"proof_type": "jwt", "jwt": "a.b.c"},
        {"proof_type": "attestation", "attestation": "a.b.c"},
        {"proof_type": "jwt"},
        "a.b.c",
    ],
)
async def test_singular_proof_cannot_bypass_proof_types(setup, dummy_request, proof):
    resp = await issue_cred(
        dummy_request(
            json_data={"credential_configuration_id": "cred_id", "proof": proof}
        )
    )
    assert (resp.status, json.loads(resp.text)["error"]) == (400, "invalid_proof")


@pytest.mark.parametrize(
    "failure", [CredProcessorError("cannot sign"), ValueError("cannot sign")]
)
async def test_batch_partial_success(
    profile, setup, batch, signer, dummy_request, failure, monkeypatch
):
    _, processor = setup
    verify = AsyncMock(wraps=credential_module.verify_key_attestation)
    monkeypatch.setattr(credential_module, "verify_key_attestation", verify)
    keys = [json.loads(Key.generate(KeyAlg.P256).get_jwk_public()) for _ in range(3)]
    processor.issue.side_effect = ["first", failure, "third"]
    nonce = await _nonce(profile)
    token = make_attestation(signer, nonce=nonce, attested_keys=keys)
    status, body = await _issue(dummy_request, {"attestation": [token]})
    assert status == 200
    assert [item["credential"] for item in body["credentials"]] == ["first", "third"]
    calls = processor.issue.call_args_list
    verify.assert_awaited_once()
    assert [call.args[3].holder_jwk for call in calls] == keys
    exchange = calls[0].args[2]
    assert all(call.args[2] is exchange for call in calls)
    assert all(call.kwargs["batch"] is calls[0].kwargs["batch"] for call in calls)
    assert exchange.state == OID4VCIExchangeRecord.STATE_ISSUED
    exchange.save.assert_awaited_once()
    status, body = await _issue(dummy_request, {"attestation": [token]})
    assert (status, body["error"]) == (400, "invalid_nonce")


@pytest.mark.parametrize("limit,stored", [(None, False), (None, True), (2, True)])
@pytest.mark.parametrize("size", ["maximum", "oversized"])
async def test_batch_key_limit(
    profile, setup, signer, dummy_request, limit, stored, size
):
    _, processor = setup
    if stored:
        async with profile.session() as session:
            await IssuerConfiguration(
                configuration_id=get_wallet_id(profile),
                new_with_id=True,
                batch_credential_issuance=None
                if limit is None
                else {"batch_size": limit},
            ).save(session)
    maximum = 1 if limit is None else limit
    count = {"maximum": maximum, "oversized": maximum + 1}[size]
    keys = [json.loads(Key.generate(KeyAlg.P256).get_jwk_public()) for _ in range(count)]
    nonce = await _nonce(profile)
    token = make_attestation(signer, nonce=nonce, attested_keys=keys)
    status, body = await _issue(dummy_request, {"attestation": [token]})
    if size == "oversized":
        assert (status, body["error"]) == (400, "invalid_credential_request")
        assert str(maximum) in body["error_description"]
        processor.issue.assert_not_awaited()
        exchange = OID4VCIExchangeRecord.retrieve_by_refresh_id.return_value
        exchange.save.assert_not_awaited()
        status, body = await _issue(
            dummy_request,
            {
                "attestation": [
                    make_attestation(signer, nonce=nonce, attested_keys=keys[:maximum])
                ]
            },
        )
        count = maximum
    assert status == 200
    assert len(body["credentials"]) == count
    assert processor.issue.await_count == count


@pytest.mark.parametrize("trusted", [True, False])
async def test_batch_limit_validation_order(
    profile, setup, signer, dummy_request, trusted
):
    _, processor = setup
    token = make_attestation(
        signer if trusted else Key.generate(KeyAlg.P256),
        nonce=await _nonce(profile),
        attested_keys=[{}] * 11,
    )
    status, body = await _issue(dummy_request, {"attestation": [token]})
    error = "invalid_credential_request" if trusted else "invalid_proof"
    assert (status, body["error"]) == (400, error)
    processor.issue.assert_not_awaited()


async def test_batch_all_fail(profile, setup, batch, signer, dummy_request):
    _, processor = setup
    processor.issue.side_effect = CredProcessorError("cannot sign")
    keys = [json.loads(Key.generate(KeyAlg.P256).get_jwk_public()) for _ in range(2)]
    token = make_attestation(signer, nonce=await _nonce(profile), attested_keys=keys)
    status, body = await _issue(dummy_request, {"attestation": [token]})
    assert (status, body["error"]) == (400, "invalid_credential_request")
    assert processor.issue.await_count == 2
    exchange = processor.issue.call_args.args[2]
    assert exchange.state == OID4VCIExchangeRecord.STATE_FAILED
    exchange.save.assert_awaited_once()


async def test_batch_invalid_key_does_not_issue_or_redeem(
    profile, setup, batch, signer, dummy_request
):
    _, processor = setup
    key = json.loads(Key.generate(KeyAlg.P256).get_jwk_public())
    nonce = await _nonce(profile)
    status, body = await _issue(
        dummy_request,
        {
            "attestation": [
                make_attestation(signer, nonce=nonce, attested_keys=[key, {"kty": "EC"}])
            ]
        },
    )
    assert (status, body["error"]) == (400, "invalid_proof")
    processor.issue.assert_not_awaited()
    status, _ = await _issue(
        dummy_request,
        {"attestation": [make_attestation(signer, nonce=nonce, attested_keys=[key])]},
    )
    assert status == 200


async def test_jwt_proofs(setup, dummy_request, monkeypatch):
    supported, processor = setup
    supported.proof_types_supported = None
    handle = AsyncMock(return_value=MagicMock(verified=True))
    monkeypatch.setattr(credential_module, "handle_proof_of_posession", handle)
    proof = {"proof_type": "jwt", "jwt": "a.b.c"}
    resp = await issue_cred(
        dummy_request(
            json_data={"credential_configuration_id": "cred_id", "proof": proof}
        )
    )
    assert resp.status == 200
    assert handle.call_args.args[1] == proof
    status, _ = await _issue(dummy_request, {"jwt": ["a.b.c"]})
    assert status == 200
    status, body = await _issue(dummy_request, {"jwt": ["a.b.c", "d.e.f"]})
    assert (status, body["error"]) == (400, "invalid_proof")
    assert handle.await_count == 2
    assert processor.issue.await_count == 2


@pytest.mark.parametrize("format", ["jwt_vc_json", "dc+sd-jwt"])
@pytest.mark.parametrize(
    "allocation_failure,status_configured", [(False, True), (True, True), (False, False)]
)
async def test_batch_shared_status_and_timestamps(
    profile,
    setup,
    batch,
    signer,
    dummy_request,
    monkeypatch,
    context,
    format,
    allocation_failure,
    status_configured,
):
    from jwt_vc_json import cred_processor as jwt_module
    from sd_jwt_vc import cred_processor as sd_module
    from oid4vc.status_handler import StatusHandler

    supported, _ = setup
    supported.format = format
    supported.format_data = {"vct": "example"}
    supported.vc_additional_data = {"type": ["Example"], "exp_seconds": 3600}
    exchange = OID4VCIExchangeRecord.retrieve_by_refresh_id.return_value
    exchange.credential_subject = {"name": "Alice"}
    exchange.issuer_id = "did:example:issuer"
    exchange.verification_method = "did:example:issuer#0"
    exchange.notification_id = "batch-notification"

    claims = []

    class AdvancingDatetime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return super().now(tz) + datetime.timedelta(seconds=len(claims) * 60)

    monkeypatch.setattr(
        jwt_module,
        "datetime",
        SimpleNamespace(datetime=AdvancingDatetime, timezone=datetime.timezone),
    )
    monkeypatch.setattr(
        sd_module, "time", SimpleNamespace(time=lambda: 2000000000 + len(claims) * 60)
    )

    async def sign_jwt(profile, headers, payload, **kwargs):
        claims.append(payload)
        if len(claims) == 1:
            raise ValueError("signing failed")
        return json.dumps(payload)

    async def sign_sd(sd_list, payload, headers, profile, did, ver_method):
        return await sign_jwt(profile, headers, payload)

    monkeypatch.setattr(jwt_module, "jwt_sign", sign_jwt)
    monkeypatch.setattr(sd_module, "sd_jwt_sign", sign_sd)
    processor = (
        jwt_module.JwtVcJsonCredProcessor()
        if format == "jwt_vc_json"
        else sd_module.SdJwtCredIssueProcessor()
    )
    monkeypatch.setattr(
        CredProcessors, "issuer_for_format", lambda self, format: processor
    )
    status_handler = MagicMock(spec=StatusHandler)
    shared_status = {"status_list": {"idx": 7, "uri": "https://issuer.example/status/1"}}
    status_handler.assign_status_entries = AsyncMock(
        return_value=shared_status if status_configured else None,
        side_effect=ValueError("allocation failed") if allocation_failure else None,
    )
    monkeypatch.setattr(context, "inject_or", lambda cls: status_handler)
    keys = [json.loads(Key.generate(KeyAlg.P256).get_jwk_public()) for _ in range(3)]
    nonce = await _nonce(profile)
    status, body = await _issue(
        dummy_request,
        {"attestation": [make_attestation(signer, nonce=nonce, attested_keys=keys)]},
    )
    if allocation_failure:
        assert (status, body["error"]) == (400, "invalid_credential_request")
        status_handler.assign_status_entries.assert_awaited_once()
        assert claims == []
        return
    assert status == 200
    assert len(body["credentials"]) == 2
    assert body["notification_id"] == "batch-notification"
    status_handler.assign_status_entries.assert_awaited_once()
    assert status_handler.assign_status_entries.call_args.args[2] == exchange.exchange_id
    if format == "jwt_vc_json":
        assert len({claim["nbf"] for claim in claims}) == 1
        assert len({claim["vc"]["issuanceDate"] for claim in claims}) == 1
        if status_configured:
            assert all(
                claim["vc"]["credentialStatus"] == shared_status for claim in claims
            )
        else:
            assert all("credentialStatus" not in claim["vc"] for claim in claims)
        assert len({claim["sub"] for claim in claims}) == 3
    else:
        assert len({claim["iat"] for claim in claims}) == 1
        assert len({claim["exp"] for claim in claims}) == 1
        assert all(claim["exp"] - claim["iat"] == 3600 for claim in claims)
        if status_configured:
            assert all(claim["status"] == shared_status for claim in claims)
        else:
            assert all("status" not in claim for claim in claims)
        assert [claim["cnf"]["jwk"]["x"] for claim in claims] == [
            key["x"] for key in keys
        ]
