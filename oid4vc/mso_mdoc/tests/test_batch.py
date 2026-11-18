import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import cbor2
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.utils.testing import create_test_profile
from aries_askar import Key, KeyAlg

from mso_mdoc import cred_processor as test_module
from mso_mdoc.signing_key import (
    generate_ec_p256_key_pem,
    generate_self_signed_certificate,
)
from oid4vc.cred_processor import CredProcessors
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.models.issuer_config import IssuerConfiguration
from oid4vc.models.wallet_provider import WalletProvider
from oid4vc.public_routes.credential import _issue_cred_inner
from oid4vc.public_routes.nonce import create_nonce
from oid4vc.tests.test_key_attestation import ISS, KID, make_attestation
from oid4vc.utils import get_wallet_id


async def test_real_mdoc_batch_binding_and_native_validity(
    supported, ex_record, monkeypatch
):
    profile = await create_test_profile(
        {
            "plugin_config": {
                "oid4vci": {
                    "host": "localhost",
                    "port": 8020,
                    "endpoint": "http://localhost:8020",
                }
            }
        }
    )
    processor = test_module.MsoMdocCredProcessor()
    profile.context.injector.bind_instance(
        CredProcessors, CredProcessors({"mso_mdoc": processor})
    )
    context = AdminRequestContext(profile)
    private_key = generate_ec_p256_key_pem()
    certificate = generate_self_signed_certificate(private_key)
    monkeypatch.setattr(
        processor,
        "_resolve_signing_key",
        AsyncMock(
            return_value={"private_key_pem": private_key, "certificate_pem": certificate}
        ),
    )
    supported.format = "mso_mdoc"
    supported.identifier = "example"
    supported.format_data = {"doctype": "org.iso.example"}
    supported.proof_types_supported = {
        "attestation": {"proof_signing_alg_values_supported": ["ES256"]}
    }
    signer = Key.generate(KeyAlg.P256)
    async with profile.session() as session:
        await WalletProvider(
            iss=ISS, jwks={"keys": [{**json.loads(signer.get_jwk_public()), "kid": KID}]}
        ).save(session)
        await IssuerConfiguration(
            configuration_id=get_wallet_id(profile),
            new_with_id=True,
            batch_credential_issuance={"batch_size": 2},
        ).save(session)
        await supported.save(session)
        ex_record.supported_cred_id = supported.supported_cred_id
        ex_record.notification_id = "batch-notification"
        await ex_record.save(session)
    keys = [json.loads(Key.generate(KeyAlg.P256).get_jwk_public()) for _ in range(2)]
    nonce = (await create_nonce(profile, 16, 300)).nonce_value
    response = await _issue_cred_inner(
        context,
        SimpleNamespace(payload={"sub": ex_record.refresh_id}),
        ex_record.refresh_id,
        {
            "credential_configuration_id": "example",
            "proofs": {
                "attestation": [make_attestation(signer, nonce=nonce, attested_keys=keys)]
            },
        },
    )
    assert response.status == 200
    body = json.loads(response.text)
    assert body["notification_id"] == "batch-notification"
    assert len(body["credentials"]) == 2
    async with profile.session() as session:
        stored = await OID4VCIExchangeRecord.retrieve_by_id(
            session, ex_record.exchange_id
        )
    assert stored.state == OID4VCIExchangeRecord.STATE_ISSUED
    msos = []
    for item in body["credentials"]:
        credential = item["credential"]
        issuer_signed = cbor2.loads(
            base64.urlsafe_b64decode(credential + "=" * (-len(credential) % 4))
        )
        tagged_mso = cbor2.loads(issuer_signed["issuerAuth"][2])
        msos.append(cbor2.loads(tagged_mso.value))
    for holder, mso in zip(keys, msos):
        key = mso["deviceKeyInfo"]["deviceKey"]
        assert key[-2] == base64.urlsafe_b64decode(holder["x"] + "==")
        validity = mso["validityInfo"]
        lifetime = validity["validUntil"] - validity["validFrom"]
        assert abs(lifetime.total_seconds() - 30 * 24 * 3600) < 1
