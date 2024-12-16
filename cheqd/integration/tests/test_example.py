import time
from os import getenv

import pytest
from acapy_controller import Controller
from acapy_controller.protocols import didexchange

from .helpers import (
    assert_active_revocation_registry,
    assert_credential_definitions,
    assert_wallet_dids,
    create_credential_definition,
    create_did,
    create_schema,
    deactivate_did,
    issue_credential_v2,
    present_proof_v2,
    resolve_did,
)

ISSUER = getenv("ISSUER", "http://issuer:3001")
HOLDER = getenv("HOLDER", "http://holder:3001")


@pytest.mark.asyncio
async def test_create_and_resolve_did():
    """Test DID creation and resolution."""
    async with Controller(base_url=ISSUER) as issuer:
        did = await create_did(issuer)
        await resolve_did(issuer, did)
        assert did is not None


@pytest.mark.asyncio
async def test_create_schema_and_credential_definition():
    """Test schema and credential definition creation."""
    async with Controller(base_url=ISSUER) as issuer:
        did = await create_did(issuer)
        schema_id = await create_schema(issuer, did)
        credential_definition_id = await create_credential_definition(
            issuer, did, schema_id
        )

        await assert_credential_definitions(issuer, credential_definition_id)
        await assert_wallet_dids(issuer, did)
        assert credential_definition_id is not None


@pytest.mark.asyncio
async def test_create_credential_definition_with_revocation():
    """Test schema and credential definition with revocation."""
    async with Controller(base_url=ISSUER) as issuer:
        did = await create_did(issuer)
        schema_id = await create_schema(issuer, did)
        credential_definition_id = await create_credential_definition(
            issuer, did, schema_id, True
        )

        await assert_credential_definitions(issuer, credential_definition_id)
        await assert_wallet_dids(issuer, did)
        assert credential_definition_id is not None
        # assert active revocation registry for credential_definition_id
        await assert_active_revocation_registry(issuer, credential_definition_id)


@pytest.mark.asyncio
async def test_issue_credential():
    """Test credential issuance."""
    async with Controller(base_url=ISSUER) as issuer, Controller(
        base_url=HOLDER
    ) as holder:
        did = await create_did(issuer)
        schema_id = await create_schema(issuer, did)
        credential_definition_id = await create_credential_definition(
            issuer, did, schema_id
        )

        # Connect issuer and holder
        issuer_conn_with_anoncreds_holder, holder_anoncreds_conn = await didexchange(
            issuer, holder
        )

        issue_credential_result = await issue_credential_v2(
            issuer,
            holder,
            issuer_conn_with_anoncreds_holder.connection_id,
            holder_anoncreds_conn.connection_id,
            credential_definition_id,
            {"score": "99"},
        )
        assert issue_credential_result is not None

        _, verifier_pres_ex = await present_proof_v2(
            holder=holder,
            verifier=issuer,
            holder_connection_id=holder_anoncreds_conn.connection_id,
            verifier_connection_id=issuer_conn_with_anoncreds_holder.connection_id,
            requested_attributes=[
                {
                    "name": "score",
                    "restrictions": [{"cred_def_id": credential_definition_id}],
                }
            ],
        )
        assert verifier_pres_ex.verified


@pytest.mark.asyncio
async def test_issue_credential_with_revocation():
    """Test credential issuance."""
    async with Controller(base_url=ISSUER) as issuer, Controller(
        base_url=HOLDER
    ) as holder:
        did = await create_did(issuer)
        schema_id = await create_schema(issuer, did)
        # create credential definition with revocation
        credential_definition_id = await create_credential_definition(
            issuer, did, schema_id, True
        )

        # Connect issuer and holder
        issuer_conn_with_anoncreds_holder, holder_anoncreds_conn = await didexchange(
            issuer, holder
        )

        issuer_cred_ex, _ = await issue_credential_v2(
            issuer,
            holder,
            issuer_conn_with_anoncreds_holder.connection_id,
            holder_anoncreds_conn.connection_id,
            credential_definition_id,
            {"score": "99"},
        )
        assert issuer_cred_ex is not None

        # Verify credential
        _, verifier_pres_ex = await present_proof_v2(
            holder=holder,
            verifier=issuer,
            holder_connection_id=holder_anoncreds_conn.connection_id,
            verifier_connection_id=issuer_conn_with_anoncreds_holder.connection_id,
            requested_predicates=[
                {
                    "name": "score",
                    "p_value": 50,
                    "p_type": ">",
                    "restrictions": [{"cred_def_id": credential_definition_id}],
                }
            ],
            non_revoked={"to": int(time.time())},
        )
        assert verifier_pres_ex.verified

        # Revoke credential
        await issuer.post(
            url="/anoncreds/revocation/revoke",
            json={
                "rev_reg_id": issuer_cred_ex.details.rev_reg_id,
                "cred_rev_id": issuer_cred_ex.details.cred_rev_id,
                "publish": True,
            },
        )

        # Verify credential
        _, verifier_pres_ex = await present_proof_v2(
            holder=holder,
            verifier=issuer,
            holder_connection_id=holder_anoncreds_conn.connection_id,
            verifier_connection_id=issuer_conn_with_anoncreds_holder.connection_id,
            requested_predicates=[
                {
                    "name": "score",
                    "p_value": 50,
                    "p_type": ">",
                    "restrictions": [{"cred_def_id": credential_definition_id}],
                }
            ],
            non_revoked={"to": int(time.time())},
        )
        assert not verifier_pres_ex.verified


@pytest.mark.asyncio
async def test_deactivate_did():
    """Test DID deactivation."""
    async with Controller(base_url=ISSUER) as issuer:
        did = await create_did(issuer)
        await deactivate_did(issuer, did)
