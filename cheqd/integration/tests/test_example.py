from os import getenv

import pytest
from acapy_controller import Controller
from acapy_controller.protocols import didexchange

from .helpers import (
    assert_credential_definitions,
    assert_wallet_dids,
    create_credential_definition,
    create_did,
    create_schema,
    deactivate_did,
    issue_credential_v2,
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


@pytest.mark.asyncio
async def test_deactivate_did():
    """Test DID deactivation."""
    async with Controller(base_url=ISSUER) as issuer:
        did = await create_did(issuer)
        await deactivate_did(issuer, did)
