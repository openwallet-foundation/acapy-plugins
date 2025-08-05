"""
Integration tests for the AnonCreds Registry.
"""

import urllib
import uuid

import pytest
from acapy_controller import Controller

from .constants import (
    SERVER_URL,
    TEST_NAMESPACE,
    TEST_SCHEMA,
    TEST_SIZE,
    TEST_TAG,
    WITNESS,
    WITNESS_KEY,
)


async def create_did(agent):
    await agent.post(
        "/did/webvh/configuration",
        json={
            "server_url": SERVER_URL,
            "witness_key": WITNESS_KEY,
            "witness": True,
            "auto_attest": True,
        },
    )
    identifier = str(uuid.uuid4())
    response = await agent.post(
        "/did/webvh/create",
        json={"options": {"namespace": TEST_NAMESPACE, "identifier": identifier}},
    )
    return response["state"]["id"]


@pytest.mark.asyncio
async def test_anoncreds():
    """Test Controller protocols."""
    async with (
        Controller(base_url=WITNESS) as agent,
    ):
        did = await create_did(agent)

        response = await agent.post(
            "/anoncreds/schema",
            json={
                "options": {},
                "schema": {
                    "attrNames": TEST_SCHEMA["attributes"],
                    "issuerId": did,
                    "name": TEST_SCHEMA["name"],
                    "version": TEST_SCHEMA["version"],
                },
            },
        )
        schema_id = response["schema_state"]["schema_id"]
        schema_id_encoded = urllib.parse.quote_plus(schema_id)
        response = await agent.get(f"/anoncreds/schema/{schema_id_encoded}")
        assert response["schema"]
        assert response["schema_id"] == schema_id

        response = await agent.post(
            "/anoncreds/credential-definition",
            json={
                "options": {"support_revocation": True},
                "credential_definition": {
                    "issuerId": did,
                    "schemaId": schema_id,
                    "tag": TEST_TAG,
                },
            },
        )
        cred_def_id = response["credential_definition_state"]["credential_definition_id"]
        assert cred_def_id
        cred_def_id_encoded = urllib.parse.quote_plus(cred_def_id)
        response = await agent.get(
            f"/anoncreds/credential-definition/{cred_def_id_encoded}"
        )
        assert response["credential_definition"]
        assert response["credential_definition_id"] == cred_def_id

        response = await agent.post(
            "/anoncreds/revocation-registry-definition",
            json={
                "options": {},
                "revocation_registry_definition": {
                    "issuerId": did,
                    "credDefId": cred_def_id,
                    "maxCredNum": TEST_SIZE,
                    "tag": TEST_TAG,
                },
            },
        )
        rev_reg_id = response["revocation_registry_definition_state"][
            "revocation_registry_definition_id"
        ]
        assert rev_reg_id
        rev_reg_id_encoded = urllib.parse.quote_plus(rev_reg_id)
        response = await agent.get(f"/anoncreds/revocation/registry/{rev_reg_id_encoded}")
        assert response["result"]
