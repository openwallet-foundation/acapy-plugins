"""
Integration tests for the AnonCreds Registry.
"""

import asyncio
from os import getenv

import pytest
import urllib.parse
from acapy_controller import Controller

WITNESS = getenv("WITNESS", "http://witness:3001")
WITNESS_KEY = 'z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i'
SERVER_URL = 'https://id.test-suite.app'

async def create_did(agent):
    await agent.post(
        "/did/webvh/configuration",
        json={
            'server_url': SERVER_URL,
            'witness_key': WITNESS_KEY,
            'witness': True
        },
    )
    response = await agent.post(
        "/did/webvh/create",
        json={"options": {"namespace": "test"}},
    )
    return response["id"] 
    

@pytest.mark.asyncio
async def test_anoncreds():
    """Test Controller protocols."""
    async with (
        Controller(base_url=WITNESS) as agent,
    ):
        did = await create_did(agent)
        
        options = {
            'serviceEndpoint': f'{SERVER_URL}/resources',
            'verificationMethod': f'{did}#key-01'
        }
        response = await agent.post(
            "/anoncreds/schema",
            json={
                'options': options,
                'schema': {
                    'attrNames': ['test'],
                    'issuerId': did,
                    'name': 'test',
                    'version': '1.0'
                }
            },
        )
        schema_id = response['schema_state']['schema_id']
        schema_id_encoded = urllib.parse.quote_plus(schema_id)
        response = await agent.get(
            f"/anoncreds/schema/{schema_id_encoded}"
        )
        assert response['schema']
        assert response['schema_id'] == schema_id
        
        
        response = await agent.post(
            "/anoncreds/credential-definition",
            json={
                'options': options | {'support_revocation': True},
                'credential_definition': {
                    'issuerId': did,
                    'schemaId': schema_id,
                    'tag': 'test'
                }
            },
        )
        cred_def_id = response['credential_definition_state']['credential_definition_id']
        assert cred_def_id
        cred_def_id_encoded = urllib.parse.quote_plus(cred_def_id)
        response = await agent.get(
            f"/anoncreds/credential-definition/{cred_def_id_encoded}"
        )
        assert response['credential_definition']
        assert response['credential_definition_id'] == cred_def_id
        
        
        response = await agent.post(
            "/anoncreds/revocation-registry-definition",
            json={
                'options': options,
                'revocation_registry_definition': {
                    'issuerId': did,
                    'credDefId': cred_def_id,
                    "maxCredNum": 4,
                    'tag': 'test'
                }
            },
        )
        rev_reg_id = response['revocation_registry_definition_state']['revocation_registry_definition_id']
        assert rev_reg_id
        rev_reg_id_encoded = urllib.parse.quote_plus(rev_reg_id)
        response = await agent.get(
            f"/anoncreds/revocation/registry/{rev_reg_id_encoded}"
        )
        assert response['result']