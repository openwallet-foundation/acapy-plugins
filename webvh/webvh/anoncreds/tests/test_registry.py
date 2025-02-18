import time
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from acapy_agent.anoncreds.base import (
    AnonCredsRegistrationError,
)
from acapy_agent.anoncreds.models.credential_definition import (
    CredDefResult,
    GetCredDefResult,
)
from acapy_agent.anoncreds.models.revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevListResult,
    RevRegDefResult,
)
from acapy_agent.anoncreds.models.schema import GetSchemaResult, SchemaResult
from acapy_agent.anoncreds.models.schema_info import AnoncredsSchemaInfo

# from ...did.manager import CheqdDIDManager
from ...validation import WEBVH_DID_VALIDATE
from ..registry import DIDWebVHRegistry


test_scid = 'Q'
test_domain = 'localhost'
test_server = 'http://localhost'
test_profile = {}
test_issuer_id = f'did:webvh:{test_scid}:{test_domain}'
test_schema = {
    'name': 'TestSchema',
    'version': '1.0',
    'attrNames': ['firstKey', 'secondKey'],
    'issuerId': test_issuer_id
}
test_schema_digest = 'zQ'
test_schema_id = f'{test_issuer_id}/{test_schema_digest}'
test_cred_tag = ''
test_cred_def = {}
test_cred_def_digest = 'zQ'
test_cred_def_id = f'{test_issuer_id}/{test_cred_def_digest}'
test_rev_reg_tag = ''
test_rev_reg_def = {}
test_rev_reg_def_digest = 'zQ'
test_rev_reg_id = f'{test_issuer_id}/{test_rev_reg_def_digest}'
test_rev_list = [0, 0, 0, 0, 0, 0, 0, 0]
test_revoked_list_indexes = [1, 3, 6]
test_rev_list_entry = {}
test_rev_list_entry_digest = 'zQ'
test_rev_list_entry_timestamp = 123
test_rev_list_entry_id = f'{test_issuer_id}/{test_rev_list_entry_digest}'
test_rev_list_update = {}
test_rev_list_update_digest = 'zQ'
test_rev_list_update_timestamp = 456
test_rev_list_update_id = f'{test_issuer_id}/{test_rev_list_update_digest}'
test_rev_list_index = [
    {
        'id': test_rev_list_entry_id,
        'timestamp': test_rev_list_entry_timestamp
    },
    {
        'id': test_rev_list_update_id,
        'timestamp': test_rev_list_update_timestamp
    }
]
test_timestamp = 234

async def test_digest_multibase():
    registry = DIDWebVHRegistry()
    result = registry._digest_multibase(test_schema)
    assert result == test_schema_digest

async def test_resource_uri():
    registry = DIDWebVHRegistry()
    result = registry._create_resource_uri(test_schema_digest)
    assert result == test_schema_id

async def test_register_schema():
    registry = DIDWebVHRegistry()
    result = await registry.register_schema(
        test_profile, test_schema
    )
    assert isinstance(result, SchemaResult)
    assert result.schema_state.state == "finished"

# async def test_get_schema():
#     registry = DIDWebVHRegistry()
#     result = await registry.get_schema(
#         test_profile, test_schema_id
#     )
#     assert isinstance(result, GetSchemaResult)
#     assert result.schema_id == test_schema_id
#     assert result.schema.name == test_schema.get('name')
#     assert result.schema.version == test_schema.get('version')
#     assert result.schema.issuer_id == test_schema.get('issuerId')
#     assert result.schema.attr_names == test_schema.get('attrNames')

# async def test_register_credential_definition():
#     registry = DIDWebVHRegistry()
#     result = await registry.register_credential_definition(
#         test_profile, test_schema, test_cred_def
#     )
#     assert isinstance(result, CredDefResult)
#     assert result.credential_definition_state.state == "finished"

# async def test_get_credential_definition():
#     registry = DIDWebVHRegistry()
#     result = await registry.get_credential_definition(
#         test_profile, test_cred_def_id
#     )
#     assert isinstance(result, GetCredDefResult)
#     assert result.credential_definition_id == test_cred_def_id
#     assert result.credential_definition.issuer_id == test_issuer_id
#     assert result.credential_definition.schema_id == test_schema_id
#     assert result.credential_definition.type == "CL"
#     assert result.credential_definition.tag == test_cred_tag
#     assert result.credential_definition.value

# async def test_register_revocation_registry_definition():
#     registry = DIDWebVHRegistry()
#     result = await registry.register_revocation_registry_definition(
#         test_profile, test_rev_reg_def
#     )
#     assert isinstance(result, RevRegDefResult)
#     assert result.revocation_registry_definition_state.state == "finished"

# async def test_get_revocation_registry_definition():
#     registry = DIDWebVHRegistry()
#     result = await registry.get_revocation_registry_definition(
#         test_profile, test_rev_reg_id
#     )
#     assert isinstance(result, GetRevRegDefResult)
#     assert result.revocation_registry_id == test_rev_reg_id
#     assert result.revocation_registry.issuer_id == test_issuer_id
#     assert result.revocation_registry.cred_def_id == test_cred_def_id
#     assert result.revocation_registry.type == "CL_ACCUM"
#     assert result.revocation_registry.tag == test_rev_reg_tag
#     assert result.revocation_registry.value

# async def test_register_revocation_list():
#     registry = DIDWebVHRegistry()
#     result = await registry.register_revocation_list(
#         test_profile, test_rev_reg_def, test_rev_list_entry
#     )
#     assert isinstance(result, RevListResult)
#     assert result.revocation_list_state.state == "finished"

# async def test_get_revocation_list():
#     registry = DIDWebVHRegistry()
#     result = await registry.get_revocation_list(
#         test_profile, test_rev_reg_id, test_timestamp
#     )
#     assert isinstance(result, GetRevListResult)
#     assert result.revocation_list.issuer_id == test_issuer_id
#     assert result.revocation_list.rev_reg_def_id == test_rev_reg_id
#     assert result.revocation_list.current_accumulator
#     assert result.revocation_list.revocation_list

# async def test_update_revocation_list():
#     registry = DIDWebVHRegistry()
#     result = await registry.update_revocation_list(
#         test_profile, test_rev_reg_def, test_rev_list, test_rev_list_update, test_revoked_list_indexes
#     )
#     assert isinstance(result, RevListResult)
#     assert result.revocation_list_state.state == "finished"
