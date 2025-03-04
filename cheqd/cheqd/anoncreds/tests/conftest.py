from unittest.mock import AsyncMock, MagicMock

import pytest
from acapy_agent.cache.base import BaseCache
from acapy_agent.cache.in_memory import InMemoryCache
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.key_type import KeyTypes

from ...did.base import ResourceCreateRequestOptions, ResourceUpdateRequestOptions
from ...did_method import CHEQD
from ..registry import PublishResourceResponse


@pytest.fixture
def mock_profile():
    return MagicMock()


@pytest.fixture
def mock_resolver():
    mock_resolver = AsyncMock()
    mock_resolver.dereference_with_metadata.return_value = MagicMock()
    mock_resolver.dereference_with_metadata.return_value.resource = {
        "attrNames": "MOCK_ATTR_NAMES",
        "name": "MOCK_NAME",
        "version": "MOCK_VERSION",
        "schemaId": "MOCK_SCHEMA_ID",
        "type": "MOCK_TYPE",
        "tag": "MOCK_TAG",
        "value": {"MOCK_KEY": "MOCK_VALUE"},
        "credDefId": "MOCK_CRED_DEF_ID",
        "revocDefType": "MOCK_REVOC_DEF_TYPE",
        "revocationList": [0, 1, 0],
        "currentAccumulator": "MOCK_ACCUMULATOR",
    }
    mock_resolver.dereference_with_metadata.return_value.metadata = {
        "MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"
    }

    return mock_resolver


@pytest.fixture
def mock_schema():
    schema = MagicMock()
    schema.issuer_id = "MOCK_ISSUER_ID"
    schema.name = "MOCK_NAME"
    schema.version = "MOCK_VERSION"
    schema.attr_names = "MOCK_ATTR_NAMES"
    schema.schema_value.name = "MOCK_NAME"
    schema.schema_id = "MOCK_ID"

    return schema


@pytest.fixture
def mock_create_and_publish_resource():
    return PublishResourceResponse(
        did_url="MOCK_ISSUER_ID/resources/MOCK_RESOURCE_ID",
        content="MOCK_VALUE",
    )


@pytest.fixture
def mock_update_and_publish_resource():
    return PublishResourceResponse(
        did_url="MOCK_ISSUER_ID/resources/MOCK_RESOURCE_ID",
        content="MOCK_VALUE",
    )


@pytest.fixture
def mock_credential_definition():
    credential_definition = MagicMock()
    credential_definition.issuer_id = "MOCK_ISSUER_ID"
    credential_definition.tag = "MOCK_TAG"
    credential_definition.type = "MOCK_TYPE"
    credential_definition.value = MagicMock()
    credential_definition.value.serialize.return_value = {
        "MOCK_KEY": "MOCK_VALUE_SERIALIZED"
    }

    return credential_definition


@pytest.fixture
def mock_get_credential_definition_result():
    cred_def_result = MagicMock()
    cred_def_result.credential_definition_metadata = {
        "resourceName": "MOCK_RESOURCE_NAME"
    }

    return cred_def_result


@pytest.fixture
def mock_rev_reg_def():
    rev_reg_def = MagicMock()
    rev_reg_def.cred_def_id = "MOCK_CRED_DEF_ID"
    rev_reg_def.issuer_id = "MOCK_ISSUER_ID"
    rev_reg_def.tag = "MOCK_TAG"
    rev_reg_def.type = "MOCK_TYPE"
    rev_reg_def.value.serialize.return_value = {"MOCK_KEY": "MOCK_VALUE"}
    rev_reg_def.revocation_registry_metadata = {"resourceName": "MOCK_RESOURCE"}

    return rev_reg_def


@pytest.fixture
def mock_get_revocation_registry_definition():
    revocation_registry_definition_result = MagicMock()
    revocation_registry_definition_result.revocation_registry_metadata = {
        "resourceName": "MOCK_RESOURCE"
    }

    return revocation_registry_definition_result


@pytest.fixture
def mock_rev_list():
    rev_list = MagicMock()
    rev_list.revocation_list = [0, 1, 0]
    rev_list.current_accumulator = "MOCK_ACCUMULATOR"
    rev_list.rev_reg_def_id = "MOCK_REV_REG_DEF_ID"

    return rev_list


@pytest.fixture
async def mock_profile_for_manager():
    did_methods = DIDMethods()
    did_methods.register(CHEQD)
    profile = await create_test_profile(
        settings={"wallet.type": "askar-anoncreds"},
    )
    profile.context.injector.bind_instance(DIDMethods, did_methods)
    profile.context.injector.bind_instance(KeyTypes, KeyTypes())
    profile.context.injector.bind_instance(BaseCache, InMemoryCache())

    return profile


@pytest.fixture
def mock_resource_create_options():
    return ResourceCreateRequestOptions(
        did="MOCK_VALUE", content="MOCK_VALUE", name="MOCK_VALUE", type="MOCK_VALUE"
    )


@pytest.fixture
def mock_resource_update_options():
    return ResourceUpdateRequestOptions(
        did="MOCK_VALUE", content=["MOCK_VALUE"], name="MOCK_VALUE", type="MOCK_VALUE"
    )
