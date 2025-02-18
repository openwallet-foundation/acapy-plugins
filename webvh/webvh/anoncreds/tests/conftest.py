from unittest.mock import AsyncMock, MagicMock

import pytest
from acapy_agent.cache.base import BaseCache
from acapy_agent.cache.in_memory import InMemoryCache
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.key_type import KeyTypes

from ...did_method import WEBVH


@pytest.fixture
def mock_profile():
    return MagicMock()


@pytest.fixture
def mock_resolver():
    mock_resolver = AsyncMock()
    mock_resolver.resolve_resource.return_value = MagicMock()
    mock_resolver.resolve_resource.return_value.resource = {
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
    mock_resolver.resolve_resource.return_value.metadata = {
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