from unittest.async_case import IsolatedAsyncioTestCase

import pytest
from acapy_agent.utils.testing import create_test_profile

from ....v1_0.validation import CHEQD_DID_VALIDATE
from .. import registry as test_module

TEST_CHEQD_DID = "did:cheqd:testnet:1686a962-6e82-46f3-bde7-e6711d63958c"
TEST_CHEQD_SCHEMA_ID = "did:cheqd:testnet:1686a962-6e82-46f3-bde7-e6711d63958c/resources/e788d345-dd0c-427a-a74b-27faf1e608cd"
TEST_CHEQD_CRED_DEF_ID = "did:cheqd:testnet:1686a962-6e82-46f3-bde7-e6711d63958c/resources/02229804-b46a-4be9-a6f1-13869109c7ea"
TEST_CHEQD_REV_REG_ENTRY = "did:cheqd:testnet:1686a962-6e82-46f3-bde7-e6711d63958c?resourceName=test&resourceType=anoncredsRevRegEntry"


@pytest.mark.anoncreds
class TestCheqdRegistry(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile(
            settings={"wallet.type": "askar-anoncreds"},
        )
        self.registry = test_module.DIDCheqdRegistry()

    async def test_supported_did_regex(self):
        """Test the supported_did_regex."""

        assert self.registry.supported_identifiers_regex == CHEQD_DID_VALIDATE.PATTERN
        assert bool(self.registry.supported_identifiers_regex.match(TEST_CHEQD_DID))
        assert bool(self.registry.supported_identifiers_regex.match(TEST_CHEQD_SCHEMA_ID))
        assert bool(
            self.registry.supported_identifiers_regex.match(TEST_CHEQD_CRED_DEF_ID)
        )
        assert bool(
            self.registry.supported_identifiers_regex.match(TEST_CHEQD_REV_REG_ENTRY)
        )
