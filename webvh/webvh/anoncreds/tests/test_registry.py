from unittest import IsolatedAsyncioTestCase

import pytest
from acapy_agent.anoncreds.models.credential_definition import (
    CredDef,
    CredDefResult,
    CredDefValue,
    CredDefValuePrimary,
    GetCredDefResult,
)
from acapy_agent.anoncreds.models.revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevRegDef,
    RevRegDefResult,
    RevRegDefValue,
)
from acapy_agent.anoncreds.models.schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
)
from acapy_agent.core.event_bus import EventBus
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.keys.manager import MultikeyManager

from ...tests.fixtures import (
    TEST_DOMAIN,
    TEST_NAMESPACE,
    TEST_SERVER_URL,
    TEST_WITNESS_SEED,
    TEST_RESOLVER,
)
from ...did.manager import ControllerManager
from ..registry import DIDWebVHRegistry

test_domain = "sandbox.bcvh.vonx.io"
test_server = "https://sandbox.bcvh.vonx.io"
test_schema = AnonCredsSchema(
    issuer_id=f"did:webvh:Q:{test_domain}:issuer:01",
    attr_names=["name", "age", "vmax"],
    name="test_schema",
    version="1.0",
)
test_rev_reg_def = {}
test_rev_list = [0, 0, 0, 0, 0, 0, 0, 0]
test_revoked_list_indexes = [1, 3, 6]
test_rev_list_update = {}


class TestAnonCredsRegistry(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile({"wallet.type": "askar-anoncreds"})
        self.profile.context.injector.bind_instance(DIDResolver, TEST_RESOLVER)
        self.profile.context.injector.bind_instance(EventBus, EventBus())
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.profile.settings.set_value(
            "plugin_config", {"did-webvh": {"server_url": TEST_SERVER_URL}}
        )
        self.registry = DIDWebVHRegistry()

        self.controller = ControllerManager(self.profile)
        async with self.profile.session() as session:
            await MultikeyManager(session).create(
                alg="ed25519",
                kid=f"webvh:{TEST_DOMAIN}@witnessKey",
                seed=TEST_WITNESS_SEED,
            )

        # Configure witness key
        await self.controller.configure(options={"auto_attest": True, "witness": True})

        # Create DID
        log_entry = await self.controller.create(options={"namespace": TEST_NAMESPACE})
        self.issuer_id = log_entry.get("state").get("id")
        self.test_schema = test_schema
        self.test_schema.issuer_id = self.issuer_id

    async def _create_schema(self):
        return await self.registry.register_schema(
            self.profile, self.test_schema, options={}
        )

    async def _create_cred_def(self, schema_id):
        return await self.registry.register_credential_definition(
            self.profile,
            GetSchemaResult(
                schema_id=schema_id,
                schema=self.test_schema,
                schema_metadata={},
                resolution_metadata={},
            ),
            CredDef(
                issuer_id=self.issuer_id,
                schema_id=schema_id,
                tag="default",
                type="CL",
                value=CredDefValue(primary=CredDefValuePrimary("1", "1", {}, "1", "1")),
            ),
            options={},
        )

    async def _create_rev_reg_def(self, cred_def_id):
        return await self.registry.register_revocation_registry_definition(
            self.profile,
            RevRegDef(
                tag="tag",
                cred_def_id=cred_def_id,
                value=RevRegDefValue(
                    max_cred_num=10,
                    public_keys={
                        "accum_key": {"z": "1 0BB...386"},
                    },
                    tails_hash="not-correct-hash",
                    tails_location="http://tails-server.com",
                ),
                issuer_id=self.issuer_id,
                type="CL_ACCUM",
            ),
            options={},
        )

    async def _create_rev_reg_list(self, cred_def_id, rev_reg_def_id):
        return await self.registry.register_revocation_list(
            self.profile,
            RevRegDef(
                tag="tag",
                cred_def_id=cred_def_id,
                value=RevRegDefValue(
                    max_cred_num=10,
                    public_keys={
                        "accum_key": {"z": "1 0BB...386"},
                    },
                    tails_hash="hash",
                    tails_location="http://tails-server.com",
                ),
                issuer_id=self.issuer_id,
                type="CL_ACCUM",
            ),
            RevList(
                issuer_id=self.issuer_id,
                current_accumulator="21 124C594B6B20E41B681E92B2C43FD165EA9E68BC3C9D63A82C8893124983CAE94 21 124C5341937827427B0A3A32113BD5E64FB7AB39BD3E5ABDD7970874501CA4897 6 5438CB6F442E2F807812FD9DC0C39AFF4A86B1E6766DBB5359E86A4D70401B0F 4 39D1CA5C4716FFC4FE0853C4FF7F081DFD8DF8D2C2CA79705211680AC77BF3A1 6 70504A5493F89C97C225B68310811A41AD9CD889301F238E93C95AD085E84191 4 39582252194D756D5D86D0EED02BF1B95CE12AED2FA5CD3C53260747D891993C",
                revocation_list=[1, 1, 1, 1],
                timestamp=1669640864487,
                rev_reg_def_id=rev_reg_def_id,
            ),
            options={},
        )

    async def test_digest_multibase(self):
        result = self.registry._digest_multibase({"hello": "world"})
        assert result == "zQmYGx7Wzqe5prvEsTSzYBQN8xViYUM9qsWJSF5EENLcNmM"

    async def test_resource_uri(self):
        mock_issuer = "did:webvh:{SCID}:example.com"
        resource_digest = self.registry._digest_multibase({"hello": "world"})
        result = self.registry._create_resource_uri(mock_issuer, resource_digest)
        assert result == f"{mock_issuer}/resources/{resource_digest}"

    async def test_register_schema(self):
        result = await self._create_schema()
        assert isinstance(result, SchemaResult)
        assert result.schema_state.state == "finished"

    async def test_get_schema(self):
        schema_id = (await self._create_schema()).schema_state.schema_id
        result = await self.registry.get_schema(self.profile, schema_id)
        assert isinstance(result, GetSchemaResult)
        assert result.schema_id == schema_id
        assert result.schema.name == test_schema.name
        assert result.schema.version == test_schema.version
        assert result.schema.issuer_id == self.issuer_id
        assert result.schema.attr_names == test_schema.attr_names

    async def test_register_credential_definition(self):
        schema_id = (await self._create_schema()).schema_state.schema_id
        result = await self._create_cred_def(schema_id)
        assert isinstance(result, CredDefResult)
        assert result.credential_definition_state.state == "finished"

    async def test_get_credential_definition(self, *_):
        schema_id = (await self._create_schema()).schema_state.schema_id
        cred_def_id = (
            await self._create_cred_def(schema_id)
        ).credential_definition_state.credential_definition_id
        result = await self.registry.get_credential_definition(self.profile, cred_def_id)
        assert isinstance(result, GetCredDefResult)
        assert result.credential_definition_id == cred_def_id
        assert result.credential_definition.issuer_id == self.issuer_id
        assert result.credential_definition.schema_id == schema_id
        assert result.credential_definition.type == "CL"
        assert result.credential_definition.tag == "default"
        assert result.credential_definition.value

    async def test_register_revocation_registry_definition(self):
        schema_id = (await self._create_schema()).schema_state.schema_id
        cred_def_id = (
            await self._create_cred_def(schema_id)
        ).credential_definition_state.credential_definition_id
        result = await self._create_rev_reg_def(cred_def_id)
        assert isinstance(result, RevRegDefResult)
        assert result.revocation_registry_definition_state.state == "finished"

    async def test_get_revocation_registry_definition(self, *_):
        schema_id = (await self._create_schema()).schema_state.schema_id
        cred_def_id = (
            await self._create_cred_def(schema_id)
        ).credential_definition_state.credential_definition_id
        rev_reg_def_id = (
            await self._create_rev_reg_def(cred_def_id)
        ).revocation_registry_definition_state.revocation_registry_definition_id
        result = await self.registry.get_revocation_registry_definition(
            self.profile, rev_reg_def_id
        )
        assert isinstance(result, GetRevRegDefResult)
        assert result.revocation_registry_id == rev_reg_def_id
        assert result.revocation_registry.issuer_id == self.issuer_id
        assert result.revocation_registry.cred_def_id == cred_def_id
        assert result.revocation_registry.type == "CL_ACCUM"
        assert result.revocation_registry.tag == "tag"
        assert result.revocation_registry.value

    async def test_register_revocation_list(self):
        schema_id = (await self._create_schema()).schema_state.schema_id
        cred_def_id = (
            await self._create_cred_def(schema_id)
        ).credential_definition_state.credential_definition_id
        rev_reg_def_id = (
            await self._create_rev_reg_def(cred_def_id)
        ).revocation_registry_definition_state.revocation_registry_definition_id
        result = await self._create_rev_reg_list(cred_def_id, rev_reg_def_id)
        assert isinstance(result, RevListResult)
        assert result.revocation_list_state.state == "finished"

    async def test_get_revocation_list(self):
        schema_id = (await self._create_schema()).schema_state.schema_id
        cred_def_id = (
            await self._create_cred_def(schema_id)
        ).credential_definition_state.credential_definition_id
        rev_reg_def_id = (
            await self._create_rev_reg_def(cred_def_id)
        ).revocation_registry_definition_state.revocation_registry_definition_id
        rev_reg_list_timestamp = (
            await self._create_rev_reg_list(cred_def_id, rev_reg_def_id)
        ).revocation_list_state.revocation_list.timestamp
        result = await self.registry.get_revocation_list(
            self.profile,
            rev_reg_def_id,
            rev_reg_list_timestamp - 1,
            rev_reg_list_timestamp + 1,
        )
        assert isinstance(result, GetRevListResult)
        assert result.revocation_list.issuer_id == self.issuer_id
        assert result.revocation_list.rev_reg_def_id == rev_reg_def_id
        assert result.revocation_list.current_accumulator
        assert result.revocation_list.revocation_list

    @pytest.mark.skip("Not implemented")
    async def test_update_revocation_list(self):
        result = await self.registry.update_revocation_list(
            self.profile,
            test_rev_reg_def,
            test_rev_list,
            test_rev_list_update,
            test_revoked_list_indexes,
        )
        assert isinstance(result, RevListResult)
        assert result.revocation_list_state.state == "finished"
