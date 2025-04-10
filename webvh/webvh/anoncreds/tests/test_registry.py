from unittest import IsolatedAsyncioTestCase, mock

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
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.key_type import KeyTypes
from acapy_agent.wallet.keys.manager import MultikeyManager

from ...resolver.resolver import DIDWebVHResolver
from ..registry import DIDWebVHRegistry

test_scid = "Q"
test_domain = "id.test-suite.app"
test_server = "https://id.test-suite.app"
test_issuer_id = f"did:webvh:{test_scid}:{test_domain}"
test_schema = AnonCredsSchema(
    issuer_id=test_issuer_id,
    attr_names=["name", "age", "vmax"],
    name="test_schema",
    version="1.0",
)
test_schema_digest = "zQmXS77mJCmsKf6aas8uwNgJ2zEh299UKcFgLJa5AVkBHTQ"
test_schema_id = f"{test_issuer_id}/resources/{test_schema_digest}"
test_cred_tag = ""
test_cred_def = {}
test_cred_def_digest = "zQ"
test_cred_def_id = f"{test_issuer_id}/{test_cred_def_digest}"
test_rev_reg_tag = ""
test_rev_reg_def = {}
test_rev_reg_def_digest = "zQ"
test_rev_reg_id = f"{test_issuer_id}/{test_rev_reg_def_digest}"
test_rev_list = [0, 0, 0, 0, 0, 0, 0, 0]
test_revoked_list_indexes = [1, 3, 6]
test_rev_list_entry = {}
test_rev_list_entry_digest = "zQ"
test_rev_list_entry_timestamp = 123
test_rev_list_entry_id = f"{test_issuer_id}/{test_rev_list_entry_digest}"
test_rev_list_update = {}
test_rev_list_update_digest = "zQ"
test_rev_list_update_timestamp = 456
test_rev_list_update_id = f"{test_issuer_id}/{test_rev_list_update_digest}"
test_rev_list_index = [
    {"id": test_rev_list_entry_id, "timestamp": test_rev_list_entry_timestamp},
    {"id": test_rev_list_update_id, "timestamp": test_rev_list_update_timestamp},
]

request_resource = mock.AsyncMock(
    return_value=mock.MagicMock(json=mock.AsyncMock(return_value={}), status=201)
)

resolve_resource = mock.AsyncMock(
    return_value=mock.MagicMock(
        json=mock.AsyncMock(
            return_value={
                "@context": ["https://w3id.org/security/data-integrity/v2"],
                "id": f"{test_issuer_id}/resources/zQma3tUVYzMn9UfrFCEvxYv4RjaWgs4vV8MZnhR9utAffLh",
                "type": ["AttestedResource"],
                "content": {
                    "issuerId": test_issuer_id,
                    "attrNames": ["score"],
                    "name": "Example schema",
                    "version": "1.0",
                },
                "metadata": {"resourceId": ""},
                "proof": {
                    "type": "Ed25519Signature2018",
                    "created": "2022-01-26T18:40:00Z",
                    "verificationMethod": f"{test_issuer_id}#key-01",
                    "proofPurpose": "assertionMethod",
                },
            }
        ),
        status=200,
    )
)

upload_resource = mock.AsyncMock(
    return_value=mock.MagicMock(json=mock.AsyncMock(return_value={}), status=200)
)


class TestAnonCredsRegistry(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile({"wallet.type": "askar-anoncreds"})
        async with self.profile.session() as session:
            await MultikeyManager(session).create(
                alg="ed25519",
                kid="webvh:id.test-suite.app@witnessKey",
            )
            self.registry = DIDWebVHRegistry()

        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())

    async def test_digest_multibase(self):
        result = self.registry._digest_multibase(test_schema.to_json())
        assert result == test_schema_digest

    async def test_resource_uri(self):
        result = self.registry._create_resource_uri(test_issuer_id, test_schema_digest)
        assert result == test_schema_id

    @mock.patch(
        "aiohttp.ClientSession.post",
        request_resource,
    )
    async def test_register_schema(self):
        async with self.profile.session() as session:
            await MultikeyManager(session).create(
                alg="ed25519",
                kid=f"{test_issuer_id}#key-01",
            )

        result = await self.registry.register_schema(
            self.profile,
            AnonCredsSchema(
                issuer_id=test_issuer_id,
                attr_names=["name", "age", "vmax"],
                name="test_schema",
                version="1.0",
            ),
            {
                "verificationMethod": f"{test_issuer_id}#key-01",
            },
        )
        assert isinstance(result, SchemaResult)
        assert result.schema_state.state == "finished"

    @mock.patch.object(
        DIDWebVHResolver,
        "resolve_resource",
        return_value={
            "content": {
                "issuerId": test_issuer_id,
                "attrNames": ["name", "age", "vmax"],
                "name": "test_schema",
                "version": "1.0",
            },
            "metadata": {"resourceId": test_schema_digest},
        },
    )
    async def test_get_schema(self, _):
        result = await self.registry.get_schema(self.profile, test_schema_id)
        assert isinstance(result, GetSchemaResult)
        assert result.schema_id == test_schema_id
        assert result.schema.name == test_schema.name
        assert result.schema.version == test_schema.version
        assert result.schema.issuer_id == test_schema.issuer_id
        assert result.schema.attr_names == test_schema.attr_names

    @mock.patch(
        "aiohttp.ClientSession.post",
        request_resource,
    )
    async def test_register_credential_definition(self):
        async with self.profile.session() as session:
            await MultikeyManager(session).create(
                alg="ed25519",
                kid=f"{test_issuer_id}#key-01",
            )

        result = await self.registry.register_credential_definition(
            self.profile,
            GetSchemaResult(
                schema_id=test_schema_id,
                schema=AnonCredsSchema(
                    issuer_id=test_issuer_id,
                    name="test_schema",
                    version="1.0",
                    attr_names=["name", "age", "vmax"],
                ),
                schema_metadata={},
                resolution_metadata={},
            ),
            CredDef(
                issuer_id="CsQY9MGeD3CQP4EyuVFo5m",
                schema_id="CsQY9MGeD3CQP4EyuVFo5m:2:MYCO Biomarker:0.0.3",
                tag="default",
                type="CL",
                value=CredDefValue(
                    primary=CredDefValuePrimary("n", "s", {}, "rctxt", "z")
                ),
            ),
            {
                "verificationMethod": f"{test_issuer_id}#key-01",
            },
        )
        assert isinstance(result, CredDefResult)
        assert result.credential_definition_state.state == "finished"

    @mock.patch.object(
        DIDWebVHResolver,
        "resolve_resource",
        return_value={
            "content": {
                "schemaId": test_schema_id,
                "type": "CL",
                "tag": test_cred_tag,
                "value": {"primary": {"n": "n", "s": "s", "rctxt": "rctxt", "z": "z"}},
            },
            "metadata": {"resourceId": test_cred_def_digest},
        },
    )
    @mock.patch.object(
        CredDefValue,
        "deserialize",
        return_value=CredDefValue(
            primary=CredDefValuePrimary("n", "s", {}, "rctxt", "z")
        ),
    )
    async def test_get_credential_definition(self, *_):
        result = await self.registry.get_credential_definition(
            self.profile, test_cred_def_id
        )
        assert isinstance(result, GetCredDefResult)
        assert result.credential_definition_id == test_cred_def_id
        assert result.credential_definition.issuer_id == test_issuer_id
        assert result.credential_definition.schema_id == test_schema_id
        assert result.credential_definition.type == "CL"
        assert result.credential_definition.tag == test_cred_tag
        assert result.credential_definition.value

    @mock.patch(
        "aiohttp.ClientSession.post",
        request_resource,
    )
    async def test_register_revocation_registry_definition(self):
        async with self.profile.session() as session:
            await MultikeyManager(session).create(
                alg="ed25519",
                kid=f"{test_issuer_id}#key-01",
            )

        result = await self.registry.register_revocation_registry_definition(
            self.profile,
            RevRegDef(
                tag="tag",
                cred_def_id=test_cred_def_id,
                value=RevRegDefValue(
                    max_cred_num=100,
                    public_keys={
                        "accum_key": {"z": "1 0BB...386"},
                    },
                    tails_hash="not-correct-hash",
                    tails_location="http://tails-server.com",
                ),
                issuer_id=test_issuer_id,
                type="CL_ACCUM",
            ),
            {
                "verificationMethod": f"{test_issuer_id}#key-01",
            },
        )
        assert isinstance(result, RevRegDefResult)
        assert result.revocation_registry_definition_state.state == "finished"

    @mock.patch.object(
        DIDWebVHResolver,
        "resolve_resource",
        return_value={
            "content": {
                "credDefId": test_cred_def_id,
                "revocDefType": "CL_ACCUM",
                "tag": test_rev_reg_tag,
                "value": {
                    "maxCredNum": 100,
                    "publicKeys": {"accumKey": {"z": "1 0BB...386"}},
                    "tailsHash": "hash",
                    "tailsLocation": "http://tails-server.com",
                },
            },
            "metadata": {"resourceId": test_rev_reg_def_digest},
        },
    )
    @mock.patch.object(
        RevRegDefValue,
        "deserialize",
        return_value=RevRegDefValue(
            max_cred_num=100,
            public_keys={
                "accum_key": {"z": "1 0BB...386"},
            },
            tails_hash="hash",
            tails_location="http://tails-server.com",
        ),
    )
    async def test_get_revocation_registry_definition(self, *_):
        result = await self.registry.get_revocation_registry_definition(
            self.profile, test_rev_reg_id
        )
        assert isinstance(result, GetRevRegDefResult)
        assert result.revocation_registry_id == test_rev_reg_id
        assert result.revocation_registry.issuer_id == test_issuer_id
        assert result.revocation_registry.cred_def_id == test_cred_def_id
        assert result.revocation_registry.type == "CL_ACCUM"
        assert result.revocation_registry.tag == test_rev_reg_tag
        assert result.revocation_registry.value

    @mock.patch(
        "aiohttp.ClientSession.post",
        request_resource,
    )
    @mock.patch(
        "aiohttp.ClientSession.get",
        resolve_resource,
    )
    @mock.patch(
        "aiohttp.ClientSession.put",
        resolve_resource,
    )
    async def test_register_revocation_list(self):
        async with self.profile.session() as session:
            await MultikeyManager(session).create(
                alg="ed25519",
                kid=f"{test_issuer_id}#key-01",
            )

        result = await self.registry.register_revocation_list(
            self.profile,
            RevRegDef(
                tag="tag",
                cred_def_id=test_cred_def_id,
                value=RevRegDefValue(
                    max_cred_num=100,
                    public_keys={
                        "accum_key": {"z": "1 0BB...386"},
                    },
                    tails_hash="hash",
                    tails_location="http://tails-server.com",
                ),
                issuer_id=test_issuer_id,
                type="CL_ACCUM",
            ),
            RevList(
                issuer_id=test_issuer_id,
                current_accumulator="21 124C594B6B20E41B681E92B2C43FD165EA9E68BC3C9D63A82C8893124983CAE94 21 124C5341937827427B0A3A32113BD5E64FB7AB39BD3E5ABDD7970874501CA4897 6 5438CB6F442E2F807812FD9DC0C39AFF4A86B1E6766DBB5359E86A4D70401B0F 4 39D1CA5C4716FFC4FE0853C4FF7F081DFD8DF8D2C2CA79705211680AC77BF3A1 6 70504A5493F89C97C225B68310811A41AD9CD889301F238E93C95AD085E84191 4 39582252194D756D5D86D0EED02BF1B95CE12AED2FA5CD3C53260747D891993C",
                revocation_list=[1, 1, 1, 1],
                timestamp=1669640864487,
                rev_reg_def_id=test_rev_reg_id,
            ),
            {
                "verificationMethod": f"{test_issuer_id}#key-01",
            },
        )
        assert isinstance(result, RevListResult)
        assert result.revocation_list_state.state == "finished"

    @mock.patch(
        "aiohttp.ClientSession.get",
        mock.AsyncMock(
            return_value=mock.MagicMock(
                json=mock.AsyncMock(
                    return_value={
                        "@context": ["https://w3id.org/security/data-integrity/v2"],
                        "id": f"{test_issuer_id}/resources/zQmPNuWdxtjcFiVuSEb2tWbD3jiALskcuUp52yzp1NvyCz2",
                        "type": ["AttestedResource"],
                        "content": {
                            "currentAccumulator": "21 124C594B6B20E41B681E92B2C43FD165EA9E68BC3C9D63A82C8893124983CAE94",
                            "revocationList": [0, 0, 0],
                        },
                        "metadata": {"resourceId": ""},
                        "proof": {
                            "type": "Ed25519Signature2018",
                            "created": "2022-01-26T18:40:00Z",
                            "verificationMethod": f"{test_issuer_id}#key-01",
                            "proofPurpose": "assertionMethod",
                        },
                        "links": [
                            {
                                "rel": "revocationList",
                                "id": f"{test_issuer_id}/resources/zQmPNuWdxtjcFiVuSEb2tWbD3jiALskcuUp52yzp1NvyCz2",
                                "timestamp": 1669640864487,
                            }
                        ],
                    }
                ),
                status=200,
            )
        ),
    )
    async def test_get_revocation_list(self):
        result = await self.registry.get_revocation_list(
            self.profile, test_rev_reg_id, 0000000000000, 9999999999999
        )
        assert isinstance(result, GetRevListResult)
        assert result.revocation_list.issuer_id == test_issuer_id
        assert result.revocation_list.rev_reg_def_id == test_rev_reg_id
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
