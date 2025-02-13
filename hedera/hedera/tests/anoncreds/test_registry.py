import re
import pytest

from dataclasses import dataclass

from unittest.mock import AsyncMock, patch

from acapy_agent.anoncreds.base import AnonCredsObjectNotFound, AnonCredsResolutionError
from acapy_agent.anoncreds.models.credential_definition import (
    CredDef,
    CredDefValue,
    CredDefValuePrimary,
    CredDefValueRevocation,
)
from acapy_agent.anoncreds.models.revocation import RevList, RevRegDef, RevRegDefValue

from hiero_did_sdk_python.anoncreds import (
    CredDefValue as HederaCredDefValue,
    CredDefValuePrimary as HederaCredDefValuePrimary,
    CredDefValueRevocation as HederaCredDefValueRevocation,
    AnonCredsRevRegDef as HederaAnonCredsRevRegDef,
    RevRegDefValue as HederaRevRegDefValue,
    AnonCredsRevList as HederaAnonCredsRevList,
)
from hiero_did_sdk_python.anoncreds.types import (
    AnonCredsCredDef as HederaAnonCredsCredDef,
    AnonCredsSchema as HederaAnonCredsSchema,
    CredDefState,
    GetCredDefResult as HederaGetCredDefResult,
    GetRevListResult as HederaGetRevListResult,
    GetRevRegDefResult as HederaGetRevRegDefResult,
    GetSchemaResult as HederaGetSchemaResult,
    RegisterCredDefResult as HederaRegisterCredDefResult,
    RegisterRevListResult as HederaRegisterRevListResult,
    RegisterRevRegDefResult as HederaRegisterRevRegDefResult,
    RegisterSchemaResult as HederaRegisterSchemaResult,
    RevListState as HederaRevListState,
    RevRegDefState as HederaRevRegDefState,
    SchemaState as HederaSchemaState,
)
from hedera.anoncreds import HederaAnonCredsRegistry
from hedera.anoncreds.registry import _validate_resolution_result
from hedera.anoncreds.types import (
    build_acapy_cred_def_result,
    build_acapy_get_cred_def_result,
    build_acapy_get_rev_list_result,
    build_acapy_get_rev_reg_def_result,
    build_acapy_get_schema_result,
    build_acapy_rev_list_result,
    build_acapy_rev_reg_def_result,
    build_acapy_schema_result,
)


@dataclass
class MockAnonCredsResult:
    result: str | None
    resolution_metadata: dict | None


MOCK_RESULT_PARAMS = {"result": "test", "resolution_metadata": {}}

MOCK_RESULT_ATTRIBUTE_NAME = "result"

MOCK_ISSUER_ID = (
    "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925"
)

MOCK_SCHEMA = HederaAnonCredsSchema(
    name="Example schema", issuer_id=MOCK_ISSUER_ID, attr_names=["score"], version="1.0"
)
MOCK_SCHEMA_ID = "did:hedera:testnet:zFwZUYPrhi333pC2anAnSkctXgZzLfeR8DXURo2N4xV1C_0.0.5284925/anoncreds/v0/SCHEMA/0.0.5284932"

MOCK_CRED_DEF = HederaAnonCredsCredDef(
    schema_id=MOCK_SCHEMA_ID,
    issuer_id=MOCK_ISSUER_ID,
    tag="mock-cred-def-tag",
    value=HederaCredDefValue(
        HederaCredDefValuePrimary(n="n", s="s", r={"key": "value"}, rctxt="rctxt", z="z"),
        HederaCredDefValueRevocation(
            g="g",
            g_dash="g_dash",
            h="h",
            h0="h0",
            h1="h1",
            h2="h2",
            htilde="htilde",
            h_cap="h_cap",
            u="u",
            pk="pk",
            y="y",
        ),
    ),
)
MOCK_CRED_DEF_ID = "did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/PUBLIC_CRED_DEF/0.0.5280968"

MOCK_REV_REG_DEF = HederaAnonCredsRevRegDef(
    issuer_id=MOCK_ISSUER_ID,
    cred_def_id=MOCK_CRED_DEF_ID,
    tag="mock-rev-reg-def-tag",
    value=HederaRevRegDefValue(
        public_keys={"accumKey": {"z": "mock-accum-key"}},
        max_cred_num=15,
        tails_location="mock-tails-location",
        tails_hash="mock-tails-hash",
    ),
)
MOCK_REV_REG_DEF_ID = "did:hedera:testnet:zcZMJMxUGZpxKmP35ACBWLhQyQVqtRc5T7LQhdyTDtEiP_0.0.5280965/anoncreds/v0/REV_REG/0.0.5280969"

MOCK_REV_LIST = HederaAnonCredsRevList(
    issuer_id=MOCK_ISSUER_ID,
    rev_reg_def_id=MOCK_REV_REG_DEF_ID,
    revocation_list=[0, 1, 0],
    current_accumulator="mock-current-accum",
)


async def create_and_setup_registry(context):
    registry = HederaAnonCredsRegistry()
    await registry.setup(context)
    return registry


class TestAnonCredsRegistry:
    async def test_validate_resolution_result(self):
        _validate_resolution_result(
            MockAnonCredsResult(**MOCK_RESULT_PARAMS), MOCK_RESULT_ATTRIBUTE_NAME
        )

        with pytest.raises(
            AnonCredsResolutionError,
            match=f"Failed to retrieve {MOCK_RESULT_ATTRIBUTE_NAME}",
        ):
            _validate_resolution_result(
                MockAnonCredsResult(**{**MOCK_RESULT_PARAMS, "result": None}),
                MOCK_RESULT_ATTRIBUTE_NAME,
            )

        with pytest.raises(AnonCredsResolutionError, match="Custom error"):
            _validate_resolution_result(
                MockAnonCredsResult(
                    **{
                        **MOCK_RESULT_PARAMS,
                        "resolution_metadata": {
                            "error": "otherError",
                            "message": "Custom error",
                        },
                    }
                ),
                MOCK_RESULT_ATTRIBUTE_NAME,
            )

        with pytest.raises(AnonCredsResolutionError, match="Unknown error"):
            _validate_resolution_result(
                MockAnonCredsResult(
                    **{
                        **MOCK_RESULT_PARAMS,
                        "resolution_metadata": {"error": "otherError"},
                    }
                ),
                MOCK_RESULT_ATTRIBUTE_NAME,
            )

        with pytest.raises(AnonCredsObjectNotFound, match="Unknown error"):
            _validate_resolution_result(
                MockAnonCredsResult(
                    **{**MOCK_RESULT_PARAMS, "resolution_metadata": {"error": "notFound"}}
                ),
                MOCK_RESULT_ATTRIBUTE_NAME,
            )

        with pytest.raises(AnonCredsObjectNotFound, match="Custom error"):
            _validate_resolution_result(
                MockAnonCredsResult(
                    **{
                        **MOCK_RESULT_PARAMS,
                        "resolution_metadata": {
                            "error": "notFound",
                            "message": "Custom error",
                        },
                    }
                ),
                MOCK_RESULT_ATTRIBUTE_NAME,
            )

    async def test_returns_supported_identifiers_regex(self, context):
        registry = await create_and_setup_registry(context)

        assert registry.supported_identifiers_regex == re.compile("^did:hedera:.*$")

    @patch("hedera.anoncreds.registry.SdkHederaAnonCredsRegistry")
    async def test_get_schema(self, mock_hedera_did_anoncreds_registry, profile, context):
        hedera_result = HederaGetSchemaResult(
            schema_id=MOCK_SCHEMA_ID,
            resolution_metadata={},
            schema_metadata={},
            schema=MOCK_SCHEMA,
        )
        mock_hedera_did_anoncreds_registry.return_value.get_schema = AsyncMock(
            return_value=hedera_result
        )

        registry = await create_and_setup_registry(context)

        result = await registry.get_schema(profile, MOCK_SCHEMA_ID)

        assert (
            result.serialize() == build_acapy_get_schema_result(hedera_result).serialize()
        )

    @patch("hedera.anoncreds.registry.SdkHederaAnonCredsRegistry")
    async def test_get_schema_info_by_id(
        self, mock_hedera_did_anoncreds_registry, profile, context
    ):
        hedera_result = HederaGetSchemaResult(
            schema_id=MOCK_SCHEMA_ID,
            resolution_metadata={},
            schema_metadata={},
            schema=MOCK_SCHEMA,
        )
        mock_hedera_did_anoncreds_registry.return_value.get_schema = AsyncMock(
            return_value=hedera_result
        )

        registry = await create_and_setup_registry(context)

        schema_info = await registry.get_schema_info_by_id(profile, MOCK_SCHEMA_ID)

        assert schema_info.issuer_id == MOCK_ISSUER_ID
        assert schema_info.name == MOCK_SCHEMA.name
        assert schema_info.version == MOCK_SCHEMA.version

    @patch("hedera.anoncreds.registry.SdkHederaAnonCredsRegistry")
    async def test_get_credential_definition(
        self, mock_hedera_did_anoncreds_registry, profile, context
    ):
        hedera_result = HederaGetCredDefResult(
            credential_definition_id=MOCK_CRED_DEF_ID,
            resolution_metadata={},
            credential_definition_metadata={},
            credential_definition=MOCK_CRED_DEF,
        )
        mock_hedera_did_anoncreds_registry.return_value.get_cred_def = AsyncMock(
            return_value=hedera_result
        )

        registry = await create_and_setup_registry(context)

        result = await registry.get_credential_definition(profile, MOCK_CRED_DEF_ID)

        assert (
            result.serialize()
            == build_acapy_get_cred_def_result(hedera_result).serialize()
        )

    @patch("hedera.anoncreds.registry.SdkHederaAnonCredsRegistry")
    async def test_get_revocation_registry_definition(
        self, mock_hedera_did_anoncreds_registry, profile, context
    ):
        hedera_result = HederaGetRevRegDefResult(
            revocation_registry_definition_id=MOCK_REV_REG_DEF_ID,
            revocation_registry_definition=MOCK_REV_REG_DEF,
            resolution_metadata={},
            revocation_registry_definition_metadata={},
        )
        mock_hedera_did_anoncreds_registry.return_value.get_rev_reg_def = AsyncMock(
            return_value=hedera_result
        )

        registry = await create_and_setup_registry(context)

        result = await registry.get_revocation_registry_definition(
            profile, MOCK_REV_REG_DEF_ID
        )

        assert (
            result.serialize()
            == build_acapy_get_rev_reg_def_result(hedera_result).serialize()
        )

    @patch("hedera.anoncreds.registry.SdkHederaAnonCredsRegistry")
    async def test_get_revocation_list(
        self, mock_hedera_did_anoncreds_registry, profile, context
    ):
        hedera_result = HederaGetRevListResult(
            revocation_registry_id=MOCK_REV_REG_DEF_ID,
            revocation_list=MOCK_REV_LIST,
            revocation_list_metadata={},
            resolution_metadata={},
        )
        mock_hedera_did_anoncreds_registry.return_value.get_rev_list = AsyncMock(
            return_value=hedera_result
        )

        registry = await create_and_setup_registry(context)

        result = await registry.get_revocation_list(
            profile, MOCK_REV_REG_DEF_ID, 0, MOCK_REV_LIST.timestamp
        )

        assert (
            result.serialize()
            == build_acapy_get_rev_list_result(hedera_result).serialize()
        )

    @patch("hedera.anoncreds.registry.SdkHederaAnonCredsRegistry")
    @patch("hedera.anoncreds.registry.get_encoded_private_key_for_did", new=AsyncMock())
    async def test_register_schema(
        self, mock_hedera_did_anoncreds_registry, profile, context
    ):
        hedera_result = HederaRegisterSchemaResult(
            schema_state=HederaSchemaState(
                state="finished", schema_id=MOCK_SCHEMA_ID, schema=MOCK_SCHEMA
            ),
            registration_metadata={},
            schema_metadata={},
        )
        mock_hedera_did_anoncreds_registry.return_value.register_schema = AsyncMock(
            return_value=hedera_result
        )

        registry = await create_and_setup_registry(context)

        result = await registry.register_schema(profile, MOCK_SCHEMA)

        assert result.serialize() == build_acapy_schema_result(hedera_result).serialize()

    @patch("hedera.anoncreds.registry.SdkHederaAnonCredsRegistry")
    @patch("hedera.anoncreds.registry.get_encoded_private_key_for_did", new=AsyncMock())
    async def test_register_credential_definition(
        self, mock_hedera_did_anoncreds_registry, profile, context
    ):
        hedera_result = HederaRegisterCredDefResult(
            credential_definition_state=CredDefState(
                state="finished",
                credential_definition_id=MOCK_CRED_DEF_ID,
                credential_definition=MOCK_CRED_DEF,
            ),
            registration_metadata={},
            credential_definition_metadata={},
        )
        mock_hedera_did_anoncreds_registry.return_value.register_cred_def = AsyncMock(
            return_value=hedera_result
        )

        schema_result = build_acapy_get_schema_result(
            HederaGetSchemaResult(
                schema_id=MOCK_SCHEMA_ID,
                resolution_metadata={},
                schema_metadata={},
                schema=MOCK_SCHEMA,
            )
        )

        registry = await create_and_setup_registry(context)

        cred_def = CredDef(
            issuer_id=MOCK_ISSUER_ID,
            schema_id=MOCK_SCHEMA_ID,
            type="CL",
            tag=MOCK_CRED_DEF.tag,
            value=CredDefValue(
                primary=CredDefValuePrimary(**MOCK_CRED_DEF.value.primary.__dict__),
                revocation=CredDefValueRevocation(
                    **MOCK_CRED_DEF.value.revocation.__dict__
                ),
            ),
        )
        result = await registry.register_credential_definition(
            profile, schema_result, cred_def
        )

        assert (
            result.serialize() == build_acapy_cred_def_result(hedera_result).serialize()
        )

    @patch("hedera.anoncreds.registry.SdkHederaAnonCredsRegistry")
    @patch("hedera.anoncreds.registry.get_encoded_private_key_for_did", new=AsyncMock())
    async def test_register_revocation_registry_definition(
        self, mock_hedera_did_anoncreds_registry, profile, context
    ):
        hedera_result = HederaRegisterRevRegDefResult(
            revocation_registry_definition_state=HederaRevRegDefState(
                state="finished",
                revocation_registry_definition_id=MOCK_REV_REG_DEF_ID,
                revocation_registry_definition=MOCK_REV_REG_DEF,
            ),
            registration_metadata={},
            revocation_registry_definition_metadata={},
        )
        mock_hedera_did_anoncreds_registry.return_value.register_rev_reg_def = AsyncMock(
            return_value=hedera_result
        )

        registry = await create_and_setup_registry(context)

        rev_reg_def = RevRegDef(
            issuer_id=MOCK_ISSUER_ID,
            cred_def_id=MOCK_CRED_DEF_ID,
            type="CL_ACCUM",
            tag=MOCK_REV_REG_DEF.tag,
            value=RevRegDefValue(**MOCK_REV_REG_DEF.value.__dict__),
        )
        result = await registry.register_revocation_registry_definition(
            profile, rev_reg_def
        )

        assert (
            result.serialize()
            == build_acapy_rev_reg_def_result(hedera_result).serialize()
        )

    @patch("hedera.anoncreds.registry.SdkHederaAnonCredsRegistry")
    @patch("hedera.anoncreds.registry.get_encoded_private_key_for_did", new=AsyncMock())
    async def test_register_revocation_list(
        self, mock_hedera_did_anoncreds_registry, profile, context
    ):
        hedera_result = HederaRegisterRevListResult(
            revocation_list_state=HederaRevListState(
                state="finished", revocation_list=MOCK_REV_LIST
            ),
            registration_metadata={},
            revocation_list_metadata={},
        )
        mock_hedera_did_anoncreds_registry.return_value.register_rev_list = AsyncMock(
            return_value=hedera_result
        )

        registry = await create_and_setup_registry(context)

        rev_reg_def = RevRegDef(
            issuer_id=MOCK_ISSUER_ID,
            cred_def_id=MOCK_CRED_DEF_ID,
            type="CL_ACCUM",
            tag=MOCK_REV_REG_DEF.tag,
            value=RevRegDefValue(**MOCK_REV_REG_DEF.value.__dict__),
        )
        rev_list = RevList(
            issuer_id=MOCK_ISSUER_ID,
            rev_reg_def_id=MOCK_REV_REG_DEF_ID,
            revocation_list=MOCK_REV_LIST.revocation_list,
            current_accumulator=MOCK_REV_LIST.current_accumulator,
            timestamp=0,
        )
        result = await registry.register_revocation_list(profile, rev_reg_def, rev_list)

        assert (
            result.serialize() == build_acapy_rev_list_result(hedera_result).serialize()
        )

    @patch("hedera.anoncreds.registry.SdkHederaAnonCredsRegistry")
    @patch("hedera.anoncreds.registry.get_encoded_private_key_for_did", new=AsyncMock())
    async def test_update_revocation_list(
        self, mock_hedera_did_anoncreds_registry, profile, context
    ):
        hedera_result = HederaRegisterRevListResult(
            revocation_list_state=HederaRevListState(
                state="finished", revocation_list=MOCK_REV_LIST
            ),
            registration_metadata={},
            revocation_list_metadata={},
        )
        mock_hedera_did_anoncreds_registry.return_value.update_rev_list = AsyncMock(
            return_value=hedera_result
        )

        registry = await create_and_setup_registry(context)

        rev_reg_def = RevRegDef(
            issuer_id=MOCK_ISSUER_ID,
            cred_def_id=MOCK_CRED_DEF_ID,
            type="CL_ACCUM",
            tag=MOCK_REV_REG_DEF.tag,
            value=RevRegDefValue(**MOCK_REV_REG_DEF.value.__dict__),
        )
        prev_rev_list = RevList(
            issuer_id=MOCK_ISSUER_ID,
            rev_reg_def_id=MOCK_REV_REG_DEF_ID,
            revocation_list=[1, 0, 0],
            current_accumulator="prev-accum",
            timestamp=0,
        )
        rev_list = RevList(
            issuer_id=MOCK_ISSUER_ID,
            rev_reg_def_id=MOCK_REV_REG_DEF_ID,
            revocation_list=MOCK_REV_LIST.revocation_list,
            current_accumulator=MOCK_REV_LIST.current_accumulator,
            timestamp=100,
        )

        result = await registry.update_revocation_list(
            profile, rev_reg_def, prev_rev_list, rev_list, [2]
        )

        assert (
            result.serialize() == build_acapy_rev_list_result(hedera_result).serialize()
        )
