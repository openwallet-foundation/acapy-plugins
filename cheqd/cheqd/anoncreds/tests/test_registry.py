import time
from unittest.mock import AsyncMock, MagicMock, patch

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
    RevRegDefResult,
    RevListResult,
)
from acapy_agent.anoncreds.models.schema import GetSchemaResult, SchemaResult
from acapy_agent.anoncreds.models.schema_info import AnoncredsSchemaInfo

from ...did.base import (
    ResourceCreateRequestOptions,
    ResourceUpdateRequestOptions,
    Options,
)
from ...did.manager import CheqdDIDManager
from ...did.tests.mocks import (
    registrar_resource_responses_no_signing_request,
    setup_mock_registrar,
    registrar_resource_responses_network_fail,
    registrar_resource_responses_not_finished,
)
from ...validation import CHEQD_DID_VALIDATE
from ..registry import DIDCheqdRegistry

TEST_CHEQD_DID = "did:cheqd:testnet:1686a962-6e82-46f3-bde7-e6711d63958c"
TEST_CHEQD_SCHEMA_ID = "did:cheqd:testnet:1686a962-6e82-46f3-bde7-e6711d63958c/resources/e788d345-dd0c-427a-a74b-27faf1e608cd"
TEST_CHEQD_CRED_DEF_ID = "did:cheqd:testnet:1686a962-6e82-46f3-bde7-e6711d63958c/resources/02229804-b46a-4be9-a6f1-13869109c7ea"
TEST_CHEQD_REV_REG_ENTRY = "did:cheqd:testnet:1686a962-6e82-46f3-bde7-e6711d63958c?resourceName=test&resourceType=anoncredsRevRegEntry"
TEST_REGISTRAR_URL = "http://localhost:9080/1.0/"
TEST_RESOLVER_URL = "http://localhost:8080/1.0/identifiers/"


async def test_supported_did_regex():
    registry = DIDCheqdRegistry()

    assert registry.supported_identifiers_regex == CHEQD_DID_VALIDATE.PATTERN
    assert bool(registry.supported_identifiers_regex.match(TEST_CHEQD_DID))
    assert bool(registry.supported_identifiers_regex.match(TEST_CHEQD_SCHEMA_ID))
    assert bool(registry.supported_identifiers_regex.match(TEST_CHEQD_CRED_DEF_ID))
    assert bool(registry.supported_identifiers_regex.match(TEST_CHEQD_REV_REG_ENTRY))


async def test_make_schema_id():
    # Arrange
    schema = MagicMock()
    schema.issuer_id = "MOCK_ID"
    resource_id = "MOCK_RESOURCE_ID"

    # Act
    schema_id = DIDCheqdRegistry.make_schema_id(schema, resource_id)

    # Assert
    assert schema_id == "MOCK_ID/resources/MOCK_RESOURCE_ID"


async def test_make_credential_definition_id():
    # Arrange
    credential_definition = MagicMock()
    credential_definition.issuer_id = "MOCK_ID"
    resource_id = "MOCK_RESOURCE_ID"

    # Act
    credential_definition_id = DIDCheqdRegistry.make_credential_definition_id(
        credential_definition, resource_id
    )

    # Assert
    assert credential_definition_id == "MOCK_ID/resources/MOCK_RESOURCE_ID"


async def test_make_revocation_registry_id():
    # Arrange
    revocation_registry_definition = MagicMock()
    revocation_registry_definition.issuer_id = "MOCK_ID"
    resource_id = "MOCK_RESOURCE_ID"

    # Act
    revocation_registry_id = DIDCheqdRegistry.make_revocation_registry_id(
        revocation_registry_definition, resource_id
    )

    # Assert
    assert revocation_registry_id == "MOCK_ID/resources/MOCK_RESOURCE_ID"


async def test_split_did_url():
    # Arrange
    did_url = "PART0/PART1/PART2"

    # Act
    result = DIDCheqdRegistry.split_did_url(did_url)

    # Assert
    assert result == ("PART0", "PART2")


async def test_get_schema(mock_profile, mock_resolver):
    schema_id = "PART0/PART1/PART2"

    with patch(
        "cheqd.cheqd.anoncreds.registry.CheqdDIDResolver", return_value=mock_resolver
    ):
        registry = DIDCheqdRegistry()
        result = await registry.get_schema(_profile=mock_profile, schema_id=schema_id)

        # Assert
        assert isinstance(result, GetSchemaResult)
        assert result.schema_id == schema_id
        assert result.schema.issuer_id == "PART0"
        assert result.schema.attr_names == "MOCK_ATTR_NAMES"
        assert result.schema.name == "MOCK_NAME"
        assert result.schema.version == "MOCK_VERSION"
        assert result.schema_metadata == {"MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"}
        assert result.resolution_metadata == {}


async def test_register_schema(
    mock_profile, mock_schema, mock_create_and_publish_resource
):
    # Arrange
    with (
        patch(
            "cheqd.cheqd.anoncreds.registry.CheqdDIDResolver.dereference_with_metadata",
            return_value=None,
        ),
        patch(
            "cheqd.cheqd.anoncreds.registry.DIDCheqdRegistry._create_and_publish_resource",
            return_value=mock_create_and_publish_resource,
        ) as mock,
    ):
        # Act
        registry = DIDCheqdRegistry()
        result = await registry.register_schema(profile=mock_profile, schema=mock_schema)

        assert isinstance(result, SchemaResult)
        assert result.schema_state.state == "finished"
        assert (
            result.schema_state.schema_id == "MOCK_ISSUER_ID/resources/MOCK_RESOURCE_ID"
        )
        assert result.schema_state.schema == mock_schema
        assert result.registration_metadata["resource_id"] == "MOCK_RESOURCE_ID"
        assert result.registration_metadata["resource_name"] == "MOCK_NAME"
        assert result.registration_metadata["resource_type"] == "anonCredsSchema"

        mock.assert_called_once_with(
            mock_profile,
            TEST_REGISTRAR_URL,
            TEST_RESOLVER_URL,
            ResourceCreateRequestOptions(
                options=Options(
                    name="MOCK_NAME",
                    type="anonCredsSchema",
                    versionId="MOCK_VERSION",
                ),
                content="eyJuYW1lIjogIk1PQ0tfTkFNRSIsICJ2ZXJzaW9uIjogIk1PQ0tfVkVSU0lPTiIsICJhdHRyTmFtZXMiOiAiTU9DS19BVFRSX05BTUVTIn0",
                did="MOCK_ISSUER_ID",
                relativeDidUrl=None,
            ),
        )


async def test_register_schema_update(
    mock_profile, mock_schema, mock_create_and_publish_resource
):
    # Arrange
    with (
        patch(
            "cheqd.cheqd.anoncreds.registry.CheqdDIDResolver.dereference_with_metadata",
            return_value={},
        ),
        patch(
            "cheqd.cheqd.anoncreds.registry.DIDCheqdRegistry._update_and_publish_resource",
            return_value=mock_create_and_publish_resource,
        ) as mock,
    ):
        # Act
        registry = DIDCheqdRegistry()
        result = await registry.register_schema(profile=mock_profile, schema=mock_schema)

        assert isinstance(result, SchemaResult)
        assert result.schema_state.state == "finished"
        assert (
            result.schema_state.schema_id == "MOCK_ISSUER_ID/resources/MOCK_RESOURCE_ID"
        )
        assert result.schema_state.schema == mock_schema
        assert result.registration_metadata["resource_id"] == "MOCK_RESOURCE_ID"
        assert result.registration_metadata["resource_name"] == "MOCK_NAME"
        assert result.registration_metadata["resource_type"] == "anonCredsSchema"

        mock.assert_called_once_with(
            mock_profile,
            TEST_REGISTRAR_URL,
            TEST_RESOLVER_URL,
            ResourceUpdateRequestOptions(
                options=Options(
                    name="MOCK_NAME",
                    type="anonCredsSchema",
                    versionId="MOCK_VERSION",
                ),
                content=[
                    "eyJuYW1lIjogIk1PQ0tfTkFNRSIsICJ2ZXJzaW9uIjogIk1PQ0tfVkVSU0lPTiIsICJhdHRyTmFtZXMiOiAiTU9DS19BVFRSX05BTUVTIn0"
                ],
                did="MOCK_ISSUER_ID",
                relativeDidUrl=None,
            ),
        )


async def test_register_schema_registration_error(mock_profile, mock_schema):
    # Arrange
    mock_create_and_publish_resource = AsyncMock()
    mock_create_and_publish_resource.side_effect = Exception("Error")

    # Act
    with (
        patch(
            "cheqd.cheqd.anoncreds.registry.CheqdDIDResolver.dereference_with_metadata",
            return_value=None,
        ),
        patch(
            "cheqd.cheqd.anoncreds.registry.DIDCheqdRegistry._create_and_publish_resource",
            return_value=mock_create_and_publish_resource,
        ),
    ):
        with pytest.raises(Exception) as e:
            registry = DIDCheqdRegistry()
            await registry.register_schema(profile=mock_profile, schema=mock_schema)

        # Assert
        assert isinstance(e.value, AnonCredsRegistrationError)


async def test_get_credential_definition(mock_profile, mock_resolver):
    # Arrange
    credential_definition_id = "PART0/PART1/PART2"

    # Act
    with (
        patch(
            "cheqd.cheqd.anoncreds.registry.CheqdDIDResolver", return_value=mock_resolver
        ),
        patch(
            "cheqd.cheqd.anoncreds.registry.CredDefValue.deserialize",
            return_value={"MOCK_KEY": "MOCK_VALUE"},
        ),
    ):
        registry = DIDCheqdRegistry()
        result = await registry.get_credential_definition(
            mock_profile, credential_definition_id
        )

        # Assert
        assert isinstance(result, GetCredDefResult)
        assert result.credential_definition_id == credential_definition_id
        assert result.credential_definition.issuer_id == "PART0"
        assert result.credential_definition.schema_id == "MOCK_SCHEMA_ID"
        assert result.credential_definition.type == "MOCK_TYPE"
        assert result.credential_definition.tag == "MOCK_TAG"
        assert result.credential_definition.value == {"MOCK_KEY": "MOCK_VALUE"}
        assert result.credential_definition_metadata == {
            "MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"
        }
        assert result.resolution_metadata == {}


async def test_register_credential_definition(
    mock_profile,
    mock_schema,
    mock_credential_definition,
    mock_create_and_publish_resource,
):
    # Arrange
    with (
        patch(
            "cheqd.cheqd.anoncreds.registry.CheqdDIDResolver.dereference_with_metadata",
            return_value=None,
        ),
        patch(
            "cheqd.cheqd.anoncreds.registry.DIDCheqdRegistry._create_and_publish_resource",
            return_value=mock_create_and_publish_resource,
        ) as mock,
    ):
        # Act
        registry = DIDCheqdRegistry()
        result = await registry.register_credential_definition(
            mock_profile, mock_schema, mock_credential_definition
        )

        # Assert
        assert isinstance(result, CredDefResult)
        assert result.credential_definition_state.state == "finished"
        assert (
            result.credential_definition_state.credential_definition_id
            == "MOCK_ISSUER_ID/resources/MOCK_RESOURCE_ID"
        )
        assert (
            result.credential_definition_state.credential_definition
            == mock_credential_definition
        )
        assert result.registration_metadata["resource_id"] == "MOCK_RESOURCE_ID"
        assert result.registration_metadata["resource_name"] == "MOCK_NAME-MOCK_TAG"
        assert result.registration_metadata["resource_type"] == "anonCredsCredDef"

        mock.assert_called_once_with(
            mock_profile,
            TEST_REGISTRAR_URL,
            TEST_RESOLVER_URL,
            ResourceCreateRequestOptions(
                options=Options(
                    name="MOCK_NAME-MOCK_TAG",
                    type="anonCredsCredDef",
                    versionId="MOCK_TAG",
                ),
                content="eyJ0eXBlIjogIk1PQ0tfVFlQRSIsICJ0YWciOiAiTU9DS19UQUciLCAidmFsdWUiOiB7Ik1PQ0tfS0VZIjogIk1PQ0tfVkFMVUVfU0VSSUFMSVpFRCJ9LCAic2NoZW1hSWQiOiAiTU9DS19JRCJ9",
                did="MOCK_ISSUER_ID",
                relativeDidUrl=None,
            ),
        )


async def test_get_revocation_registry_definition(mock_profile, mock_resolver):
    # Arrange
    revocation_registry_id = "PART0/PART1/PART2"

    # Act
    with (
        patch(
            "cheqd.cheqd.anoncreds.registry.CheqdDIDResolver", return_value=mock_resolver
        ),
        patch(
            "cheqd.cheqd.anoncreds.registry.RevRegDefValue.deserialize",
            return_value={"MOCK_KEY": "MOCK_VALUE"},
        ),
    ):
        registry = DIDCheqdRegistry()
        result = await registry.get_revocation_registry_definition(
            mock_profile, revocation_registry_id
        )

        # Assert
        assert isinstance(result, GetRevRegDefResult)
        assert result.revocation_registry_id == "PART0/PART1/PART2"
        assert result.revocation_registry.issuer_id == "PART0"
        assert result.revocation_registry.cred_def_id == "MOCK_CRED_DEF_ID"
        assert result.revocation_registry.type == "MOCK_REVOC_DEF_TYPE"
        assert result.revocation_registry.tag == "MOCK_TAG"
        assert result.revocation_registry.value == {"MOCK_KEY": "MOCK_VALUE"}
        assert result.revocation_registry_metadata == {
            "MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"
        }
        assert result.resolution_metadata == {}


async def test_register_revocation_registry_definition(
    mock_profile,
    mock_rev_reg_def,
    mock_get_credential_definition_result,
    mock_create_and_publish_resource,
):
    # Arrange
    with (
        patch(
            "cheqd.cheqd.anoncreds.registry.DIDCheqdRegistry.get_credential_definition",
            return_value=mock_get_credential_definition_result,
        ),
        patch(
            "cheqd.cheqd.anoncreds.registry.CheqdDIDResolver.dereference_with_metadata",
            return_value=None,
        ),
        patch(
            "cheqd.cheqd.anoncreds.registry.DIDCheqdRegistry._create_and_publish_resource",
            return_value=mock_create_and_publish_resource,
        ) as mock,
    ):
        # Act
        registry = DIDCheqdRegistry()
        result = await registry.register_revocation_registry_definition(
            mock_profile, mock_rev_reg_def
        )

        # Assert
        assert isinstance(result, RevRegDefResult)
        assert result.revocation_registry_definition_state.state == "finished"
        assert (
            result.revocation_registry_definition_state.revocation_registry_definition_id
            == "MOCK_ISSUER_ID/resources/MOCK_RESOURCE_ID"
        )
        assert (
            result.revocation_registry_definition_state.revocation_registry_definition
            == mock_rev_reg_def
        )
        assert result.registration_metadata["resource_id"] == "MOCK_RESOURCE_ID"
        assert (
            result.registration_metadata["resource_name"] == "MOCK_RESOURCE_NAME-MOCK_TAG"
        )
        assert result.registration_metadata["resource_type"] == "anonCredsRevocRegDef"
        assert result.revocation_registry_definition_metadata == {}
        mock.assert_called_once_with(
            mock_profile,
            TEST_REGISTRAR_URL,
            TEST_RESOLVER_URL,
            ResourceCreateRequestOptions(
                options=Options(
                    name="MOCK_RESOURCE_NAME-MOCK_TAG",
                    type="anonCredsRevocRegDef",
                    versionId="MOCK_TAG",
                ),
                content="eyJyZXZvY0RlZlR5cGUiOiAiTU9DS19UWVBFIiwgInRhZyI6ICJNT0NLX1RBRyIsICJ2YWx1ZSI6IHsiTU9DS19LRVkiOiAiTU9DS19WQUxVRSJ9LCAiY3JlZERlZklkIjogIk1PQ0tfQ1JFRF9ERUZfSUQifQ",
                did="MOCK_ISSUER_ID",
                relativeDidUrl=None,
            ),
        )


async def test_get_revocation_list(mock_profile, mock_resolver, mock_rev_reg_def):
    # Arrange
    revocation_registry_id = "PART0/PART1/PART2"

    # Act
    with (
        patch(
            "cheqd.cheqd.anoncreds.registry.CheqdDIDResolver", return_value=mock_resolver
        ),
        patch(
            "cheqd.cheqd.anoncreds.registry.DIDCheqdRegistry.get_revocation_registry_definition",
            AsyncMock(return_value=mock_rev_reg_def),
        ),
    ):
        registry = DIDCheqdRegistry()
        result = await registry.get_revocation_list(
            mock_profile, revocation_registry_id, timestamp_to=int(time.time())
        )

        # Assert
        assert isinstance(result, GetRevListResult)
        assert result.revocation_list.issuer_id == "PART0"
        assert result.revocation_list.rev_reg_def_id == revocation_registry_id
        assert result.revocation_list.current_accumulator == "MOCK_ACCUMULATOR"
        assert result.revocation_list.revocation_list == [0, 1, 0]
        assert result.resolution_metadata == {}
        assert result.revocation_registry_metadata == {
            "MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"
        }


async def test_register_revocation_status_list(
    mock_profile,
    mock_rev_list,
    mock_rev_reg_def,
    mock_get_revocation_registry_definition,
    mock_create_and_publish_resource,
):
    # Arrange
    with (
        patch(
            "cheqd.cheqd.anoncreds.registry.DIDCheqdRegistry.get_revocation_registry_definition",
            return_value=mock_get_revocation_registry_definition,
        ),
        patch(
            "cheqd.cheqd.anoncreds.registry.DIDCheqdRegistry._create_and_publish_resource",
            return_value=mock_create_and_publish_resource,
        ) as mock,
    ):
        # Act
        registry = DIDCheqdRegistry()
        result = await registry.register_revocation_list(
            mock_profile, mock_rev_reg_def, mock_rev_list
        )

        # Assert
        assert isinstance(result, RevListResult)
        assert result.revocation_list_state.state == "finished"
        assert result.revocation_list_state.revocation_list == mock_rev_list
        assert result.registration_metadata["resource_id"] == "MOCK_RESOURCE_ID"
        assert result.registration_metadata["resource_name"] == "MOCK_RESOURCE"
        assert result.registration_metadata["resource_type"] == "anonCredsStatusList"
        assert result.revocation_list_metadata == {}


async def test_update_revocation_status_list(
    mock_profile,
    mock_rev_list,
    mock_rev_reg_def,
    mock_get_revocation_registry_definition,
    mock_create_and_publish_resource,
):
    # Arrange
    with (
        patch(
            "cheqd.cheqd.anoncreds.registry.DIDCheqdRegistry.get_revocation_registry_definition",
            return_value=mock_get_revocation_registry_definition,
        ),
        patch(
            "cheqd.cheqd.anoncreds.registry.DIDCheqdRegistry._update_and_publish_resource",
            return_value=mock_create_and_publish_resource,
        ) as mock,
    ):
        # Act
        registry = DIDCheqdRegistry()
        result = await registry.update_revocation_list(
            mock_profile, mock_rev_reg_def, mock_rev_list, mock_rev_list, []
        )

        # Assert
        assert isinstance(result, RevListResult)
        assert result.revocation_list_state.state == "finished"
        assert result.revocation_list_state.revocation_list == mock_rev_list
        assert result.registration_metadata["resource_id"] == "MOCK_RESOURCE_ID"
        assert result.registration_metadata["resource_name"] == "MOCK_RESOURCE"
        assert result.registration_metadata["resource_type"] == "anonCredsStatusList"
        assert result.revocation_list_metadata == {}


async def test_get_schema_info_by_id(mock_resolver, mock_profile):
    # Arrange
    schema_id = "PART0/PART1/PART2"

    # Act
    with patch(
        "cheqd.cheqd.anoncreds.registry.CheqdDIDResolver", return_value=mock_resolver
    ):
        registry = DIDCheqdRegistry()
        result = await registry.get_schema_info_by_id(mock_profile, schema_id)

        # Assert
        assert isinstance(result, AnoncredsSchemaInfo)
        assert result.issuer_id == "PART0"
        assert result.name == "MOCK_NAME"
        assert result.version == "MOCK_VERSION"


@patch("cheqd.cheqd.did.manager.DIDRegistrar")
@pytest.mark.asyncio
async def test_create_and_publish_resource_with_signing_failure(
    mock_registrar_instance,
    mock_profile_for_manager,
    mock_resource_create_options,
):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        create_resource_responses=registrar_resource_responses_no_signing_request,
    )

    # Act
    manager = CheqdDIDManager(mock_profile_for_manager)
    await manager.create()

    registry = DIDCheqdRegistry()

    with pytest.raises(Exception) as e:
        await registry._create_and_publish_resource(
            mock_profile_for_manager,
            "MOCK_REGISTRAR_URL",
            "MOCK_RESOLVER_URL",
            mock_resource_create_options,
        )

    # Assert
    assert isinstance(e.value, Exception)
    assert str(e.value) == "No signing requests available for update."


@patch("cheqd.cheqd.did.manager.DIDRegistrar")
@pytest.mark.asyncio
async def test_update_and_publish_resource_with_signing_failure(
    mock_registrar_instance,
    mock_profile_for_manager,
    mock_resource_update_options,
):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        update_resource_responses=registrar_resource_responses_no_signing_request,
    )

    # Act
    manager = CheqdDIDManager(mock_profile_for_manager)
    await manager.create()

    registry = DIDCheqdRegistry()

    with pytest.raises(Exception) as e:
        await registry._update_and_publish_resource(
            mock_profile_for_manager,
            "MOCK_REGISTRAR_URL",
            "MOCK_RESOLVER_URL",
            mock_resource_update_options,
        )

    # Assert
    assert isinstance(e.value, Exception)
    assert str(e.value) == "No signing requests available for update."


@patch("cheqd.cheqd.did.manager.DIDRegistrar")
@pytest.mark.asyncio
async def test_create_with_network_failure(
    mock_registrar_instance,
    mock_profile_for_manager,
    mock_resource_create_options,
):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        create_resource_responses=registrar_resource_responses_network_fail,
    )

    # Act
    manager = CheqdDIDManager(mock_profile_for_manager)
    await manager.create()

    registry = DIDCheqdRegistry()
    with pytest.raises(Exception) as e:
        await registry._create_and_publish_resource(
            mock_profile_for_manager,
            "MOCK_REGISTRAR_URL",
            "MOCK_RESOLVER_URL",
            mock_resource_create_options,
        )

    # Assert
    assert isinstance(e.value, AnonCredsRegistrationError)
    assert str(e.value) == "Error publishing Resource Network failure"


@patch("cheqd.cheqd.did.manager.DIDRegistrar")
@pytest.mark.asyncio
async def test_create_not_finished(
    mock_registrar_instance,
    mock_profile_for_manager,
    mock_resource_create_options,
):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        create_resource_responses=registrar_resource_responses_not_finished,
    )

    # Act
    manager = CheqdDIDManager(mock_profile_for_manager)
    await manager.create()

    registry = DIDCheqdRegistry()
    with pytest.raises(Exception) as e:
        await registry._create_and_publish_resource(
            mock_profile_for_manager,
            "MOCK_REGISTRAR_URL",
            "MOCK_RESOLVER_URL",
            mock_resource_create_options,
        )

    # Assert
    assert isinstance(e.value, AnonCredsRegistrationError)
    assert str(e.value) == "Error publishing Resource Not finished"
