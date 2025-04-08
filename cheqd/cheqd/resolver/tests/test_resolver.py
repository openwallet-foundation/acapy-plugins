import pytest
from acapy_agent.resolver.base import DIDNotFound, ResolverError
from aioresponses import aioresponses

from ...validation import CheqdDID


def test_supported_did_regex(resolver):
    # Act
    pattern = resolver.supported_did_regex

    # Assert
    assert pattern == CheqdDID.PATTERN


@pytest.mark.asyncio
async def test_resolve(resolver, resolve_url, did):
    # Arrange
    mock_response = {
        "didDocument": {"id": did},
        "didDocumentMetadata": {"deactivated": False},
    }

    with aioresponses() as mocked:
        mocked.get(resolve_url, status=200, payload=mock_response)

        # Act
        did_doc = await resolver.resolve(None, did)

        # Assert
        assert did_doc == {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
        }


@pytest.mark.asyncio
async def test_resolve_deactivated(resolver, resolve_url, did):
    # Arrange
    mock_response = {
        "didDocument": {"id": did},
        "didDocumentMetadata": {"deactivated": True},
    }

    with aioresponses() as mocked:
        mocked.get(resolve_url, status=200, payload=mock_response)

        # Act
        did_doc = await resolver.resolve(None, did)

        # Assert
        assert did_doc == {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "deactivated": True,
        }


@pytest.mark.asyncio
async def test_resolve_incorrectly_formatted(resolver, resolve_url, did):
    # Arrange
    mock_response = {
        "MOCK_KEY": {"didDocument": {"id": did}},
        "didDocumentMetadata": {"deactivated": False},
    }

    with aioresponses() as mocked:
        mocked.get(resolve_url, status=200, payload=mock_response)

        # Act
        with pytest.raises(Exception) as excinfo:
            await resolver.resolve(None, did)

        # Assert
        assert str(excinfo.value) == "Response was incorrectly formatted"
        assert isinstance(excinfo.value, ResolverError)


@pytest.mark.asyncio
async def test_resolve_path_not_found(resolver, resolve_url, did):
    # Arrange
    with aioresponses() as mocked:
        mocked.get(resolve_url, status=404)

        # Act
        with pytest.raises(Exception) as excinfo:
            await resolver.resolve(None, did)

        # Assert
        assert str(excinfo.value) == f"No document found for {did}"
        assert isinstance(excinfo.value, DIDNotFound)


@pytest.mark.asyncio
async def test_resolve_resource(resolver, resolve_resource_params):
    # Arrange
    mock_response = {
        "contentStream": {"MOCK_KEY": "MOCK_VALUE"},
        "contentMetadata": {"MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"},
    }
    did_resource, resolve_resource_url, resolve_resource_metadata_url = (
        resolve_resource_params
    )

    with aioresponses() as mocked:
        mocked.get(resolve_resource_url, status=200, payload=mock_response)

        # Act
        response = await resolver.dereference_with_metadata(None, did_resource)

        # Assert
        assert response is not None
        assert response.resource["MOCK_KEY"] == "MOCK_VALUE"
        assert response.metadata["MOCK_METADATA_KEY"] == "MOCK_METADATA_VALUE"


@pytest.mark.asyncio
async def test_resolve_resource_incorrectly_formatted(resolver, resolve_resource_params):
    # Arrange
    did_resource, resolve_resource_url, _ = resolve_resource_params

    with aioresponses() as mocked:
        mocked.get(resolve_resource_url, status=200, body="Invalid JSON Response")

        # Act
        with pytest.raises(Exception) as excinfo:
            await resolver.dereference_with_metadata(None, did_resource)

        # Assert
        assert str(excinfo.value) == "Response was incorrectly formatted"
        assert isinstance(excinfo.value, ResolverError)


@pytest.mark.asyncio
async def test_resolve_resource_path_not_found(resolver, resolve_resource_params):
    # Arrange
    did_resource, resolve_resource_url, _ = resolve_resource_params

    with aioresponses() as mocked:
        mocked.get(resolve_resource_url, status=404)

        # Act
        with pytest.raises(Exception) as excinfo:
            await resolver.dereference_with_metadata(None, did_resource)

        # Assert
        assert str(excinfo.value) == f"No document found for {did_resource}"
        assert isinstance(excinfo.value, DIDNotFound)


@pytest.mark.asyncio
async def test_resolve_resource_metadata_incorrectly_formatted(
    resolver, resolve_resource_params
):
    # Arrange
    mock_response = {
        "contentStream": {"MOCK_KEY": "MOCK_VALUE"},
        "contentMetadata": "MOCK_VALUE",
    }
    did_resource, resolve_resource_url, resolve_resource_metadata_url = (
        resolve_resource_params
    )

    with aioresponses() as mocked:
        mocked.get(resolve_resource_url, status=200, payload=mock_response)

        # Act
        with pytest.raises(Exception) as excinfo:
            await resolver.dereference_with_metadata(None, did_resource)

        # Assert
        assert (
            str(excinfo.value) == "DidUrlDereferencing result was incorrectly formatted"
        )
        assert isinstance(excinfo.value, ResolverError)
