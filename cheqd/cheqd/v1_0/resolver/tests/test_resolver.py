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
        did_doc = await resolver._resolve(None, did)

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
        did_doc = await resolver._resolve(None, did)

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
            await resolver._resolve(None, did)

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
            await resolver._resolve(None, did)

        # Assert
        assert str(excinfo.value) == f"No document found for {did}"
        assert isinstance(excinfo.value, DIDNotFound)


@pytest.mark.asyncio
async def test_resolve_resource(resolver, resolve_resource_url, did):
    # Arrange
    mock_response = {"MOCK_KEY": "MOCK_VALUE"}

    with aioresponses() as mocked:
        mocked.get(resolve_resource_url, status=200, payload=mock_response)

        # Act
        response = await resolver.resolve_resource(did)

        # Assert
        assert response is not None
        assert response["MOCK_KEY"] == "MOCK_VALUE"


@pytest.mark.asyncio
async def test_resolve_resource_incorrectly_formatted(
    resolver, resolve_resource_url, did
):
    # Arrange
    with aioresponses() as mocked:
        mocked.get(resolve_resource_url, status=200, body="Invalid JSON Response")

        # Act
        with pytest.raises(Exception) as excinfo:
            await resolver.resolve_resource(did)

        # Assert
        assert str(excinfo.value) == "Response was incorrectly formatted"
        assert isinstance(excinfo.value, ResolverError)


@pytest.mark.asyncio
async def test_resolve_resource_path_not_found(resolver, resolve_resource_url, did):
    # Arrange
    with aioresponses() as mocked:
        mocked.get(resolve_resource_url, status=404)

        # Act
        with pytest.raises(Exception) as excinfo:
            await resolver.resolve_resource(did)

        # Assert
        assert str(excinfo.value) == f"No resource found for {did}"
        assert isinstance(excinfo.value, DIDNotFound)