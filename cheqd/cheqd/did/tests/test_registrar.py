import pytest
import json
from aiohttp import web
from aioresponses import aioresponses
from yarl import URL


@pytest.mark.asyncio
async def test_create(registrar_url, registrar, mock_options, mock_response):
    # Arrange
    create_url = registrar_url + "create"

    with aioresponses() as mocked:
        mocked.post(create_url, status=201, payload=mock_response)

        # Act
        response = await registrar.create(mock_options)

        # Assert
        assert response is not None
        assert response["MOCK_KEY"] == "MOCK_VALUE"

        request = mocked.requests[("POST", URL(create_url))][0]
        assert json.loads(request.kwargs["json"]) == mock_options


@pytest.mark.asyncio
async def test_update(registrar_url, registrar, mock_options, mock_response):
    # Arrange
    update_url = registrar_url + "update"

    with aioresponses() as mocked:
        mocked.post(update_url, status=200, payload=mock_response)

        # Act
        response = await registrar.update(mock_options)

        # Assert
        assert response is not None
        assert response["MOCK_KEY"] == "MOCK_VALUE"

        request = mocked.requests[("POST", URL(update_url))][0]
        assert json.loads(request.kwargs["json"]) == mock_options


@pytest.mark.asyncio
async def test_deactivate(registrar_url, registrar, mock_options, mock_response):
    # Arrange
    deactivate_url = registrar_url + "deactivate"

    with aioresponses() as mocked:
        mocked.post(deactivate_url, status=200, payload=mock_response)

        # Act
        response = await registrar.deactivate(mock_options)

        # Assert
        assert response is not None
        assert response["MOCK_KEY"] == "MOCK_VALUE"

        request = mocked.requests[("POST", URL(deactivate_url))][0]
        assert json.loads(request.kwargs["json"]) == mock_options


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 201])
async def test_create_resource(
    registrar_url, registrar, status, mock_options, mock_response
):
    # Arrange
    create_resource_url = registrar_url + "/createResource"

    with aioresponses() as mocked:
        mocked.post(create_resource_url, status=status, payload=mock_response)

        # Act
        response = await registrar.create_resource(mock_options)

        # Assert
        assert response is not None
        assert response["MOCK_KEY"] == "MOCK_VALUE"

        request = mocked.requests[("POST", URL(create_resource_url))][0]
        assert json.loads(request.kwargs["json"]) == mock_options


@pytest.mark.asyncio
async def test_create_resource_unhappy(registrar_url, registrar, mock_options):
    create_resource_url = registrar_url + "/createResource"

    with aioresponses() as mocked:
        mocked.post(create_resource_url, status=404)

        # Act
        with pytest.raises(Exception) as excinfo:
            await registrar.create_resource(mock_options)

        # Assert
        assert isinstance(excinfo.value, web.HTTPInternalServerError)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200])
async def test_update_resource(
    registrar_url, registrar, status, mock_options, mock_response
):
    update_resource_url = registrar_url + "/updateResource"

    with aioresponses() as mocked:
        mocked.post(update_resource_url, status=status, payload=mock_response)

        # Act
        response = await registrar.update_resource(mock_options)

        # Assert
        assert response is not None
        assert response["MOCK_KEY"] == "MOCK_VALUE"

        request = mocked.requests[("POST", URL(update_resource_url))][0]
        assert json.loads(request.kwargs["json"]) == mock_options


@pytest.mark.asyncio
async def test_deactivate_resource(registrar, mock_options):
    # Arrange
    did = "did:cheqd:testnet:123"

    # Act
    with pytest.raises(NotImplementedError) as excinfo:
        await registrar.deactivate_resource(mock_options)

    # Assert
    assert str(excinfo.value) == "This method will not be implemented for did:cheqd."
