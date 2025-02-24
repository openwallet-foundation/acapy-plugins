import pytest
from aioresponses import aioresponses
from yarl import URL

from cheqd.cheqd.did.base import DidResponse, DidSuccessState, DIDRegistrarError


@pytest.mark.asyncio
async def test_create(
    registrar_url, registrar, mock_did_create_options, mock_did_response
):
    # Arrange
    create_url = registrar_url + "create?method=cheqd"

    with aioresponses() as mocked:
        mocked.post(create_url, status=201, payload=mock_did_response)

        # Act
        response = await registrar.create(mock_did_create_options)
        did_state = response.didState

        # Assert
        assert isinstance(response, DidResponse)
        assert isinstance(did_state, DidSuccessState)

        request = mocked.requests[("POST", URL(create_url))][0]
        assert request.kwargs["json"] == mock_did_create_options.dict(exclude_none=True)


@pytest.mark.asyncio
async def test_create_registration_error(
    registrar_url,
    registrar,
    mock_did_create_options,
    mock_did_response,
    mock_did_invalid_response,
):
    create_url = registrar_url + "create?method=cheqd"

    with aioresponses() as mocked:
        mocked.post(create_url, status=201, payload=mock_did_response)

        # invalid type
        with pytest.raises(Exception) as excinfo:
            await registrar.create({})

        assert isinstance(excinfo.value, DIDRegistrarError)

    with aioresponses() as mocked:
        mocked.post(create_url, status=201, payload=mock_did_invalid_response)

        with pytest.raises(Exception) as excinfo:
            await registrar.create(mock_did_create_options)

        assert isinstance(excinfo.value, DIDRegistrarError)


@pytest.mark.asyncio
async def test_update(
    registrar_url, registrar, mock_did_update_options, mock_did_response
):
    # Arrange
    update_url = registrar_url + "update?method=cheqd"

    with aioresponses() as mocked:
        mocked.post(update_url, status=200, payload=mock_did_response)

        # Act
        response = await registrar.update(mock_did_update_options)
        did_state = response.didState

        # Assert
        assert isinstance(response, DidResponse)
        assert isinstance(did_state, DidSuccessState)

        request = mocked.requests[("POST", URL(update_url))][0]
        assert request.kwargs["json"] == mock_did_update_options.dict(exclude_none=True)


@pytest.mark.asyncio
async def test_update_registration_error(
    registrar_url,
    registrar,
    mock_did_update_options,
    mock_did_response,
    mock_did_invalid_response,
):
    update_url = registrar_url + "update?method=cheqd"

    with aioresponses() as mocked:
        mocked.post(update_url, status=201, payload=mock_did_response)

        # invalid type
        with pytest.raises(Exception) as excinfo:
            await registrar.update({})

        assert isinstance(excinfo.value, DIDRegistrarError)

    with aioresponses() as mocked:
        mocked.post(update_url, status=201, payload=mock_did_invalid_response)

        with pytest.raises(Exception) as excinfo:
            await registrar.update(mock_did_update_options)

        assert isinstance(excinfo.value, DIDRegistrarError)


@pytest.mark.asyncio
async def test_deactivate(
    registrar_url, registrar, mock_did_deactivate_options, mock_did_response
):
    # Arrange
    deactivate_url = registrar_url + "deactivate?method=cheqd"

    with aioresponses() as mocked:
        mocked.post(deactivate_url, status=200, payload=mock_did_response)

        # Act
        response = await registrar.deactivate(mock_did_deactivate_options)
        did_state = response.didState

        # Assert
        assert isinstance(response, DidResponse)
        assert isinstance(did_state, DidSuccessState)

        request = mocked.requests[("POST", URL(deactivate_url))][0]
        assert request.kwargs["json"] == mock_did_deactivate_options.dict(
            exclude_none=True
        )


@pytest.mark.asyncio
async def test_deactivate_registration_error(
    registrar_url,
    registrar,
    mock_did_deactivate_options,
    mock_did_response,
    mock_did_invalid_response,
):
    # Arrange
    deactivate_url = registrar_url + "deactivate?method=cheqd"
    with aioresponses() as mocked:
        mocked.post(deactivate_url, status=201, payload=mock_did_response)
        # invalid type
        with pytest.raises(Exception) as excinfo:
            await registrar.deactivate({})

        assert isinstance(excinfo.value, DIDRegistrarError)

    with aioresponses() as mocked:
        mocked.post(deactivate_url, status=201, payload=mock_did_invalid_response)
        with pytest.raises(Exception) as excinfo:
            await registrar.deactivate(mock_did_deactivate_options)

        assert isinstance(excinfo.value, DIDRegistrarError)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 201])
async def test_create_resource(
    registrar_url, registrar, status, mock_resource_create_options, mock_resource_response
):
    # Arrange
    create_resource_url = registrar_url + "createResource?method=cheqd"

    with aioresponses() as mocked:
        mocked.post(create_resource_url, status=status, payload=mock_resource_response)

        # Act
        response = await registrar.create_resource(mock_resource_create_options)

        # Assert
        assert response is not None

        request = mocked.requests[("POST", URL(create_resource_url))][0]
        assert request.kwargs["json"] == mock_resource_create_options.dict(
            exclude_none=True
        )


@pytest.mark.asyncio
async def test_create_resource_unhappy(
    registrar_url, registrar, mock_resource_create_options
):
    # Arrange
    create_resource_url = registrar_url + "createResource?method=cheqd"

    with aioresponses() as mocked:
        mocked.post(create_resource_url, status=404)

        # Act
        with pytest.raises(Exception) as excinfo:
            await registrar.create_resource(mock_resource_create_options)

        # Assert
        assert isinstance(excinfo.value, DIDRegistrarError)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200])
async def test_update_resource(
    registrar_url, registrar, status, mock_resource_update_options, mock_resource_response
):
    update_resource_url = registrar_url + "updateResource?method=cheqd"

    with aioresponses() as mocked:
        mocked.post(update_resource_url, status=status, payload=mock_resource_response)

        # Act
        response = await registrar.update_resource(mock_resource_update_options)

        # Assert
        assert response is not None

        request = mocked.requests[("POST", URL(update_resource_url))][0]
        assert request.kwargs["json"] == mock_resource_update_options.dict(
            exclude_none=True
        )


@pytest.mark.asyncio
async def test_update_resource_unhappy(
    registrar_url, registrar, mock_resource_update_options
):
    # Arrange
    update_resource_url = registrar_url + "updateResource?method=cheqd"

    with aioresponses() as mocked:
        mocked.post(update_resource_url, status=404)

        # Act
        with pytest.raises(Exception) as excinfo:
            await registrar.update_resource(mock_resource_update_options)

        # Assert
        assert isinstance(excinfo.value, DIDRegistrarError)


@pytest.mark.asyncio
async def test_deactivate_resource(registrar, mock_options):
    # Act
    with pytest.raises(NotImplementedError) as excinfo:
        await registrar.deactivate_resource(mock_options)

    # Assert
    assert str(excinfo.value) == "This method will not be implemented for did:cheqd."
