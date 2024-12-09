import pytest
from aiohttp import web
from aioresponses import aioresponses
from yarl import URL


@pytest.mark.asyncio
async def test_generate_did_doc(registrar, mock_did_document_url, mock_response):
    # Arrange
    network = "testnet"
    public_key_hex = "abc123"

    with aioresponses() as mocked:
        mocked.get(mock_did_document_url, status=200, payload=mock_response)

        # Act
        did_doc = await registrar.generate_did_doc(network, public_key_hex)

        # Assert
        assert did_doc is not None
        assert did_doc["MOCK_KEY"] == "MOCK_VALUE"

        expected_params = {
            "methodSpecificIdAlgo": "uuid",
            "network": network,
            "publicKeyHex": public_key_hex,
            "verificationMethod": "Ed25519VerificationKey2020",
        }
        request_call = mocked.requests[("GET", mock_did_document_url)][0]
        assert request_call.kwargs["params"] == expected_params


@pytest.mark.asyncio
async def test_generate_did_doc_unhappy(registrar, mock_did_document_url):
    # Arrange
    network = "testnet"
    public_key_hex = "abc123"

    with aioresponses() as mocked:
        mocked.get(mock_did_document_url, status=404)

        # Act
        with pytest.raises(Exception) as excinfo:
            await registrar.generate_did_doc(network, public_key_hex)

        # Assert
        assert "404" in str(excinfo.value)


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
        assert request.kwargs["json"] == mock_options


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
        assert request.kwargs["json"] == mock_options


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
        assert request.kwargs["json"] == mock_options


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 201])
async def test_create_resource(
    registrar_url, registrar, status, mock_options, mock_response
):
    # Arrange
    did = "did:cheqd:testnet:123"
    create_resource_url = registrar_url + did + "/create-resource"

    with aioresponses() as mocked:
        mocked.post(create_resource_url, status=status, payload=mock_response)

        # Act
        response = await registrar.create_resource(did, mock_options)

        # Assert
        assert response is not None
        assert response["MOCK_KEY"] == "MOCK_VALUE"

        request = mocked.requests[("POST", URL(create_resource_url))][0]
        assert request.kwargs["json"] == mock_options


@pytest.mark.asyncio
async def test_create_resource_unhappy(registrar_url, registrar, mock_options):
    # Arrange
    did = "did:cheqd:testnet:123"
    create_resource_url = registrar_url + did + "/create-resource"

    with aioresponses() as mocked:
        mocked.post(create_resource_url, status=404)

        # Act
        with pytest.raises(Exception) as excinfo:
            await registrar.create_resource(did, mock_options)

        # Assert
        assert isinstance(excinfo.value, web.HTTPInternalServerError)


@pytest.mark.asyncio
async def test_update_resource(registrar, mock_options):
    # Arrange
    did = "did:cheqd:testnet:123"

    # Act
    with pytest.raises(NotImplementedError) as excinfo:
        await registrar.update_resource(did, mock_options)

    # Assert
    assert str(excinfo.value) == "This method has not been implemented yet."


@pytest.mark.asyncio
async def test_deactivate_resource(registrar, mock_options):
    # Arrange
    did = "did:cheqd:testnet:123"

    # Act
    with pytest.raises(NotImplementedError) as excinfo:
        await registrar.deactivate_resource(did, mock_options)

    # Assert
    assert str(excinfo.value) == "This method will not be implemented for did:cheqd."
