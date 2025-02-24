import json
from unittest.mock import AsyncMock, patch

import pytest
from acapy_agent.wallet.error import WalletError
from aiohttp import web

from ..did.manager import CheqdDIDManagerError
from ..routes import create_cheqd_did, deactivate_cheqd_did, update_cheqd_did


@pytest.mark.asyncio
async def test_create_cheqd_did(mock_request, mock_create_body, mock_manager):
    # Arrange
    mock_request.json = mock_create_body

    with patch(
        "cheqd.cheqd.routes.CheqdDIDManager", return_value=mock_manager
    ) as mock_constructor:
        # Act
        response = await create_cheqd_did(mock_request)

    # Assert
    assert response.status == 200
    response_json = json.loads(response.text)
    assert response_json["did"] == "did:cheqd:testnet:123"
    assert response_json["verkey"] == "MOCK_VERIFICATION_KEY"
    mock_manager.create.assert_called_with(
        None, {"network": "testnet", "key_type": "ed25519"}
    )
    mock_constructor.assert_called_once_with(
        mock_request["context"].profile, "MOCK_REGISTRAR_URL", "MOCK_RESOLVER_URL"
    )


@pytest.mark.asyncio
async def test_create_cheqd_did_missing_body(mock_request, mock_manager):
    # Arrange
    mock_request.json = AsyncMock(side_effect=Exception("Invalid JSON"))
    with patch("cheqd.cheqd.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        response = await create_cheqd_did(mock_request)

    # Assert
    assert response.status == 200
    response_json = json.loads(response.text)
    assert response_json["did"] == "did:cheqd:testnet:123"
    assert response_json["verkey"] == "MOCK_VERIFICATION_KEY"
    mock_manager.create.assert_called_with(None, None)


@pytest.mark.asyncio
async def test_create_cheqd_did_manager_error(mock_request, mock_manager):
    # Arrange
    mock_manager.create.side_effect = CheqdDIDManagerError("Manager error")
    with patch("cheqd.cheqd.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        with pytest.raises(web.HTTPInternalServerError) as e:
            await create_cheqd_did(mock_request)

        # Assert
        assert "Manager error" in str(e.value)
        assert isinstance(e.value, web.HTTPInternalServerError)


@pytest.mark.asyncio
async def test_create_cheqd_did_wallet_error(mock_request, mock_manager):
    # Arrange
    mock_manager.create.side_effect = WalletError("Wallet error")
    with patch("cheqd.cheqd.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        with pytest.raises(web.HTTPBadRequest) as e:
            await create_cheqd_did(mock_request)

        # Assert
        assert "Wallet error" in str(e.value)
        assert isinstance(e.value, web.HTTPBadRequest)


@pytest.mark.asyncio
async def test_update_cheqd_did(mock_request, mock_update_body, mock_manager):
    # Arrange
    mock_request.json = mock_update_body

    with patch(
        "cheqd.cheqd.routes.CheqdDIDManager", return_value=mock_manager
    ) as mock_constructor:
        # Act
        response = await update_cheqd_did(mock_request)

    # Assert
    assert response.status == 200
    response_json = json.loads(response.text)
    assert response_json == {"MOCK_KEY": "MOCK_VALUE"}
    mock_manager.update.assert_called_with(
        "did:cheqd:testnet:123",
        {"MOCK_KEY": "MOCK_VALUE"},
        {"MOCK_OPTION_KEY": "MOCK_OPTION_VALUE"},
    )
    mock_constructor.assert_called_once_with(
        mock_request["context"].profile, "MOCK_REGISTRAR_URL", "MOCK_RESOLVER_URL"
    )


@pytest.mark.asyncio
async def test_update_cheqd_did_missing_body(mock_request, mock_manager):
    # Arrange
    mock_request.json = AsyncMock(side_effect=Exception("Invalid JSON"))
    with patch("cheqd.cheqd.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        response = await update_cheqd_did(mock_request)

    # Assert
    assert response.status == 200
    response_json = json.loads(response.text)
    assert response_json == {"MOCK_KEY": "MOCK_VALUE"}
    mock_manager.update.assert_called_with(None, None, None)


@pytest.mark.asyncio
async def test_update_cheqd_did_manager_error(mock_request, mock_manager):
    # Arrange
    mock_manager.update.side_effect = CheqdDIDManagerError("Manager error")
    with patch("cheqd.cheqd.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        with pytest.raises(web.HTTPInternalServerError) as e:
            await update_cheqd_did(mock_request)

        # Assert
        assert "Manager error" in str(e.value)
        assert isinstance(e.value, web.HTTPInternalServerError)


@pytest.mark.asyncio
async def test_update_cheqd_did_wallet_error(mock_request, mock_manager):
    # Arrange
    mock_manager.update.side_effect = WalletError("Wallet error")
    with patch("cheqd.cheqd.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        with pytest.raises(web.HTTPBadRequest) as e:
            await update_cheqd_did(mock_request)

        # Assert
        assert "Wallet error" in str(e.value)
        assert isinstance(e.value, web.HTTPBadRequest)


@pytest.mark.asyncio
async def test_deactivate_cheqd_did(mock_request, mock_deactivate_body, mock_manager):
    # Arrange
    mock_request.json = mock_deactivate_body

    with patch(
        "cheqd.cheqd.routes.CheqdDIDManager", return_value=mock_manager
    ) as mock_constructor:
        # Act
        response = await deactivate_cheqd_did(mock_request)

    # Assert
    assert response.status == 200
    response_json = json.loads(response.text)
    assert response_json == {"MOCK_KEY": "MOCK_VALUE"}
    mock_manager.deactivate.assert_called_with(
        "did:cheqd:testnet:123",
    )
    mock_constructor.assert_called_once_with(
        mock_request["context"].profile, "MOCK_REGISTRAR_URL", "MOCK_RESOLVER_URL"
    )


@pytest.mark.asyncio
async def test_deactivate_cheqd_did_missing_body(mock_request, mock_manager):
    # Arrange
    mock_request.json = AsyncMock(side_effect=Exception("Invalid JSON"))
    with patch("cheqd.cheqd.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        response = await deactivate_cheqd_did(mock_request)

    # Assert
    assert response.status == 200
    response_json = json.loads(response.text)
    assert response_json == {"MOCK_KEY": "MOCK_VALUE"}
    mock_manager.deactivate.assert_called_with(None)


@pytest.mark.asyncio
async def test_deactivate_cheqd_did_manager_error(mock_request, mock_manager):
    # Arrange
    mock_manager.deactivate.side_effect = CheqdDIDManagerError("Manager error")
    with patch("cheqd.cheqd.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        with pytest.raises(web.HTTPInternalServerError) as e:
            await deactivate_cheqd_did(mock_request)

        # Assert
        assert "Manager error" in str(e.value)
        assert isinstance(e.value, web.HTTPInternalServerError)


@pytest.mark.asyncio
async def test_deactivate_cheqd_did_wallet_error(mock_request, mock_manager):
    # Arrange
    mock_manager.deactivate.side_effect = WalletError("Wallet error")
    with patch("cheqd.cheqd.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        with pytest.raises(web.HTTPBadRequest) as e:
            await deactivate_cheqd_did(mock_request)

        # Assert
        assert "Wallet error" in str(e.value)
        assert isinstance(e.value, web.HTTPBadRequest)
