from unittest.mock import patch

import pytest
from acapy_agent.wallet.error import WalletError

from ...did.base import CheqdDIDManagerError
from ..manager import CheqdDIDManager
from .mocks import (
    registrar_create_responses,
    registrar_create_responses_network_fail,
    registrar_create_responses_no_signing_request,
    registrar_generate_did_doc_response,
    setup_mock_registrar,
)


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_create_did(mock_registrar_instance, profile):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        registrar_generate_did_doc_response,
        registrar_create_responses,
    )
    manager = CheqdDIDManager(profile)

    # Act
    response = await manager.create()

    # Assert
    assert response["did"] == "did:cheqd:testnet:123456"
    assert response["verkey"] is not None
    assert response["didDocument"] is not None


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_create_did_with_insecure_seed(mock_registrar_instance, profile):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        registrar_generate_did_doc_response,
        registrar_create_responses,
    )
    profile.settings["wallet.allow_insecure_seed"] = False
    manager = CheqdDIDManager(profile)

    # Act
    options = {"seed": "insecure-seed"}
    with pytest.raises(Exception) as e:
        await manager.create(options=options)

    # Assert
    assert isinstance(e.value, WalletError)
    assert str(e.value) == "Insecure seed is not allowed"


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_create_did_with_invalid_did_document(
    mock_registrar_instance,
    profile,
):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        None,
        registrar_create_responses,
    )
    manager = CheqdDIDManager(profile)

    # Act
    with pytest.raises(Exception) as e:
        await manager.create()

    # Assert
    assert isinstance(e.value, CheqdDIDManagerError)
    assert str(e.value) == "Error constructing DID Document"


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_create_did_with_signing_failure(
    mock_registrar_instance,
    profile,
):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        registrar_generate_did_doc_response,
        registrar_create_responses_no_signing_request,
    )
    manager = CheqdDIDManager(profile)

    # Act
    with pytest.raises(Exception) as e:
        await manager.create()

    # Assert
    assert isinstance(e.value, CheqdDIDManagerError)
    assert str(e.value) == "No signing requests available for create."


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_create_did_with_registration_failure(
    mock_registrar_instance,
    profile,
):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        registrar_generate_did_doc_response,
        registrar_create_responses_network_fail,
    )
    manager = CheqdDIDManager(profile)

    # Act
    with pytest.raises(Exception) as e:
        await manager.create()

    # Assert
    assert isinstance(e.value, CheqdDIDManagerError)
    assert str(e.value) == "Error registering DID Network failure"
