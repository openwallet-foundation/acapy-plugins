from unittest.mock import AsyncMock

import pytest
from aiohttp import web

from ..base import BaseDIDManager, SigningResponse, SigningRequest


@pytest.mark.asyncio
async def test_validate_did_doc():
    # Arrange
    incorrect_did_doc = {"id": "did:cheqd:testnet:123456"}

    # Act
    result = await BaseDIDManager.validate_did_doc(incorrect_did_doc)

    # Assert
    assert result is True


@pytest.mark.asyncio
async def test_validate_did_doc_incorrect():
    # Arrange
    incorrect_did_doc = {"MOCK_KEY": "MOCK_VALUE"}

    # Act
    with pytest.raises(Exception) as e:
        await BaseDIDManager.validate_did_doc(incorrect_did_doc)

    # Assert
    assert isinstance(e.value, web.HTTPBadRequest)


@pytest.mark.parametrize(
    "success, result, error, expected_response",
    [
        (
            True,
            {"data": "sample"},
            None,
            {"success": True, "result": {"data": "sample"}, "error": None},
        ),
        (
            False,
            None,
            "An error occurred.",
            {"success": False, "result": None, "error": "An error occurred."},
        ),
        (
            False,
            {"data": "sample"},
            None,
            {"success": False, "result": None, "error": None},
        ),
        (
            True,
            None,
            "An error occurred.",
            {"success": True, "result": None, "error": None},
        ),
    ],
)
def test_format_response(success, result, error, expected_response):
    # Act
    response = BaseDIDManager.format_response(success=success, result=result, error=error)

    # Assert
    assert response == expected_response


@pytest.mark.asyncio
async def test_sign_requests():
    # Arrange
    wallet = AsyncMock()
    wallet.get_key_by_kid.side_effect = [
        AsyncMock(verkey="verkey1"),
        AsyncMock(verkey="verkey2"),
    ]
    wallet.sign_message.side_effect = [
        b"signature1",
        b"signature2",
    ]

    signing_requests = {
        "signingRequest0": SigningRequest(kid="key1", serializedPayload="payload1"),
        "signingRequest1": SigningRequest(kid="key2", serializedPayload="payload2"),
    }

    expected_responses = {
        "signingRequest0": SigningResponse(kid="key1", signature="c2lnbmF0dXJlMQ=="),
        "signingRequest1": SigningResponse(kid="key2", signature="c2lnbmF0dXJlMg=="),
    }

    # Act
    signed_responses = await BaseDIDManager.sign_requests(wallet, signing_requests)

    # Assert
    assert signed_responses == expected_responses
    assert wallet.get_key_by_kid.call_count == 2
    assert wallet.sign_message.call_count == 2


@pytest.mark.asyncio
async def test_sign_requests_missing_key():
    # Arrange
    wallet = AsyncMock()
    wallet.get_key_by_kid.return_value = None

    signing_requests = {
        "signingRequest0": SigningRequest(
            kid="MOCK_KID",
            serializedPayload="TW9jaw==",
        )
    }

    # Act
    with pytest.raises(Exception) as e:
        await BaseDIDManager.sign_requests(wallet, signing_requests)

    # Assert
    assert isinstance(e.value, ValueError)
    assert str(e.value) == "No key found for kid: MOCK_KID"


@pytest.mark.asyncio
async def test_sign_requests_empty_requests():
    # Arrange
    wallet = AsyncMock()
    signing_requests = {}

    # Act
    signed_responses = await BaseDIDManager.sign_requests(wallet, signing_requests)

    # Assert
    assert signed_responses == {}
    wallet.get_key_by_kid.assert_not_called()
    wallet.sign_message.assert_not_called()
