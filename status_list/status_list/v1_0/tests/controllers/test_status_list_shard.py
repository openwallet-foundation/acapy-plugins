import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp.web import HTTPNotFound, HTTPInternalServerError

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.storage.error import StorageError, StorageNotFoundError

from ...controllers import status_list_shard as controller


@pytest.mark.asyncio
async def test_assign_status_list_entry(context: AdminRequestContext, seed_db):
    """Test status_list_shard routes."""

    # Test assign_status_list_entry
    request_dict = {
        "context": context,
        "outbound_message_router": AsyncMock(),
    }
    request = MagicMock(
        app={},
        match_info={"def_id": "definition_id"},
        query={},
        __getitem__=lambda _, k: request_dict[k],
        headers={},
        json={},
    )

    with patch.object(controller, "web", autospec=True) as mock_web:
        await controller.assign_status_list_entry(request)
        result = mock_web.json_response.call_args[0][0]
        result = SimpleNamespace(**result)
        assert result.assigned

    # Test get_status_list_cred errors
    with patch(
        "status_list.v1_0.status_handler.assign_status_list_entry",
        side_effect=StorageNotFoundError("No record found"),
    ):
        with pytest.raises(HTTPNotFound) as err:
            await controller.assign_status_list_entry(request)
    assert isinstance(err.value, HTTPNotFound)

    with patch(
        "status_list.v1_0.status_handler.assign_status_list_entry",
        side_effect=StorageError("Storage error"),
    ):
        with pytest.raises(HTTPInternalServerError) as err:
            await controller.assign_status_list_entry(request)
    assert isinstance(err.value, HTTPInternalServerError)


@pytest.mark.asyncio
async def test_get_status_list(context: AdminRequestContext, seed_db):
    """Test status_list_shard routes."""

    # Test get_status_list
    request_dict = {
        "context": context,
        "outbound_message_router": AsyncMock(),
    }
    request = MagicMock(
        app={},
        match_info={"def_id": "definition_id", "list_num": "0"},
        query={},  # {"issuer_did": "did:web:dev.lab.di.gov.on.ca"},
        __getitem__=lambda _, k: request_dict[k],
        headers={},
        json={},
    )
    with patch.object(controller, "web", autospec=True) as mock_web:
        await controller.get_status_list(request)
        result = mock_web.json_response.call_args[0][0]
        assert result

    # Test get_status_list errors
    with patch(
        "status_list.v1_0.status_handler.get_status_list",
        side_effect=StorageNotFoundError("No record found"),
    ):
        with pytest.raises(HTTPNotFound) as err:
            await controller.get_status_list(request)
    assert isinstance(err.value, HTTPNotFound)

    with patch(
        "status_list.v1_0.status_handler.get_status_list",
        side_effect=StorageError("Storage error"),
    ):
        with pytest.raises(HTTPInternalServerError) as err:
            await controller.get_status_list(request)
    assert isinstance(err.value, HTTPInternalServerError)
