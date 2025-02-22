import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp.web import HTTPNotFound, HTTPBadRequest, HTTPInternalServerError

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.storage.error import StorageError, StorageNotFoundError

from ...controllers import status_list_cred as controller


@pytest.mark.asyncio
async def test_status_list_cred_routes(context: AdminRequestContext, seed_db):
    """Test status_list_cred routes."""

    request_dict = {
        "context": context,
        "outbound_message_router": AsyncMock(),
    }
    request = MagicMock(
        app={},
        match_info={"def_id": "definition_id", "cred_id": "credential_id"},
        query={},
        __getitem__=lambda _, k: request_dict[k],
        headers={},
        json={},
    )

    # Test update_status_list_cred
    request.json = AsyncMock(return_value={"status": "1"})

    with patch.object(controller, "web", autospec=True) as mock_web:
        await controller.update_status_list_cred(request)
        result = mock_web.json_response.call_args[0][0]
        result = SimpleNamespace(**result)
        assert result.status == "1"

    # Test update_status_list_cred errors
    with patch(
        "status_list.v1_0.models.StatusListCred.retrieve_by_tag_filter",
        side_effect=StorageNotFoundError("No record found"),
    ):
        with pytest.raises(HTTPNotFound) as err:
            await controller.update_status_list_cred(request)
    assert isinstance(err.value, HTTPNotFound)

    with patch(
        "status_list.v1_0.models.StatusListCred.retrieve_by_tag_filter",
        side_effect=StorageError("Storage error"),
    ):
        with pytest.raises(HTTPInternalServerError) as err:
            await controller.update_status_list_cred(request)
    assert isinstance(err.value, HTTPInternalServerError)

    request.json.return_value["status"] = "0x2a"
    try:
        await controller.update_status_list_cred(request)
    except HTTPBadRequest as err:
        assert err

    del request.json.return_value["status"]
    try:
        await controller.update_status_list_cred(request)
    except HTTPBadRequest as err:
        assert err
    with patch.object(controller, "web", autospec=True) as mock_web:
        await controller.get_status_list_cred(request)
        result = mock_web.json_response.call_args[0][0]
        result = SimpleNamespace(**result)
        assert result.status == "1"

    # Test get_status_list_cred errors
    with patch(
        "status_list.v1_0.models.StatusListCred.retrieve_by_tag_filter",
        side_effect=StorageNotFoundError("No record found"),
    ):
        with pytest.raises(HTTPNotFound) as err:
            await controller.get_status_list_cred(request)
    assert isinstance(err.value, HTTPNotFound)

    with patch(
        "status_list.v1_0.models.StatusListCred.retrieve_by_tag_filter",
        side_effect=StorageError("Storage error"),
    ):
        with pytest.raises(HTTPInternalServerError) as err:
            await controller.get_status_list_cred(request)
    assert isinstance(err.value, HTTPInternalServerError)
