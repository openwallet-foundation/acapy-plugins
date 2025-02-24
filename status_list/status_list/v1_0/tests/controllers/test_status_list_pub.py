import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp.web import HTTPNotFound, HTTPBadRequest, HTTPInternalServerError

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.storage.error import StorageError, StorageNotFoundError

from ...controllers import status_list_pub as controller


@pytest.mark.asyncio
async def test_status_list_pub_routes(context: AdminRequestContext, seed_db):
    """Test status_list_pub routes."""

    request_dict = {
        "context": context,
        "outbound_message_router": AsyncMock(),
    }
    request = MagicMock(
        app={},
        match_info={"def_id": "definition_msg_id"},
        query={},
        __getitem__=lambda _, k: request_dict[k],
        headers={},
        json=AsyncMock(
            return_value={
                "did": "did:web:dev.lab.di.gov.on.ca",
                "verification_method": "did:web:dev.lab.di.gov.on.ca#3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx",
            }
        ),
    )
    # Test publish_status_list in "w3c" format
    request.json.return_value["status_type"] = "w3c"
    with patch.object(controller, "web", autospec=True) as mock_web:
        await controller.publish_status_list(request)
        result = mock_web.json_response.call_args[0][0]
        assert len(result) > 0
        assert result["status_lists"][0]["vc"]

    # Test publish_status_list in "ietf" format
    request.json.return_value["status_type"] = "ietf"
    with patch.object(controller, "web", autospec=True) as mock_web:
        await controller.publish_status_list(request)
        result = mock_web.json_response.call_args[0][0]
        assert len(result) > 0
        assert result["status_lists"][0]["status_list"]

    # Test get_status_list_pub with errors
    with patch(
        "status_list.v1_0.models.StatusListDef.retrieve_by_id",
        side_effect=StorageNotFoundError("No record found"),
    ):
        with pytest.raises(HTTPNotFound) as err:
            await controller.publish_status_list(request)
    assert isinstance(err.value, HTTPNotFound)

    with patch(
        "status_list.v1_0.models.StatusListDef.retrieve_by_id",
        side_effect=StorageError("Storage error"),
    ):
        with pytest.raises(HTTPInternalServerError) as err:
            await controller.publish_status_list(request)
    assert isinstance(err.value, HTTPInternalServerError)

    del request.json.return_value["status_type"]
    try:
        await controller.publish_status_list(request)
    except HTTPBadRequest as err:
        assert err

    del request.json.return_value["did"]
    del request.json.return_value["verification_method"]
    try:
        await controller.publish_status_list(request)
    except HTTPBadRequest as err:
        assert err
