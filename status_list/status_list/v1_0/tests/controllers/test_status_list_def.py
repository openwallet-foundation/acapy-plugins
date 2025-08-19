import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp.web import HTTPNotFound, HTTPBadRequest, HTTPInternalServerError

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.storage.error import StorageError, StorageNotFoundError

from ...models import StatusListDef, StatusListCred
from ...controllers import status_list_def as controller


@pytest.mark.asyncio
async def test_status_list_def_routes(
    context: AdminRequestContext, status_list_cred: StatusListCred
):
    """Test status_list_def routes."""

    # Test create_status_list_def
    request_dict = {
        "context": context,
        "outbound_message_router": AsyncMock(),
    }
    request = MagicMock(
        app={},
        match_info={},
        query={},
        __getitem__=lambda _, k: request_dict[k],
        headers={},
        json=AsyncMock(return_value={"supported_cred_id": "supported_cred_id"}),
    )

    await controller.create_status_list_def(request)
    async with context.profile.session() as session:
        records = await StatusListDef.query(
            session,
            {"status_purpose": "revocation", "supported_cred_id": "supported_cred_id"},
        )
    assert records
    saved = records[0]
    assert saved
    assert saved.status_purpose == "revocation"
    assert saved.supported_cred_id == "supported_cred_id"

    request.json.return_value = {
        "status_size": 2,
        "status_purpose": "message",
        "status_message": [
            {"status": "0x00", "message": "active"},
            {"status": "0x01", "message": "revoked"},
            {"status": "0x10", "message": "pending"},
            {"status": "0x11", "message": "suspended"},
        ],
        "supported_cred_id": "supported_cred_id",
        "list_type": "ietf",
        "issuer_did": "did:web:dev.lab.di.gov.on.ca",
        "verification_method": "did:web:dev.lab.di.gov.on.ca#z6Mkgg342Ycpuk263R9d8Aq6MUaxPn1DDeHyGo38EefXmgDL",
    }
    await controller.create_status_list_def(request)
    async with context.profile.session() as session:
        records = await StatusListDef.query(
            session,
            {"status_purpose": "message", "supported_cred_id": "supported_cred_id"},
        )
    assert records
    message = records[0]
    assert message
    assert message.status_purpose == "message"
    assert message.supported_cred_id == "supported_cred_id"

    # Test create_status_list_def errors
    with patch(
        "status_list.v1_0.status_handler.assign_status_list_number",
        side_effect=StorageNotFoundError("No record found"),
    ):
        with pytest.raises(HTTPNotFound) as err:
            await controller.create_status_list_def(request)
    assert isinstance(err.value, HTTPNotFound)

    with patch(
        "status_list.v1_0.status_handler.assign_status_list_number",
        side_effect=StorageError("Storage error"),
    ):
        with pytest.raises(HTTPInternalServerError) as err:
            await controller.create_status_list_def(request)
    assert isinstance(err.value, HTTPInternalServerError)

    request.json.return_value = {"list_size": 11}
    try:
        await controller.create_status_list_def(request)
    except HTTPBadRequest as err:
        assert err

    request.json.return_value = {"shard_size": -1}
    try:
        await controller.create_status_list_def(request)
    except HTTPBadRequest as err:
        assert err

    request.json.return_value = {"status_size": -1}
    try:
        await controller.create_status_list_def(request)
    except HTTPBadRequest as err:
        assert err

    request.json.return_value = {"status_purpose": "message"}
    try:
        await controller.create_status_list_def(request)
    except HTTPBadRequest as err:
        assert err

    request.json.return_value = {"status_purpose": "message", "status_message": []}
    try:
        await controller.create_status_list_def(request)
    except HTTPBadRequest as err:
        assert err

    request.json.return_value = {"status_purpose": "suspention", "status_size": 2}
    try:
        await controller.create_status_list_def(request)
    except HTTPBadRequest as err:
        assert err

    # Test get_status_list_defs
    request.query = {"supported_cred_id": "supported_cred_id"}
    with patch.object(controller, "web", autospec=True) as mock_web:
        await controller.get_status_list_defs(request)
        records = mock_web.json_response.call_args[0][0]
        assert records
        record = records[0]
        assert record
        record = SimpleNamespace(**record)
        assert record.supported_cred_id == "supported_cred_id"

    # Test get_status_list_defs errors
    with patch(
        "status_list.v1_0.models.StatusListDef.query",
        side_effect=StorageNotFoundError("No record found"),
    ):
        with pytest.raises(HTTPNotFound) as err:
            await controller.get_status_list_defs(request)
    assert isinstance(err.value, HTTPNotFound)

    with patch(
        "status_list.v1_0.models.StatusListDef.query",
        side_effect=StorageError("Storage error"),
    ):
        with pytest.raises(HTTPInternalServerError) as err:
            await controller.get_status_list_defs(request)
    assert isinstance(err.value, HTTPInternalServerError)

    # Test get_status_list_def
    request.match_info = {"def_id": saved.id}
    with patch.object(controller, "web", autospec=True) as mock_web:
        await controller.get_status_list_def(request)
        record = mock_web.json_response.call_args[0][0]
        assert record
        record = SimpleNamespace(**record)
        assert record.supported_cred_id == "supported_cred_id"

    # Test get_status_list_def errors
    with patch(
        "status_list.v1_0.models.StatusListDef.retrieve_by_id",
        side_effect=StorageNotFoundError("No record found"),
    ):
        with pytest.raises(HTTPNotFound) as err:
            await controller.get_status_list_def(request)
    assert isinstance(err.value, HTTPNotFound)

    with patch(
        "status_list.v1_0.models.StatusListDef.retrieve_by_id",
        side_effect=StorageError("Storage error"),
    ):
        with pytest.raises(HTTPInternalServerError) as err:
            await controller.get_status_list_def(request)
    assert isinstance(err.value, HTTPInternalServerError)

    # Test delete_status_list_def
    request.match_info = {"def_id": message.id}
    request.json = AsyncMock(return_value={"recursive_delete": True})

    # Seed status list cred
    async with context.profile.session() as session:
        status_list_cred.definition_id = message.id
        await status_list_cred.save(session)

    with patch.object(controller, "web", autospec=True) as mock_web:
        await controller.delete_status_list_def(request)
        result = mock_web.json_response.call_args[0][0]
        assert result
        result = SimpleNamespace(**result)
        assert result.deleted
        assert result.def_id == message.id

    # Test delete_status_list_def errors
    with patch(
        "status_list.v1_0.models.StatusListDef.retrieve_by_id",
        side_effect=StorageNotFoundError("No record found"),
    ):
        with pytest.raises(HTTPNotFound) as err:
            await controller.delete_status_list_def(request)
    assert isinstance(err.value, HTTPNotFound)

    with patch(
        "status_list.v1_0.models.StatusListDef.retrieve_by_id",
        side_effect=StorageError("Storage error"),
    ):
        with pytest.raises(HTTPInternalServerError) as err:
            await controller.delete_status_list_def(request)
    assert isinstance(err.value, HTTPInternalServerError)

    del request.json.return_value["recursive_delete"]
    try:
        await controller.delete_status_list_def(request)
    except HTTPBadRequest as err:
        assert err
