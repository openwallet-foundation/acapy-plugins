import pytest
import gzip
from bitarray import bitarray
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp.web import HTTPNotFound, HTTPBadRequest, HTTPInternalServerError

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.util import b64_to_bytes, pad

from ...controllers import status_list_pub as controller
from ... import status_handler


@pytest.mark.asyncio
async def test_status_list_pub_routes(context: AdminRequestContext, seed_db):
    """Test status_list_pub routes."""

    # Seed status list cred
    async with context.profile.session() as session:
        # Set status list entry
        result = await status_handler.update_status_list_entry(
            session, "definition_id", "credential_id", "1"
        )
        result = SimpleNamespace(**result)
        assert result.status == "1"
        # Get status list entry
        result = await status_handler.get_status_list_entry(
            session, "definition_id", "credential_id"
        )
        result = SimpleNamespace(**result)
        assert result.status == "1"

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
    # Test publish_status_list
    with patch.object(controller, "web", autospec=True) as mock_web:
        await controller.publish_status_list(request)
        result = mock_web.json_response.call_args[0][0]
        assert len(result) > 0

        list_0 = result["status_lists"][0]
        encoded_list = (
            list_0["vc"]["credentialSubject"]["encodedList"]
            if hasattr(list_0, "vc")
            else None
        )
        encoded_list = (
            list_0["status_list"]["lst"] if hasattr(list_0, "status_list") else None
        )
        if encoded_list:
            # Verify status entry
            encoded_list = pad(encoded_list)
            decoded_list = b64_to_bytes(encoded_list, True)
            decoded_list = gzip.decompress(decoded_list)
            status_bits = bitarray()
            status_bits.frombytes(decoded_list)
            assert status_bits[57608] == 1

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

    del request.json.return_value["did"]
    del request.json.return_value["verification_method"]
    try:
        await controller.publish_status_list(request)
    except HTTPBadRequest as err:
        assert err
