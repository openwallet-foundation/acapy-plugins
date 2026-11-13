import pytest
import gzip
import cbor2
from bitarray import bitarray
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp.web import HTTPNotFound, HTTPBadRequest, HTTPInternalServerError

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.jwt import b64_to_dict
from acapy_agent.wallet.util import b64_to_bytes, pad

from ...controllers import status_list_pub as controller
from ...cwt import to_cwt_claims
from ... import status_handler


@pytest.mark.asyncio
@pytest.mark.parametrize("definition_id", ["definition_id", "definition_msg_id"])
async def test_publication_formats(
    context,
    seed_db,
    status_list_def,
    status_list_def_msg,
    plugin_config,
    tmp_path,
    definition_id,
):
    definition = (
        status_list_def if definition_id == "definition_id" else status_list_def_msg
    )
    request_values = {"context": context}
    request = MagicMock(
        app={},
        match_info={"def_id": definition_id},
        headers={},
        __getitem__=lambda request, key: request_values[key],
    )
    config = replace(plugin_config, file_path=str(tmp_path / "{list_number}"))

    with patch.object(controller.Config, "from_settings", return_value=config):
        response = await controller.publish_status_list(request)

    assert response.status == 200
    for list_number in definition.list_numbers:
        jwt = (tmp_path / list_number).read_text()
        assert jwt.count(".") == 2
        cwt_path = tmp_path / f"{list_number}.cwt"
        if definition.list_type == "ietf":
            token = cbor2.loads(cwt_path.read_bytes())
            assert isinstance(token, cbor2.CBORTag)
            assert token.tag == 18
            jwt_claims = b64_to_dict(jwt.split(".")[1])
            assert cbor2.loads(token.value[2]) == to_cwt_claims(jwt_claims)
        else:
            assert not cwt_path.exists()


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
                "did": "did:web:example.com",
                "verification_method": "did:web:example.com#3Dn1SJNPaCXcvvJvSbsFWP2xaCjMom3can8CQNhWrTRx",
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
