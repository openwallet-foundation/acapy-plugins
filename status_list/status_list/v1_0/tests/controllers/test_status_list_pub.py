import pytest
import gzip
import json
import cbor2
from bitarray import bitarray
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from aiohttp.web import HTTPNotFound, HTTPBadRequest, HTTPInternalServerError

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.wallet.util import b64_to_bytes, pad

from ...controllers import status_list_pub as controller
from ...cwt import to_cwt_claims
from ...models import StatusListDef
from ... import status_handler


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "definition_id, token_format",
    [
        ("definition_id", "jwt"),
        ("definition_id", "cwt"),
        ("definition_msg_id", "jwt"),
    ],
)
async def test_publication_writes_definition_format(
    context, seed_db, plugin_config, tmp_path, definition_id, token_format
):
    request_values = {"context": context}
    request = MagicMock(
        app={},
        match_info={"def_id": definition_id},
        headers={},
        __getitem__=lambda request, key: request_values[key],
    )
    config = replace(plugin_config, file_path=str(tmp_path / "{list_number}"))
    retrieve = StatusListDef.retrieve_by_id
    published_definition = {}

    async def retrieve_with_format(session, record_id, **kwargs):
        definition = await retrieve(session, record_id, **kwargs)
        definition.token_format = token_format
        published_definition["value"] = definition
        return definition

    with (
        patch.object(controller.Config, "from_settings", return_value=config),
        patch.object(
            controller.StatusListDef, "retrieve_by_id", side_effect=retrieve_with_format
        ),
    ):
        response = await controller.publish_status_list(request)

    assert response.status == 200
    payloads = json.loads(response.body)["status_lists"]
    list_numbers = published_definition["value"].list_numbers
    assert len(payloads) == len(list_numbers)
    for list_number, payload in zip(list_numbers, payloads):
        jwt_path = tmp_path / list_number
        cwt_path = tmp_path / f"{list_number}.cwt"
        if token_format == "cwt":
            assert not jwt_path.exists()
            token = cbor2.loads(cwt_path.read_bytes())
            assert token.tag == 18
            assert cbor2.loads(token.value[2]) == to_cwt_claims(payload)
        else:
            assert not cwt_path.exists()
            assert jwt_path.read_text().count(".") == 2


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
