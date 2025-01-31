import pytest
from types import SimpleNamespace
from bitarray import util as bitutil
from unittest.mock import MagicMock, patch

from acapy_agent.admin.request_context import AdminRequestContext

from ..error import StatusListError
from ..models import StatusListDef, StatusListShard, StatusListReg
from .. import status_handler


def test_get_wallet_id(context: AdminRequestContext):
    wallet_id = status_handler.get_wallet_id(context)
    assert wallet_id == "base"

    mcok_context = MagicMock(spec=context)
    mcok_context.metadata = {"wallet_id": "wallet_id"}
    wallet_id = status_handler.get_wallet_id(mcok_context)
    assert wallet_id == "wallet_id"


def test_get_status_list_path(context: AdminRequestContext):
    path = status_handler.get_status_list_path(context, "base", "w3c", "0")
    assert path == "/tenants/base/w3c/status/0"


def test_get_status_list_public_url(context: AdminRequestContext):
    path = status_handler.get_status_list_public_url(context, "base", "w3c", "0")
    assert path == "https://dev.lab.di.gov.on.ca/tenants/base/w3c/status/0"


def test_get_status_list_file_path(context: AdminRequestContext):
    path = status_handler.get_status_list_file_path(context, "base", "w3c", "0")
    assert path == "/tmp/aries/bitstring/tenants/base/w3c/status/0"


async def test_assign_status_list_number(context: AdminRequestContext):
    wallet_id = status_handler.get_wallet_id(context)
    async with context.profile.session() as session:
        list_number = await status_handler.assign_status_list_number(session, wallet_id)
        assert int(list_number) >= 0

    # Test status list registry has negative list count error
    with patch(
        "status_list.v1_0.models.StatusListReg.retrieve_by_id", autospec=True
    ) as mock_retrieve:
        mock_registry = MagicMock(spec=StatusListReg)
        mock_registry.list_count = -1
        mock_retrieve.return_value = mock_registry
        try:
            async with context.profile.session() as session:
                list_number = await status_handler.assign_status_list_number(
                    session, wallet_id
                )
        except Exception as e:
            assert isinstance(e, StatusListError)


@pytest.mark.asyncio
async def test_generate_random_index(context: AdminRequestContext, seed_db):
    async with context.profile.session() as session:
        definition = await StatusListDef.retrieve_by_id(
            session, "definition_id", for_update=True
        )
        definition.list_index = definition.list_size - 1
        await definition.save(session)

    await status_handler.generate_random_index(context, "definition_id")

    async with context.profile.session() as session:
        definition = await StatusListDef.retrieve_by_id(session, "definition_id")

    assert definition.list_index == 0


@pytest.mark.asyncio
async def test_assign_status_entries(context: AdminRequestContext, seed_db):
    status_list = await status_handler.assign_status_entries(
        context, "supported_cred_id", "credential_id", "w3c"
    )
    status_list = status_list[0] if isinstance(status_list, list) else status_list
    status_list = SimpleNamespace(**status_list)
    assert status_list.type == "BitstringStatusListEntry"

    status_list = await status_handler.assign_status_entries(
        context, "supported_cred_id", "credential_id", "ietf"
    )
    status_list = SimpleNamespace(**status_list)
    assert status_list.idx >= 0

    status_list = await status_handler.assign_status_entries(
        context, "supported_cred_id1", "credential_id", "w3c"
    )
    assert status_list is None

    # Test unsupported status type error
    try:
        status_list = await status_handler.assign_status_entries(
            context, "supported_cred_id1", "credential_id", "other"
        )
    except Exception as e:
        assert isinstance(e, StatusListError)

    # Test entry is already assigned error
    real_retrieve = StatusListShard.retrieve_by_tag_filter

    with patch(
        "status_list.v1_0.models.StatusListShard.retrieve_by_tag_filter", autospec=True
    ) as mock_retrieve:

        async def modify_return(txn, tag_filter, for_update=False):
            shard = await real_retrieve(txn, tag_filter, for_update=for_update)
            shard.mask_bits = bitutil.zeros(shard.shard_size)
            return shard

        mock_retrieve.side_effect = modify_return
        try:
            status_list = await status_handler.assign_status_entries(
                context, "supported_cred_id", "credential_id", "w3c"
            )
        except Exception as e:
            assert isinstance(e, StatusListError)
