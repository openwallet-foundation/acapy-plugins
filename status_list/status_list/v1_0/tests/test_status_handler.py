import pytest
import os
from bitarray import util as bitutil
from unittest.mock import MagicMock, Mock, patch
from filelock import Timeout

from acapy_agent.admin.request_context import AdminRequestContext

from ..error import StatusListError
from ..models import StatusListDef, StatusListShard, StatusListReg
from .. import status_handler


def test_with_retries():
    mock_func = Mock(return_value="success")

    @status_handler.with_retries(max_attempts=3, delay=0)
    def wrapped():
        return mock_func()

    result = wrapped()
    assert result == "success"
    assert mock_func.call_count == 1

    mock_func = Mock(side_effect=ValueError("fail"))

    @status_handler.with_retries(max_attempts=3, delay=0)
    def wrapped():
        return mock_func()

    with pytest.raises(ValueError, match="fail"):
        wrapped()
    assert mock_func.call_count == 3

    mock_func = Mock(side_effect=[Exception("fail1"), Exception("fail2"), "success"])

    @status_handler.with_retries(max_attempts=5, delay=0)
    def wrapped():
        return mock_func()

    result = wrapped()
    assert result == "success"
    assert mock_func.call_count == 3

    mock_func = Mock(side_effect=Exception("fail"))

    @status_handler.with_retries(max_attempts=3, delay=1)
    def wrapped():
        return mock_func()

    with patch("time.sleep", return_value=None) as mock_sleep:
        with pytest.raises(Exception):
            wrapped()
        # sleep should be called twice (between 3 attempts)
        assert mock_sleep.call_count == 2


def test_write_to_file_success(tmp_path):
    file_path = tmp_path / "test.txt"
    content = b"hello world"

    status_handler.write_to_file(str(file_path), content)

    assert file_path.exists()
    assert file_path.read_bytes() == content

    file_path = tmp_path / "test_retry.txt"
    content = b"retry test"

    # Patch os.replace to fail once then succeed
    call_tracker = {"count": 0}

    def flaky_replace(src, dst):
        if call_tracker["count"] == 0:
            call_tracker["count"] += 1
            raise OSError("Simulated failure")
        return original_replace(src, dst)

    original_replace = os.replace

    with patch("status_list.v1_0.status_handler.os.replace", side_effect=flaky_replace):
        status_handler.write_to_file(str(file_path), content)

    assert file_path.exists()
    assert file_path.read_bytes() == content

    file_path = tmp_path / "fail.txt"
    content = b"should fail"

    # Patch os.replace to always raise
    with patch(
        "status_list.v1_0.status_handler.os.replace", side_effect=OSError("always fail")
    ):
        with pytest.raises(OSError, match="always fail"):
            status_handler.write_to_file(str(file_path), content)

    # Final file should not exist
    assert not file_path.exists()

    file_path = tmp_path / "locked.txt"
    content = b"locked"

    # Patch FileLock to raise Timeout
    with patch(
        "status_list.v1_0.status_handler.FileLock", side_effect=Timeout("lock timeout")
    ):
        with pytest.raises(Timeout, match="lock timeout"):
            status_handler.write_to_file(str(file_path), content)

    assert not file_path.exists()


def test_get_wallet_id(context: AdminRequestContext):
    wallet_id = status_handler.get_wallet_id(context)
    assert wallet_id == "base"

    mcok_context = MagicMock(spec=context)
    mcok_context.metadata = {"wallet_id": "wallet_id"}
    wallet_id = status_handler.get_wallet_id(mcok_context)
    assert wallet_id == "wallet_id"


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
        context, "supported_cred_id", "credential_id"
    )
    assert status_list

    status_list = await status_handler.assign_status_entries(
        context, "supported_cred_id1", "credential_id"
    )
    assert status_list is None

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
                context, "supported_cred_id", "credential_id"
            )
        except Exception as e:
            assert isinstance(e, StatusListError)


@pytest.mark.asyncio
async def test_get_status_list_token(context: AdminRequestContext, seed_db):
    token = await status_handler.get_status_list_token(context, "1")

    assert token
