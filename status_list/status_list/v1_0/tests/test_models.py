import pytest

from acapy_agent.core.profile import Profile

from ..models import StatusListDef, StatusListShard, StatusListCred
from ..status_handler import create_next_status_list
from ..error import DuplicateListNumberError


@pytest.mark.asyncio
async def test_status_list_models(
    profile: Profile, status_list_def: StatusListDef, status_list_cred: StatusListCred
):
    async with profile.session() as session:
        # Test status_list_def
        await status_list_def.save(session)
        definition = await StatusListDef.retrieve_by_id(session, status_list_def.id)
        assert definition == status_list_def

        random_index, shard_number, shard_index = definition.get_random_entry()
        assert random_index < definition.list_size
        assert shard_number < status_list_def.list_size // status_list_def.shard_size
        assert shard_index < status_list_def.shard_size

        # Test status_list_def errors
        try:
            status_list_def.add_list_number("100_000")
            status_list_def.add_list_number("100_000")
        except Exception as err:
            assert isinstance(err, DuplicateListNumberError)
            status_list_def.list_numbers.remove("100_000")

        # Test status_list_shard
        await create_next_status_list(session, status_list_def)
        shards = await StatusListShard.query(
            session,
            {
                "definition_id": status_list_def.id,
                "list_number": definition.list_number,
            },
        )
        assert len(shards) == definition.list_size // definition.shard_size
        assert shards[0].definition_id == status_list_def.id

        # Test status_list_cred
        await status_list_cred.save(session)
        cred = await StatusListCred.retrieve_by_id(session, status_list_cred.id)
        assert cred == status_list_cred

        # Clean up
        for shard in shards:
            await shard.delete_record(session)
