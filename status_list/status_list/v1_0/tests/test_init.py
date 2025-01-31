import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from acapy_agent.core.event_bus import EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.core.util import STARTUP_EVENT_PATTERN

from ..error import StatusListError
from ..models import StatusListReg
from ..status_handler import get_wallet_id
from .. import setup, on_startup


@pytest.mark.asyncio
async def test_setup():
    mock_event_bus = MagicMock()
    mock_event_bus.subscribe = AsyncMock()

    mock_context = MagicMock()
    mock_context.inject = MagicMock(return_value=mock_event_bus)

    await setup(mock_context)

    mock_context.inject.assert_called_once_with(EventBus)
    mock_event_bus.subscribe.assert_called_once_with(STARTUP_EVENT_PATTERN, on_startup)


@pytest.mark.asyncio
async def test_on_startup(profile: Profile):

    async with profile.session() as session:
        wallet_id = get_wallet_id(profile.context)
        registry = await StatusListReg.retrieve_by_id(session, wallet_id)
        assert registry

    mock_registry = MagicMock()
    mock_registry.list_count = -1

    with patch(
        "status_list.v1_0.models.StatusListReg.retrieve_by_id",
        AsyncMock(return_value=mock_registry),
    ):
        try:
            await on_startup(profile, MagicMock())
        except StatusListError as error:
            assert error
