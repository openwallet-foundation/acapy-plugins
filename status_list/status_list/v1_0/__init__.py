"""Status List Plugin v1.0."""

import logging

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.core.util import STARTUP_EVENT_PATTERN
from acapy_agent.storage.error import StorageNotFoundError

from .error import StatusListError
from .models import StatusListReg
from .status_handler import get_wallet_id

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""

    event_bus = context.inject(EventBus)
    event_bus.subscribe(STARTUP_EVENT_PATTERN, on_startup)


async def on_startup(profile: Profile, event: Event):
    """Startup event handler."""

    async with profile.session() as session:
        wallet_id = get_wallet_id(profile.context)
        try:
            registry = await StatusListReg.retrieve_by_id(session, wallet_id)
            if registry.list_count < 0:
                raise StatusListError("Status list registry has negative list count.")
        except StorageNotFoundError:
            registry = StatusListReg(id=wallet_id, list_count=0, new_with_id=True)
            await registry.save(session, reason="Create new status list registry.")
