"""OID4VCI plugin."""

import logging

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.event_bus import Event, EventBus
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.core.util import SHUTDOWN_EVENT_PATTERN, STARTUP_EVENT_PATTERN

from .config import Config
from .oid4vci_server import Oid4vciServer

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    event_bus = context.inject(EventBus)
    event_bus.subscribe(STARTUP_EVENT_PATTERN, startup)
    event_bus.subscribe(SHUTDOWN_EVENT_PATTERN, shutdown)


async def startup(profile: Profile, event: Event):
    """Startup event handler; start the OpenID4VCI server."""
    try:
        config = Config.from_context(profile.context)
        oid4vci = Oid4vciServer(
            config.host,
            config.port,
            profile.context,
            profile,
        )
        profile.context.injector.bind_instance(Oid4vciServer, oid4vci)
    except Exception:
        LOGGER.exception("Unable to register admin server")
        raise

    oid4vci = profile.inject(Oid4vciServer)
    await oid4vci.start()


async def shutdown(context: InjectionContext):
    """Teardown the plugin."""
    oid4vci = context.inject(Oid4vciServer)
    await oid4vci.stop()
