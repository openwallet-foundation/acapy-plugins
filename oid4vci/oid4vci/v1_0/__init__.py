import logging
from os import getenv

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.core.event_bus import Event, EventBus
from aries_cloudagent.core.profile import Profile
from aries_cloudagent.protocols.endorse_transaction.v1_0.routes import (
    STARTUP_EVENT_PATTERN,
)
from oid4vci.v1_0.oid4vci_server import Oid4vciServer

LOGGER = logging.getLogger(__name__)

OID4VCI_HOST = getenv("OID4VCI_HOST", default="0.0.0.0")
OID4VCI_PORT: str = getenv("OID4VCI_PORT", default="8081")


async def setup(context: InjectionContext):
    """Setup the plugin."""
    LOGGER.info("> oid4vci plugin setup...")

    event_bus = context.inject(EventBus)
    if not event_bus:
        raise ValueError("EventBus missing in context")

    event_bus.subscribe(STARTUP_EVENT_PATTERN, started_event_handler)
    LOGGER.info("< oid4vci plugin setup.")


async def started_event_handler(profile: Profile, event: Event):
    """Event handler for Basic Messages."""
    LOGGER.info(event.payload)
    try:
        # -o oid4vci.host=0.0.0.0 -o oid4vci.port=8081
        plugin_settings = profile.context.settings.for_plugin("oid4vci")
        host = plugin_settings.get("host") or OID4VCI_HOST
        port = plugin_settings.get("port") or OID4VCI_PORT
        assert host
        assert port

        oid4vci = Oid4vciServer(
            host,
            port,
            profile.context,
            profile,
        )
        profile.context.injector.bind_instance(Oid4vciServer, oid4vci)
    except Exception:
        LOGGER.exception("Unable to register admin server")
        raise
    oid4vci = profile.inject(Oid4vciServer)
    await oid4vci.start()
