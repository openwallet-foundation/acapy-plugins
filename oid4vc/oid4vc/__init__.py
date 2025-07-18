"""OID4VC plugin."""

import logging

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.core.util import SHUTDOWN_EVENT_PATTERN, STARTUP_EVENT_PATTERN
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.key_type import KeyTypes

from jwt_vc_json.cred_processor import JwtVcJsonCredProcessor
from oid4vc.cred_processor import CredProcessors
from .status_handler import StatusHandler

from .config import Config
from .jwk import DID_JWK, P256
from .jwk_resolver import JwkResolver
from .oid4vci_server import Oid4vciServer

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    event_bus = context.inject(EventBus)
    event_bus.subscribe(STARTUP_EVENT_PATTERN, startup)
    event_bus.subscribe(SHUTDOWN_EVENT_PATTERN, shutdown)

    resolver = context.inject(DIDResolver)
    resolver.register_resolver(JwkResolver())

    methods = context.inject(DIDMethods)
    methods.register(DID_JWK)

    key_types = context.inject(KeyTypes)
    key_types.register(P256)

    # Include jwt_vc_json by default
    jwt_vc_json = JwtVcJsonCredProcessor()
    processors = CredProcessors()
    processors.register_issuer("jwt_vc_json", jwt_vc_json)
    processors.register_issuer("jwt_vc", jwt_vc_json)
    processors.register_cred_verifier("jwt_vc_json", jwt_vc_json)
    processors.register_cred_verifier("jwt_vc", jwt_vc_json)
    processors.register_pres_verifier("jwt_vp_json", jwt_vc_json)
    processors.register_pres_verifier("jwt_vp", jwt_vc_json)

    context.injector.bind_instance(CredProcessors, processors)

    status_handler = StatusHandler(context)
    context.injector.bind_instance(StatusHandler, status_handler)


async def startup(profile: Profile, event: Event):
    """Startup event handler; start the OpenID4VCI server."""
    try:
        config = Config.from_settings(profile.settings)
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
