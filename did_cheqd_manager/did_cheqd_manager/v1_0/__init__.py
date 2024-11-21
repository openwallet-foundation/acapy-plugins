import logging

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.resolver.did_resolver import DIDResolver
from .resolver.cheqd import CheqdDIDResolver
from acapy_agent.wallet.did_method import DIDMethods
from .wallet.did_method import CHEQD


LOGGER = logging.getLogger(__name__)

async def setup(context: InjectionContext):
    from acapy_agent.wallet.routes import DIDListQueryStringSchema
    from .wallet.did_method import CustomDIDListQueryStringSchema
    """Setup the plugin."""
    LOGGER.info("< did_cheqd_manager plugin setup...")
    registry = context.inject_or(DIDResolver)
    if not registry:
        LOGGER.warning("No DID Resolver instance found in context")
        return
    
    customSchema = CustomDIDListQueryStringSchema()

    registry.register_resolver(CheqdDIDResolver())
    context.injector.bind_instance(DIDListQueryStringSchema, customSchema)

    did_methods = context.inject_or(DIDMethods)
    did_methods.register(CHEQD)
    
    LOGGER.info("< did_cheqd_manager plugin setup.")
