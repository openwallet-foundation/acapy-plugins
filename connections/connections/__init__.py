"""Integrate Connections Protocol Plugin."""

import logging
from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.config.provider import ClassProvider
from aries_cloudagent.connections.base_manager import BaseConnectionManager
from aries_cloudagent.core.profile import Profile

from connections.v1_0.manager import ConnectionManager


LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    LOGGER.debug("Binding BaseConnectionManager to ConnectionManager")
    context.injector.bind_provider(
        BaseConnectionManager,
        ClassProvider(ConnectionManager, ClassProvider.Inject(Profile)),
    )
