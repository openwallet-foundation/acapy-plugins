"""Integrate Connections Protocol Plugin."""

import logging
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.config.provider import ClassProvider
from acapy_agent.connections.base_manager import BaseConnectionManager
from acapy_agent.core.profile import Profile

from connections.v1_0.manager import ConnectionManager


LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    LOGGER.debug("Binding BaseConnectionManager to ConnectionManager")
    context.injector.bind_provider(
        BaseConnectionManager,
        ClassProvider(ConnectionManager, ClassProvider.Inject(Profile)),
    )
