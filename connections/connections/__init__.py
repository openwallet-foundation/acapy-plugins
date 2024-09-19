"""Integrate Connections Protocol Plugin."""

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.config.provider import ClassProvider
from aries_cloudagent.connections.base_manager import BaseConnectionManager
from aries_cloudagent.core.profile import Profile

from connections.v1_0.manager import ConnectionManager


async def setup(context: InjectionContext):
    """Setup the plugin."""
    context.injector.bind_provider(
        BaseConnectionManager,
        ClassProvider(
            ConnectionManager,
            ClassProvider.Inject(Profile)
        )
    )
