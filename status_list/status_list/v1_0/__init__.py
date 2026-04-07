"""Status List Plugin v1.0."""

import logging

from acapy_agent.admin.base_server import BaseAdminServer
from acapy_agent.config.injection_context import InjectionContext

from . import routes

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    LOGGER.info("> status_list plugin setup...")

    admin_server = context.inject_or(BaseAdminServer)
    if admin_server:
        await routes.register(admin_server.app)

    LOGGER.info("< status_list plugin setup.")
