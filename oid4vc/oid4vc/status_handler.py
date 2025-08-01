"""Status handler module."""

import logging

from acapy_agent.core.plugin_registry import PluginRegistry
from acapy_agent.admin.request_context import AdminRequestContext
from .config import Config

logger = logging.getLogger(__name__)


class StatusHandler:
    """Status handler class."""

    def __init__(self, context: AdminRequestContext):
        """Initialize the StatusHandler class."""

        self.context = context
        self.handler = None

        config = Config.from_settings(context.settings)
        plugin_registry = context.inject_or(PluginRegistry)

        if config and config.status_handler:
            status_handler_path = config.status_handler
            plugin_index = -1
            plugin_name = ""
            for index, name in enumerate(plugin_registry.plugin_names):
                if status_handler_path.startswith(name):
                    plugin_index = index
                    plugin_name = name
                    break

            if plugin_name:
                plugin_name += "."
            if plugin_index != -1:
                self.handler = plugin_registry.plugins[plugin_index]
                attributes = status_handler_path.removeprefix(plugin_name).split(".")
                # Get handler object
                for attribute in attributes:
                    self.handler = getattr(self.handler, attribute, None)
                    if self.handler is None:
                        logger.error(
                            f"Invalid attribute '{attribute}' in status handler path: "
                            f"{status_handler_path}"
                        )
                        break

    async def assign_status_entries(self, context, supported_cred_id, exchange_id):
        """Assign status entries."""

        if self.handler:
            return await self.handler.assign_status_entries(
                context, supported_cred_id, exchange_id
            )

    async def get_status_list(self, context, list_number):
        """Get status list."""

        if self.handler:
            return await self.handler.get_status_list_token(context, list_number)
