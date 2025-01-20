"""Status handler module."""

from acapy_agent.core.plugin_registry import PluginRegistry
from acapy_agent.admin.request_context import AdminRequestContext
from .config import Config


class StatusHandler:
    """Status handler class."""

    def __init__(self, context: AdminRequestContext):
        """Initialize the StatusHandler class."""

        self.context = context
        self.handler = None

        config = Config.from_settings(context.settings)
        plugin_registry = context.inject_or(PluginRegistry)

        # "status_list.v1_0.status_handler"
        status_handler_path = config.status_handler

        plugin_index = -1
        for index, name in enumerate(plugin_registry.plugin_names):
            if status_handler_path.startswith(name):
                plugin_index = index
                plugin_name = name
                break

        plugin_name = f"{plugin_name}." if plugin_name else ""
        if plugin_index != -1:
            self.handler = plugin_registry.plugins[plugin_index]
            attributes = status_handler_path.lstrip(plugin_name).split(".")
            # Get handler object
            for attribute in attributes:
                self.handler = getattr(self.handler, attribute)

    def assign_status_entries(self, supported_cred_id, exchange_id, status_type):
        """Assign status entries."""

        if self.handler:
            return self.handler.assign_status_entries(
                self.context, supported_cred_id, exchange_id, status_type
            )
