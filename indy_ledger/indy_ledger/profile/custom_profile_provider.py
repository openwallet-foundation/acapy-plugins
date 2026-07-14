"""Custom profile manager provider for ACA-Py."""

import logging

from acapy_agent.config.base import InjectionError
from acapy_agent.config.injector import BaseInjector
from acapy_agent.config.provider import BaseProvider
from acapy_agent.config.settings import BaseSettings
from acapy_agent.utils.classloader import ClassLoader, ClassNotFoundError

LOGGER = logging.getLogger(__name__)


class ProfileManagerProvider(BaseProvider):
    """The standard profile manager provider which keys off the selected wallet type."""

    MANAGER_TYPES = {
        "askar": "indy_ledger.profile.askar_profile.AskarProfileManager",
        "askar-anoncreds": "indy_ledger.profile.askar_profile_anon.AskarAnonProfileManager",  # noqa: E501
        "kanon-anoncreds": "indy_ledger.profile.askar_profile_kanon_anon.KanonAnonProfileManager",  # noqa: E501
    }

    def __init__(self):
        """Initialize the profile manager provider."""
        self._inst = {}

    def provide(self, settings: BaseSettings, injector: BaseInjector):
        """Create the profile manager instance."""
        mgr_type = settings.get_value("wallet.type", default="askar")

        # mgr_type may be a fully qualified class name
        mgr_class = self.MANAGER_TYPES.get(mgr_type.lower(), mgr_type)

        if mgr_class not in self._inst:
            LOGGER.info("Create profile manager: %s", mgr_type)
            try:
                self._inst[mgr_class] = ClassLoader.load_class(mgr_class)()
            except ClassNotFoundError as err:
                raise InjectionError(f"Unknown profile manager: {mgr_type}") from err

        return self._inst[mgr_class]
