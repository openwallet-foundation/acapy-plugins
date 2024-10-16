"""Profile manager for multitenancy."""

import logging

from acapy_agent.config.base import InjectionError
from acapy_agent.config.injector import BaseInjector
from acapy_agent.config.settings import BaseSettings
from acapy_agent.multitenant.manager_provider import MultitenantManagerProvider
from acapy_agent.utils.classloader import ClassLoader, ClassNotFoundError

from .config import MultitenantProviderConfig

LOGGER = logging.getLogger(__name__)


class CustomMultitenantManagerProvider(MultitenantManagerProvider):
    """Profile manager for multitenancy."""

    def __init__(self, root_profile):
        """Initialize the multitenant manager provider."""
        super().__init__(root_profile)
        self.manager_class = None

    def provide(self, settings: BaseSettings, injector: BaseInjector):
        """Create the multitenant manager instance."""

        if not self.manager_class:
            config = self.root_profile.inject(MultitenantProviderConfig)
            # we have not loaded a manager...
            manager_class = config.manager.class_name
            LOGGER.info(f"Create multitenant manager (class={manager_class})")
            try:
                self._inst[manager_class] = ClassLoader.load_class(manager_class)(
                    self.root_profile
                )
                self.manager_class = manager_class
            except ClassNotFoundError as err:
                raise InjectionError(
                    f"Error loading multitenant manager, class '{manager_class}' not found."  # noqa: E501
                ) from err

        # return our loaded manager class...
        return self._inst[self.manager_class]
