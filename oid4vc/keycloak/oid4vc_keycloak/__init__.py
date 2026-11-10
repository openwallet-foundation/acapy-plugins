"""Keycloak authorization server integration for the OID4VC plugin.

Load alongside ``oid4vc`` (``--plugin oid4vc --plugin oid4vc_keycloak``) and
configure an authorization server entry with ``"type": "keycloak"``. Keycloak
needs the OID4VCI pre-authorized code grant extension from
``oid4vc/keycloak/extension``. See ``oid4vc/keycloak/README.md``.
"""

import logging

from acapy_agent.config.injection_context import InjectionContext

from oid4vc.auth_providers import AuthServerRegistry

from .provider import KeycloakProvider

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Register the Keycloak authorization server provider."""
    registry = context.inject_or(AuthServerRegistry)
    if not registry:
        registry = AuthServerRegistry()
        context.injector.bind_instance(AuthServerRegistry, registry)
    registry.register(KeycloakProvider())
    LOGGER.info("Registered Keycloak authorization server provider")
