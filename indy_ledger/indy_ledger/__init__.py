import asyncio
import logging

from acapy_agent.anoncreds.registry import AnonCredsRegistry
from acapy_agent.commands.provision import ProvisionError
from acapy_agent.config.base import BaseError
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.config.provider import ClassProvider
from acapy_agent.config.wallet import wallet_config
from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.plugin_registry import PluginRegistry
from acapy_agent.core.profile import Profile, ProfileManager
from acapy_agent.core.protocol_registry import ProtocolRegistry
from acapy_agent.core.util import STARTUP_EVENT_PATTERN
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.utils.profiles import get_subwallet_profiles_from_storage
from acapy_agent.wallet.singletons import IsAnonCredsSingleton

from indy_ledger.wallet.anoncreds_upgrade import upgrade_wallet_to_anoncreds_if_requested

from .argparser import parse_ledger_args
from .did.resolver import IndyDIDResolver
from .ledger.config import (
    get_genesis_transactions,
    ledger_config,
    load_multiple_genesis_transactions_from_config,
)
from .profile.custom_profile_provider import ProfileManagerProvider

LOGGER = logging.getLogger(__name__)


async def setup(context: InjectionContext):
    """Setup the plugin."""
    LOGGER.info("Setting up indy_ledger plugin...")
    ledger_settings = parse_ledger_args(context.settings.get("plugin_config", {}))
    for setting in ledger_settings:
        LOGGER.debug("Indy Ledger setting: %s = %s", setting, ledger_settings[setting])
        context.settings.set_value(setting, ledger_settings[setting])

    plugin_registry = context.inject(PluginRegistry)

    # Register the ledger plugin
    plugin_registry.register_plugin("indy_ledger.ledger")

    # Register the revocation plugin
    plugin_registry.register_plugin("indy_ledger.revocation")

    # Register the credential definitions and schemas plugin
    plugin_registry.register_plugin("indy_ledger.credential_definitions")
    plugin_registry.register_plugin("indy_ledger.endorse_transaction")
    plugin_registry.register_plugin("indy_ledger.schemas")
    plugin_registry.register_plugin("indy_ledger.issue_credential")

    context.injector.bind_provider(ProfileManager, ProfileManagerProvider())
    protocol_registry = context.inject(ProtocolRegistry)
    assert protocol_registry

    # Provision the ledger
    # if context.settings.get("ledger.auto_provision"):
    try:
        if context.settings.get("ledger.ledger_config_list"):
            await load_multiple_genesis_transactions_from_config(context.settings)
        if (
            context.settings.get("ledger.genesis_transactions")
            or context.settings.get("ledger.genesis_file")
            or context.settings.get("ledger.genesis_url")
        ):
            await get_genesis_transactions(context.settings)

        root_profile, public_did = await wallet_config(context, provision=True)

        if await ledger_config(root_profile, public_did and public_did.did, True):
            LOGGER.info("Ledger configured")
        else:
            LOGGER.warning("Ledger not configured")

        await root_profile.close()
    except BaseError as e:
        raise ProvisionError("Error during provisioning") from e

    root_profile, _ = await wallet_config(context, provision=False)

    # Register the indy resolver
    did_resolver_registry = context.inject_or(DIDResolver)
    if not did_resolver_registry:
        LOGGER.warning("No DID Resolver instance found in context")
        return

    indy_did_resolver = IndyDIDResolver()
    await indy_did_resolver.setup(context)
    did_resolver_registry.register_resolver(indy_did_resolver)

    # Register the anoncreds registry
    registry = context.inject_or(AnonCredsRegistry)
    legacy_indy_registry = ClassProvider(
        "indy_ledger.anoncreds.registry.LegacyIndyRegistry",
        # supported_identifiers=[],
        # method_name="",
    ).provide(context.settings, context.injector)
    await legacy_indy_registry.setup(context)
    registry.register(legacy_indy_registry)

    # Updrade anoncreds if requested
    async def check_for_wallet_upgrades_in_progress(root_profile):
        """Check for upgrade and upgrade if needed."""
        if context.settings.get_value("multitenant.enabled"):
            # Sub-wallets
            subwallet_profiles = await get_subwallet_profiles_from_storage(root_profile)
            await asyncio.gather(
                *[
                    upgrade_wallet_to_anoncreds_if_requested(profile, is_subwallet=True)
                    for profile in subwallet_profiles
                ]
            )

        # Stand-alone or admin wallet
        await upgrade_wallet_to_anoncreds_if_requested(root_profile)

    try:
        LOGGER.info("Checking for wallet upgrades in progress.")
        await check_for_wallet_upgrades_in_progress(root_profile)
        LOGGER.info("Wallet upgrades check completed.")
    except Exception:
        LOGGER.exception(
            "An exception was caught while checking for wallet upgrades in progress."
        )

    # Ensure anoncreds wallet is added to singleton (avoids unnecessary upgrade check)
    if context.settings.get("wallet.type") == "askar-anoncreds":
        IsAnonCredsSingleton().set_wallet(context.settings.get("wallet.name"))

    LOGGER.info("indy_ledger plugin setup complete.")

    # After startup if needed
    bus = context.inject(EventBus)
    if not bus:
        raise ValueError("EventBus missing in context")

    bus.subscribe(STARTUP_EVENT_PATTERN, on_startup)


async def on_startup(profile: Profile, event: Event):
    """Handle startup event."""
    LOGGER.debug("Indy Ledger settings applied")
