"""Helper functions for managing agent or tenant configurations."""

import json

from acapy_agent.core.profile import Profile
from acapy_agent.storage.base import BaseStorage
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.storage.record import StorageRecord

from ..did.exceptions import ConfigurationError
from .webvh_config_record import WebvhConfigRecord

WALLET_ID = "wallet.id"
WALLET_NAME = "wallet.name"


def _get_wallet_identifier(profile: Profile):
    """Get the wallet identifier."""
    return profile.settings.get(WALLET_ID) or profile.settings.get(WALLET_NAME)


async def get_plugin_config(profile: Profile):
    """Get the plugin settings."""
    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        stored_config = None
        try:
            stored_config = await storage.get_record(
                WebvhConfigRecord.RECORD_TYPE,
                _get_wallet_identifier(profile),
            )
        except StorageNotFoundError:
            pass

    if stored_config:
        return json.loads(stored_config.value)["config"]
    return profile.settings.get("plugin_config", {}).get("did-webvh", {})


async def is_controller(profile: Profile):
    """Check if the current agent is a controller."""
    return False if (await get_plugin_config(profile)).get("witness") else True


async def is_witness(profile: Profile):
    """Check if the current agent is a witness."""
    return True if (await get_plugin_config(profile)).get("witness") else False


async def notify_watchers(profile: Profile):
    """Check if we should notify watchers."""
    return (await get_plugin_config(profile)).get("notify_watchers", False)


async def get_server_url(profile: Profile):
    """Get the server info."""
    server_url = (await get_plugin_config(profile)).get("server_url")

    if not server_url:
        raise ConfigurationError("Invalid configuration. Check server url is set.")

    return server_url


async def get_server_domain(profile: Profile):
    """Get the server domain."""
    server_url = await get_server_url(profile)
    """Replace %3A with : if domain is URL encoded."""
    domain = server_url.split("://")[-1]
    if "%3A" in domain:
        domain = domain.replace("%3A", ":")
    return domain


async def get_witnesses(profile: Profile):
    """Get the server info."""
    witnesses = (await get_plugin_config(profile)).get("witnesses")

    if not witnesses:
        raise ConfigurationError("No witnesses exists.")

    return witnesses


async def use_strict_ssl(profile: Profile):
    """Check if the agent should use strict SSL."""
    return (await get_plugin_config(profile)).get("strict_ssl", True)


async def set_config(profile: Profile, config: dict):
    """Set the configuration."""
    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        # Update
        try:
            stored_config_record = await storage.get_record(
                WebvhConfigRecord.RECORD_TYPE, _get_wallet_identifier(profile)
            )
            if stored_config_record:
                await storage.update_record(
                    stored_config_record,
                    value=json.dumps(
                        WebvhConfigRecord(
                            record_id=_get_wallet_identifier(profile), config=config
                        ).serialize()
                    ),
                    tags={},
                )
        # Add
        except StorageNotFoundError:
            await storage.add_record(
                StorageRecord(
                    type=WebvhConfigRecord.RECORD_TYPE,
                    id=_get_wallet_identifier(profile),
                    value=json.dumps(
                        WebvhConfigRecord(
                            record_id=_get_wallet_identifier(profile), config=config
                        ).serialize()
                    ),
                )
            )


async def add_scid_mapping(profile: Profile, scid: str, did: str):
    """Add a scid mapping."""
    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        stored_config_record = await storage.get_record(
            WebvhConfigRecord.RECORD_TYPE,
            _get_wallet_identifier(profile),
        )
        config = json.loads(stored_config_record.value)["config"]
        config["scids"] = config.get("scids", {})
        config["scids"][scid] = did
        await storage.update_record(
            stored_config_record,
            value=json.dumps(
                WebvhConfigRecord(
                    record_id=_get_wallet_identifier(profile), config=config
                ).serialize()
            ),
            tags={},
        )


async def did_from_scid(profile: Profile, scid: str):
    """Find DID mapped to a specific SCID."""
    async with profile.session() as session:
        storage = session.inject(BaseStorage)
        stored_config_record = await storage.get_record(
            WebvhConfigRecord.RECORD_TYPE,
            _get_wallet_identifier(profile),
        )
        config = json.loads(stored_config_record.value)["config"]
        if not config["scids"].get(scid):
            raise ConfigurationError(f"SCID {scid} not listed.")
        return config["scids"].get(scid)
