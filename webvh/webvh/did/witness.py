"""Module to manage witnesses for a DID."""

import copy
import logging
from typing import Optional

from acapy_agent.core.profile import Profile
from acapy_agent.messaging.responder import BaseResponder

from ..config.config import get_plugin_config, set_config

from .utils import parse_did_key
from .exceptions import WitnessError, ConfigurationError
from ..protocols.attested_resource.record import PendingAttestedResourceRecord
from ..protocols.attested_resource.messages import (
    WitnessRequest as AttestedResourceWitnessRequest,
    WitnessResponse as AttestedResrouceWitnessResponse,
)
from ..protocols.log_entry.record import PendingLogEntryRecord
from ..protocols.log_entry.messages import (
    WitnessRequest as LogEntryWitnessRequest,
    WitnessResponse as LogEntryWitnessResponse,
)
from ..protocols.states import WitnessingState
from ..did.server_client import WebVHServerClient
from ..did.utils import add_proof, url_to_domain, format_witness_ready_message
from ..did.key_chain import KeyChainManager
from ..did.connection import WebVHConnectionManager

LOGGER = logging.getLogger(__name__)


class WitnessManager:
    """Class to manage witnesses for a DID."""

    def __init__(self, profile: Profile):
        """Initialize the witness manager."""
        self.profile = profile
        self.server_client = WebVHServerClient(profile)
        self.key_chain = KeyChainManager(profile)
        self.witness_connection = WebVHConnectionManager(profile)
        self.proof_options = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "assertionMethod",
        }

    async def configure(self, config: dict = None, log_message: bool = False) -> dict:
        """Configure this agent as a witness.

        This creates the witness key, invitation, and updates the config.
        Can be called from the configuration endpoint or during startup.

        Args:
            config: Configuration dict. If None, will be fetched from profile.
            log_message: If True, log and print formatted witness ready message.

        Returns:
            Config dict with invitation_url (for API responses)
        """
        if config is None:
            config = await get_plugin_config(self.profile)

        if not config.get("witness", False):
            if log_message:
                LOGGER.debug("Skipping witness configuration - witness not enabled")
            return config

        config.setdefault("witnesses", [])
        key_alias = self.key_alias

        # If witness_id is provided, try to use that key
        if witness_id := config.get("witness_id", None):
            parsed_key = parse_did_key(witness_id)
            witness_key = parsed_key.key
            await self.key_chain.bind_key(witness_key, key_alias)
            if log_message:
                LOGGER.info("Using configured witness_id: %s", witness_id)
        else:
            # Otherwise, find existing key or create new one
            witness_key = await self.key_chain.find_key(key_alias)
            if not witness_key:
                LOGGER.info("Creating witness key for alias %s", key_alias)
                witness_key = await self.key_chain.create_key(key_alias)
            witness_id = f"did:key:{witness_key}"

        # Store witness_id in config if not already set
        if not config.get("witness_id"):
            config["witness_id"] = witness_id
            await set_config(self.profile, config)

        if witness_id not in config["witnesses"]:
            config["witnesses"].append(witness_id)
            await set_config(self.profile, config)

        # Create witness invitation
        invitation_record = await self.witness_connection.create_witness_invitation(
            witness_key=witness_key,
            alias=None,
            label="Witness Service",
            multi_use=True,
        )
        invitation_url = self.witness_connection.extract_invitation_url(invitation_record)
        invitation_url = self.witness_connection.format_invitation_url(invitation_url)

        # Log and print formatted message if requested (for startup visibility)
        if log_message:
            message = format_witness_ready_message(witness_id, invitation_url)
            # Log each line separately for better log parsing
            for line in message.strip().split("\n"):
                LOGGER.warning(line)
            print(message, end="")

        # Return config with invitation_url for API response (but don't persist it)
        response_config = config.copy()
        response_config["invitation_url"] = invitation_url
        return response_config

    @property
    def key_alias(self) -> str:
        """Derive witness key alias from configured server URL."""
        config = self.profile.settings.get("plugin_config", {}).get("webvh", {}) or {}
        server_url = config.get("server_url")
        if not server_url:
            raise ConfigurationError("No server url configured for witness.")
        domain = url_to_domain(server_url)
        return f"webvh:{domain}@witnessKey"

    async def sign(self, document: dict) -> dict:
        """Sign a document with the witness key.

        Args:
            document: The document to sign (dict)

        Returns:
            The signed document with proof added

        Raises:
            WitnessError: If witness key cannot be retrieved
        """
        witness_key = await self.key_chain.get_key(self.key_alias, WitnessError)
        return await add_proof(
            self.profile,
            document,
            f"did:key:{witness_key}#{witness_key}",
        )

    async def witness_log_entry(
        self,
        scid: str,
        log_entry: dict,
        witness_request_id: str,
    ) -> Optional[dict]:
        """Witness the document with the given parameters."""
        config = await get_plugin_config(self.profile)

        # Self witness
        if config.get("witness", False):
            record = PendingLogEntryRecord()
            if config.get("auto_attest", False):
                return await self.sign({"versionId": log_entry.get("versionId")})

            await record.save_pending_record(
                self.profile, scid, log_entry, witness_request_id
            )

        # Need proof from witness agent
        else:
            responder = self.profile.inject(BaseResponder)

            witness_connection = await self.witness_connection.get_active_connection(
                auto_connect=True
            )
            if not witness_connection:
                raise WitnessError("No active witness connection found.")

            await responder.send(
                message=LogEntryWitnessRequest(
                    document=log_entry, request_id=witness_request_id
                ),
                connection_id=witness_connection.connection_id,
            )

    async def witness_attested_resource(
        self,
        scid: str,
        attested_resource: dict,
        witness_request_id: str,
    ) -> Optional[dict]:
        """Witness the document with the given parameters."""
        config = await get_plugin_config(self.profile)

        # Self witness
        if config.get("witness", False):
            record = PendingAttestedResourceRecord()
            if config.get("auto_attest", False):
                return await self.sign(attested_resource)
            await record.save_pending_record(
                self.profile,
                scid,
                attested_resource,
                witness_request_id,
            )

        # Need proof from witness agent
        else:
            responder = self.profile.inject(BaseResponder)

            witness_connection = await self.witness_connection.get_active_connection(
                auto_connect=True
            )
            if not witness_connection:
                raise WitnessError("No active witness connection found.")

            await responder.send(
                message=AttestedResourceWitnessRequest(
                    document=attested_resource, request_id=witness_request_id
                ),
                connection_id=witness_connection.connection_id,
            )

    async def approve_log_entry(
        self, log_entry: dict, connection_id: str, request_id: str = None
    ) -> dict[str, str]:
        """Attest a did request doc."""

        if not log_entry.get("proof", None):
            raise WitnessError("No proof found in log entry. Cannot witness.")

        witness_signature = await self.sign({"versionId": log_entry.get("versionId")})

        if not connection_id:
            # NOTE: will have to review this behavior when witness threshold is > 1
            # is supported
            from ..did.controller import ControllerManager

            await ControllerManager(self.profile).finish_did_operation(
                log_entry, witness_signature
            )
        else:
            await self.profile.inject(BaseResponder).send(
                message=LogEntryWitnessResponse(
                    state=WitnessingState.ATTESTED.value,
                    document=log_entry,
                    witness_proof=witness_signature.get("proof")[0],
                    request_id=request_id,
                ),
                connection_id=connection_id,
            )

        return {"status": "success", "message": "Witness successful."}

    async def approve_attested_resource(
        self, attested_resource: dict, connection_id: str = None, request_id: str = None
    ) -> dict[str, str]:
        """Approve an attested resource."""

        if not attested_resource.get("proof", None):
            raise WitnessError("No proof found in log entry. Cannot witness.")

        witnessed_resource = await self.sign(copy.deepcopy(attested_resource))

        if not connection_id:
            # Upload resource to server
            await self.server_client.upload_attested_resource(witnessed_resource)
            return attested_resource
        else:
            await self.profile.inject(BaseResponder).send(
                message=AttestedResrouceWitnessResponse(
                    state=WitnessingState.ATTESTED.value,
                    document=attested_resource,
                    witness_proof=witnessed_resource.get("proof")[-1],
                    request_id=request_id,
                ),
                connection_id=connection_id,
            )

        return {"status": "success", "message": "Witness successful."}
