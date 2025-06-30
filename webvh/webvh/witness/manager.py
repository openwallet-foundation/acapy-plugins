"""Module to manage witnesses for a DID."""

import asyncio
import json
import logging
from typing import Optional

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.protocols.out_of_band.v1_0.manager import (
    OutOfBandManager,
    OutOfBandManagerError,
)
from acapy_agent.protocols.out_of_band.v1_0.messages.invitation import (
    HSProto,
)

from aries_askar import AskarError

from ..config.config import get_plugin_config, get_server_domain, set_config

from .exceptions import WitnessSetupError, WitnessError
from .messages import WitnessRequest, WitnessResponse
from .states import WitnessingState
from ..did.server_client import WebVHServerClient
from ..did.utils import create_key, find_key, bind_key, add_proof

LOGGER = logging.getLogger(__name__)


PENDING_LOG_ENTRY_TABLE_NAME = "did_webvh_pending_log_entry"
PENDING_ATTESTED_RESOURCE_TABLE_NAME = "did_webvh_pending_attested_resource"


class WitnessManager:
    """Class to manage witnesses for a DID."""

    def __init__(self, profile: Profile):
        """Initialize the witness manager."""
        self.profile = profile
        self.role = "witness"
        self.server_client = WebVHServerClient(profile)
        # self.controller = ControllerManager(self.profile)
        self.proof_options = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "assertionMethod",
        }

    async def key_alias(self):
        domain = await get_server_domain(self.profile)
        return f"{domain}@witnessKey"

    async def connection_alias(self):
        domain = await get_server_domain(self.profile)
        return f"{domain}@witness"

    async def _get_active_witness_connection(self) -> Optional[ConnRecord]:
        witness_alias = self.witness_connection_alias()
        async with self.profile.session() as session:
            connection_records = await ConnRecord.retrieve_by_alias(
                session, witness_alias
            )

        active_connections = [
            conn for conn in connection_records if conn.state == "active"
        ]

        if len(active_connections) > 0:
            return active_connections[0]

        return None

    async def get_witness_key(self) -> str:
        """Return the witness key."""
        witness_alias = await self.key_alias()
        witness_key = await find_key(self.profile, witness_alias)
        if not witness_key:
            raise WitnessError(f"Witness key [{witness_alias}] not found.")

        return witness_key

    async def configure(self, auto_attest=False, multikey=None) -> dict:
        """Ensure witness key is setup."""

        config = await get_plugin_config(self.profile)
        config["role"] = self.role
        config["auto_attest"] = auto_attest

        key_alias = await self.key_alias()
        witness_key = (
            await find_key(self.profile, key_alias)
            or await bind_key(self.profile, multikey, key_alias)
            or await create_key(self.profile, key_alias)
        )
        if not witness_key:
            raise WitnessError("Error create witness key.")

        witness_id = f"did:key:{witness_key}"
        if witness_id not in config["witnesses"]:
            config["witnesses"].append(witness_id)

        await set_config(self.profile, config)

        return {"id": witness_id}

    async def witness_log_entry(
        self,
        scid: str,
        log_entry: dict,
    ) -> Optional[dict]:
        """Witness the document with the given parameters."""
        config = await get_plugin_config(self.profile)

        # Self witness
        if config.get("role") == "witness":
            if not config.get("auto_attest", False):
                await self.save_log_entry_for_witnessing(
                    scid, log_entry, connection_id=""
                )
                return

            witness_key = await self.get_witness_key()
            witness_signature = await add_proof(
                self.profile,
                {"versionId": log_entry.get("versionId")},
                f"did:key:{witness_key}#{witness_key}",
            )
            return witness_signature

        # Need proof from witness agent
        else:
            responder = self.profile.inject(BaseResponder)

            witness_connection = await self._get_active_witness_connection()
            if not witness_connection:
                raise WitnessError("No active witness connection found.")

            await responder.send(
                message=WitnessRequest(log_entry),
                connection_id=witness_connection.connection_id,
            )

    async def save_log_entry_for_witnessing(
        self, scid: str, log_entry: dict, connection_id: Optional[str] = ""
    ):
        """Save a log entry to the wallet to be witnessed."""
        async with self.profile.session() as session:
            try:
                await session.handle.insert(
                    PENDING_LOG_ENTRY_TABLE_NAME,
                    scid,
                    value_json=log_entry,
                    tags={"connection_id": connection_id},
                )
            except AskarError as e:
                raise WitnessError(f"Error adding pending document: {e}")

    async def get_pending_log_entries(self) -> list:
        """Get did request docs that are pending a witness."""
        async with self.profile.session() as session:
            entries = await session.handle.fetch_all(PENDING_LOG_ENTRY_TABLE_NAME)
            return [entry.value_json for entry in entries]

    async def approve_log_entry(self, entry_id: str) -> dict[str, str]:
        """Attest a did request doc."""
        async with self.profile.session() as session:
            entry = await session.handle.fetch(PENDING_LOG_ENTRY_TABLE_NAME, entry_id)

        if entry is None:
            raise WitnessError("Failed to find pending document.")

        connection_id = entry.tags.get("connection_id")
        log_entry = entry.value_json

        if not log_entry.get("proof", None):
            raise WitnessError("No proof found in log entry. Cannot witness.")

        witness_key = await self.get_witness_key()
        witness_signature = await add_proof(
            self.profile,
            {"versionId": log_entry.get("versionId")},
            f"did:key:{witness_key}#{witness_key}",
        )

        if not connection_id:
            # NOTE: will have to review this behavior when witness threshold is > 1
            # is supported
            from ..did.manager import ControllerManager

            if witness_signature.get("versionId")[0] == "1":
                await ControllerManager(self.profile).finish_create(
                    log_entry, witness_signature
                )
        else:
            await self.profile.inject(BaseResponder).send(
                message=WitnessResponse(
                    state=WitnessingState.ATTESTED.value,
                    document=witness_signature,
                ),
                connection_id=connection_id,
            )

        async with self.profile.session() as session:
            await session.handle.remove(PENDING_LOG_ENTRY_TABLE_NAME, entry_id)

        return {"status": "success", "message": "Witness successful."}

    async def reject_log_entry(self, entry_id: str) -> dict[str, str]:
        """Reject a did request doc."""
        async with self.profile.session() as session:
            await session.handle.remove(PENDING_LOG_ENTRY_TABLE_NAME, entry_id)

        return {"status": "success", "message": "Removed registration."}

    async def save_attested_resource_witnessing(
        self, scid: str, attested_resource: dict, connection_id: Optional[str] = ""
    ):
        """Save an attested resource to the wallet to be witnessed."""
        async with self.profile.session() as session:
            try:
                await session.handle.insert(
                    PENDING_ATTESTED_RESOURCE_TABLE_NAME,
                    scid,
                    value_json=attested_resource,
                    tags={"connection_id": connection_id},
                )
            except AskarError as e:
                raise WitnessError(f"Error adding pending document: {e}")

    async def get_pending_attested_resources(self) -> list:
        """Get attested_resources that are pending a witness."""
        async with self.profile.session() as session:
            entries = await session.handle.fetch_all(PENDING_ATTESTED_RESOURCE_TABLE_NAME)
            return [entry.value_json for entry in entries]

    async def approve_attested_resource(self, entry_id: str) -> dict[str, str]:
        """Approve an attested resource."""
        async with self.profile.session() as session:
            entry = await session.handle.fetch(
                PENDING_ATTESTED_RESOURCE_TABLE_NAME, entry_id
            )

        if entry is None:
            raise WitnessError("Failed to find pending document.")

        connection_id = entry.tags.get("connection_id")
        attested_resource = entry.value_json

        if not attested_resource.get("proof", None):
            raise WitnessError("No proof found in log entry. Cannot witness.")

        witness_key = await self.get_witness_key()
        attested_resource = await add_proof(
            self.profile, attested_resource, f"did:key:{witness_key}#{witness_key}"
        )

        if not connection_id:
            # Upload resource to server
            namespace = attested_resource.get("id").split("/")[0].split(":")[4]
            identifier = attested_resource.get("id").split("/")[0].split(":")[5]
            await self.server_client.upload_attested_resource(
                namespace, identifier, attested_resource
            )
            return attested_resource
        else:
            await self.profile.inject(BaseResponder).send(
                message=WitnessResponse(
                    state=WitnessingState.ATTESTED.value,
                    document=attested_resource,
                ),
                connection_id=connection_id,
            )

        async with self.profile.session() as session:
            await session.handle.remove(PENDING_LOG_ENTRY_TABLE_NAME, entry_id)

        return {"status": "success", "message": "Witness successful."}

    async def reject_attested_resource(self, entry_id: str) -> dict[str, str]:
        """Reject an attested resource."""
        async with self.profile.session() as session:
            await session.handle.remove(PENDING_ATTESTED_RESOURCE_TABLE_NAME, entry_id)

        return {"status": "success", "message": "Removed registration."}

    async def create_invitation(self, alias=None, label=None, multi_use=False) -> str:
        """Create a witness invitation."""
        witness_key = await self.get_witness_key()
        try:
            invi_rec = await OutOfBandManager(self.profile).create_invitation(
                hs_protos=[
                    HSProto.get("https://didcomm.org/didexchange/1.0"),
                    HSProto.get("https://didcomm.org/didexchange/1.1"),
                ],
                alias=alias,
                my_label=label,
                # TODO, register attachment?
                # attachments=[{"type": "Witness", "id": f"did:key:{witness_key}"}],
                goal_code="witness-service",
                goal=f"did:key:{witness_key}",
                multi_use=multi_use,
            )
            return invi_rec.serialize()
        except OutOfBandManagerError as e:
            raise WitnessError(e)
