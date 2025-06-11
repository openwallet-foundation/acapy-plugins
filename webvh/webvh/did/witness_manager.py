"""Module to manage witnesses for a DID."""

import asyncio
import json
import logging
from typing import Optional

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.protocols.out_of_band.v1_0.manager import (
    OutOfBandManager,
    OutOfBandManagerError,
)
from acapy_agent.protocols.out_of_band.v1_0.messages.invitation import (
    HSProto,
    InvitationMessage,
)
from acapy_agent.vc.data_integrity.manager import DataIntegrityManager
from acapy_agent.vc.data_integrity.models.options import DataIntegrityProofOptions
from acapy_agent.wallet.error import WalletNotFoundError
from acapy_agent.wallet.keys.manager import MultikeyManager, MultikeyManagerError
from aries_askar import AskarError

from ..config.config import get_plugin_config, get_server_url, is_controller
from .exceptions import ConfigurationError, WitnessError
from .messages.witness import WitnessRequest, WitnessResponse
from .registration_state import RegistrationState
from .utils import create_alias, server_url_to_domain

LOGGER = logging.getLogger(__name__)


PENDING_DOCUMENT_TABLE_NAME = "did_webvh_pending_document"


class WitnessManager:
    """Class to manage witnesses for a DID."""

    def __init__(self, profile: Profile):
        """Initialize the witness manager."""
        self.profile = profile

    async def _get_active_witness_connection(self) -> Optional[ConnRecord]:
        server_url = await get_server_url(self.profile)
        witness_alias = create_alias(
            server_url_to_domain(server_url), "witnessConnection"
        )
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

    async def _create_or_get_witness_did(self, key_alias, key=None):
        """Create new multikey with alias or return existing one."""
        async with self.profile.session() as session:
            manager = MultikeyManager(session)
            try:
                if key:
                    key_info = await manager.update(
                        kid=key_alias,
                        multikey=key,
                    )
                else:
                    key_info = await manager.create(
                        kid=key_alias,
                        alg="ed25519",
                    )
            except MultikeyManagerError:
                key_info = await manager.from_kid(key_alias)
            except WalletNotFoundError:
                raise ConfigurationError("Provided key not found in wallet.")
        return key_info

    async def witness_registration_document(
        self,
        registration_document: dict,
        proof_options: dict,
        parameter_options: dict,
    ) -> Optional[dict]:
        """Witness the document with the given parameters."""
        config = await get_plugin_config(self.profile)
        role = config.get("role")
        async with self.profile.session() as session:
            # Self witness
            if not role or role == "witness":
                server_url = await get_server_url(self.profile)
                witness_alias = create_alias(
                    server_url_to_domain(server_url), "witnessKey"
                )
                witness_key_exists = await MultikeyManager(session).kid_exists(
                    witness_alias
                )
                if not witness_key_exists:
                    raise WitnessError(f"Witness key [{witness_alias}] not found.")

                witness_key_info = await MultikeyManager(session).from_kid(witness_alias)
                witness_key = witness_key_info.get("multikey")

                signed_doc = await DataIntegrityManager(session).add_proof(
                    registration_document,
                    DataIntegrityProofOptions.deserialize(
                        proof_options
                        | {"verificationMethod": f"did:key:{witness_key}#{witness_key}"}
                    ),
                )

                if not config.get("auto_attest", True):
                    await self.save_did_request_doc_for_witnessing(
                        signed_doc, connection_id=None, parameters=parameter_options
                    )
                    return

                return signed_doc

            # Need proof from witness agent
            else:
                responder = self.profile.inject(BaseResponder)

                witness_connection = await self._get_active_witness_connection()
                if not witness_connection:
                    raise WitnessError("No active witness connection found.")

                await responder.send(
                    message=WitnessRequest(registration_document, parameter_options),
                    connection_id=witness_connection.connection_id,
                )

    async def setup_witness_key(self, server_url, key=None) -> None:
        """Ensure witness key is setup."""

        witness_alias = create_alias(server_url_to_domain(server_url), "witnessKey")

        witness_key_info = await self._create_or_get_witness_did(witness_alias, key)

        if not witness_key_info.get("multikey"):
            raise WitnessError("Witness key creation error.")

        return {
            "multikey": witness_key_info.get("multikey"),
            "kid": witness_key_info.get("kid"),
        }

    async def auto_witness_setup(self) -> None:
        """Automatically set up the witness the connection."""
        server_url = await get_server_url(self.profile)
        witness_alias = create_alias(
            server_url_to_domain(server_url), "witnessConnection"
        )

        if not await is_controller(self.profile):
            return

        # Get the witness connection is already set up
        if await self._get_active_witness_connection():
            LOGGER.info("Connected to witness from previous connection.")
            return

        witness_invitation = (await get_plugin_config(self.profile)).get(
            "witness_invitation"
        )
        if not witness_invitation:
            LOGGER.info("No witness invitation, can't create connection automatically.")
            return
        oob_mgr = OutOfBandManager(self.profile)
        try:
            await oob_mgr.receive_invitation(
                invitation=InvitationMessage.from_url(witness_invitation),
                auto_accept=True,
                alias=witness_alias,
            )
        except BaseModelError as err:
            raise WitnessError(f"Error receiving witness invitation: {err}")

        for _ in range(5):
            if await self._get_active_witness_connection():
                LOGGER.info("Connected to witness agent.")
                return
            await asyncio.sleep(1)

        LOGGER.info(
            "No immediate response when trying to connect to witness agent. You can "
            f"try manually setting up a connection with alias {witness_alias} or "
            "restart the agent when witness is available."
        )

    async def save_did_request_doc_for_witnessing(
        self, log_entry: dict, connection_id: Optional[str] = None, parameters: dict = {}
    ):
        """Save an did request doc to the wallet to be witnessed."""
        async with self.profile.session() as session:
            try:
                await session.handle.insert(
                    PENDING_DOCUMENT_TABLE_NAME,
                    log_entry["id"],
                    value_json=log_entry,
                    tags={
                        "connection_id": connection_id or "",
                        "parameters": json.dumps(parameters),
                    },
                )
            except AskarError as e:
                raise WitnessError(f"Error adding pending document: {e}")

    async def get_pending_did_request_docs(self) -> list:
        """Get did request docs that are pending a witness."""
        async with self.profile.session() as session:
            entries = await session.handle.fetch_all(PENDING_DOCUMENT_TABLE_NAME)
            return [entry.value_json for entry in entries]

    async def attest_did_request_doc(self, entry_id: str) -> dict[str, str]:
        """Attest a did request doc."""
        async with self.profile.session() as session:
            entry = await session.handle.fetch(PENDING_DOCUMENT_TABLE_NAME, entry_id)

            if entry is None:
                raise WitnessError("Failed to find pending document.")

            connection_id = entry.tags.get("connection_id")
            document_json = entry.value_json

            proof = document_json.get("proof")
            if not proof:
                raise WitnessError("No proof found in log entry. Cannot witness.")

            proof = proof[0]

            key_alias = create_alias(proof.get("domain"), "witnessKey")

            # Attempt to get the witness key for the domain
            if not await MultikeyManager(session).kid_exists(key_alias):
                # If the key is not found, return an error
                raise WitnessError(
                    f"Witness key not found for alias: {key_alias}. The "
                    "administrator must add the key to the wallet that matches the key on"
                    " the server."
                )

            # If the key is found, perform witness attestation
            witness_key_info = await MultikeyManager(session).from_kid(key_alias)
            witness_key = witness_key_info.get("multikey")

            # Note: The witness key is used as the verification method
            witnessed_document = await DataIntegrityManager(session).add_proof(
                document_json,
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{witness_key}#{witness_key}",
                    expires=proof.get("expires"),
                    domain=proof.get("domain"),
                    challenge=proof.get("challenge"),
                ),
            )

            if not connection_id:
                # Becomes the controller / Avoid circular import
                # NOTE: will have to review this behavior when witness threshold is > 1
                # is supported
                from .controller_manager import ControllerManager

                await ControllerManager(self.profile).finish_registration(
                    entry.value_json, json.loads(entry.tags.get("parameters", "{}"))
                )
            else:
                responder = self.profile.inject(BaseResponder)
                await responder.send(
                    message=WitnessResponse(
                        state=RegistrationState.ATTESTED.value,
                        document=witnessed_document,
                        parameters={},
                    ),
                    connection_id=connection_id,
                )

            await session.handle.remove(PENDING_DOCUMENT_TABLE_NAME, entry_id)

            return {"status": "success", "message": "Witness successful."}

    async def reject_did_request_doc(self, entry_id: str) -> dict[str, str]:
        """Reject a did request doc."""
        async with self.profile.session() as session:
            await session.handle.remove(PENDING_DOCUMENT_TABLE_NAME, entry_id)

        return {"status": "success", "message": "Removed registration."}

    async def get_witness_key(self) -> str:
        """Return the witness key."""
        async with self.profile.session() as session:
            server_url = await get_server_url(self.profile)
            witness_alias = create_alias(server_url_to_domain(server_url), "witnessKey")
            if not await MultikeyManager(session).kid_exists(witness_alias):
                raise WitnessError(f"Witness key [{witness_alias}] not found.")
            witness_key_info = await MultikeyManager(session).from_kid(witness_alias)
            return witness_key_info.get("multikey")

    async def create_invitation(self, alias=None, label=None) -> str:
        """Create a witness invitation."""
        witness_key = await self.get_witness_key()
        if not witness_key:
            raise WitnessError("No active witness key.")
        try:
            invi_rec = await OutOfBandManager(self.profile).create_invitation(
                hs_protos=[
                    HSProto.get("https://didcomm.org/didexchange/1.0"),
                    HSProto.get("https://didcomm.org/didexchange/1.1"),
                ],
                alias=alias,
                my_label=label,
                goal_code="witness-service",
                goal=f"did:key:{witness_key}",
            )
            return invi_rec.serialize()
        except OutOfBandManagerError as e:
            raise WitnessError(e.roll_up)
