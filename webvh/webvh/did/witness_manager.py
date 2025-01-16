"""Module to manage witnesses for a DID."""

import asyncio
import logging
from typing import Optional

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.protocols.out_of_band.v1_0.manager import OutOfBandManager
from acapy_agent.protocols.out_of_band.v1_0.messages.invitation import InvitationMessage
from acapy_agent.vc.data_integrity.manager import DataIntegrityManager
from acapy_agent.vc.data_integrity.models.options import DataIntegrityProofOptions
from acapy_agent.wallet.error import WalletDuplicateError
from acapy_agent.wallet.keys.manager import (
    MultikeyManager,
    MultikeyManagerError,
)
from aries_askar import AskarError

from .exceptions import WitnessError
from .messages.witness import WitnessRequest, WitnessResponse
from .registration_state import RegistrationState
from .utils import (
    get_plugin_settings,
    get_server_url,
    get_url_decoded_domain,
    is_controller,
)

LOGGER = logging.getLogger(__name__)


DOCUMENT_TABLE_NAME = "did_webvh_pending_document"


class WitnessManager:
    """Class to manage witnesses for a DID."""

    def __init__(self, profile: Profile):
        """Initialize the witness manager."""
        self.profile = profile

    async def _get_active_witness_connection(self) -> Optional[ConnRecord]:
        witness_alias = get_server_url(self.profile) + "@Witness"
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

    async def witness_registration_document(
        self,
        controller_secured_document: dict,
        expiration: str,
        domain: str,
        challenge: str,
        parameters: dict,
    ) -> Optional[dict]:
        """Witness the document with the given parameters."""
        role = get_plugin_settings(self.profile).get("role")
        async with self.profile.session() as session:
            # Self witness
            if not role or role == "witness":
                try:
                    url_decoded_domain = get_url_decoded_domain(domain)

                    witness_key_info = await MultikeyManager(session).create(
                        kid=url_decoded_domain,
                        alg="ed25519",
                    )
                except (MultikeyManagerError, WalletDuplicateError):
                    witness_key_info = await MultikeyManager(session).from_kid(
                        url_decoded_domain
                    )
                return await DataIntegrityManager(session).add_proof(
                    controller_secured_document,
                    DataIntegrityProofOptions(
                        type="DataIntegrityProof",
                        cryptosuite="eddsa-jcs-2022",
                        proof_purpose="assertionMethod",
                        verification_method=f"did:key:{witness_key_info.get('multikey')}#{witness_key_info.get('multikey')}",
                        expires=expiration,
                        domain=domain,
                        challenge=challenge,
                    ),
                )
            # Need proof from witness agent
            else:
                responder = self.profile.inject(BaseResponder)

                witness_connection = await self._get_active_witness_connection()
                if not witness_connection:
                    raise WitnessError("No active witness connection found.")

                await responder.send(
                    message=WitnessRequest(controller_secured_document, parameters),
                    connection_id=witness_connection.connection_id,
                )

    async def auto_witness_setup(self) -> None:
        """Automatically set up the witness the connection."""
        if not is_controller(self.profile):
            return

        # Get the witness connection is already set up
        if await self._get_active_witness_connection():
            LOGGER.info("Connected to witness from previous connection.")
            return

        witness_invitation = get_plugin_settings(self.profile).get("witness_invitation")
        if not witness_invitation:
            LOGGER.info("No witness invitation, can't create connection automatically.")
            return

        witness_alias = get_server_url(self.profile) + "@Witness"
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
        self, log_entry: dict, connection_id: str = None
    ):
        """Save an did request doc to the wallet to be witnessed."""
        async with self.profile.session() as session:
            try:
                await session.handle.insert(
                    DOCUMENT_TABLE_NAME,
                    log_entry["id"],
                    value_json=log_entry,
                    tags={
                        "connection_id": connection_id,
                    },
                )
            except AskarError:
                raise WitnessError("log entry already pending a witness.")

    async def get_pending_did_request_docs(self) -> list:
        """Get did request docs that are pending a witness."""
        async with self.profile.session() as session:
            entries = await session.handle.fetch_all(DOCUMENT_TABLE_NAME)
            return [entry.value_json for entry in entries]

    async def attest_did_request_doc(self, entry_id: str) -> dict[str, str]:
        """Attest a did request doc."""
        async with self.profile.session() as session:
            entry = await session.handle.fetch(DOCUMENT_TABLE_NAME, entry_id)

            if entry is None:
                raise WitnessError("Failed to find pending document.")

            document_json = entry.value_json

            proof = document_json.get("proof")[0]

            domain = proof.get("domain")
            url_decoded_domain = get_url_decoded_domain(domain)

            # Attempt to get the witness key for the domain
            if not await MultikeyManager(session).kid_exists(url_decoded_domain):
                # If the key is not found, return an error
                raise WitnessError(
                    f"Witness key not found for domain: {url_decoded_domain}. The "
                    "administrator must add the key to the wallet that matches the key on"
                    " the server."
                )

            # If the key is found, perform witness attestation
            witness_key_info = await MultikeyManager(session).from_kid(url_decoded_domain)
            witnessed_document = await DataIntegrityManager(session).add_proof(
                document_json,
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{witness_key_info.get('multikey')}#{witness_key_info.get('multikey')}",
                    expires=proof.get("expires"),
                    domain=domain,
                    challenge=proof.get("challenge"),
                ),
            )
            responder = self.profile.inject(BaseResponder)
            await responder.send(
                message=WitnessResponse(
                    document=witnessed_document, state=RegistrationState.POSTED.value
                ),
                connection_id=entry.tags.get("connection_id"),
            )

            await session.handle.remove(DOCUMENT_TABLE_NAME, entry_id)

            return {"status": "success", "message": "Witness successful."}
