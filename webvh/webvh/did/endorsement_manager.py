"""Module to manage endorsements for a DID."""

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

from .exceptions import EndorsementError
from .messages.endorsement import EndorsementRequest, EndorsementResponse
from .registration_state import RegistrationState
from .utils import (
    get_plugin_settings,
    get_server_info,
    get_url_decoded_domain,
    is_controller,
)

LOGGER = logging.getLogger(__name__)


DOCUMENT_TABLE_NAME = "did_webvh_pending_document"


class EndorsementManager:
    """Class to manage endorsements for a DID."""

    def __init__(self, profile: Profile):
        """Initialize the endorsement manager."""
        self.profile = profile

    async def _get_active_endorser_connection(self) -> Optional[ConnRecord]:
        endorser_alias = get_server_info(self.profile) + "-endorser"
        async with self.profile.session() as session:
            connection_records = await ConnRecord.retrieve_by_alias(
                session, endorser_alias
            )

        active_connections = [
            conn for conn in connection_records if conn.state == "active"
        ]

        if len(active_connections) > 0:
            return active_connections[0]

        return None

    async def endorse_registration_document(
        self,
        controller_secured_document: dict,
        expiration: str,
        domain: str,
        challenge: str,
        parameters: dict,
    ) -> Optional[dict]:
        """Endorse the document with the given parameters."""
        role = get_plugin_settings(self.profile).get("role")
        async with self.profile.session() as session:
            # Self endorsement
            if not role or role == "endorser":
                try:
                    url_decoded_domain = get_url_decoded_domain(domain)

                    key_info_endorser = await MultikeyManager(session).create(
                        kid=url_decoded_domain,
                        alg="ed25519",
                    )
                except (MultikeyManagerError, WalletDuplicateError):
                    key_info_endorser = await MultikeyManager(session).from_kid(
                        url_decoded_domain
                    )
                return await DataIntegrityManager(session).add_proof(
                    controller_secured_document,
                    DataIntegrityProofOptions(
                        type="DataIntegrityProof",
                        cryptosuite="eddsa-jcs-2022",
                        proof_purpose="assertionMethod",
                        verification_method=f"did:key:{key_info_endorser.get('multikey')}#{key_info_endorser.get('multikey')}",
                        expires=expiration,
                        domain=domain,
                        challenge=challenge,
                    ),
                )
            # Need proof from endorser agent
            else:
                responder = self.profile.inject(BaseResponder)

                endorser_connection = await self._get_active_endorser_connection()
                if not endorser_connection:
                    raise EndorsementError("No active endorser connection found.")

                await responder.send(
                    message=EndorsementRequest(controller_secured_document, parameters),
                    connection_id=endorser_connection.connection_id,
                )

    async def auto_endorsement_setup(self) -> None:
        """Automatically set up the endorsement the connection."""
        if not is_controller(self.profile):
            return

        # Get the endorser connection is already set up
        if await self._get_active_endorser_connection():
            LOGGER.info("Connected to endorser from previous connection.")
            return

        endorser_invitation = get_plugin_settings(self.profile).get("endorser_invitation")
        if not endorser_invitation:
            LOGGER.info("No endorser invitation, can't create connection automatically.")
            return

        endorser_alias = get_server_info(self.profile) + "-endorser"
        oob_mgr = OutOfBandManager(self.profile)
        try:
            await oob_mgr.receive_invitation(
                invitation=InvitationMessage.from_url(endorser_invitation),
                auto_accept=True,
                alias=endorser_alias,
            )
        except BaseModelError as err:
            raise EndorsementError(f"Error receiving endorser invitation: {err}")

        for _ in range(5):
            if await self._get_active_endorser_connection():
                LOGGER.info("Connected to endorser agent.")
                return
            await asyncio.sleep(1)

        LOGGER.info(
            "No immediate response when trying to connect to endorser agent. You can "
            f"try manually setting up a connection with alias {endorser_alias} or "
            "restart the agent when endorser is available."
        )

    async def save_log_entry(self, log_entry: dict, connection_id: str = None):
        """Save a log entry to the wallet."""
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
                raise EndorsementError("Endorsement entry already pending.")

    async def get_pending(self) -> list:
        """Save a log entry to the wallet."""
        async with self.profile.session() as session:
            entries = await session.handle.fetch_all(DOCUMENT_TABLE_NAME)
            return [entry.value_json for entry in entries]

    async def endorse_entry(self, entry_id: str) -> dict[str, str]:
        """Endorse a log entry."""
        async with self.profile.session() as session:
            entry = await session.handle.fetch(DOCUMENT_TABLE_NAME, entry_id)

            if entry is None:
                raise EndorsementError("Failed to find pending document.")

            document_json = entry.value_json

            proof = document_json.get("proof")[0]

            domain = proof.get("domain")
            url_decoded_domain = get_url_decoded_domain(domain)

            # Attempt to get the endorsement key for the domain
            if not await MultikeyManager(session).kid_exists(url_decoded_domain):
                # If the key is not found, return an error
                raise EndorsementError(
                    f"Endorsement key not found for domain: {url_decoded_domain}. The "
                    "administrator must add the key to the wallet that matches the key on"
                    " the server."
                )

            # If the key is found, perform endorsement
            endorsement_key_info = await MultikeyManager(session).from_kid(
                url_decoded_domain
            )
            endorsed_document = await DataIntegrityManager(session).add_proof(
                document_json,
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{endorsement_key_info.get('multikey')}#{endorsement_key_info.get('multikey')}",
                    expires=proof.get("expires"),
                    domain=domain,
                    challenge=proof.get("challenge"),
                ),
            )
            responder = self.profile.inject(BaseResponder)
            await responder.send(
                message=EndorsementResponse(
                    document=endorsed_document, state=RegistrationState.POSTED.value
                ),
                connection_id=entry.tags.get("connection_id"),
            )

            await session.handle.remove(DOCUMENT_TABLE_NAME, entry_id)

            return {"status": "success", "message": "Endorsement successful."}
