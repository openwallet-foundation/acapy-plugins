"""WebVH Connection Manager for handling WebVH connection lifecycle."""

import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.core.profile import Profile
from acapy_agent.did.did_key import DIDKey
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.protocols.out_of_band.v1_0.manager import (
    OutOfBandManager,
    OutOfBandManagerError,
)
from acapy_agent.protocols.out_of_band.v1_0.models.invitation import InvitationRecord
from acapy_agent.protocols.out_of_band.v1_0.models.oob_record import OobRecord
from acapy_agent.protocols.out_of_band.v1_0.messages.invitation import (
    HSProto,
    InvitationMessage,
)
from acapy_agent.storage.error import StorageNotFoundError

from ..config.config import (
    get_plugin_config,
    get_server_url,
)
from .exceptions import ConfigurationError, OperationError, WitnessError
from .server_client import WebVHServerClient
from .utils import parse_did_key

LOGGER = logging.getLogger(__name__)

CONNECTION_WAIT_RETRIES = 5
CONNECTION_WAIT_INTERVAL_SECONDS = 1


class WebVHConnectionManager:
    """Manages WebVH connection lifecycle for controllers."""

    def __init__(self, profile: Profile):
        """Initialize the WebVHConnectionManager with a profile."""
        self.profile = profile

    async def get_active_connection(
        self,
        server_url: str = None,
        witness_id: str = None,
    ) -> Optional[ConnRecord]:
        """Get an active witness connection if one exists.

        Args:
            server_url: Server URL to get connection for.
                If not provided, will be fetched from config.
            witness_id: Optional witness_id to get connection for.
                If not provided, will be fetched from config.

        Returns:
            An active ConnRecord if found, None otherwise
        """
        # Get server_url if not provided
        if server_url is None:
            try:
                server_url = await get_server_url(self.profile)
            except ConfigurationError:
                # No server_url configured yet, so no active connection possible
                return None

        # Get witness_id if not provided
        if witness_id is None:
            config = await get_plugin_config(self.profile)
            witness_id = config.get("witness_id")

        # witness_id is required
        if not witness_id:
            raise ConfigurationError("witness_id is required for witness connections")

        # Build alias with witness_id
        parsed_key = parse_did_key(witness_id)
        witness_key = parsed_key.key
        # Extract domain from server_url
        domain = urlparse(server_url).netloc
        witness_alias = f"webvh:{domain}@{witness_key}"
        LOGGER.debug(f"Looking for active connection with alias: {witness_alias}")
        async with self.profile.session() as session:
            connection_records = await ConnRecord.retrieve_by_alias(
                session, witness_alias
            )

        active_connections = [
            conn for conn in connection_records if conn.state == "active"
        ]

        if len(active_connections) > 0:
            LOGGER.info(
                f"Found active connection to witness {witness_id} "
                f"(connection_id: {active_connections[0].connection_id})"
            )
            return active_connections[0]

        LOGGER.debug(f"No active connection found for witness {witness_id}")
        return None

    async def connect(
        self,
        server_url: str = None,
        witness_id: str = None,
        wait_for_connection: bool = True,
        max_retries: int = CONNECTION_WAIT_RETRIES,
        retry_interval: float = CONNECTION_WAIT_INTERVAL_SECONDS,
    ) -> str:
        """Connect to a witness service.

        This method:
        1. Gets server_url and witness_id from config if not provided
        2. Fetches the witness invitation from the server
        3. Validates the invitation
        4. Checks if already connected
        5. Receives the invitation and establishes connection
        6. Optionally waits for the connection to become active

        Args:
            server_url: Optional server URL. If not provided, will be fetched from config
            witness_id: Optional DID of the witness service (e.g., "did:key:...")
                       If not provided, will be fetched from config
            wait_for_connection: If True, wait for connection to become active
            max_retries: Maximum number of retries when waiting for connection
            retry_interval: Seconds to wait between retries

        Returns:
            The witness_id that was connected to

        Raises:
            OperationError: If witness is not found, invitation is invalid,
                or connection fails
            ConfigurationError: If server_url or witness_id is not configured
        """
        # Get server_url from config if not provided
        if server_url is None:
            server_url = await get_server_url(self.profile)

        # Get witness_id from config if not provided
        if witness_id is None:
            config = await get_plugin_config(self.profile)
            witness_id = config.get("witness_id")
            if not witness_id:
                raise ConfigurationError(
                    "No witness_id configured. Cannot connect to witness."
                )

        # Fetch invitation from server
        LOGGER.info(
            f"Fetching witness invitation for {witness_id} from server {server_url}"
        )
        server_client = WebVHServerClient(self.profile)
        try:
            invitation = await server_client.get_witness_invitation(witness_id)
        except Exception as e:
            LOGGER.error(f"Failed to fetch witness invitation: {e}")
            raise

        if not invitation:
            raise OperationError(f"Witness {witness_id} not listed by server document.")

        LOGGER.info(f"Received invitation: {invitation.get('@id', 'unknown id')}")

        # Validate invitation
        if invitation.get("goal_code", None) != "witness-service":
            raise OperationError("Missing invitation goal-code and witness did.")

        if invitation.get("goal", None) != witness_id:
            raise OperationError("Wrong invitation goal must match witness id.")

        # Check if already connected
        if await self.get_active_connection(server_url=server_url, witness_id=witness_id):
            LOGGER.info("Connected to witness from previous connection.")
            return witness_id

        # Receive invitation and establish connection
        try:
            # Extract key from witness_id for alias
            parsed_key = parse_did_key(witness_id)
            witness_key = parsed_key.key
            # Extract domain from server_url
            domain = urlparse(server_url).netloc
            witness_alias = f"webvh:{domain}@{witness_key}"
            LOGGER.info(f"Receiving invitation with alias: {witness_alias}")
            await OutOfBandManager(self.profile).receive_invitation(
                invitation=InvitationMessage.deserialize(invitation),
                auto_accept=True,
                alias=witness_alias,
            )
            LOGGER.info("Invitation received successfully, waiting for connection...")
        except BaseModelError as err:
            LOGGER.error(f"Error receiving witness invitation: {err}")
            raise OperationError(f"Error receiving witness invitation: {err}")

        # Wait for connection to become active (if requested)
        if wait_for_connection:
            for attempt in range(max_retries):
                if await self.get_active_connection(
                    server_url=server_url, witness_id=witness_id
                ):
                    LOGGER.info("Connected to witness agent.")
                    return witness_id
                await asyncio.sleep(retry_interval)

            LOGGER.info(
                "No immediate response when trying to connect to witness agent. You can "
                f"try manually setting up a connection with alias {witness_alias} or "
                "restart the agent when witness is available."
            )

        return witness_id

    async def create_witness_invitation(
        self,
        witness_id: str,
        alias: str = None,
        label: str = None,
        multi_use: bool = False,
    ) -> dict:
        """Create a witness invitation for controllers to connect.

        Args:
            witness_id: The witness DID (e.g., "did:key:...")
            alias: Optional alias for the invitation
            label: Optional label for the witness service
            multi_use: Whether the invitation can be used multiple times

        Returns:
            Dictionary containing the invitation (with invitation_url key)

        Raises:
            WitnessError: If invitation creation fails
        """
        # Get current ACA-Py endpoint to compare with existing invitation endpoint
        current_endpoint = self.profile.settings.get("default_endpoint")

        # Check if there's already an existing invitation for this witness
        # Goal is stored in the invitation message, not as a tag, so we need to
        # query all OOB records and filter by checking invitation.goal and serviceEndpoint
        async with self.profile.session() as session:
            # Query all OOB records (we'll filter by goal and endpoint in the invitation message)
            oob_records = await OobRecord.query(
                session,
                tag_filter={"role": OobRecord.ROLE_SENDER},
            )

            # Find an OOB record with matching goal and endpoint
            from acapy_agent.protocols.out_of_band.v1_0.messages.service import Service
            for oob_rec in oob_records:
                invitation_msg = oob_rec.invitation
                if not invitation_msg:
                    continue
                
                # Check if goal matches
                if invitation_msg.goal != witness_id:
                    continue
                
                # Check if serviceEndpoint matches current endpoint
                if not current_endpoint:
                    continue
                
                # Find first Service object with service_endpoint
                existing_endpoint = None
                if invitation_msg.services:
                    for service_item in invitation_msg.services:
                        if isinstance(service_item, Service) and service_item.service_endpoint:
                            existing_endpoint = service_item.service_endpoint
                            break
                
                # Must have matching endpoint to reuse
                if existing_endpoint != current_endpoint:
                    continue
                
                # Found matching invitation with correct goal and endpoint
                invitation_url = invitation_msg.to_url()
                invi_rec = InvitationRecord(
                    invitation_id=oob_rec.oob_id,
                    state=InvitationRecord.STATE_AWAIT_RESPONSE,
                    invi_msg_id=oob_rec.invi_msg_id,
                    invitation=invitation_msg,
                    invitation_url=invitation_url,
                    oob_id=oob_rec.oob_id,
                )
                LOGGER.info(
                    f"Reusing existing invitation for witness "
                    f"{witness_id} (oob_id: {oob_rec.oob_id})"
                )
                return invi_rec.serialize()

        # Create new invitation if none found or endpoint changed
        try:
            invi_rec = await OutOfBandManager(self.profile).create_invitation(
                hs_protos=[
                    HSProto.get("https://didcomm.org/didexchange/1.0"),
                    HSProto.get("https://didcomm.org/didexchange/1.1"),
                ],
                alias=alias,
                my_label=label,
                goal_code="witness-service",
                goal=witness_id,
                multi_use=multi_use,
                # Don't use use_did - it requires services which did:key doesn't have
            )

            return invi_rec.serialize()
        except OutOfBandManagerError as e:
            raise WitnessError(e)
