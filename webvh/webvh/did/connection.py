"""WebVH Connection Manager for handling WebVH connection lifecycle."""

import asyncio
import logging
from typing import Optional

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.protocols.out_of_band.v1_0.manager import (
    OutOfBandManager,
    OutOfBandManagerError,
)
from acapy_agent.protocols.out_of_band.v1_0.messages.invitation import HSProto

from ..config.config import (
    get_plugin_config,
    get_server_domain,
    get_server_url,
    is_controller,
    set_config,
)
from .exceptions import ConfigurationError, OperationError, WitnessError
from .server_client import WebVHServerClient
from .utils import create_alias, url_to_domain

LOGGER = logging.getLogger(__name__)

CONNECTION_WAIT_RETRIES = 5
CONNECTION_WAIT_INTERVAL_SECONDS = 1


class WebVHConnectionManager:
    """Manages WebVH connection lifecycle for controllers."""

    def __init__(self, profile: Profile):
        """Initialize the WebVHConnectionManager with a profile."""
        self.profile = profile

    def _get_connection_alias(self) -> str:
        """Get the witness connection alias for this controller.

        Returns:
            The connection alias string (e.g., "webvh:example.com@witness")
        """
        # This will be called after server_url is configured,
        # so we can get it synchronously
        # For async operations, use get_active_connection() which handles this properly
        try:
            # Try to get server_url from settings synchronously
            config = self.profile.settings.get("plugin_config", {}).get("webvh", {})
            server_url = config.get("server_url")
            if server_url:
                domain = url_to_domain(server_url)
                return create_alias(domain, "witnessConnection")
        except Exception:
            pass
        # Fallback - will be resolved async in get_active_connection
        return "webvh:unknown@witness"

    async def get_active_connection(
        self, auto_connect: bool = False
    ) -> Optional[ConnRecord]:
        """Get an active witness connection if one exists.

        Args:
            auto_connect: If True, attempt to establish connection
                if not already connected

        Returns:
            An active ConnRecord if found, None otherwise
        """
        try:
            server_url = await get_server_url(self.profile)
        except ConfigurationError:
            # No server_url configured yet, so no active connection possible
            return None

        witness_alias = create_alias(url_to_domain(server_url), "witnessConnection")
        async with self.profile.session() as session:
            connection_records = await ConnRecord.retrieve_by_alias(
                session, witness_alias
            )

        active_connections = [
            conn for conn in connection_records if conn.state == "active"
        ]

        if len(active_connections) > 0:
            return active_connections[0]

        # Attempt to connect if requested and no active connection found
        if auto_connect:
            try:
                await self.connect()
                # Try again after connecting
                async with self.profile.session() as session:
                    connection_records = await ConnRecord.retrieve_by_alias(
                        session, witness_alias
                    )
                active_connections = [
                    conn for conn in connection_records if conn.state == "active"
                ]
                if len(active_connections) > 0:
                    return active_connections[0]
            except (ConfigurationError, OperationError) as err:
                LOGGER.debug("Failed to auto-connect to witness: %s", err)

        return None

    async def connect(
        self,
        witness_id: str = None,
        wait_for_connection: bool = True,
        max_retries: int = CONNECTION_WAIT_RETRIES,
        retry_interval: float = CONNECTION_WAIT_INTERVAL_SECONDS,
    ) -> str:
        """Connect to a witness service.

        This method:
        1. Gets witness_id from config if not provided
        2. Fetches the witness invitation from the server
        3. Validates the invitation
        4. Checks if already connected
        5. Receives the invitation and establishes connection
        6. Optionally waits for the connection to become active

        Args:
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
            ConfigurationError: If witness_id is not configured
        """
        # Get witness_id from config if not provided
        if witness_id is None:
            config = await get_plugin_config(self.profile)
            witness_id = config.get("witness_id")
            if not witness_id:
                raise ConfigurationError(
                    "No witness_id configured. Cannot connect to witness."
                )

        # Fetch invitation from server
        server_client = WebVHServerClient(self.profile)
        invitation = await server_client.get_witness_invitation(witness_id)

        if not invitation:
            raise OperationError(f"Witness {witness_id} not listed by server document.")

        # Validate invitation
        if invitation.get("goal-code", None) != "witness-service":
            raise OperationError("Missing invitation goal-code and witness did.")

        if invitation.get("goal", None) != witness_id:
            raise OperationError("Wrong invitation goal must match witness id.")

        # Check if already connected
        if await self.get_active_connection():
            LOGGER.info("Connected to witness from previous connection.")
            return witness_id

        # Receive invitation and establish connection
        try:
            server_domain = await get_server_domain(self.profile)
            witness_alias = f"webvh:{server_domain}@witness"
            await OutOfBandManager(self.profile).receive_invitation(
                invitation=invitation,
                auto_accept=True,
                alias=witness_alias,
            )
        except BaseModelError as err:
            raise OperationError(f"Error receiving witness invitation: {err}")

        # Wait for connection to become active (if requested)
        if wait_for_connection:
            for attempt in range(max_retries):
                if await self.get_active_connection():
                    LOGGER.info("Connected to witness agent.")
                    return witness_id
                await asyncio.sleep(retry_interval)

            LOGGER.info(
                "No immediate response when trying to connect to witness agent. You can "
                f"try manually setting up a connection with alias {witness_alias} or "
                "restart the agent when witness is available."
            )

        return witness_id

    async def setup(
        self,
        config: dict = None,
        update_config: bool = False,
        require_controller: bool = True,
    ) -> Optional[str]:
        """Set up witness connection with unified logic.

        Args:
            config: Optional configuration dict. If not provided,
                will be fetched from profile.
            update_config: If True, update config to add witness_id to witnesses list
            require_controller: If True, only proceed if agent is configured as controller

        Returns:
            The witness_id that was connected to, or None if setup was skipped

        Raises:
            ConfigurationError: If no server_url is configured
        """
        # Check if controller (if required)
        if require_controller and not await is_controller(self.profile):
            return None

        # Get configuration
        if config is None:
            config = await get_plugin_config(self.profile)

        if not config.get("server_url"):
            if require_controller:
                raise ConfigurationError("No server url configured.")
            return None

        witness_id = config.get("witness_id")

        if not witness_id:
            LOGGER.info("No witness identifier, can't create connection automatically.")
            return None

        # Check if already connected
        already_connected = await self.get_active_connection()
        if already_connected:
            LOGGER.info("Connected to witness from previous connection.")
        else:
            # Attempt to connect
            try:
                await self.connect(witness_id)
            except OperationError as err:
                LOGGER.info("Witness connection setup failed: %s", err)
                return None

        # Update config if requested (regardless of connection status)
        if update_config:
            if witness_id not in config.get("witnesses", []):
                config.setdefault("witnesses", []).append(witness_id)
                await set_config(self.profile, config)

        return witness_id

    async def create_witness_invitation(
        self,
        witness_key: str,
        alias: str = None,
        label: str = None,
        multi_use: bool = False,
    ) -> dict:
        """Create a witness invitation for controllers to connect.

        Args:
            witness_key: The witness key multikey
            alias: Optional alias for the invitation
            label: Optional label for the witness service
            multi_use: Whether the invitation can be used multiple times

        Returns:
            Dictionary containing the invitation (with invitation_url key)

        Raises:
            WitnessError: If invitation creation fails
        """
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
                multi_use=multi_use,
            )
            return invi_rec.serialize()
        except OutOfBandManagerError as e:
            raise WitnessError(e)

    @staticmethod
    def extract_invitation_url(invitation_record) -> str:
        """Extract invitation URL from invitation record.

        Args:
            invitation_record: Invitation record (dict or object)

        Returns:
            The invitation URL, or None if not found
        """
        if isinstance(invitation_record, dict):
            return invitation_record.get("invitation_url")
        return getattr(invitation_record, "invitation_url", None)

    @staticmethod
    def format_invitation_url(invitation_url: str) -> str:
        """Convert HTTP invitation URL to didcomm:// format if needed.

        Args:
            invitation_url: The invitation URL (may be HTTP or didcomm format)

        Returns:
            The formatted invitation URL (didcomm:// format if HTTP, otherwise unchanged)
        """
        if invitation_url and invitation_url.startswith("http"):
            from urllib.parse import urlparse, parse_qs

            parsed = urlparse(invitation_url)
            query = parse_qs(parsed.query)
            if "oob" in query:
                oob_param = query["oob"][0]
                return f"didcomm://?oob={oob_param}"
        return invitation_url
