"""States and state handling for witness protocols."""

import asyncio
import logging
from enum import Enum
from typing import Optional, Callable, Awaitable, TYPE_CHECKING

from acapy_agent.core.profile import Profile

if TYPE_CHECKING:
    from .events import WitnessEventManager

LOGGER = logging.getLogger(__name__)

WITNESS_WAIT_TIMEOUT_SECONDS = 2


class WitnessingState(Enum):
    """Enum for the attestation state of a DID."""

    SUCCESS = "success"
    PENDING = "pending"
    ATTESTED = "attested"
    POSTED = "posted"
    FINISHED = "finished"


class WitnessingStateHandler:
    """Handles witnessing state transitions using strategy pattern."""

    def __init__(self, profile: Profile, event_manager: "WitnessEventManager"):
        """Initialize the WitnessingStateHandler."""
        self.profile = profile
        self.event_manager = event_manager

    async def handle_attested_state(
        self,
        record_id: str,
        document: dict,
        witness_signature: Optional[dict],
        pending_record_manager,
        document_type: str = "log_entry",
    ) -> Optional[dict]:
        """Handle ATTESTED state.

        Args:
            record_id: The record ID
            document: The document (log entry or attested resource)
            witness_signature: Optional witness signature
            pending_record_manager: Manager for pending records
            document_type: Type of document ("log_entry" or "attested_resource")

        Returns:
            None if record was removed, otherwise should continue processing
        """
        await self.event_manager.fire_attested_event(
            record_id, document, witness_signature, document_type=document_type
        )

        await asyncio.sleep(WITNESS_WAIT_TIMEOUT_SECONDS)
        record_ids = await pending_record_manager.get_pending_record_ids(self.profile)

        if record_id is None or record_id not in record_ids:
            return None

        await pending_record_manager.remove_pending_record_id(self.profile, record_id)
        return {"continue": True}

    async def handle_pending_state(
        self,
        record_id: str,
        document: dict,
        document_type: str = "log_entry",
    ) -> dict:
        """Handle PENDING state.

        Args:
            record_id: The record ID
            document: The document (log entry or attested resource)
            document_type: Type of document ("log_entry" or "attested_resource")

        Returns:
            Dict indicating processing should stop
        """
        await self.event_manager.fire_pending_event(
            record_id, document, document_type=document_type
        )
        return {"stop": True}

    async def handle_success_state(
        self,
        record_id: str,
        document: dict,
        did: str,
        submit_handler: Callable[[dict, Optional[dict]], Awaitable[dict]],
        witness_signature: Optional[dict] = None,
        post_process_handler: Optional[Callable[[str], Awaitable]] = None,
    ) -> dict:
        """Handle SUCCESS/FINISHED state.

        Args:
            record_id: The record ID
            document: The document (log entry or attested resource)
            did: The DID
            submit_handler: Async function to submit the document (e.g., submit_log_entry)
            witness_signature: Optional witness signature
            post_process_handler: Optional async function for post-processing
                (e.g., notify watchers)

        Returns:
            Result from submit_handler
        """
        # Submit the document
        response = await submit_handler(document, witness_signature)

        # Post-process if handler provided
        if post_process_handler:
            await post_process_handler(did)

        # Fire post-attested event
        await self.event_manager.fire_post_attested_event(record_id, did)

        return response

    async def process_state(
        self,
        state: str,
        record_id: Optional[str],
        document: dict,
        witness_signature: Optional[dict],
        pending_record_manager,
        submit_handler: Callable[[dict, Optional[dict]], Awaitable[dict]],
        document_type: str = "log_entry",
        did: Optional[str] = None,
        post_process_handler: Optional[Callable[[str], Awaitable]] = None,
    ) -> Optional[dict]:
        """Process a witnessing state using the appropriate handler.

        Args:
            state: The witnessing state
            record_id: Optional record ID
            document: The document to process
            witness_signature: Optional witness signature
            pending_record_manager: Manager for pending records
            submit_handler: Function to submit the document
            document_type: Type of document ("log_entry" or "attested_resource")
            did: Optional DID (extracted from document if not provided)
            post_process_handler: Optional post-processing handler

        Returns:
            Result from state handler, or None if processing should stop
        """
        # Extract DID if not provided
        if not did:
            did = (
                document.get("state", {}).get("id")
                or document.get("id", "").split("/")[0]
            )

        # Handle PENDING state (early return)
        if state == WitnessingState.PENDING.value:
            result = await self.handle_pending_state(record_id, document, document_type)
            if result.get("stop"):
                return None

        # Handle ATTESTED state
        if state == WitnessingState.ATTESTED.value:
            result = await self.handle_attested_state(
                record_id,
                document,
                witness_signature,
                pending_record_manager,
                document_type,
            )
            if result is None:
                return None

        # Handle SUCCESS/FINISHED state (default)
        if state in (WitnessingState.SUCCESS.value, WitnessingState.FINISHED.value):
            return await self.handle_success_state(
                record_id,
                document,
                did,
                submit_handler,
                witness_signature,
                post_process_handler,
            )

        # For other states or fallback, just submit
        return await submit_handler(document, witness_signature)
