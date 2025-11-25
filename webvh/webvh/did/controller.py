"""DID Webvh Manager."""

import asyncio
import json
import logging
import re
from uuid import uuid4
from typing import Callable, Awaitable
import uuid

from acapy_agent.core.event_bus import EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.askar import CATEGORY_DID
from acapy_agent.wallet.keys.manager import (
    multikey_to_verkey,
    verkey_to_multikey,
)
from did_webvh.core.state import DocumentState

from ..config.config import (
    add_scid_mapping,
    did_from_scid,
    get_plugin_config,
    get_server_domain,
    is_witness,
    notify_watchers,
)
from ..protocols.attested_resource.record import PendingAttestedResourceRecord
from ..protocols.log_entry.record import PendingLogEntryRecord
from ..protocols.states import WitnessingState, WitnessingStateHandler
from .witness import WitnessManager
from ..protocols.events import WitnessEventManager
from .connection import WebVHConnectionManager
from .utils import parse_webvh
from .key_chain import KeyChainManager
from .parameters import ParameterResolver
from .exceptions import DidCreationError
from .server_client import WebVHServerClient, WebVHWatcherClient
from .utils import (
    multikey_to_jwk,
    add_proof,
    verify_proof,
    validate_did,
)

LOGGER = logging.getLogger(__name__)

WITNESS_WAIT_TIMEOUT_SECONDS = 2
PENDING_MESSAGE = {
    "status": WitnessingState.PENDING.value,
    "message": "The witness is pending.",
}


class ControllerManager:
    """DID Webvh Manager class."""

    def __init__(self, profile: Profile) -> None:
        """Initialize the DID Webvh Manager."""
        self.profile = profile
        self.witness = WitnessManager(self.profile)
        self.event_manager = WitnessEventManager(self.profile)
        self.witness_connection = WebVHConnectionManager(self.profile)
        self.key_chain = KeyChainManager(self.profile)
        self.parameter_resolver = ParameterResolver(self.profile)
        self.state_handler = WitnessingStateHandler(self.profile, self.event_manager)
        self.pending_log_entries = PendingLogEntryRecord()
        self.pending_attested_resource = PendingAttestedResourceRecord()
        self.server_client = WebVHServerClient(self.profile)
        self.watcher_client = WebVHWatcherClient(self.profile)

    async def _sign_log_entry(self, log_entry):
        did = log_entry.get("state", {}).get("id", None)
        update_key = await self.key_chain.update_key(did)
        return await add_proof(
            self.profile,
            log_entry,
            f"did:key:{update_key}#{update_key}",
        )

    async def _request_witness_signature(self, request_id):
        if await is_witness(self.profile):
            return PENDING_MESSAGE

        try:
            await self.pending_log_entries.set_pending_record_id(self.profile, request_id)
            return await asyncio.wait_for(
                self._wait_for_log_entry(request_id),
                WITNESS_WAIT_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            return {
                "status": "unknown",
                "message": "No immediate response from witness agent.",
            }

    async def _save_local_did(self, did):
        parsed = parse_webvh(did)
        signing_key = await self.key_chain.signing_key(did)
        async with self.profile.session() as session:
            await session.handle.insert(
                CATEGORY_DID,
                did,
                value_json={
                    "did": did,
                    "verkey": multikey_to_verkey(signing_key) if signing_key else None,
                    "metadata": {
                        "posted": True,
                        "scid": parsed.scid,
                        "domain": parsed.domain,
                        "namespace": parsed.namespace,
                        "identifier": parsed.identifier,
                    },
                    "method": "webvh",
                    "key_type": "ed25519",
                },
                tags={},
            )

    def _create_didcomm_service(self, did_doc):
        did = did_doc.get("id")
        return {
            "id": f"{did}#did-communication",
            "type": "did-communication",
            "serviceEndpoint": self.profile.settings.get("default_endpoint"),
            "recipientKeys": [did_doc.get("authentication", None)[0]],
        }

    async def _create_preliminary_doc(self, placeholder_id):
        # Create a signing key
        signing_key = await self.key_chain.create_key()
        public_signing_key_id = f"{placeholder_id}#{signing_key}"

        # Bind signing key for placeholder DID
        await self.key_chain.bind_key(signing_key, public_signing_key_id)

        # Bind parallel DID
        # https://identity.foundation/didwebvh/next/#publishing-a-parallel-didweb-did
        did_web = placeholder_id.replace(r"did:webvh:{SCID}:", "did:web:")
        await self.key_chain.bind_key(signing_key, f"{did_web}#{signing_key}")

        return {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://www.w3.org/ns/cid/v1",
            ],
            "id": placeholder_id,
            "authentication": [public_signing_key_id],
            "assertionMethod": [public_signing_key_id],
            "verificationMethod": [
                {
                    "type": "Multikey",
                    "id": public_signing_key_id,
                    "controller": placeholder_id,
                    "publicKeyMultibase": signing_key,
                }
            ],
            "service": [],
        }

    async def _create_initial_log_entry(
        self, preliminary_doc, parameters_input, timestamp: str = None
    ):
        # We update the key id's stored during the preliminary log entry processing
        placeholder_id = preliminary_doc.get("id")
        doc_state = DocumentState.initial(
            parameters_input, preliminary_doc, timestamp=timestamp
        )
        initial_log_entry = doc_state.history_line()
        document = initial_log_entry.get("state")
        did = document.get("id")

        # Migrate keys from placeholder DID to final DID
        await self.key_chain.migrate_key(placeholder_id, did, "signingKey")
        await self.key_chain.migrate_key(placeholder_id, did, "updateKey")
        if parameters_input.get("nextKeyHashes"):
            await self.key_chain.migrate_key(placeholder_id, did, "nextKey")

        return initial_log_entry

    async def _wait_for_witness_event(
        self,
        record_id: str,
        pending_record_manager,
        handler: Callable[[dict, str], Awaitable],
    ):
        """Generic method to wait for witness events.

        Args:
            record_id: The record ID to wait for
            pending_record_manager: The pending record manager to use for cleanup
            handler: Async function to call when event is received (not pending)
                    Should accept (event_payload, record_id) and return result

        Returns:
            Result from handler or PENDING_MESSAGE if event is pending
        """
        event_bus = self.profile.inject(EventBus)
        with event_bus.wait_for_event(
            self.profile, re.compile(self.event_manager.get_event_pattern(record_id))
        ) as await_event:
            event = await await_event
            if (
                event.payload.get("metadata", {}).get("state")
                == WitnessingState.PENDING.value
            ):
                return PENDING_MESSAGE
            else:
                await pending_record_manager.remove_pending_record_id(
                    self.profile, record_id
                )
                return await handler(event.payload, record_id)

    async def _wait_for_log_entry(self, record_id: str):
        """Wait for log entry witness event."""

        async def handler(event_payload, record_id):
            return await self.finish_did_operation(
                event_payload.get("document"),
                event_payload.get("witness_signature", None),
                state=WitnessingState.FINISHED.value,
                record_id=record_id,
            )

        return await self._wait_for_witness_event(
            record_id, self.pending_log_entries, handler
        )

    async def _wait_for_resource(self, record_id: str):
        """Wait for resource witness event."""

        async def handler(event_payload, record_id):
            document = event_payload.get("document")
            await self.upload_resource(
                document, state=WitnessingState.FINISHED.value, record_id=record_id
            )

        return await self._wait_for_witness_event(
            record_id, self.pending_attested_resource, handler
        )

    async def configure(self, config: dict) -> dict:
        """Configure did controller.

        This method only stores the configuration. Witness connection setup
        is handled separately via WebVHConnectionManager.setup() or can be
        done lazily when needed.
        """
        # Configuration is already stored by the route handler
        # No need to establish witness connection here
        return config

    async def create(self, options: dict):
        """Create DID and first log entry."""

        # Set default namespace and random identifier if none provided
        domain = await get_server_domain(self.profile)
        namespace = options.get("namespace", "default")
        identifier = options.get("identifier", str(uuid4()))

        # Contact the server to request the identifier
        requested_identifier = await self.server_client.request_identifier(
            namespace, identifier
        )

        # Validate if the returned identifier matches the provided options
        placeholder_id = requested_identifier.get("state", {}).get("id", None)
        if not validate_did(placeholder_id, domain, namespace, identifier):
            raise DidCreationError(f"Server returned invalid did: {placeholder_id}")

        # Resolve parameters (apply defaults, policy, and build parameters dict)
        config = await get_plugin_config(self.profile)
        (
            resolved_options,
            parameters_input,
        ) = await self.parameter_resolver.resolve_and_build(
            placeholder_id=placeholder_id,
            user_options=options,
            config_defaults=config.get("parameter_options", {}),
            server_parameters=requested_identifier.get("parameters"),
            apply_policy=options.get("apply_policy", False),
        )

        # Add a verification method to the initial state document & create preliminary doc
        preliminary_doc = await self._create_preliminary_doc(placeholder_id)

        if resolved_options.get("didcomm", False):
            preliminary_doc["service"].append(
                self._create_didcomm_service(preliminary_doc)
            )

        # Create and sign initial log entry
        initial_log_entry = await self._create_initial_log_entry(
            preliminary_doc, parameters_input, resolved_options.get("version_time", None)
        )
        return await self._sign_log_entry(initial_log_entry)

    async def update(self, scid: str, did_document: dict = None, options: dict = None):
        """Update a Webvh DID."""
        did = await did_from_scid(self.profile, scid)
        document_state = await self.server_client.fetch_document_state(did)

        parameters = document_state.params
        params_update = {}

        # Process prerotation
        if parameters.get("nextKeyHashes"):
            update_key, next_key_hash = await self.key_chain.rotate_update_key(did)
            params_update["updateKeys"] = [update_key]
            params_update["nextKeyHashes"] = [next_key_hash]

        # Create and sign log entry
        new_log_entry = document_state.create_next(
            document=did_document or None, params_update=params_update
        )
        return await self._sign_log_entry(new_log_entry.history_line())

    async def deactivate(self, scid: str, options: dict = None):
        """Create a Webvh DID."""
        did = await did_from_scid(self.profile, scid)
        document_state = await self.server_client.fetch_document_state(did)

        parameters = document_state.params
        params_update = {"deactivated": True}

        # Process prerotation
        if parameters.get("nextKeyHashes"):
            update_key, next_key_hash = await self.key_chain.rotate_update_key(did)
            params_update["nextKeyHashes"] = [next_key_hash]

        log_entry = document_state.create_next(
            {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": document_state.document_id,
            },
            params_update,
        )
        return await self._sign_log_entry(log_entry.history_line())

    async def streamline_did_operation(self, log_entry):
        """Streamline all DID operations."""

        # Process witnessing
        did = log_entry.get("state", {}).get("id", None)
        parsed = parse_webvh(did)
        document_state = DocumentState.load_history_line(
            log_entry, await self.server_client.fetch_document_state(did)
        )
        witness_signature = None
        if document_state.witness_rule:
            witness_request_id = str(uuid.uuid4())
            witness_signature = await self.witness.witness_log_entry(
                parsed.scid, log_entry, witness_request_id
            )

            if not isinstance(witness_signature, dict):
                return await self._request_witness_signature(witness_request_id)

        return await self.finish_did_operation(
            log_entry,
            witness_signature,
            state=WitnessingState.SUCCESS.value,
        )

    async def finish_did_operation(
        self,
        log_entry: dict,
        witness_signature: dict = None,
        state: str = WitnessingState.SUCCESS.value,
        record_id: str = None,
    ):
        """Finish all DID operations."""

        async def submit_handler(document, sig):
            """Submit log entry to server."""
            return await self.server_client.submit_log_entry(document, sig)

        async def post_process_handler(did):
            """Post-process after submission."""
            # Process local did records
            if log_entry.get("versionId")[0] == "1":
                await self._save_local_did(did)
                await add_scid_mapping(self.profile, did)

            # Process watchers
            if await notify_watchers(self.profile):
                watchers = log_entry.get("parameters").get("watchers", [])
                await self.watcher_client.notify_watchers(did, watchers)

        return await self.state_handler.process_state(
            state=state,
            record_id=record_id,
            document=log_entry,
            witness_signature=witness_signature,
            pending_record_manager=self.pending_log_entries,
            submit_handler=submit_handler,
            document_type="log_entry",
            post_process_handler=post_process_handler,
        )

    async def add_verification_method(
        self,
        scid: str,
        key_type: str,
        relationships: list,
        key_id: str = None,
        multikey: str = None,
    ):
        """Add a verification method."""
        async with self.profile.session() as session:
            scid_info = await session.handle.fetch("scid", scid)

        did_document = scid_info.value_json.get("didDocument")
        did = did_document.get("id")
        multikey = (
            await self.key_chain.find_multikey(multikey)
            if multikey
            else await self.key_chain.create_key()
        )
        if key_type == "Multikey":
            verification_method = {
                "type": key_type,
                "id": f"{did}#{key_id}" if key_id else f"{did}#{multikey}",
                "controller": did,
                "publicKeyMultibase": multikey,
            }
        elif key_type == "JsonWebKey":
            jwk, thumbprint = multikey_to_jwk(multikey)
            verification_method = {
                "type": key_type,
                "id": f"{did}#{key_id}" if key_id else f"{did}#{thumbprint}",
                "controller": did,
                "publicKeyJwk": jwk,
            }

        await self.key_chain.bind_verification_method(
            did, verification_method["id"], multikey
        )
        did_document["verificationMethod"].append(verification_method)
        for relationship in relationships:
            did_document[relationship].append(verification_method["id"])

        return did_document

    async def remove_verification_method(self, scid: str, key_id: str):
        """Remove a verification method."""
        did = await did_from_scid(self.profile, scid)
        await self.key_chain.unbind_verification_method(did, key_id)
        return {"status": "ok"}

    async def update_whois(self, scid: str, presentation: dict, options: dict = {}):
        """Update WHOIS linked VP."""

        holder_id = await did_from_scid(self.profile, scid)

        # Overwrite holder_id with controller did
        presentation["holder"] = holder_id

        for credential in presentation.get("verifiableCredential"):
            if credential.get("credentialSubject").get("id") != holder_id:
                # NOTE, should we enforce this?
                pass
                # raise OperationError("Credential subject id doesn't match holder.")

            if not (await verify_proof(self.profile, credential)).verified:
                # NOTE, should we enforce this?
                pass
                # LOGGER.info("Credential verification failed.")
                # LOGGER.info(json.dumps(credential))
                # raise OperationError("Credential verification failed.")

        async with self.profile.session() as session:
            did_info = await session.handle.fetch(CATEGORY_DID, holder_id)

        signing_key = verkey_to_multikey(
            json.loads(did_info.value).get("verkey"), "ed25519"
        )

        vp = await add_proof(
            self.profile, presentation, f"{holder_id}#{signing_key}", "authentication"
        )
        return await self.server_client.submit_whois(vp)

    async def upload_resource(self, attested_resource, state, record_id):
        """Upload an attested resource to the server."""

        async def submit_handler(document, sig):
            """Upload resource to server."""
            await self.server_client.upload_attested_resource(document)
            return {"status": "ok"}

        return await self.state_handler.process_state(
            state=state,
            record_id=record_id,
            document=attested_resource,
            witness_signature=None,
            pending_record_manager=self.pending_attested_resource,
            submit_handler=submit_handler,
            document_type="attested_resource",
        )
