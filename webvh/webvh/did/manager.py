"""DID Webvh Manager."""

import asyncio
import json
import logging
import re
from uuid import uuid4
from typing import Optional
from operator import itemgetter
import uuid

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.protocols.out_of_band.v1_0.manager import (
    OutOfBandManager,
)
from acapy_agent.protocols.out_of_band.v1_0.messages.invitation import (
    InvitationMessage,
)
from acapy_agent.resolver.did_resolver import DIDResolver
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
    get_server_url,
    get_server_domain,
    get_witnesses,
    is_controller,
    is_witness,
    notify_watchers,
    set_config,
)
from ..protocols.attested_resource.record import PendingAttestedResourceRecord
from ..protocols.log_entry.record import PendingLogEntryRecord
from ..protocols.states import WitnessingState
from .witness import WitnessManager
from .exceptions import DidCreationError, OperationError
from .server_client import WebVHServerClient, WebVHWatcherClient
from .utils import (
    decode_invitation,
    key_hash,
    multikey_to_jwk,
    create_alias,
    url_to_domain,
    create_key,
    find_key,
    find_multikey,
    bind_key,
    unbind_key,
    add_proof,
    verify_proof,
    validate_did,
)

LOGGER = logging.getLogger(__name__)

WEBVH_METHOD = "did:webvh:1.0"
WITNESS_WAIT_TIMEOUT_SECONDS = 2
WITNESS_EVENT = "witness_response::"
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
        self.pending_log_entries = PendingLogEntryRecord()
        self.pending_attested_resource = PendingAttestedResourceRecord()
        self.server_client = WebVHServerClient(self.profile)
        self.watcher_client = WebVHWatcherClient(self.profile)

    async def _get_active_witness_connection(self) -> Optional[ConnRecord]:
        server_url = await get_server_url(self.profile)
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

        return None

    async def _sign_log_entry(self, log_entry):
        did = log_entry.get("state", {}).get("id", None)
        update_key = await find_key(self.profile, f"{did}#updateKey")
        return await add_proof(
            self.profile,
            log_entry,
            f"did:key:{update_key}#{update_key}",
        )

    async def _set_parameters_input(self, placeholder_id, options):
        # Method
        # https://identity.foundation/didwebvh/next/#didwebvh-did-method-parameters
        parameters = {"method": WEBVH_METHOD}

        # Portability
        # https://identity.foundation/didwebvh/next/#did-portability
        if options.get("portable", False):
            parameters["portable"] = True

        # Witness
        # https://identity.foundation/didwebvh/next/#did-witnesses
        if options.get("witnessThreshold", 0):
            parameters["witness"] = {
                "threshold": options.get("witnessThreshold"),
                "witnesses": [
                    {"id": witness} for witness in await get_witnesses(self.profile)
                ],
            }

        # Watchers
        # https://identity.foundation/didwebvh/next/#did-watchers
        if options.get("watchers", []):
            parameters["watchers"] = options.get("watchers")

        # Provision Update Key
        # https://identity.foundation/didwebvh/next/#authorized-keys
        update_key = await create_key(self.profile, f"{placeholder_id}#updateKey")
        parameters["updateKeys"] = [update_key]

        # Provision Rotation Key
        # https://identity.foundation/didwebvh/next/#pre-rotation-key-hash-generation-and-verification
        if options.get("prerotation", False):
            next_key = await create_key(self.profile, f"{placeholder_id}#nextKey")
            parameters["nextKeyHashes"] = [key_hash(next_key)]

        return parameters

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
        scid, domain, namespace, identifier = itemgetter(2, 3, 4, 5)(did.split(":"))
        signing_key = await find_key(self.profile, f"{did}#signingKey")
        async with self.profile.session() as session:
            await session.handle.insert(
                CATEGORY_DID,
                did,
                value_json={
                    "did": did,
                    "verkey": multikey_to_verkey(signing_key) if signing_key else None,
                    "metadata": {
                        "posted": True,
                        "scid": scid,
                        "domain": domain,
                        "namespace": namespace,
                        "identifier": identifier,
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

    async def _fire_pending_event(self, record_id, log_entry):
        event_bus = self.profile.inject(EventBus)
        await event_bus.notify(
            self.profile,
            Event(
                f"{WITNESS_EVENT}{record_id}",
                {
                    "document": log_entry,
                    "metadata": {
                        "state": WitnessingState.PENDING.value,
                    },
                },
            ),
        )

    async def _fire_attested_event(self, record_id, log_entry, witness_signature=None):
        event_bus = self.profile.inject(EventBus)
        await event_bus.notify(
            self.profile,
            Event(
                f"{WITNESS_EVENT}{record_id}",
                {
                    "document": log_entry,
                    "witness_signature": witness_signature,
                    "metadata": {"state": WitnessingState.ATTESTED.value},
                },
            ),
        )

    async def _fire_post_attested_event(self, record_id, did):
        async with self.profile.session() as session:
            resolver = session.inject(DIDResolver)

            resolved_did_doc = (
                await resolver.resolve_with_metadata(self.profile, did)
            ).serialize()

        event_bus = self.profile.inject(EventBus)

        metadata = resolved_did_doc["metadata"]
        metadata["state"] = WitnessingState.ATTESTED.value
        await event_bus.notify(
            self.profile,
            Event(
                f"{WITNESS_EVENT}{record_id}",
                {"document": resolved_did_doc["did_document"], "metadata": metadata},
            ),
        )

    async def _create_preliminary_doc(self, placeholder_id):
        # Create a signing key
        signing_key = await create_key(self.profile)
        public_signing_key_id = f"{placeholder_id}#{signing_key}"
        await bind_key(self.profile, signing_key, f"{placeholder_id}#signingKey")
        await bind_key(self.profile, signing_key, public_signing_key_id)

        # Bind parallel DID
        # https://identity.foundation/didwebvh/next/#publishing-a-parallel-didweb-did
        did_web = placeholder_id.replace(r"did:webvh:{SCID}:", "did:web:")
        await bind_key(self.profile, signing_key, f"{did_web}#{signing_key}")

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
        update_key = await find_key(self.profile, f"{placeholder_id}#updateKey")
        doc_state = DocumentState.initial(
            parameters_input, preliminary_doc, timestamp=timestamp
        )
        initial_log_entry = doc_state.history_line()
        document = initial_log_entry.get("state")
        did = document.get("id")

        await bind_key(self.profile, update_key, f"{did}#updateKey")

        # Update default signing key
        signing_key = await find_key(self.profile, f"{placeholder_id}#signingKey")
        await bind_key(self.profile, signing_key, f"{did}#signingKey")
        await bind_key(self.profile, signing_key, f"{did}#{signing_key}")

        # Update prerotation key
        if parameters_input.get("nextKeyHashes"):
            next_key = await find_key(self.profile, f"{placeholder_id}#nextKey")
            await bind_key(self.profile, next_key, f"{did}#nextKey")

        return initial_log_entry

    async def _wait_for_log_entry(self, record_id: str):
        event_bus = self.profile.inject(EventBus)
        with event_bus.wait_for_event(
            self.profile, re.compile(rf"^{WITNESS_EVENT}{record_id}$")
        ) as await_event:
            event = await await_event
            if (
                event.payload.get("metadata", {}).get("state")
                == WitnessingState.PENDING.value
            ):
                return PENDING_MESSAGE
            else:
                await self.pending_log_entries.remove_pending_record_id(
                    self.profile, record_id
                )
                return await self.finish_did_operation(
                    event.payload.get("document"),
                    event.payload.get("witness_signature", None),
                    state=WitnessingState.FINISHED.value,
                    record_id=record_id,
                )

    async def _wait_for_resource(self, record_id: str):
        event_bus = self.profile.inject(EventBus)
        with event_bus.wait_for_event(
            self.profile, re.compile(rf"^{WITNESS_EVENT}{record_id}$")
        ) as await_event:
            event = await await_event
            if (
                event.payload.get("metadata", {}).get("state")
                == WitnessingState.PENDING.value
            ):
                return PENDING_MESSAGE
            else:
                await self.pending_attested_resource.remove_pending_record_id(
                    self.profile, record_id
                )
                document = event.payload.get("document")
                await self.upload_resource(
                    document, state=WitnessingState.FINISHED.value, record_id=record_id
                )

    async def _apply_config_defaults(self, options: dict, defaults: dict):
        """Apply default parameter options if not overwritten by request.

        options: The user provided did creation options.
        defaults: The default configured options.

        """
        options["portability"] = options.get(
            "portability", defaults.get("portability", False)
        )
        options["prerotation"] = options.get(
            "prerotation", defaults.get("prerotation", False)
        )
        options["witness_threshold"] = options.get(
            "witness_threshold", defaults.get("witness_threshold", 0)
        )
        options["watchers"] = options.get("watchers", defaults.get("watchers", None))
        return options

    async def _apply_policy(self, parameters: dict, options: dict):
        """Apply server policy to did creation options.

        parameters: The parameters object returned by the server,
        based on the configured policies.

        options: The user provided did creation options.

        """
        if parameters.get("witness", {}).get("threshold", 0):
            options["witness_threshold"] = parameters.get("witness").get("threshold")

        if parameters.get("watchers", None):
            options["watchers"] = parameters.get("watchers")

        if parameters.get("portability", False):
            options["portability"] = parameters.get("portability")

        if parameters.get("nextKeyHashes", None) == []:
            options["prerotation"] = True

        return options

    async def configure(self, options: dict) -> dict:
        """Configure did controller and/or witness."""

        config = await get_plugin_config(self.profile)
        config["scids"] = config.get("scids", {})
        config["witnesses"] = config.get("witnesses", [])
        config["witness"] = options.get("witness", False)
        config["endorsement"] = options.get("endorsement", False)
        config["auto_attest"] = options.get("auto_attest", False)
        config["server_url"] = options.get("server_url", config.get("server_url")).rstrip(
            "/"
        )
        config["parameter_options"] = options.get("parameter_options", {})

        if not config.get("server_url"):
            raise OperationError("No server url configured.")

        await set_config(self.profile, config)

        if config.get("witness", False):
            # Create a local witness key to setup self witnessing
            domain = url_to_domain(config["server_url"])
            key_alias = f"webvh:{domain}@witnessKey"
            if options.get("witness_key", None):
                witness_key = await bind_key(
                    self.profile, options.get("witness_key"), key_alias
                )
            else:
                witness_key = await find_key(self.profile, key_alias) or await create_key(
                    self.profile, key_alias
                )
            if not witness_key:
                raise OperationError("Error creating witness key.")

            witness_id = f"did:key:{witness_key}"

        else:
            # Connect to witness service
            witness_id = await self.connect_to_witness(options.get("witness_invitation"))

        if witness_id not in config["witnesses"]:
            config["witnesses"].append(witness_id)

        await set_config(self.profile, config)

        return config

    async def connect_to_witness(self, witness_invitation) -> None:
        """Process witness invitation and connect."""
        if not witness_invitation:
            raise OperationError("No witness invitation provided.")

        try:
            decoded_invitation = decode_invitation(witness_invitation)
        except UnicodeDecodeError:
            raise OperationError("Invalid witness invitation.")

        if (
            not decoded_invitation.get("goal").startswith("did:key:")
            and not decoded_invitation.get("goal-code") == "witness-service"
        ):
            raise OperationError("Missing invitation goal-code and witness did.")

        # Get the witness connection is already set up
        if await self._get_active_witness_connection():
            LOGGER.info("Connected to witness from previous connection.")
            return decoded_invitation.get("goal")

        try:
            server_domain = await get_server_domain(self.profile)
            alias = f"webvh:{server_domain}@witness"
            await OutOfBandManager(self.profile).receive_invitation(
                invitation=InvitationMessage.from_url(witness_invitation),
                auto_accept=True,
                alias=alias,
            )
        except BaseModelError as err:
            raise OperationError(f"Error receiving witness invitation: {err}")

        for _ in range(5):
            if await self._get_active_witness_connection():
                LOGGER.info("Connected to witness agent.")
                return decoded_invitation.get("goal")
            await asyncio.sleep(1)

        LOGGER.info(
            "No immediate response when trying to connect to witness agent. You can "
            f"try manually setting up a connection with alias {alias} or "
            "restart the agent when witness is available."
        )
        return decoded_invitation.get("goal")

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

        config = await get_plugin_config(self.profile)
        options = await self._apply_config_defaults(
            options, config.get("parameter_options", {})
        )

        # Apply provided options & policies to the requested identifier
        if options.get("apply_policy", False):
            options = await self._apply_policy(
                requested_identifier.get("parameters"), options
            )

        # Add a verification method to the initial state document & create preliminary doc
        preliminary_doc = await self._create_preliminary_doc(placeholder_id)

        if options.get("didcomm", False):
            preliminary_doc["service"].append(
                self._create_didcomm_service(preliminary_doc)
            )

        # Create update keys and set parameters
        parameters_input = await self._set_parameters_input(placeholder_id, options)

        # Create and sign initial log entry
        initial_log_entry = await self._create_initial_log_entry(
            preliminary_doc, parameters_input, options.get("version_time", None)
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
            update_key, next_key_hash = await self._rotate_update_key(did)
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
            update_key, next_key_hash = await self._rotate_update_key(did)
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
        scid = itemgetter(2)(did.split(":"))
        document_state = DocumentState.load_history_line(
            log_entry, await self.server_client.fetch_document_state(did)
        )
        witness_signature = None
        if document_state.witness_rule:
            witness_request_id = str(uuid.uuid4())
            witness_signature = await self.witness.witness_log_entry(
                scid, log_entry, witness_request_id
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

        # Process witnessing states
        if state == WitnessingState.ATTESTED.value:
            await self._fire_attested_event(record_id, log_entry, witness_signature)

            await asyncio.sleep(WITNESS_WAIT_TIMEOUT_SECONDS)
            record_ids = await self.pending_log_entries.get_pending_record_ids(
                self.profile
            )

            if record_id is None or record_id not in record_ids:
                return

            await self.pending_log_entries.remove_pending_record_id(
                self.profile, record_id
            )

        if state == WitnessingState.PENDING.value:
            await self._fire_pending_event(log_entry, record_id)
            return

        # Publish log entry
        response_json = await self.server_client.submit_log_entry(
            log_entry, witness_signature
        )

        # Process local did records
        did = log_entry["state"]["id"]
        if log_entry.get("versionId")[0] == "1":
            await self._save_local_did(did)
            await add_scid_mapping(self.profile, did)
        else:
            pass

        await self._fire_post_attested_event(record_id, did)

        # Process watchers
        if await notify_watchers(self.profile):
            watchers = log_entry.get("parameters").get("watchers", [])
            await self.watcher_client.notify_watchers(did, watchers)

        return response_json

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
            await find_multikey(self.profile, multikey)
            if multikey
            else await create_key(self.profile)
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

        await bind_key(multikey, verification_method["id"])
        did_document["verificationMethod"].append(verification_method)
        for relationship in relationships:
            did_document[relationship].append(verification_method["id"])

        return did_document

    async def remove_verification_method(self, scid: str, key_id: str):
        """Remove a verification method."""
        did = await did_from_scid(self.profile, scid)
        key_id = f"{did}#{key_id}"
        multikey = await find_key(self.profile, key_id)
        await unbind_key(self.profile, multikey, key_id)
        return {"status": "ok"}

    async def _rotate_update_key(self, did: str):
        """Pre rotation."""
        next_key_id = f"{did}#nextKey"
        update_key_id = f"{did}#updateKey"

        previous_next_key = await find_key(self.profile, next_key_id)
        previous_update_key = await find_key(self.profile, update_key_id)

        # Unbind previous update key
        await unbind_key(self.profile, previous_update_key, update_key_id)

        # Bind previous next key to new update key
        await bind_key(self.profile, previous_next_key, update_key_id)

        # Unbind previous next key
        await unbind_key(self.profile, previous_next_key, next_key_id)

        # Create and bind new next key
        next_key = await create_key(self.profile, next_key_id)

        # Find new update key
        update_key = await find_key(self.profile, update_key_id)

        return update_key, key_hash(next_key)

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
        if state == WitnessingState.ATTESTED.value:
            event_bus = self.profile.inject(EventBus)
            await event_bus.notify(
                self.profile,
                Event(
                    f"{WITNESS_EVENT}{record_id}",
                    {
                        "document": attested_resource,
                        "metadata": {"state": WitnessingState.ATTESTED.value},
                    },
                ),
            )
            await asyncio.sleep(WITNESS_WAIT_TIMEOUT_SECONDS)
            record_ids = await self.pending_attested_resource.get_pending_record_ids(
                self.profile
            )
            if record_id is None or record_id not in record_ids:
                return
            await self.pending_attested_resource.remove_pending_record_id(
                self.profile, record_id
            )

        if state == WitnessingState.PENDING.value:
            event_bus = self.profile.inject(EventBus)
            await event_bus.notify(
                self.profile,
                Event(
                    f"{WITNESS_EVENT}{record_id}",
                    {
                        "document": attested_resource,
                        "metadata": {
                            "state": WitnessingState.PENDING.value,
                        },
                    },
                ),
            )
            return

        await self.server_client.upload_attested_resource(attested_resource)

    async def auto_witness_setup(self) -> None:
        """Automatically set up the witness the connection."""
        domain = await get_server_domain(self.profile)
        witness_alias = create_alias(domain, "witnessConnection")

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
            raise OperationError(f"Error receiving witness invitation: {err}")

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
