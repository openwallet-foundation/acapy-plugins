"""DID Webvh Manager."""

import asyncio
import copy
import json
import logging
import re
from datetime import datetime, timezone
from uuid import uuid4
from typing import Optional

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
from acapy_agent.vc.data_integrity.manager import DataIntegrityManager
from acapy_agent.vc.data_integrity.models.options import DataIntegrityProofOptions
from acapy_agent.wallet.askar import CATEGORY_DID
from acapy_agent.wallet.keys.manager import (
    MultikeyManager,
    MultikeyManagerError,
    multikey_to_verkey,
    verkey_to_multikey,
)
from aiohttp import ClientResponseError
from did_webvh.core.state import DocumentState
from pydid import DIDDocument

from ..config.config import (
    add_scid_mapping,
    did_from_scid,
    get_plugin_config,
    get_server_url,
    get_witnesses,
    notify_watchers,
    set_config,
)
from .exceptions import DidCreationError, OperationError
from .registration_state import RegistrationState
from .server_client import WebVHServerClient, WebVHWatcherClient
from .utils import (
    all_are_not_none,
    decode_invitation,
    get_namespace_and_identifier_from_did,
    key_hash,
    multikey_to_jwk,
    create_alias,
    server_url_to_domain
)
from .witness_manager import WitnessManager
from .witness_queue import PendingRegistrations

LOGGER = logging.getLogger(__name__)

WEBVH_METHOD = "did:webvh:1.0"
WITNESS_WAIT_TIMEOUT_SECONDS = 2
WITNESS_EVENT = "witness_response::"
PENDING_MESSAGE = {
    "status": RegistrationState.PENDING.value,
    "message": "The witness is pending.",
}


class ControllerManager:
    """DID Webvh Manager class."""

    def __init__(self, profile: Profile) -> None:
        """Initialize the DID Webvh Manager."""
        self.profile = profile
        self.server_client = WebVHServerClient(profile)
        self.watcher_client = WebVHWatcherClient(profile)

    async def _get_or_create_key(self, key_alias):
        async with self.profile.session() as session:
            key_manager = MultikeyManager(session)
            try:
                key_info = await key_manager.create(alg="ed25519", kid=key_alias)
            except MultikeyManagerError:
                key_info = await key_manager.from_kid(key_alias)

        return key_info

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

    async def _create_parameters_input(self, options, placeholder_id):
        # Creating the input parameters
        parameters = {
            "method": WEBVH_METHOD,
            "portable": options.get("portable", False)
        }

        # Witness
        if options.get("witnessThreshold"):
            parameters["witness"] = {
                "threshold": options.get("witnessThreshold"),
                "witnesses": [
                    {"id": witness} for witness in await get_witnesses(self.profile)
                ],
            }

        # Watchers
        if options.get("watchers"):
            parameters["watchers"] = options.get("watchers")

        # Key provisioning
        async with self.profile.session() as session:
            key_manager = MultikeyManager(session)
            
            # Update Key
            update_key = (
                await key_manager.create(
                    alg="ed25519", 
                    kid=f"{placeholder_id}#updateKey"
                )
            ).get("multikey")
            parameters["updateKeys"] = [update_key]
            
            # Next Key
            if options.get("prerotation", None):
                next_key = (
                    await key_manager.create(
                        alg="ed25519",
                        kid=f"{placeholder_id}#nextKey"
                    )
                ).get("multikey")
                parameters["nextKeyHashes"] = [key_hash(next_key)]
                
        return parameters

    async def _create_preliminary_doc(self, placeholder_id):
        
        # Create a signing key
        async with self.profile.session() as session:
            key_manager = MultikeyManager(session)
            
            signing_key = (await key_manager.create(alg="ed25519")).get("multikey")
            signing_key_id = f"{placeholder_id}#{signing_key}"
            
            # Bind parralel DID
            web_did = placeholder_id.replace(r'did:webvh:{SCID}:', 'did:web:')
            await key_manager.update(kid=f"{web_did}#{signing_key}", multikey=signing_key)
        
        return {
            '@context': [
                "https://www.w3.org/ns/did/v1",
                "https://www.w3.org/ns/cid/v1",
            ],
            'id': placeholder_id,
            'authentication': [signing_key_id],
            'assertionMethod': [signing_key_id],
            'verificationMethod': [
                {
                    "type": "Multikey",
                    "id": signing_key_id,
                    "controller": placeholder_id,
                    "publicKeyMultibase": signing_key,
                }
            ]
        }

    async def _create_initial_log_entry(self, parameters, preliminary_doc):
        placeholder_id = preliminary_doc.get('id')
        doc_state = DocumentState.initial(
            parameters,
            preliminary_doc,
        )
        update_key = doc_state.update_keys[0]
        signing_key = doc_state.document['verificationMethod'][0]['publicKeyMultibase']
        async with self.profile.session() as session:
            
            di_manager = DataIntegrityManager(session)
            initial_log_entry = await di_manager.add_proof(
                doc_state.history_line(),
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{update_key}#{update_key}",
                ),
            )
            did = initial_log_entry.get('state').get('id')
            
            key_manager = MultikeyManager(session)
            
            if parameters.get('nextKeyHashes'):
                next_key = await key_manager.from_kid(kid=f"{placeholder_id}#nextKey")
                await key_manager.update(kid=f"{did}#nextKey", multikey=next_key)
                
            await key_manager.update(kid=f"{did}#updateKey", multikey=update_key)
            await key_manager.update(kid=f"{did}#{signing_key}", multikey=signing_key)

        return initial_log_entry

    async def _wait_for_witness(self, scid: str):
        event_bus = self.profile.inject(EventBus)
        with event_bus.wait_for_event(
            self.profile, re.compile(rf"^{WITNESS_EVENT}{scid}$")
        ) as await_event:
            event = await await_event
            if (
                event.payload.get("metadata", {}).get("state")
                == RegistrationState.PENDING.value
            ):
                return PENDING_MESSAGE
            else:
                await PendingRegistrations().remove_pending_scid(self.profile, scid)
                return await self.finish_create(
                    event.payload.get("document"),
                    state=RegistrationState.FINISHED.value,
                )


    async def configure(self, server_url, witness_invitation) -> None:
        """Configure controller."""
        config = await get_plugin_config(self.profile)
        config["role"] = "controller"
        
        if not witness_invitation:
            raise OperationError("No witness invitation provided.")
        
        try:
            decoded_invitation = decode_invitation(witness_invitation)
        except UnicodeDecodeError:
            raise OperationError("Invalid witness invitation.")

        witness_id = decoded_invitation.get("goal")
        if (
            not witness_id.startswith("did:key:")
            and not decoded_invitation.get("goal-code") == "witness-service"
        ):
            raise OperationError("Missing invitation goal-code and witness did.")
        
        witness_alias = create_alias(
            server_url_to_domain(server_url), "witnessConnection"
        )
        await self.connect_to_witness(witness_alias, witness_invitation)

        if witness_id not in config["witnesses"]:
            config["witnesses"].append(witness_id)
            
        await set_config(self.profile, config)
        return {"status": "success"}
            


    async def connect_to_witness(self, alias, invitation) -> None:
        """Process witness invitation and connect."""
        
        # Get the witness connection is already set up
        if await self._get_active_witness_connection():
            LOGGER.info("Connected to witness from previous connection.")
            return
        
        try:
            await OutOfBandManager(self.profile).receive_invitation(
                invitation=InvitationMessage.from_url(invitation),
                auto_accept=True,
                alias=alias,
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
            f"try manually setting up a connection with alias {alias} or "
            "restart the agent when witness is available."
        )
        

    async def create(self, options: dict):
        """Create DID and first log entry."""

        # Set default namespace and random identifier if none provided
        namespace = options.get("namespace", "default")
        identifier = options.get("identifier", str(uuid4()))

        # Contact the server to request the identifier
        input_doc = await self.server_client.request_identifier(
            namespace, identifier
        )
        
        placeholder_id = input_doc.get("state").get("id")
            
        parameters_input = await self._create_parameters_input(options, placeholder_id)
        preliminary_doc = await self._create_preliminary_doc(placeholder_id)
        initial_log_entry = await self._create_initial_log_entry(
            parameters_input, 
            preliminary_doc
        )
        
        scid = initial_log_entry.get('parameters').get('scid')
        witness_signature = None
        if initial_log_entry.get('parameters').get('witness', None):
            witness_signature = await WitnessManager(self.profile).witness_log_entry(
                scid,
                initial_log_entry
            )

            if not isinstance(witness_signature, dict):
            
                if (await get_plugin_config(self.profile)).get("role") == "witness":
                    return PENDING_MESSAGE

                try:
                    await PendingRegistrations().set_pending_log_entry(self.profile, scid)
                    return await asyncio.wait_for(
                        self._wait_for_witness(scid),
                        WITNESS_WAIT_TIMEOUT_SECONDS,
                    )
                except asyncio.TimeoutError:
                    return {
                        "status": "unknown",
                        "message": "No immediate response from witness agent.",
                    }

        return await self.finish_create(
            initial_log_entry,
            witness_signature,
            state=RegistrationState.SUCCESS.value,
        )

        
    async def finish_create(
        self,
        initial_log_entry: dict,
        witness_signature: dict = None,
        state: str = RegistrationState.SUCCESS.value,
    ):
        """Finish the registration of the DID."""
        did_state = initial_log_entry["state"]
        did = did_state["id"]
        scid = did.split(":")[2]
        namespace = did.split(":")[4]
        identifier = did.split(":")[5]
        
        if state == RegistrationState.ATTESTED.value:
            event_bus = self.profile.inject(EventBus)
            await event_bus.notify(
                self.profile,
                Event(
                    f"{WITNESS_EVENT}{scid}",
                    {
                        "document": initial_log_entry,
                        "metadata": {
                            "state": RegistrationState.ATTESTED.value
                        },
                    },
                ),
            )
            await asyncio.sleep(WITNESS_WAIT_TIMEOUT_SECONDS)
            if scid not in await PendingRegistrations().get_pending_scids(self.profile):
                return
            await PendingRegistrations().remove_pending_scid(self.profile, scid)

        if state == RegistrationState.PENDING.value:
            event_bus = self.profile.inject(EventBus)
            await event_bus.notify(
                self.profile,
                Event(
                    f"{WITNESS_EVENT}{scid}",
                    {
                        "document": initial_log_entry,
                        "metadata": {
                            "state": RegistrationState.PENDING.value,
                        },
                    },
                ),
            )
            return

        response_json = await self.server_client.submit_log_entry(
            initial_log_entry,
            witness_signature,
            namespace,
            identifier,
        )
        if did != response_json.get("state", {}).get("id"):
            raise DidCreationError("Bad state returned")
        
        signing_key = did_state['verificationMethod'][0]['publicKeyMultibase']

        async with self.profile.session() as session:
            # Save the did in the wallet
            await session.handle.insert(
                CATEGORY_DID,
                did,
                value_json={
                    "did": did,
                    # We use the created signing as the default DID key
                    "verkey": multikey_to_verkey(signing_key),
                    "metadata": {
                        "posted": True,
                        "scid": scid,
                        "namespace": namespace,
                        "identifier": identifier,
                    },
                    "method": "webvh",
                    "key_type": "ed25519",
                },
                tags={},
            )

            resolver = session.inject(DIDResolver)

            resolved_did_doc = (
                await resolver.resolve_with_metadata(self.profile, did)
            ).serialize()

            event_bus = self.profile.inject(EventBus)

            metadata = resolved_did_doc["metadata"]
            metadata["state"] = RegistrationState.ATTESTED.value
            await event_bus.notify(
                self.profile,
                Event(
                    f"{WITNESS_EVENT}{scid}",
                    {"document": resolved_did_doc["did_document"], "metadata": metadata},
                ),
            )

            # Save the active scid parameters in the wallet
            await add_scid_mapping(self.profile, scid, did)

        return response_json.get("state", {})


    async def update(self, scid: str, did_document: dict = None):
        """Update a Webvh DID."""
        did = await did_from_scid(self.profile, scid)
        document_state = await self.server_client.fetch_document_state(
            get_namespace_and_identifier_from_did(did)
        )
        parameters = document_state.params

        params_update = {}

        if parameters.get("nextKeyHashes"):
            update_key, next_key_hash = await self._rotate_update_key(did)

            params_update["updateKeys"] = [update_key]
            params_update["nextKeyHashes"] = [next_key_hash]

        new_log_entry = document_state.create_next(
            document=did_document, params_update=params_update
        )

        async with self.profile.session() as session:
            key_manager = MultikeyManager(session)
            di_manager = DataIntegrityManager(session)

            update_key = (await key_manager.from_kid(kid=f"{did}#updateKey")).get(
                "multikey"
            )

            signed_log_entry = await di_manager.add_proof(
                new_log_entry.history_line(),
                DataIntegrityProofOptions.deserialize(
                    {
                        "type": "DataIntegrityProof",
                        "cryptosuite": "eddsa-jcs-2022",
                        "proofPurpose": "assertionMethod",
                        "verificationMethod": f"did:key:{update_key}#{update_key}",
                    }
                ),
            )
        return await self.finish_update_did(signed_log_entry, document_state.params)

    async def deactivate(self, options: dict):
        """Create a Webvh DID."""

        namespace = options.get("namespace")
        identifier = options.get("identifier")

        if not all_are_not_none(namespace, identifier):
            raise DidCreationError("Namespace and identifier are required.")

        # Get the document state from the server
        document_state = None
        try:
            async for line in self.server_client.fetch_jsonl(namespace, identifier):
                document_state = DocumentState.load_history_line(line, document_state)
        except ClientResponseError:
            raise DidCreationError("Failed to fetch the jsonl file from the server.")

        document = document_state.document_copy()

        document["verificationMethod"] = []
        document["authentication"] = []
        document["assertionMethod"] = []

        update_key_id = document_state.document["id"]
        async with self.profile.session() as session:
            if not await MultikeyManager(session).kid_exists(update_key_id):
                raise DidCreationError("Signing key not found.")

            update_key_info = await MultikeyManager(session).from_kid(update_key_id)

        document_state = document_state.create_next(
            document,
            {
                "deactivated": True,
                "updateKeys": [],
            },
            datetime.now(timezone.utc).replace(microsecond=0),
        )

        async with self.profile.session() as session:
            # Submit the log entry
            # NOTE: The authorized key is used as the verification method.
            log_entry = document_state.history_line()
            signed_log_entry = await DataIntegrityManager(session).add_proof(
                log_entry,
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{update_key_info.get('multikey')}#{update_key_info.get('multikey')}",
                ),
            )

            await self.server_client.deactivate_did(
                namespace, identifier, signed_log_entry
            )

            resolver = session.inject(DIDResolver)

            return (
                await resolver.resolve_with_metadata(
                    self.profile, document_state.document["id"]
                )
            ).serialize()

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
        async with self.profile.session() as session:
            key_manager = MultikeyManager(session)
            multikey = (
                await key_manager.from_multikey(multikey)
                if multikey
                else await key_manager.create()
            ).get("multikey")
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

            await key_manager.update(multikey, verification_method["id"])
            did_document["verificationMethod"].append(verification_method)
            for relationship in relationships:
                did_document[relationship].append(verification_method["id"])

        return did_document

    async def remove_verification_method(self, scid: str, key_id: str):
        """Remove a verification method."""
        did = await did_from_scid(self.profile, scid)
        key_id = f"{did}#{key_id}"
        async with self.profile.session() as session:
            key_info = await MultikeyManager(session).from_kid(
                kid=key_id,
            )
            await MultikeyManager(session).update(
                kid="",
                multikey=key_info.get("multikey"),
            )
        return {"status": "ok"}

    async def _rotate_update_key(self, did: str):
        """Pre rotation."""
        next_key_id = f"{did}#nextKey"
        update_key_id = f"{did}#updateKey"

        async with self.profile.session() as session:
            manager = MultikeyManager(session)

            # Find current keys
            update_key_info = await manager.from_kid(kid=update_key_id)
            next_key_info = await manager.from_kid(kid=next_key_id)

            # Unbind current update key and replace with next key
            await manager.update(kid="", multikey=update_key_info.get("multikey"))
            await manager.update(
                kid=update_key_id, multikey=next_key_info.get("multikey")
            )
            update_key_info = next_key_info

            # Create and update the new next key
            new_next_key_info = await manager.create(alg="ed25519")
            await manager.update(
                kid=next_key_id, multikey=new_next_key_info.get("multikey")
            )

        return update_key_info.get("multikey"), key_hash(
            new_next_key_info.get("multikey")
        )

    async def finish_update_did(self, signed_log_entry, params={}):
        """Finish updating an existing did."""
        did_document = signed_log_entry.get("state")
        did = did_document.get("id")
        payload = {"logEntry": signed_log_entry}
        if signed_log_entry.get("parameters").get("witness"):
            # TODO fetch queued witness signatures
            payload["witnessSignature"] = {}

        namespace, identifier = get_namespace_and_identifier_from_did(did)
        async with self.profile.session() as session:
            response = await self.server_client.submit_log_entry(
                payload,
                namespace,
                identifier,
            )
            await session.handle.replace(
                "scid",
                did.split(":")[2],
                value_json={
                    "didDocument": did_document,
                    "parameters": signed_log_entry.get("parameters"),
                },
                tags={},
            )

        if notify_watchers(self.profile):
            await self.watcher_client.notify_watchers(did, params.get("watchers", []))

        return await response.json()

    async def update_whois(self, scid: str, presentation: dict, options: dict = {}):
        """Update WHOIS linked VP."""

        async with self.profile.session() as session:
            scid_info = await session.handle.fetch(
                "scid",
                scid,
            )
            holder_id = json.loads(scid_info.value).get("didDocument").get("id")

            # NOTE, if presentation has holder, ensure it's the same as the provided SCID
            if presentation.get("holder"):
                pres_holder = presentation.get("holder")
                pres_holder_id = (
                    pres_holder if isinstance(pres_holder, str) else pres_holder["id"]
                )

                if holder_id != pres_holder_id:
                    raise OperationError("Holder ID mismatch.")

            di_manager = DataIntegrityManager(session)

            for credential in presentation.get("verifiableCredential"):
                # Check if holder is the credential subject
                if credential.get("credentialSubject").get("id") != holder_id:
                    # TODO, should we enforce this?
                    pass

                if not (await di_manager.verify_proof(credential)).verified:
                    LOGGER.info("Credential verification failed.")
                    LOGGER.info(json.dumps(credential))
                    raise OperationError("Credential verification failed.")

            # NOTE, we get the default signing key from the DID record
            did_info = await session.handle.fetch(CATEGORY_DID, holder_id)
            signing_multikey = verkey_to_multikey(
                json.loads(did_info.value).get("verkey"), "ed25519"
            )

            vp = await di_manager.add_proof(
                presentation,
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="authentication",
                    verification_method=f"{holder_id}#{signing_multikey}",
                ),
            )

        namespace, identifier = get_namespace_and_identifier_from_did(holder_id)
        return await self.server_client.submit_whois(
            namespace,
            identifier,
            vp,
        )
