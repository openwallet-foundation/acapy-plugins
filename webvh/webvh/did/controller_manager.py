"""DID Webvh Manager."""

import asyncio
import copy
import json
import logging
import re
from datetime import datetime, timezone
from uuid import uuid4

from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.profile import Profile
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
    get_witnesses,
    notify_watchers,
)
from .exceptions import DidCreationError, OperationError
from .registration_state import RegistrationState
from .server_client import WebVHServerClient, WebVHWatcherClient
from .utils import (
    all_are_not_none,
    get_namespace_and_identifier_from_did,
    key_hash,
    multikey_to_jwk,
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

    async def _create_registration_document(self, did, proof_options):
        async with self.profile.session() as session:
            # We create an initial verification method
            key_manager = MultikeyManager(session)
            signing_key_info = await key_manager.create(alg="ed25519")
            signing_key = signing_key_info.get("multikey")
            signing_key_id = f"{did}#{signing_key}"
            await key_manager.update(kid=signing_key_id, multikey=signing_key)

            # Sign registration document with registration key
            return await DataIntegrityManager(session).add_proof(
                DIDDocument(
                    context=[
                        "https://www.w3.org/ns/did/v1",
                        "https://www.w3.org/ns/cid/v1",
                    ],
                    id=did,
                    key_agreement=[],
                    authentication=[signing_key_id],
                    assertion_method=[signing_key_id],
                    verification_method=[
                        {
                            "type": "Multikey",
                            "id": signing_key_id,
                            "controller": did,
                            "publicKeyMultibase": signing_key,
                        }
                    ],
                    capability_invocation=[],
                    capability_delegation=[],
                    service=[],
                ).serialize(),
                DataIntegrityProofOptions.deserialize(proof_options),
            )

    async def _wait_for_witness(self, did: str):
        event_bus = self.profile.inject(EventBus)
        with event_bus.wait_for_event(
            self.profile, re.compile(rf"^{WITNESS_EVENT}{did}$")
        ) as await_event:
            event = await await_event
            if (
                event.payload.get("metadata", {}).get("state")
                == RegistrationState.PENDING.value
            ):
                return PENDING_MESSAGE
            else:
                await PendingRegistrations().remove_pending_did(self.profile, did)
                return await self.finish_registration(
                    event.payload.get("document"),
                    state=RegistrationState.FINISHED.value,
                    parameters=event.payload.get("metadata", {}).get("parameters"),
                )

    async def register(self, options: dict):
        """Register identities."""

        # Set default namespace and random identifier if none provided
        namespace = options.get("namespace", "default")
        identifier = options.get("identifier", str(uuid4()))

        # Contact the server to request the identifier
        did_doc, proof_options = await self.server_client.request_identifier(
            namespace, identifier
        )
        did = did_doc.get("id")

        # Create local update key
        update_key = (await self._get_or_create_key(f"{did}#updateKey")).get("multikey")

        # Create controller proof
        registration_document = await self._create_registration_document(
            did,
            copy.deepcopy(proof_options)
            | {"verificationMethod": f"did:key:{update_key}#{update_key}"},
        )

        # Set webvh parameters options
        parameter_options = {
            "watchers": options.get("watchers", None),
            "portable": options.get("portable", False),
            "prerotation": options.get("prerotation", False),
            "witnessThreshold": options.get("witnessThreshold", None),
        }

        result = await WitnessManager(self.profile).witness_registration_document(
            registration_document, copy.deepcopy(proof_options), parameter_options
        )

        if isinstance(result, dict):
            return await self.finish_registration(
                result,
                parameters=parameter_options,
                state=RegistrationState.SUCCESS.value,
            )

        if (await get_plugin_config(self.profile)).get("role") == "witness":
            return PENDING_MESSAGE

        try:
            await PendingRegistrations().set_pending_did(self.profile, did)
            return await asyncio.wait_for(
                self._wait_for_witness(did),
                WITNESS_WAIT_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            return {
                "status": "unknown",
                "message": "No immediate response from witness agent.",
            }

    async def _create_initial_log_entry(
        self, registration_document: str, param_options: dict
    ):
        registration_document.pop("proof")
        web_did = registration_document.get("id")

        preliminary_doc = json.loads(
            (json.dumps(registration_document).replace("did:web:", r"did:webvh:{SCID}:"))
        )

        # Transform create options into webvh parameters
        update_key = (await self._get_or_create_key(f"{web_did}#updateKey")).get(
            "multikey"
        )
        parameters = {
            "method": WEBVH_METHOD,
            "portable": param_options.get("portable", False),
            "updateKeys": [update_key],
        }

        if param_options.get("watchers", None):
            parameters["watchers"] = param_options.get("watchers")

        if param_options.get("prerotation", None):
            # If prerotation is enabled, we create the next update key and hash it
            next_key_info = await self._get_or_create_key(f"{web_did}#nextKey")
            parameters["nextKeyHashes"] = [key_hash(next_key_info.get("multikey"))]

        if param_options.get("witnessThreshold"):
            # If witnessing is enabled, we add the list of our active witnesses
            witnesses = await get_witnesses(self.profile)
            parameters["witness"] = {
                "threshold": param_options.get("witnessThreshold"),
                "witnesses": [],
            }
            for witness in witnesses:
                parameters["witness"]["witnesses"].append({"id": witness})

        doc_state = DocumentState.initial(
            parameters,
            preliminary_doc,
        )

        # Add controller authorized proof to the log entry
        async with self.profile.session() as session:
            signed_entry = await DataIntegrityManager(session).add_proof(
                doc_state.history_line(),
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{update_key}#{update_key}",
                ),
            )

        return signed_entry

    async def finish_registration(
        self,
        registration_document: dict,
        parameters: dict,
        state: str = RegistrationState.SUCCESS.value,
    ):
        """Finish the registration of the DID."""
        did = registration_document["id"]
        if state == RegistrationState.ATTESTED.value:
            event_bus = self.profile.inject(EventBus)
            await event_bus.notify(
                self.profile,
                Event(
                    f"{WITNESS_EVENT}{did}",
                    {
                        "document": registration_document,
                        "metadata": {
                            "state": RegistrationState.ATTESTED.value,
                            "parameters": parameters,
                        },
                    },
                ),
            )
            await asyncio.sleep(WITNESS_WAIT_TIMEOUT_SECONDS)
            if did not in await PendingRegistrations().get_pending_dids(self.profile):
                return
            await PendingRegistrations().remove_pending_did(self.profile, did)

        if state == RegistrationState.PENDING.value:
            event_bus = self.profile.inject(EventBus)
            await event_bus.notify(
                self.profile,
                Event(
                    f"{WITNESS_EVENT}{did}",
                    {
                        "document": registration_document,
                        "metadata": {
                            "state": RegistrationState.PENDING.value,
                            "parameters": parameters,
                        },
                    },
                ),
            )
            return

        await self.server_client.register_did_doc(registration_document)

        return await self.create(registration_document, parameters)

    async def create(self, registration_document: dict, parameters: dict):
        """Create DID and first log entry."""
        web_did = registration_document.get("id")
        # Create initial log entry
        namespace = web_did.split(":")[-2]
        identifier = web_did.split(":")[-1]
        # update_key = parameters.get("updateKeys")[0]
        signing_key = registration_document["verificationMethod"][0].get(
            "publicKeyMultibase"
        )

        initial_log_entry = await self._create_initial_log_entry(
            registration_document,
            parameters,
        )

        response_json = await self.server_client.submit_log_entry(
            initial_log_entry,
            namespace,
            identifier,
        )

        webvh_did = response_json.get("state", {}).get("id")
        if not webvh_did:
            raise DidCreationError("No state returned")

        scid = webvh_did.split(":")[2]

        async with self.profile.session() as session:
            # Save the did in the wallet
            await session.handle.insert(
                CATEGORY_DID,
                webvh_did,
                value_json={
                    "did": webvh_did,
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
                await resolver.resolve_with_metadata(self.profile, webvh_did)
            ).serialize()

            event_bus = self.profile.inject(EventBus)

            metadata = resolved_did_doc["metadata"]
            metadata["state"] = RegistrationState.ATTESTED.value
            await event_bus.notify(
                self.profile,
                Event(
                    f"{WITNESS_EVENT}{web_did}",
                    {"document": resolved_did_doc["did_document"], "metadata": metadata},
                ),
            )

            # Save the active scid parameters in the wallet
            await add_scid_mapping(self.profile, scid, webvh_did)
            await session.handle.insert(
                "scid",
                scid,
                value_json={
                    "didDocument": response_json.get("state"),
                    "parameters": initial_log_entry.get("parameters"),
                },
                tags={},
            )

            # Update the key id's with the webvh did
            key_manager = MultikeyManager(session)
            parameters = initial_log_entry.get("parameters")
            update_key = parameters.get("updateKeys")[0]

            await key_manager.update(multikey=update_key, kid=f"{webvh_did}#updateKey")
            await key_manager.update(
                multikey=signing_key, kid=f"{webvh_did}#{signing_key}"
            )

            if initial_log_entry.get("parameters").get("nextKeyHashes"):
                next_key = (await key_manager.from_kid(f"{web_did}#nextKey")).get(
                    "multikey"
                )
                await key_manager.update(multikey=next_key, kid=f"{webvh_did}#nextKey")

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
