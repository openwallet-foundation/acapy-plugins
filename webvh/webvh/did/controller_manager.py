"""DID Webvh Manager."""

import asyncio
import copy
import http
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
)
from aiohttp import ClientConnectionError, ClientResponseError, ClientSession
from did_webvh.core.state import DocumentState
from pydid import DIDDocument

from ..config.config import (
    add_scid_mapping,
    did_from_scid,
    get_server_url,
    get_witnesses,
    use_strict_ssl,
)
from .exceptions import DidCreationError
from .registration_state import RegistrationState
from .utils import (
    fetch_document_state,
    key_hash,
    multikey_to_jwk,
)
from .witness_manager import WitnessManager
from .witness_queue import PendingRegistrations

LOGGER = logging.getLogger(__name__)

WEBVH_METHOD = "did:webvh:0.5"
WITNESS_WAIT_TIMEOUT_SECONDS = 2
WITNESS_EVENT = "witness_response::"


class ControllerManager:
    """DID Webvh Manager class."""

    def __init__(self, profile: Profile) -> None:
        """Initialize the DID Webvh Manager."""
        self.profile = profile

    def _all_are_not_none(*args):
        return all(v is not None for v in args)

    async def _request_identifier(self, server_url, namespace, identifier) -> tuple:
        """Contact the trust did web server to request an identifier."""
        async with ClientSession() as session:
            try:
                response = await session.get(
                    server_url,
                    params={
                        "namespace": namespace,
                        "identifier": identifier,
                    },
                    ssl=(await use_strict_ssl(self.profile)),
                )
            except ClientConnectionError as err:
                raise DidCreationError(f"Failed to connect to Webvh server: {err}")

            response_json = await response.json()
            if (
                response.status == http.HTTPStatus.BAD_REQUEST
                or response.status == http.HTTPStatus.CONFLICT
            ):
                raise DidCreationError(response_json.get("detail"))

            did_document = response_json.get("didDocument", {})
            did = did_document.get("id")

            proof_options = response_json.get("proofOptions", {})
            challenge = proof_options.get("challenge")
            domain = proof_options.get("domain")
            expiration = proof_options.get("expires")

            if self._all_are_not_none(did, challenge, domain, expiration):
                return did_document, proof_options
            else:
                raise DidCreationError(
                    "Invalid response from Webvh server requesting identifier"
                )

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
                return {
                    "status": RegistrationState.PENDING.value,
                    "message": "The witness is pending.",
                }
            else:
                await PendingRegistrations().remove_pending_did(self.profile, did)
                return await self.finish_registration(
                    event.payload.get("document"),
                    state=RegistrationState.FINISHED.value,
                    parameters=event.payload.get("metadata", {}).get("parameters"),
                )

    async def register(self, options: dict):
        """Register identities."""

        server_url = await get_server_url(self.profile)

        # Set default namespace and random identifier if none provided
        namespace = options.get("namespace", "default")
        identifier = options.get("identifier", str(uuid4()))

        # Contact the server to request the identifier
        did_doc, proof_options = await self._request_identifier(
            server_url, namespace, identifier
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

        async with ClientSession() as session:
            # Register did document and did with the server
            server_url = await get_server_url(self.profile)
            response = await session.post(
                server_url,
                json={"didDocument": registration_document},
                ssl=(await use_strict_ssl(self.profile)),
            )
            response_json = await response.json()
            if response.status == http.HTTPStatus.BAD_REQUEST:
                raise DidCreationError(response_json.get("detail"))

        return await self.create(registration_document, parameters)

    async def create(self, registration_document: dict, parameters: dict):
        """Create DID and first log entry."""
        web_did = registration_document.get("id")
        async with ClientSession() as http_session:
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
            payload = {"logEntry": initial_log_entry}
            # TODO, handle witness signatures
            # payload['witnessSignatures'] = {}

            # Submit the initial log entry
            server_url = await get_server_url(self.profile)
            response = await http_session.post(
                f"{server_url}/{namespace}/{identifier}",
                json=payload,
                ssl=(await use_strict_ssl(self.profile)),
            )

            if response.status == http.HTTPStatus.INTERNAL_SERVER_ERROR:
                raise DidCreationError("Server had a problem creating log entry.")

            response_json = await response.json()
            if response.status == http.HTTPStatus.BAD_REQUEST:
                raise DidCreationError(response_json.get("detail"))

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
        server_url = await get_server_url(self.profile)
        namespace = did.split(":")[4]
        identifier = did.split(":")[5]
        document_state = await fetch_document_state(
            f"{server_url}/{namespace}/{identifier}/did.jsonl"
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
        return await self.finish_update_did(signed_log_entry)

    async def deactivate(self, options: dict):
        """Create a Webvh DID."""
        server_url = await get_server_url(self.profile)

        namespace = options.get("namespace")
        identifier = options.get("identifier")

        if not self._all_are_not_none(namespace, identifier):
            raise DidCreationError("Namespace and identifier are required.")

        # Get the document state from the server
        document_state = None
        try:
            async for line in self.fetch_jsonl(
                f"{server_url}/{namespace}/{identifier}/did.jsonl"
            ):
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

        async with ClientSession() as http_session, self.profile.session() as session:
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

            response = await http_session.delete(
                f"{server_url}/{namespace}/{identifier}",
                json={"logEntry": signed_log_entry},
                ssl=(await use_strict_ssl(self.profile)),
            )

            response_json = await response.json()

            if response_json.get("detail") == "Key unauthorized.":
                raise DidCreationError("Problem creating log entry: Key unauthorized.")

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

    async def finish_update_did(self, signed_log_entry):
        """Finish updating an existing did."""
        did_document = signed_log_entry.get("state")
        did = did_document.get("id")
        payload = {"logEntry": signed_log_entry}
        if signed_log_entry.get("parameters").get("witness"):
            # TODO fetch queued witness signatures
            payload["witnessSignature"] = {}

        server_url = await get_server_url(self.profile)
        namespace = did.split(":")[4]
        identifier = did.split(":")[5]
        async with ClientSession() as http_session, self.profile.session() as session:
            try:
                response = await http_session.post(
                    f"{server_url}/{namespace}/{identifier}", json=payload
                )
            except ClientConnectionError as err:
                raise DidCreationError(f"Failed to connect to Webvh server: {err}")
            await session.handle.replace(
                "scid",
                did.split(":")[2],
                value_json={
                    "didDocument": did_document,
                    "parameters": signed_log_entry.get("parameters"),
                },
                tags={},
            )
        return await response.json()
