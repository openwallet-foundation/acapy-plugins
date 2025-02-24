"""DID Webvh Manager."""

import asyncio
import copy
import http
import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.profile import Profile, ProfileSession
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

from ..config.config import get_server_url, use_strict_ssl
from .exceptions import DidCreationError
from .pending_dids import PendingWebvhDids
from .registration_state import RegistrationState
from .utils import create_alias, key_to_did_key_vm
from .witness_manager import WitnessManager

LOGGER = logging.getLogger(__name__)

WEBVH_METHOD = "did:webvh:0.5"
WITNESS_WAIT_TIMEOUT_SECONDS = 2
WITNESS_EVENT = "witness_response::"


class DidWebvhOperationsManager:
    """DID Webvh Manager class."""

    def __init__(self, profile: Profile) -> None:
        """Initialize the DID Webvh Manager."""
        self.profile = profile

    def _all_are_not_none(*args):
        return all(v is not None for v in args)

    async def fetch_jsonl(self, url):
        """Fetch a JSONL file from the given URL."""
        async with ClientSession() as session:
            async with session.get(
                url, ssl=(await use_strict_ssl(self.profile))
            ) as response:
                # Check if the response is OK
                response.raise_for_status()

                # Read the response line by line
                async for line in response.content:
                    # Decode each line and parse as JSON
                    decoded_line = line.decode("utf-8").strip()
                    if decoded_line:  # Ignore empty lines
                        yield json.loads(decoded_line)

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
            if response.status == http.HTTPStatus.BAD_REQUEST:
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

    async def _get_key(self, key_alias):
        async with self.profile.session() as session:
            if not await MultikeyManager(session).kid_exists(key_alias):
                raise DidCreationError("Signing key not found.")

            return await MultikeyManager(session).from_kid(key_alias)

    async def _get_or_create_key(self, key_alias):
        async with self.profile.session() as session:
            try:
                # NOTE: kid management needs to be addressed with key rotation
                key_info = await MultikeyManager(session).create(
                    alg="ed25519",
                    kid=key_alias,
                )
            except MultikeyManagerError:
                key_info = await MultikeyManager(session).from_kid(key_alias)

        return key_info

    async def _create_controller_signed_registration_document(
        self, did, ver_key_info, proof_options
    ):
        async with self.profile.session() as session:
            return await DataIntegrityManager(session).add_proof(
                DIDDocument(
                    context=[
                        "https://www.w3.org/ns/did/v1",
                        "https://w3id.org/security/multikey/v1",
                    ],
                    id=did,
                    authentication=[ver_key_info.get("kid")],
                    assertion_method=[ver_key_info.get("kid")],
                    verification_method=[
                        {
                            "id": ver_key_info.get("kid"),
                            "type": "Multikey",
                            "controller": did,
                            "publicKeyMultibase": ver_key_info.get("multikey"),
                        }
                    ],
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
                await PendingWebvhDids().remove_pending_did(self.profile, did)
                return await self.finish_create(
                    event.payload.get("document"),
                    state=RegistrationState.FINISHED.value,
                    authorized_key_info=event.payload.get("authorized_key_info"),
                    parameters=event.payload.get("metadata", {}).get("parameters"),
                )

    async def create(self, options: dict):
        """Register identities."""

        server_url = await get_server_url(self.profile)

        # Set default namespace if none provided
        namespace = options.get("namespace", "default")

        # Generate a random identifier if not provided
        identifier = options.get("identifier", str(uuid4()))

        # Contact the server to request an identifier
        did_doc, proof_options = await self._request_identifier(
            server_url, namespace, identifier
        )
        did = did_doc.get("id")

        update_key_alias = create_alias(did.replace("did:web:", "webvh"), "updateKey")
        authorized_key_info = await self._get_or_create_key(update_key_alias)

        first_key_alias = f"{did}#key-01"
        first_key_info = await self._get_or_create_key(first_key_alias)

        controller_proof_options = copy.deepcopy(proof_options)
        controller_proof_options["verificationMethod"] = key_to_did_key_vm(
            authorized_key_info.get("multikey")
        )
        controller_secured_document = (
            await self._create_controller_signed_registration_document(
                did, first_key_info, controller_proof_options
            )
        )

        parameters = options.get("parameters", {})
        witness_proof_options = copy.deepcopy(proof_options)
        result = await WitnessManager(self.profile).witness_registration_document(
            controller_secured_document, witness_proof_options, parameters
        )

        if isinstance(result, dict):
            return await self.finish_create(
                result,
                parameters=parameters,
                state=RegistrationState.SUCCESS.value,
                authorized_key_info=authorized_key_info,
            )

        try:
            await PendingWebvhDids().set_pending_did(self.profile, did)
            return await asyncio.wait_for(
                self._wait_for_witness(did),
                WITNESS_WAIT_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            return {
                "status": "unknown",
                "message": "No immediate response from witness agent.",
            }

    async def _create_signed_initial_log_entry(
        self,
        session: ProfileSession,
        domain: str,
        namespace: str,
        identifier: str,
        parameters: dict,
        authorized_key_info: dict,
    ):
        initial_doc = {
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
            ],
            "id": r"did:webvh:{SCID}:" + f"{domain}:{namespace}:{identifier}",
        }

        first_webvh_key_id = initial_doc["id"] + "#key-01"
        first_webvh_key_info = await self._get_or_create_key(first_webvh_key_id)

        initial_doc["authentication"] = [first_webvh_key_info.get("kid")]
        initial_doc["assertionMethod"] = [first_webvh_key_info.get("kid")]
        initial_doc["verificationMethod"] = [
            {
                "id": first_webvh_key_info.get("kid"),
                "type": "Multikey",
                "controller": initial_doc["id"],
                "publicKeyMultibase": first_webvh_key_info.get("multikey"),
            }
        ]
        # TODO: Add support for prerotation and portable
        doc_state = DocumentState.initial(
            {
                "updateKeys": [authorized_key_info.get("multikey")],
                # "prerotation": parameters.get("prerotation", False),
                # "portable": parameters.get("portable", False),
                "method": WEBVH_METHOD,
            },
            initial_doc,
        )

        # Add controller authorized proof to the log entry
        signed_entry = await DataIntegrityManager(session).add_proof(
            doc_state.history_line(),
            DataIntegrityProofOptions(
                type="DataIntegrityProof",
                cryptosuite="eddsa-jcs-2022",
                proof_purpose="assertionMethod",
                verification_method=key_to_did_key_vm(
                    authorized_key_info.get("multikey")
                ),
            ),
        )
        async with self.profile.session() as session:
            await MultikeyManager(session).update(
                multikey=first_webvh_key_info.get("multikey"),
                kid=signed_entry.get("state").get("verificationMethod")[0].get("id"),
            )

        return signed_entry

    async def finish_create(
        self,
        witnessed_document: dict,
        parameters: dict,
        state: str = RegistrationState.SUCCESS.value,
        authorized_key_info: Optional[dict] = None,
    ):
        """Finish the creation of a Webvh DID."""
        if state == RegistrationState.ATTESTED.value:
            event_bus = self.profile.inject(EventBus)
            await event_bus.notify(
                self.profile,
                Event(
                    f"{WITNESS_EVENT}{witnessed_document['id']}",
                    {
                        "document": witnessed_document,
                        "metadata": {
                            "state": RegistrationState.ATTESTED.value,
                            "parameters": parameters,
                        },
                    },
                ),
            )
            await asyncio.sleep(WITNESS_WAIT_TIMEOUT_SECONDS)
            if witnessed_document["id"] not in await PendingWebvhDids().get_pending_dids(
                self.profile
            ):
                return
            await PendingWebvhDids().remove_pending_did(
                self.profile, witnessed_document["id"]
            )

        if state == RegistrationState.PENDING.value:
            event_bus = self.profile.inject(EventBus)
            await event_bus.notify(
                self.profile,
                Event(
                    f"{WITNESS_EVENT}{witnessed_document['id']}",
                    {
                        "document": witnessed_document,
                        "metadata": {
                            "state": RegistrationState.PENDING.value,
                            "parameters": parameters,
                        },
                    },
                ),
            )
            return

        async with ClientSession() as http_session, self.profile.session() as session:
            # Register did document and did with the server
            server_url = await get_server_url(self.profile)
            response = await http_session.post(
                server_url,
                json={"didDocument": witnessed_document},
                ssl=(await use_strict_ssl(self.profile)),
            )
            response_json = await response.json()
            if response.status == http.HTTPStatus.BAD_REQUEST:
                raise DidCreationError(response_json.get("detail"))

            if not authorized_key_info:
                key_alias = create_alias(
                    witnessed_document["id"].replace("did:web:", "webvh"), "updateKey"
                )
                authorized_key_info = await self._get_key(key_alias)

            # Create initial log entry
            namespace = witnessed_document["id"].split(":")[-2]
            identifier = witnessed_document["id"].split(":")[-1]

            signed_initial_log_entry = await self._create_signed_initial_log_entry(
                session,
                witnessed_document["proof"][0]["domain"],
                namespace,
                identifier,
                parameters,
                authorized_key_info,
            )

            # Submit the initial log entry
            response = await http_session.post(
                f"{server_url}/{namespace}/{identifier}",
                json={"logEntry": signed_initial_log_entry},
                ssl=(await use_strict_ssl(self.profile)),
            )

            if response.status == http.HTTPStatus.INTERNAL_SERVER_ERROR:
                raise DidCreationError("Server had a problem creating log entry.")

            response_json = await response.json()
            if response.status == http.HTTPStatus.BAD_REQUEST:
                raise DidCreationError(response_json.get("detail"))
            did = response_json.get("state", {}).get("id")

            # Save the did in the wallet
            await session.handle.insert(
                CATEGORY_DID,
                did,
                value_json={
                    "did": did,
                    "verkey": multikey_to_verkey(authorized_key_info.get("multikey")),
                    "metadata": {
                        "posted": True,
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
                    f"{WITNESS_EVENT}{witnessed_document['id']}",
                    {"document": resolved_did_doc["did_document"], "metadata": metadata},
                ),
            )

        return response_json.get("state", {})

    async def update(self, options: dict, features: dict):
        """Update a Webvh DID."""
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

        for feature, values in features.items():
            document[feature].extend([values])

        authorized_key_info = await self._get_key(document_state.document["id"])

        document_state = document_state.create_next(
            document, {}, datetime.now(timezone.utc).replace(microsecond=0)
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
                    verification_method=f"did:key:{authorized_key_info.get('multikey')}#{authorized_key_info.get('multikey')}",
                ),
            )

            response = await http_session.put(
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

        authorized_key_info = await self._get_key(document_state.document["id"])

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
                    verification_method=f"did:key:{authorized_key_info.get('multikey')}#{authorized_key_info.get('multikey')}",
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
