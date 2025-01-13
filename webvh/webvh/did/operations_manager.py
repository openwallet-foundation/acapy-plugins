"""DID Webvh Manager."""

import asyncio
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

from .endorsement_manager import EndorsementManager
from .exceptions import DidCreationError
from .registration_state import RegistrationState
from .utils import get_server_info, use_strict_ssl

LOGGER = logging.getLogger(__name__)

WEBVH_METHOD = "did:webvh:0.4"
ENDORSEMENT_WAIT_TIMEOUT_SECONDS = 2
ENDORSEMENT_EVENT = "endorsement_response::"
AUTHORIZED_KEY_ID = "authorizedKey"


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
            async with session.get(url, ssl=use_strict_ssl(self.profile)) as response:
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
                    ssl=use_strict_ssl(self.profile),
                )
            except ClientConnectionError as err:
                raise DidCreationError(f"Failed to connect to Webvh server: {err}")

            response_json = await response.json()
            if response.status == http.HTTPStatus.BAD_REQUEST:
                raise DidCreationError(response_json.get("detail"))

            document = response_json.get("didDocument", {})
            did = document.get("id")

            proof_options = response_json.get("proofOptions", {})
            challenge = proof_options.get("challenge")
            domain = proof_options.get("domain")
            expiration = proof_options.get("expires")

            if self._all_are_not_none(did, challenge, domain, expiration):
                return did, challenge, domain, expiration
            else:
                raise DidCreationError(
                    "Invalid response from Webvh server requesting identifier"
                )

    async def _get_or_create_authorized_key(self, did):
        async with self.profile.session() as session:
            try:
                # NOTE: kid management needs to be addressed with key rotation
                authorized_key_info = await MultikeyManager(session).create(
                    alg="ed25519",
                    kid=f"{did}#{AUTHORIZED_KEY_ID}",
                )
            except MultikeyManagerError:
                authorized_key_info = await MultikeyManager(session).from_kid(
                    f"{did}#{AUTHORIZED_KEY_ID}"
                )

        return authorized_key_info

    async def _create_controller_signed_registration_document(
        self, did, authorized_key_info, expiration, domain, challenge
    ):
        async with self.profile.session() as session:
            # NOTE: The authorized key is used as the verification method. This needs to
            # be discussed and potentially changed to a different key.
            return await DataIntegrityManager(session).add_proof(
                DIDDocument(
                    context=[
                        "https://www.w3.org/ns/did/v1",
                        "https://w3id.org/security/multikey/v1",
                    ],
                    id=did,
                    authentication=[authorized_key_info.get("kid")],
                    assertion_method=[authorized_key_info.get("kid")],
                    verification_method=[
                        {
                            "id": authorized_key_info.get("kid"),
                            "type": "Multikey",
                            "controller": did,
                            "publicKeyMultibase": authorized_key_info.get("multikey"),
                        }
                    ],
                ).serialize(),
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{authorized_key_info.get('multikey')}#{authorized_key_info.get('multikey')}",
                    expires=expiration,
                    domain=domain,
                    challenge=challenge,
                ),
            )

    async def _wait_for_endorsement(self, did: str):
        event_bus = self.profile.inject(EventBus)
        with event_bus.wait_for_event(
            self.profile, re.compile(rf"^{ENDORSEMENT_EVENT}{did}$")
        ) as await_event:
            event = await await_event
            return await self.finish_create(
                event.payload.get("document"),
                state=RegistrationState.FINISHED.value,
                authorized_key_info=event.payload.get("authorized_key_info"),
                parameters=event.payload.get("metadata", {}).get("parameters"),
            )

    async def create(self, options: dict):
        """Register identities."""

        server_url = get_server_info(self.profile)
        namespace = options.get("namespace", "default")

        if namespace is None:
            raise DidCreationError("Namespace is required.")

        # Generate a random identifier if not provided
        identifier = options.get("identifier", str(uuid4()))

        # Contact the server to request an identifier
        did, challenge, domain, expiration = await self._request_identifier(
            server_url, namespace, identifier
        )

        authorized_key_info = await self._get_or_create_authorized_key(did)
        controller_secured_document = (
            await self._create_controller_signed_registration_document(
                did, authorized_key_info, expiration, domain, challenge
            )
        )

        parameters = options.get("parameters", {})
        result = await EndorsementManager(self.profile).endorse_registration_document(
            controller_secured_document, expiration, domain, challenge, parameters
        )

        if isinstance(result, dict):
            return await self.finish_create(
                result,
                parameters=parameters,
                state=RegistrationState.SUCCESS.value,
                authorized_key_info=authorized_key_info,
            )

        try:
            return await asyncio.wait_for(
                self._wait_for_endorsement(did),
                ENDORSEMENT_WAIT_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            return {
                "status": "unknown",
                "message": "No immediate response from endorser agent.",
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
            "@context": "https://www.w3.org/ns/did/v1",
            "id": r"did:webvh:{SCID}:" + f"{domain}:{namespace}:{identifier}",
        }
        doc_state = DocumentState.initial(
            {
                "updateKeys": [authorized_key_info.get("multikey")],
                "prerotation": parameters.get("prerotation", False),
                "portable": parameters.get("portable", False),
                "method": WEBVH_METHOD,
            },
            initial_doc,
        )

        # Add controller authorized proof to the log entry
        # NOTE: The authorized key is used as the verification method.
        return await DataIntegrityManager(session).add_proof(
            doc_state.history_line(),
            DataIntegrityProofOptions(
                type="DataIntegrityProof",
                cryptosuite="eddsa-jcs-2022",
                proof_purpose="assertionMethod",
                verification_method=f"did:key:{authorized_key_info.get('multikey')}#{authorized_key_info.get('multikey')}",
            ),
        )

    async def finish_create(
        self,
        endorsed_document: dict,
        parameters: dict,
        state: str = RegistrationState.SUCCESS.value,
        authorized_key_info: Optional[dict] = None,
    ):
        """Finish the creation of a Webvh DID."""
        if state == RegistrationState.POSTED.value:
            event_bus = self.profile.inject(EventBus)
            await event_bus.notify(
                self.profile,
                Event(
                    f"{ENDORSEMENT_EVENT}{endorsed_document['id']}",
                    {
                        "document": endorsed_document,
                        "metadata": {
                            "state": RegistrationState.POSTED.value,
                            "parameters": parameters,
                        },
                    },
                ),
            )
            return

        if state == RegistrationState.PENDING.value:
            event_bus = self.profile.inject(EventBus)
            await event_bus.notify(
                self.profile,
                Event(
                    f"{ENDORSEMENT_EVENT}{endorsed_document['id']}",
                    {
                        "document": endorsed_document,
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
            server_url = get_server_info(self.profile)
            response = await http_session.post(
                server_url,
                json={"didDocument": endorsed_document},
                ssl=use_strict_ssl(self.profile),
            )
            response_json = await response.json()
            if response.status == http.HTTPStatus.BAD_REQUEST:
                raise DidCreationError(response_json.get("detail"))

            if not authorized_key_info:
                authorized_key_info = await self._get_or_create_authorized_key(
                    endorsed_document["id"]
                )

            # Create initial log entry
            id_parts = endorsed_document["id"].split(":")
            namespace = id_parts[-2]
            identifier = id_parts[-1]

            signed_initial_log_entry = await self._create_signed_initial_log_entry(
                session,
                endorsed_document["proof"][0]["domain"],
                namespace,
                identifier,
                parameters,
                authorized_key_info,
            )

            # Submit the initial log entry
            response = await http_session.post(
                f"{server_url}/{namespace}/{identifier}",
                json={"logEntry": signed_initial_log_entry},
                ssl=use_strict_ssl(self.profile),
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
            metadata["state"] = RegistrationState.POSTED.value
            await event_bus.notify(
                self.profile,
                Event(
                    f"{ENDORSEMENT_EVENT}{endorsed_document['id']}",
                    {"document": resolved_did_doc["did_document"], "metadata": metadata},
                ),
            )

        return resolved_did_doc

    async def update(self, options: dict, features: dict):
        """Update a Webvh DID."""
        server_url = get_server_info(self.profile)

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

        authorized_key_info = await self._get_or_create_authorized_key(
            document_state.document["id"]
        )

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
                ssl=use_strict_ssl(self.profile),
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
        server_url = get_server_info(self.profile)

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

        authorized_key_info = await self._get_or_create_authorized_key(
            document_state.document["id"]
        )

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
                ssl=use_strict_ssl(self.profile),
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
