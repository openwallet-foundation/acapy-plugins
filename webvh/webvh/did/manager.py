"""DID Webvh Manager."""

import asyncio
import http
import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from acapy_agent.connections.models.conn_record import ConnRecord
from acapy_agent.core.event_bus import Event, EventBus
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.responder import BaseResponder
from acapy_agent.protocols.out_of_band.v1_0.manager import OutOfBandManager
from acapy_agent.protocols.out_of_band.v1_0.messages.invitation import InvitationMessage
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.vc.data_integrity.manager import DataIntegrityManager
from acapy_agent.vc.data_integrity.models.options import DataIntegrityProofOptions
from acapy_agent.wallet.askar import CATEGORY_DID
from acapy_agent.wallet.error import WalletDuplicateError
from acapy_agent.wallet.keys.manager import (
    MultikeyManager,
    MultikeyManagerError,
    multikey_to_verkey,
)
from aiohttp import ClientConnectionError, ClientResponseError, ClientSession
from aries_askar import AskarError
from did_webvh.core.state import DocumentState
from pydid import DIDDocument

from .exceptions import ConfigurationError, DidCreationError, EndorsementError
from .messages.endorsement import EndorsementRequest, EndorsementResponse

LOGGER = logging.getLogger(__name__)

DOCUMENT_TABLE_NAME = "did_webvh_pending_document"


class DidWebvhManager:
    """DID Webvh Manager class."""

    def __init__(self, profile: Profile) -> None:
        """Initialize the DID Webvh Manager."""
        self.profile = profile

    def _get_plugin_settings(self):
        return self.profile.settings.get("plugin_config", {}).get("did-webvh", {})

    def _is_author(self):
        """Check if the current agent is the author."""
        return self._get_plugin_settings().get("role") == "author"

    def _get_server_info(self):
        server_url = self._get_plugin_settings().get("server_url")

        if not server_url:
            raise ConfigurationError("Invalid configuration. Check server url is set.")

        return server_url

    def _all_are_not_none(*args):
        return all(v is not None for v in args)

    async def _get_active_endorser_connection(self) -> Optional[ConnRecord]:
        endorser_alias = self._get_server_info() + "-endorser"
        async with self.profile.session() as session:
            connection_records = await ConnRecord.retrieve_by_alias(
                session, endorser_alias
            )

        active_connections = [
            conn for conn in connection_records if conn.state == "active"
        ]

        if len(active_connections) > 0:
            return active_connections[0]

        return None

    async def fetch_jsonl(self, url):
        """Fetch a JSONL file from the given URL."""
        async with ClientSession() as session:
            async with session.get(url, ssl=False) as response:
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
                    ssl=False,
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

    async def _get_or_create_author_key(self, did):
        async with self.profile.session() as session:
            try:
                key_info_author = await MultikeyManager(session).create(
                    alg="ed25519",
                    kid=f"{did}#author",
                )
            except MultikeyManagerError:
                key_info_author = await MultikeyManager(session).from_kid(f"{did}#author")

        return key_info_author

    async def _create_author_signed_document(
        self, did, author_key_info, expiration, domain, challenge
    ):
        async with self.profile.session() as session:
            return await DataIntegrityManager(session).add_proof(
                DIDDocument(
                    context=[
                        "https://www.w3.org/ns/did/v1",
                        "https://w3id.org/security/multikey/v1",
                    ],
                    id=did,
                    authentication=[author_key_info.get("kid")],
                    assertion_method=[author_key_info.get("kid")],
                    verification_method=[
                        {
                            "id": author_key_info.get("kid"),
                            "type": "Multikey",
                            "controller": did,
                            "publicKeyMultibase": author_key_info.get("multikey"),
                        }
                    ],
                ).serialize(),
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{author_key_info.get('multikey')}#{author_key_info.get('multikey')}",
                    expires=expiration,
                    domain=domain,
                    challenge=challenge,
                ),
            )

    async def _endorse_document(
        self, author_secured_document, expiration, domain, challenge
    ):
        role = self._get_plugin_settings().get("role")
        async with self.profile.session() as session:
            # Self endorsement
            if not role or role == "endorser":
                try:
                    # Replace %3A with : is domain is URL encoded
                    if "%3A" in domain:
                        url_decoded_domain = domain.replace("%3A", ":")
                    else:
                        url_decoded_domain = domain

                    key_info_endorser = await MultikeyManager(session).create(
                        kid=url_decoded_domain,
                        alg="ed25519",
                    )
                except (MultikeyManagerError, WalletDuplicateError):
                    key_info_endorser = await MultikeyManager(session).from_kid(
                        url_decoded_domain
                    )
                return await DataIntegrityManager(session).add_proof(
                    author_secured_document,
                    DataIntegrityProofOptions(
                        type="DataIntegrityProof",
                        cryptosuite="eddsa-jcs-2022",
                        proof_purpose="assertionMethod",
                        verification_method=f"did:key:{key_info_endorser.get('multikey')}#{key_info_endorser.get('multikey')}",
                        expires=expiration,
                        domain=domain,
                        challenge=challenge,
                    ),
                )
            # Need proof from endorser agent
            else:
                responder = self.profile.inject(BaseResponder)

                endorser_connection = await self._get_active_endorser_connection()
                if not endorser_connection:
                    raise EndorsementError("No active endorser connection found.")

                await responder.send(
                    message=EndorsementRequest(author_secured_document),
                    connection_id=endorser_connection.connection_id,
                )

    async def _wait_for_endorsement(self, did: str):
        event_bus = self.profile.inject(EventBus)
        with event_bus.wait_for_event(
            self.profile, re.compile(rf"^endorsement_response::{did}$")
        ) as await_event:
            event = await await_event
            return {
                "did_document": event.payload.get("document"),
                "metadata": event.payload.get("metadata"),
            }

    async def create(self, options: dict):
        """Register identities."""

        server_url = self._get_server_info()

        namespace = options.get("namespace")

        if namespace is None:
            raise DidCreationError("Namespace is required.")

        # Generate a random identifier if not provided
        identifier = options.get("identifier", str(uuid4()))

        # Contact the server to request an identifier
        did, challenge, domain, expiration = await self._request_identifier(
            server_url, namespace, identifier
        )

        author_key_info = await self._get_or_create_author_key(did)
        author_secured_document = await self._create_author_signed_document(
            did, author_key_info, expiration, domain, challenge
        )

        result = await self._endorse_document(
            author_secured_document, expiration, domain, challenge
        )

        if isinstance(result, dict):
            return await self.finish_create(
                result, state="success", author_key_info=author_key_info
            )

        try:
            return await asyncio.wait_for(
                self._wait_for_endorsement(did),
                2,
            )
        except asyncio.TimeoutError:
            return {
                "status": "unknown",
                "message": "No immediate response from endorser agent.",
            }

    async def finish_create(
        self,
        endorsed_document: dict,
        state: str = "success",
        author_key_info: Optional[dict] = None,
    ):
        """Finish the creation of a Webvh DID."""

        if state == "posted":
            event_bus = self.profile.inject(EventBus)
            await event_bus.notify(
                self.profile,
                Event(
                    f"endorsement_response::{endorsed_document['id']}",
                    {"document": endorsed_document, "metadata": {"state": "posted"}},
                ),
            )
            return

        if state == "pending":
            event_bus = self.profile.inject(EventBus)
            await event_bus.notify(
                self.profile,
                Event(
                    f"endorsement_response::{endorsed_document['id']}",
                    {"document": endorsed_document, "metadata": {"state": "pending"}},
                ),
            )
            return

        async with ClientSession() as http_session, self.profile.session() as session:
            # Register did document and did with the server
            server_url = self._get_server_info()
            response = await http_session.post(
                server_url,
                json={"didDocument": endorsed_document},
                ssl=False,
            )
            response_json = await response.json()
            if response.status == http.HTTPStatus.BAD_REQUEST:
                raise DidCreationError(response_json.get("detail"))

            log_entry = response_json.get("logEntry")

            if not author_key_info:
                author_key_info = await self._get_or_create_author_key(
                    endorsed_document["id"]
                )

            # Add author proof to the log entry
            signed_log_entry = await DataIntegrityManager(session).add_proof(
                log_entry,
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{author_key_info.get('multikey')}#{author_key_info.get('multikey')}",
                ),
            )

            id_parts = endorsed_document["id"].split(":")
            namespace = id_parts[-2]
            identifier = id_parts[-1]

            # Submit the initial log entry
            response = await http_session.post(
                f"{server_url}/{namespace}/{identifier}",
                json={"logEntry": signed_log_entry},
                ssl=False,
            )
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
                    "verkey": multikey_to_verkey(author_key_info.get("multikey")),
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
            metadata["state"] = "posted"
            await event_bus.notify(
                self.profile,
                Event(
                    f"endorsement_response::{endorsed_document['id']}",
                    {"document": resolved_did_doc["did_document"], "metadata": metadata},
                ),
            )

        return resolved_did_doc

    async def update(self, options: dict, features: dict):
        """Update a Webvh DID."""
        server_url = self._get_server_info()

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

        author_key_info = await self._get_or_create_author_key(
            document_state.document["id"]
        )

        document_state = document_state.create_next(
            document, {}, datetime.now(timezone.utc).replace(microsecond=0)
        )

        async with ClientSession() as http_session, self.profile.session() as session:
            # Submit the log entry
            log_entry = document_state.history_line()
            signed_log_entry = await DataIntegrityManager(session).add_proof(
                log_entry,
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{author_key_info.get('multikey')}#{author_key_info.get('multikey')}",
                ),
            )

            response = await http_session.post(
                f"{server_url}/{namespace}/{identifier}",
                json={"logEntry": signed_log_entry},
                ssl=False,
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
        server_url = self._get_server_info()

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

        author_key_info = await self._get_or_create_author_key(
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
            log_entry = document_state.history_line()
            signed_log_entry = await DataIntegrityManager(session).add_proof(
                log_entry,
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{author_key_info.get('multikey')}#{author_key_info.get('multikey')}",
                ),
            )

            response = await http_session.post(
                f"{server_url}/{namespace}/{identifier}",
                json={"logEntry": signed_log_entry},
                ssl=False,
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

    async def auto_endorsement_setup(self):
        """Automatically set up the endorsement the connection."""
        if not self._is_author():
            return

        # Get the endorser connection is already set up
        if await self._get_active_endorser_connection():
            LOGGER.info("Connected to endorser from previous connection.")
            return

        endorser_invitation = self._get_plugin_settings().get("endorser_invitation")
        if not endorser_invitation:
            LOGGER.info("No endorser invitation, can't create connection automatically.")
            return

        endorser_alias = self._get_server_info() + "-endorser"
        oob_mgr = OutOfBandManager(self.profile)
        try:
            await oob_mgr.receive_invitation(
                invitation=InvitationMessage.from_url(endorser_invitation),
                auto_accept=True,
                alias=endorser_alias,
            )
        except BaseModelError as err:
            raise EndorsementError(f"Error receiving endorser invitation: {err}")

        for _ in range(5):
            if await self._get_active_endorser_connection():
                LOGGER.info("Connected to endorser agent.")
                return
            await asyncio.sleep(1)

        LOGGER.info(
            "No immediate response when trying to connect to endorser agent. You can "
            f"try manually setting up a connection with alias {endorser_alias} or "
            "restart the agent when endorser is available."
        )

    async def save_log_entry(self, log_entry: dict, connection_id: str = None):
        """Save a log entry to the wallet."""
        async with self.profile.session() as session:
            try:
                await session.handle.insert(
                    DOCUMENT_TABLE_NAME,
                    log_entry["id"],
                    value_json=log_entry,
                    tags={
                        "connection_id": connection_id,
                    },
                )
            except AskarError:
                raise EndorsementError("Endorsement entry already pending.")

    async def get_pending(self):
        """Save a log entry to the wallet."""
        async with self.profile.session() as session:
            entries = await session.handle.fetch_all(DOCUMENT_TABLE_NAME)
            return [entry.value_json for entry in entries]

    async def endorse_entry(self, entry_id: str):
        """Endorse a log entry."""
        async with self.profile.session() as session:
            entry = await session.handle.fetch(DOCUMENT_TABLE_NAME, entry_id)

            if entry is None:
                raise EndorsementError("Failed to find pending document.")

            document_json = entry.value_json

            proof = document_json.get("proof")[0]

            domain = proof.get("domain")
            # Replace %3A with : is domain is URL encoded
            if "%3A" in domain:
                url_decoded_domain = domain.replace("%3A", ":")
            else:
                url_decoded_domain = domain

            # Attempt to get the endorsement key for the domain
            if not await MultikeyManager(session).kid_exists(url_decoded_domain):
                # If the key is not found, return an error
                raise EndorsementError(
                    f"Endorsement key not found for domain: {domain}. The administrator "
                    "must add the key to the wallet that matches the key on the server."
                )

            # If the key is found, perform endorsement
            endorsement_key_info = await MultikeyManager(session).from_kid(
                url_decoded_domain
            )
            endorsed_document = await DataIntegrityManager(session).add_proof(
                document_json,
                DataIntegrityProofOptions(
                    type="DataIntegrityProof",
                    cryptosuite="eddsa-jcs-2022",
                    proof_purpose="assertionMethod",
                    verification_method=f"did:key:{endorsement_key_info.get('multikey')}#{endorsement_key_info.get('multikey')}",
                    expires=proof.get("expires"),
                    domain=domain,
                    challenge=proof.get("challenge"),
                ),
            )
            responder = self.profile.inject(BaseResponder)
            await responder.send(
                message=EndorsementResponse(document=endorsed_document, state="posted"),
                connection_id=entry.tags.get("connection_id"),
            )

            await session.handle.remove(DOCUMENT_TABLE_NAME, entry_id)

            return {"status": "success", "message": "Endorsement successful."}
