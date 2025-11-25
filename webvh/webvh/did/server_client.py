"""A client for interacting with the WebVH server API."""

import http
import json
import logging

from acapy_agent.core.profile import Profile
from aiohttp import ClientConnectionError, ClientResponseError, ClientSession
from did_webvh.core.state import DocumentState

from ..config.config import get_server_url, use_strict_ssl
from .utils import parse_did_key, parse_webvh
from .exceptions import DidCreationError, OperationError
from .utils import all_are_not_none

LOGGER = logging.getLogger(__name__)


class WebVHWatcherClient:
    """A class to handle communication with the WebVH watchers."""

    def __init__(self, profile: Profile):
        """Initialize the WebVHWatcherClient with a profile."""
        self.profile = profile

    async def notify_watchers(self, did: str, watchers: str):
        """Notify watchers."""

        async with ClientSession() as http_session:
            for watcher in watchers:
                await http_session.post(f"{watcher}/log?did={did}")


class WebVHServerClient:
    """A class to handle communication with the WebVH server."""

    def __init__(self, profile: Profile):
        """Initialize the WebVHServerClient with a profile."""
        self.profile = profile

    async def get_document(self):
        """Get the server document."""
        async with ClientSession() as session:
            response = await session.get(
                f"{await get_server_url(self.profile)}/.well-known/did.json"
            )
        return response.json()

    async def get_witness_services(self):
        """Get the witness services from the server document."""
        document = await self.get_document()
        return document.get("service", [])

    async def get_witness_invitation(self, witness_id: str):
        """Get the witness invitation from the server document."""
        witness_services = await self.get_witness_services()
        witness_service = next(
            (svc for svc in witness_services if svc.get("id") == witness_id), None
        )
        if not witness_service:
            raise OperationError(f"Witness {witness_id} not listed by server document.")

        invitation_url = witness_service.get("serviceEndpoint")
        parsed_key = parse_did_key(witness_id)
        if (
            invitation_url
            != f"{await get_server_url(self.profile)}?_oobid={parsed_key.key}"
        ):
            raise OperationError(
                "Witness service endpoint does not match server document."
            )

        async with ClientSession() as session:
            response = await session.get(invitation_url)

        return response.json()

    async def request_identifier(self, namespace, identifier) -> tuple:
        """Contact the webvh server to request an identifier."""
        async with ClientSession() as session:
            try:
                response = await session.get(
                    await get_server_url(self.profile),
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

            parameters = response_json.get("parameters", {})
            method = parameters.get("method", None)

            state = response_json.get("state", {})
            placeholder_id = state.get("id", None)

            proof_options = parameters.get("proof", {})

            if all_are_not_none(parameters, state, placeholder_id, method, proof_options):
                return response_json
            else:
                raise DidCreationError(
                    "Invalid response from Webvh server requesting identifier"
                )

    async def submit_log_entry(self, log_entry, witness_signature):
        """Submit a log entry to the WebVH server."""
        did = log_entry.get("state", {}).get("id")
        parsed = parse_webvh(did)
        async with ClientSession() as session:
            server_url = await get_server_url(self.profile)
            response = await session.post(
                f"{server_url}/{parsed.namespace}/{parsed.identifier}",
                json={"logEntry": log_entry, "witnessSignature": witness_signature},
                ssl=(await use_strict_ssl(self.profile)),
            )

            if response.status == http.HTTPStatus.INTERNAL_SERVER_ERROR:
                raise OperationError("Server had a problem creating log entry.")

            response_json = await response.json()
            if response.status == http.HTTPStatus.BAD_REQUEST:
                raise OperationError(response_json.get("detail"))

        did = log_entry.get("state", {}).get("id", None)
        if response_json.get("state", {}).get("id") != did:
            raise OperationError("Bad state returned")

        return response_json

    async def fetch_jsonl(self, did: str):
        """Fetch a JSONL file from the given URL."""
        parsed = parse_webvh(did)
        async with ClientSession() as session:
            server_url = await get_server_url(self.profile)
            async with session.get(
                f"{server_url}/{parsed.namespace}/{parsed.identifier}/did.jsonl"
            ) as response:
                # Check if the response is OK
                response.raise_for_status()

                # Read the response line by line
                async for line in response.content:
                    # Decode each line and parse as JSON
                    decoded_line = line.decode("utf-8").strip()
                    if decoded_line:  # Ignore empty lines
                        yield json.loads(decoded_line)

    async def fetch_document_state(self, did: str):
        """Fetch a JSONL file from the given URL."""
        # Get the document state from the server
        document_state = None
        try:
            async for line in self.fetch_jsonl(did):
                document_state = DocumentState.load_history_line(line, document_state)
        except ClientResponseError:
            pass
        return document_state

    async def submit_whois(self, vp: dict):
        """Submit a whois Verifiable Presentation for a given identifier."""
        holder_id = vp.get("holder")
        parsed = parse_webvh(holder_id)
        async with ClientSession() as http_session:
            try:
                server_url = await get_server_url(self.profile)
                response = await http_session.post(
                    f"""
                    {server_url}/{parsed.namespace}/{parsed.identifier}/whois
                    """,
                    json={"verifiablePresentation": vp},
                )
            except ClientConnectionError as err:
                raise OperationError(f"Failed to connect to Webvh server: {err}")

            return await response.json()

    async def upload_attested_resource(self, resource: dict):
        """Submit a whois Verifiable Presentation for a given identifier."""
        author_id = resource.get("id").split("/")[0]
        server_url = await get_server_url(self.profile)
        parsed = parse_webvh(author_id)
        async with ClientSession() as http_session:
            try:
                response = await http_session.post(
                    f"{server_url}/{parsed.namespace}/{parsed.identifier}/resources",
                    json={"attestedResource": resource},
                )
            except ClientConnectionError as err:
                raise OperationError(f"Failed to connect to Webvh server: {err}")

            return await response.json()
