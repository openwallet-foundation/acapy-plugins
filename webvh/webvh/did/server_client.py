"""A client for interacting with the WebVH server API."""

import http
import json
import logging

from acapy_agent.core.profile import Profile
from aiohttp import ClientConnectionError, ClientResponseError, ClientSession
from did_webvh.core.state import DocumentState

from ..config.config import get_server_url, use_strict_ssl
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

    async def submit_log_entry(self, log_entry, witness_signature, namespace, identifier):
        """Submit an initial log entry to the WebVH server."""
        async with ClientSession() as session:
            response = await session.post(
                f"{await get_server_url(self.profile)}/{namespace}/{identifier}",
                json={"logEntry": log_entry, "witnessSignature": witness_signature},
                ssl=(await use_strict_ssl(self.profile)),
            )

            if response.status == http.HTTPStatus.INTERNAL_SERVER_ERROR:
                raise DidCreationError("Server had a problem creating log entry.")

            response_json = await response.json()
            if response.status == http.HTTPStatus.BAD_REQUEST:
                raise DidCreationError(response_json.get("detail"))

        return response_json

    async def deactivate_did(
        self, namespace: str, identifier: str, signed_log_entry: dict
    ):
        """Deactivate a DID by sending a request to the WebVH server."""
        async with ClientSession() as session:
            response = await session.delete(
                f"{await get_server_url(self.profile)}/{namespace}/{identifier}",
                json={"logEntry": signed_log_entry},
                ssl=(await use_strict_ssl(self.profile)),
            )

            response_json = await response.json()

            if response_json.get("detail") == "Key unauthorized.":
                raise DidCreationError("Problem creating log entry: Key unauthorized.")

    async def fetch_jsonl(self, namespace: str, identifier: str):
        """Fetch a JSONL file from the given URL."""
        async with ClientSession() as session:
            async with session.get(
                f"{await get_server_url(self.profile)}/{namespace}/{identifier}/did.jsonl"
            ) as response:
                # Check if the response is OK
                response.raise_for_status()

                # Read the response line by line
                async for line in response.content:
                    # Decode each line and parse as JSON
                    decoded_line = line.decode("utf-8").strip()
                    if decoded_line:  # Ignore empty lines
                        yield json.loads(decoded_line)

    async def fetch_document_state(self, namespace: str, identifier: str):
        """Fetch a JSONL file from the given URL."""
        # Get the document state from the server
        document_state = None
        try:
            async for line in self.fetch_jsonl(namespace, identifier):
                document_state = DocumentState.load_history_line(line, document_state)
        except ClientResponseError:
            pass
        return document_state

    async def submit_whois(self, namespace: str, identifier: str, vp: dict):
        """Submit a whois Verifiable Presentation for a given identifier."""
        async with ClientSession() as http_session:
            try:
                response = await http_session.post(
                    f"""
                    {await get_server_url(self.profile)}/{namespace}/{identifier}/whois
                    """,
                    json={"verifiablePresentation": vp},
                )
            except ClientConnectionError as err:
                raise OperationError(f"Failed to connect to Webvh server: {err}")

            return await response.json()

    async def upload_attested_resource(
        self,
        namespace: str,
        identifier: str,
        resource: dict,
    ):
        """Submit a whois Verifiable Presentation for a given identifier."""
        server_url = await get_server_url(self.profile)
        async with ClientSession() as http_session:
            try:
                response = await http_session.post(
                    f"{server_url}/{namespace}/{identifier}/resources",
                    json={"attestedResource": resource},
                )
            except ClientConnectionError as err:
                raise OperationError(f"Failed to connect to Webvh server: {err}")

            return await response.json()
