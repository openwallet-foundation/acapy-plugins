"""A client for interacting with the WebVH server API."""

import http
import json

from acapy_agent.core.profile import Profile
from aiohttp import ClientConnectionError, ClientResponseError, ClientSession
from did_webvh.core.state import DocumentState

from ..config.config import get_server_url, use_strict_ssl
from .exceptions import DidCreationError, OperationError
from .utils import all_are_not_none


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

            did_document = response_json.get("didDocument", {})
            did = did_document.get("id")

            proof_options = response_json.get("proofOptions", {})
            challenge = proof_options.get("challenge")
            domain = proof_options.get("domain")
            expiration = proof_options.get("expires")

            if all_are_not_none(did, challenge, domain, expiration):
                return did_document, proof_options
            else:
                raise DidCreationError(
                    "Invalid response from Webvh server requesting identifier"
                )

    async def register_did_doc(self, registration_document):
        """Register a DID document and did with the WebVH server."""
        async with ClientSession() as session:
            # Register did document and did with the server
            response = await session.post(
                await get_server_url(self.profile),
                json={"didDocument": registration_document},
                ssl=(await use_strict_ssl(self.profile)),
            )
            response_json = await response.json()
            if response.status == http.HTTPStatus.BAD_REQUEST:
                raise DidCreationError(response_json.get("detail"))

    async def submit_log_entry(self, log_entry, namespace, identifier):
        """Submit an initial log entry to the WebVH server."""
        async with ClientSession() as session:
            response = await session.post(
                f"{await get_server_url(self.profile)}/{namespace}/{identifier}",
                json={"logEntry": log_entry},
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
