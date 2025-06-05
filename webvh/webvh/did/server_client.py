"""A client for interacting with the WebVH server API."""

import http

from acapy_agent.core.profile import Profile
from aiohttp import ClientConnectionError, ClientSession

from ..config.config import get_server_url, use_strict_ssl
from .exceptions import DidCreationError
from .utils import all_are_not_none


class WebVHServerClient:
    """A class to handle communication with the WebVH server."""

    def __init__(self, profile: Profile):
        """Initialize the WebVHServerClient with a profile."""
        self.profile = profile

    async def request_identifier(self, namespace, identifier) -> tuple:
        """Contact the trust did web server to request an identifier."""
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

    async def submit_initial_log_entry(self, log_entry, namespace, identifier):
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
