"""A client for interacting with the WebVH server API."""

import asyncio
import http
import json
import logging

from operator import itemgetter

from acapy_agent.core.profile import Profile
from aiohttp import (
    ClientConnectionError,
    ClientResponseError,
    ClientSession,
    ClientTimeout,
    ServerTimeoutError,
)
from did_webvh.core.state import DocumentState

from ..config.config import get_server_url, use_strict_ssl
from .exceptions import DidCreationError, OperationError
from .utils import all_are_not_none

LOGGER = logging.getLogger(__name__)

# Total wait sits above the common 30s proxy cut so we observe the reset, then
# recover with GET rather than aborting while the server is still writing.
HTTP_TIMEOUT = ClientTimeout(total=45, connect=10, sock_connect=10)


def _already_exists(body) -> bool:
    """Return True if a 409/error body reports a duplicate resource."""
    if isinstance(body, dict):
        detail = body.get("detail", body)
        text = detail if isinstance(detail, str) else json.dumps(detail)
    else:
        text = str(body)
    return "already exists" in text.lower()


def _as_attested_resource(parsed, expected_id: str) -> dict | None:
    """Return parsed JSON only if it is the attested resource for expected_id.

    Empty objects, proxy 200s, and unrelated JSON must not count as a stored
    resource (that would report STATE_FINISHED and 404 later).
    """
    if not expected_id or not isinstance(parsed, dict) or not parsed:
        return None
    if parsed.get("id") != expected_id:
        return None
    if not isinstance(parsed.get("content"), dict):
        return None
    return parsed


class WebVHWatcherClient:
    """A class to handle communication with the WebVH watchers."""

    def __init__(self, profile: Profile):
        """Initialize the WebVHWatcherClient with a profile."""
        self.profile = profile

    async def notify_watchers(self, did: str, watchers: str):
        """Notify watchers."""

        async with ClientSession(timeout=HTTP_TIMEOUT) as http_session:
            for watcher in watchers:
                async with http_session.post(f"{watcher}/log?did={did}") as response:
                    await response.read()


class WebVHServerClient:
    """A class to handle communication with the WebVH server."""

    def __init__(self, profile: Profile):
        """Initialize the WebVHServerClient with a profile."""
        self.profile = profile

    async def _ssl(self):
        """SSL verification flag for outbound requests."""
        return await use_strict_ssl(self.profile)

    async def _read_response(self, response):
        """Read response text once; parse JSON when advertised."""
        raw = await response.text()
        parsed = None
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type and raw:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = None
        return raw, parsed

    async def request_identifier(self, namespace, identifier) -> tuple:
        """Contact the webvh server to request an identifier."""
        async with ClientSession(timeout=HTTP_TIMEOUT) as session:
            try:
                async with session.get(
                    await get_server_url(self.profile),
                    params={
                        "namespace": namespace,
                        "identifier": identifier,
                    },
                    ssl=(await self._ssl()),
                ) as response:
                    response_json = await response.json()
            except (
                ClientConnectionError,
                asyncio.TimeoutError,
                ServerTimeoutError,
            ) as err:
                raise DidCreationError(
                    f"Failed to connect to Webvh server: {err}"
                ) from err

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
        namespace, identifier = itemgetter(4, 5)(did.split(":"))
        async with ClientSession(timeout=HTTP_TIMEOUT) as session:
            async with session.post(
                f"{await get_server_url(self.profile)}/{namespace}/{identifier}",
                json={"logEntry": log_entry, "witnessSignature": witness_signature},
                ssl=(await self._ssl()),
            ) as response:
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
        namespace, identifier = itemgetter(4, 5)(did.split(":"))
        async with ClientSession(timeout=HTTP_TIMEOUT) as session:
            async with session.get(
                f"{await get_server_url(self.profile)}"
                f"/{namespace}/{identifier}/did.jsonl",
                ssl=(await self._ssl()),
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
        namespace, identifier = itemgetter(4, 5)(holder_id.split(":"))
        async with ClientSession(timeout=HTTP_TIMEOUT) as http_session:
            try:
                async with http_session.post(
                    f"""
                    {await get_server_url(self.profile)}/{namespace}/{identifier}/whois
                    """,
                    json={"verifiablePresentation": vp},
                    ssl=(await self._ssl()),
                ) as response:
                    return await response.json()
            except (
                ClientConnectionError,
                asyncio.TimeoutError,
                ServerTimeoutError,
            ) as err:
                raise OperationError(f"Failed to connect to Webvh server: {err}") from err

    def _derive_update_url(self, server_url: str, resource_id: str) -> str:
        """Derive full URL for updating an existing resource. Uses server_url as base."""
        parts = resource_id.split(":")
        namespace = parts[4] if len(parts) > 4 else ""
        identifier_part = parts[5] if len(parts) > 5 else ""
        identifier = (
            identifier_part.split("/")[0] if "/" in identifier_part else identifier_part
        )
        digest = resource_id.split("/")[-1] if "/" in resource_id else ""
        base = server_url.rstrip("/")
        return f"{base}/{namespace}/{identifier}/resources/{digest}"

    async def get_attested_resource(self, resource_id: str) -> dict | None:
        """GET an attested resource by id.

        Return the resource only when status is 200 and the body is that
        resource (matching id and content). Empty or unrelated JSON is None.
        """
        if not resource_id:
            return None
        server_url = (await get_server_url(self.profile)).rstrip("/")
        url = self._derive_update_url(server_url, resource_id)
        try:
            async with ClientSession(timeout=HTTP_TIMEOUT) as session:
                async with session.get(url, ssl=(await self._ssl())) as response:
                    if response.status == http.HTTPStatus.NOT_FOUND:
                        return None
                    if response.status == http.HTTPStatus.OK:
                        _raw, parsed = await self._read_response(response)
                        stored = _as_attested_resource(parsed, resource_id)
                        if stored is None:
                            LOGGER.warning(
                                "GET 200 for attested resource %s was empty or "
                                "not that resource; treating as missing",
                                resource_id,
                            )
                        return stored
                    LOGGER.warning(
                        "Unexpected status %s fetching attested resource %s",
                        response.status,
                        resource_id,
                    )
                    return None
        except (
            ClientConnectionError,
            asyncio.TimeoutError,
            ServerTimeoutError,
        ) as err:
            LOGGER.warning("Failed to GET attested resource %s: %s", resource_id, err)
            return None

    async def _finish_upload_response(self, response, resource: dict):
        """Interpret POST/PUT status: success, idempotent conflict, or error.

        200/201 with a matching resource body succeed. Empty 200/201 and 409
        succeed only after GET confirms the digest we signed.
        """
        resource_id = resource.get("id", "")
        raw, parsed = await self._read_response(response)
        if response.status in (http.HTTPStatus.OK, http.HTTPStatus.CREATED):
            stored = _as_attested_resource(parsed, resource_id)
            if stored is not None:
                return stored
            confirmed = await self.get_attested_resource(resource_id)
            if confirmed is not None:
                return confirmed
            raise OperationError(
                f"WebVH server error uploading attested resource: "
                f"status={response.status} body={parsed if parsed is not None else raw}"
            )
        if response.status == http.HTTPStatus.CONFLICT or (
            response.status >= 400
            and _already_exists(parsed if parsed is not None else raw)
        ):
            confirmed = await self.get_attested_resource(resource_id)
            if confirmed is not None:
                return confirmed
        raise OperationError(
            f"WebVH server error uploading attested resource: "
            f"status={response.status} body={parsed if parsed is not None else raw}"
        )

    async def upload_attested_resource(self, resource: dict, *, _replayed: bool = False):
        """Upload an attested resource.

        PUT for rev reg def updates (has links), else POST. Retries with PUT if POST
        returns 500 (resource may already exist). On timeout, GET the digest then
        replay the same payload once so ACA-Py does not mint a new resource id.
        """
        resource_id = resource.get("id", "")
        author_id = resource_id.split("/")[0]
        server_url = (await get_server_url(self.profile)).rstrip("/")
        namespace, identifier = itemgetter(4, 5)(author_id.split(":"))
        metadata = resource.get("metadata", {})
        use_put = metadata.get("resourceType") == "anonCredsRevocRegDef" and bool(
            resource.get("links")
        )
        put_url = self._derive_update_url(server_url, resource_id)
        put_payload = {
            "attestedResource": resource,
            "options": {
                "resourceId": metadata.get("resourceId"),
                "resourceType": metadata.get("resourceType"),
            },
        }
        post_url = f"{server_url}/{namespace}/{identifier}/resources"
        ssl = await self._ssl()

        try:
            async with ClientSession(timeout=HTTP_TIMEOUT) as http_session:
                if use_put:
                    async with http_session.put(
                        put_url, json=put_payload, ssl=ssl
                    ) as response:
                        return await self._finish_upload_response(response, resource)
                async with http_session.post(
                    post_url, json={"attestedResource": resource}, ssl=ssl
                ) as response:
                    if response.status == http.HTTPStatus.INTERNAL_SERVER_ERROR:
                        async with http_session.put(
                            put_url, json=put_payload, ssl=ssl
                        ) as put_response:
                            return await self._finish_upload_response(
                                put_response, resource
                            )
                    return await self._finish_upload_response(response, resource)
        except (
            ClientConnectionError,
            asyncio.TimeoutError,
            ServerTimeoutError,
        ) as err:
            stored = await self.get_attested_resource(resource_id)
            if stored is not None:
                LOGGER.info(
                    "Upload timed out but resource %s is present on the server",
                    resource_id,
                )
                return stored
            if not _replayed and not use_put:
                LOGGER.info("Replaying attested resource POST for %s", resource_id)
                return await self.upload_attested_resource(resource, _replayed=True)
            raise OperationError(f"Failed to connect to Webvh server: {err}") from err
