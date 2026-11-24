"""Resolver for did:webvh Attested Resources."""

import logging
import urllib.parse
from dataclasses import dataclass
from typing import Optional

import jcs
from acapy_agent.resolver.base import (
    DIDNotFound,
    ResolverError,
)
from aiohttp import ClientSession
from did_webvh.core.did_url import DIDUrl
from did_webvh.core.proof import di_jcs_verify
from did_webvh.core.resolver import reference_map
from did_webvh.resolver import resolve_did
from multiformats import multibase, multihash

LOGGER = logging.getLogger(__name__)

REQUIRED_FIELDS = ("@context", "type", "id", "content", "metadata", "proof")
ATTESTED_RESOURCE_CRYPTOSUITE = "eddsa-jcs-2022"


@dataclass
class DIDLinkedResourceWithMetadata:
    """Schema for DID Linked Resource with metadata."""

    resource: dict
    metadata: dict


def digest_multibase(content) -> str:
    """Calculate the digestMultibase of Attested Resource content."""
    return multibase.encode(
        multihash.digest(jcs.canonicalize(content), "sha2-256"), "base58btc"
    )


class DIDWebVHResolver:
    """Resolver for did:webvh Attested Resources."""

    async def resolve_resource(
        self, resource_id: str, resource_type: Optional[str] = None
    ) -> dict:
        """Resolve and verify a did:webvh Attested Resource.

        The issuer DID is resolved and its log validated, the resource is fetched
        from the DID's files service, and it is accepted only if:

        - its ``id`` is the requested identifier;
        - its ``metadata.resourceId`` and the digest of its ``content`` both match
          the digest at the end of the identifier;
        - its ``metadata.resourceType`` matches ``resource_type``, if given;
        - it carries a valid proof by an assertion method of the issuer DID.

        Args:
            resource_id: The Attested Resource identifier.
            resource_type: The expected resource type, such as ``anonCredsSchema``.

        Returns:
            The verified Attested Resource.

        Raises:
            DIDNotFound: If the issuer DID or the resource can't be found.
            ResolverError: If the resource can't be fetched or fails verification.
        """
        did, path, digest = self._parse_resource_id(resource_id)
        document = await self._resolve_issuer(did)
        resource_url = self._resource_url(document, path)
        LOGGER.info(f"Resolving Resource: id={resource_id}, url={resource_url}")
        resource = await self._fetch(resource_id, resource_url)

        self._check_resource(resource, resource_id, digest, resource_type)
        self._check_issuer_proof(resource, document)

        return resource

    @staticmethod
    def _parse_resource_id(resource_id: str) -> tuple[str, str, str]:
        """Split a resource identifier into its DID, path and digest."""
        try:
            did_url = DIDUrl.decode(resource_id)
        except (ValueError, AttributeError) as err:
            raise ResolverError(f"Invalid resource identifier: {resource_id}") from err
        if (
            did_url.method != "webvh"
            or not did_url.path
            or did_url.query
            or did_url.fragment
        ):
            raise ResolverError(f"Invalid resource identifier: {resource_id}")
        digest = did_url.path.rsplit("/", 1)[-1]
        if not digest:
            raise ResolverError(f"Invalid resource identifier: {resource_id}")
        return did_url.did, did_url.path, digest

    @staticmethod
    async def _resolve_issuer(did: str) -> dict:
        """Resolve the issuer DID, validating its log."""
        try:
            result = await resolve_did(did)
        except Exception as err:
            raise ResolverError(f"Could not resolve issuer DID {did}") from err
        if not result.document:
            error = (result.resolution_metadata or {}).get("error")
            if error == "notFound":
                raise DIDNotFound(f"Issuer DID not found: {did}")
            raise ResolverError(f"Could not resolve issuer DID {did}: {error}")
        if not isinstance(result.document, dict) or result.document.get("id") != did:
            raise ResolverError("Resolved DID document does not match issuer DID")
        return result.document

    @staticmethod
    def _resource_url(document: dict, path: str) -> str:
        """Map the resource path to a URL under the DID's files service."""
        did = document["id"]
        try:
            services = reference_map(document).get("service", {})
        except ValueError as err:
            raise ResolverError(f"Invalid DID document for {did}: {err}") from err
        service = services.get(f"{did}#files")
        endpoint = service.get("serviceEndpoint") if service else None
        if not isinstance(endpoint, str) or urllib.parse.urlparse(endpoint).scheme != (
            "https"
        ):
            raise ResolverError(f"No usable files service for {did}")
        base = endpoint if endpoint.endswith("/") else f"{endpoint}/"
        url = urllib.parse.urljoin(base, path.removeprefix("/"))
        if not url.startswith(base):
            raise ResolverError(f"Resource path is outside the files service of {did}")
        return url

    @staticmethod
    async def _fetch(resource_id: str, resource_url: str) -> dict:
        """Fetch a resource document."""
        async with ClientSession() as session:
            response = await session.get(resource_url)
            if response.status == 200:
                try:
                    return await response.json(content_type=None)
                except Exception as err:
                    raise ResolverError("Response was incorrectly formatted") from err
            elif response.status == 404:
                raise DIDNotFound(f"No resource found for {resource_id}")
            else:
                raise ResolverError(
                    f"Could not find resource for {resource_id}: {await response.text()}"
                )

    @staticmethod
    def _check_resource(
        resource, resource_id: str, digest: str, resource_type: Optional[str]
    ):
        """Check the resource identifier, digest and type."""
        if not isinstance(resource, dict) or not all(
            resource.get(field) for field in REQUIRED_FIELDS
        ):
            raise ResolverError("Resource is missing required fields")

        types = resource["type"]
        types = types if isinstance(types, list) else [types]
        if "AttestedResource" not in types:
            raise ResolverError("Resource is not an AttestedResource")

        if resource["id"] != resource_id:
            raise ResolverError("Resource id does not match the requested identifier")

        metadata = resource["metadata"]
        if not isinstance(metadata, dict) or metadata.get("resourceId") != digest:
            raise ResolverError("Resource metadata.resourceId does not match")

        if digest_multibase(resource["content"]) != digest:
            raise ResolverError("Resource content does not match its digest")

        if resource_type and metadata.get("resourceType") != resource_type:
            raise ResolverError(
                f"Resource type {metadata.get('resourceType')!r} is not {resource_type!r}"
            )

    @staticmethod
    def _check_issuer_proof(resource: dict, document: dict):
        """Require a valid proof by an assertion method of the issuer DID."""
        did = document["id"]

        def absolute(ref: str) -> str:
            return f"{did}{ref}" if ref.startswith("#") else ref

        methods = {}
        for method in document.get("verificationMethod") or []:
            if isinstance(method, dict) and isinstance(method.get("id"), str):
                methods[absolute(method["id"])] = method
        assertion_methods = set()
        for ref in document.get("assertionMethod") or []:
            if isinstance(ref, dict) and isinstance(ref.get("id"), str):
                methods[absolute(ref["id"])] = ref
                assertion_methods.add(absolute(ref["id"]))
            elif isinstance(ref, str):
                assertion_methods.add(absolute(ref))

        proofs = resource["proof"]
        proofs = proofs if isinstance(proofs, list) else [proofs]
        for proof in proofs:
            if not isinstance(proof, dict):
                continue
            method_id = proof.get("verificationMethod")
            if not isinstance(method_id, str):
                continue
            method_id = absolute(method_id)
            if (
                proof.get("cryptosuite") != ATTESTED_RESOURCE_CRYPTOSUITE
                or proof.get("proofPurpose") != "assertionMethod"
                or method_id not in assertion_methods
                or method_id not in methods
            ):
                # Not an issuer proof, such as a witness proof
                continue
            try:
                di_jcs_verify(resource, proof, methods[method_id])
            except Exception as err:
                LOGGER.info(f"Attested resource proof failed to verify: {err}")
                continue
            return

        raise ResolverError(
            "Resource is not signed by an assertion method of its issuer DID"
        )
