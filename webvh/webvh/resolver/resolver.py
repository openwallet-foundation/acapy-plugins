"""DID Resolver for Cheqd."""

import logging
from dataclasses import dataclass

from acapy_agent.resolver.base import (
    DIDNotFound,
    ResolverError,
)
from aiohttp import ClientSession

LOGGER = logging.getLogger(__name__)


@dataclass
class DIDLinkedResourceWithMetadata:
    """Schema for DID Linked Resource with metadata."""

    resource: dict
    metadata: dict


class DIDWebVHResolver:
    """DID Resolver implementation for did:webvh."""

    def _id_to_url(self, resource_id: str):
        domain = resource_id.split(":")[3]
        path = "/".join(resource_id.split(":")[4:])
        return f"https://{domain}/{path}"

    async def resolve_resource(self, resource_id: str) -> dict:
        """Resolve a WebVH DID Linked Resource and its Metadata."""
        resource_url = self._id_to_url(resource_id)
        LOGGER.info(f"Resolving Resource: id={resource_id}, url={resource_url}")
        async with ClientSession() as session:
            # Fetch the main resource
            response = await session.get(resource_url)
            if response.status == 200:
                try:
                    resource = await response.json()
                except Exception as err:
                    raise ResolverError("Response was incorrectly formatted") from err
            elif response.status == 404:
                raise DIDNotFound(f"No resource found for {resource_id}")
            else:
                raise ResolverError(
                    f"Could not find resource for {resource_id}: {await response.text()}"
                )

        # TODO: Fetch the metadata

        # Validate
        try:
            assert resource.get("@context")
            assert resource.get("type")
            assert resource.get("id")
            assert resource.get("content")
            assert resource.get("metadata")
            assert resource.get("proof")
        except AssertionError as err:
            raise ResolverError("Resource is missing required fields") from err

        attested_resource = resource

        # TODO: Validate the proof
        # proof = resource.pop("proof")
        # proof = proof if isinstance(proof, dict) else proof[0]

        resource_digest = attested_resource.get("metadata").get("resourceId")
        assert resource_digest == resource_url.split("/")[-1].split(".")[0]

        return attested_resource
