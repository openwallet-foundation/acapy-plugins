"""DID Resolver for Cheqd."""

import json
import logging
from dataclasses import dataclass
from typing import Optional, Pattern, Sequence, Text

from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.resolver.base import (
    BaseDIDResolver,
    DIDNotFound,
    ResolverError,
    ResolverType,
)
from aiohttp import ClientSession
from pydid import DIDDocument

from ..validation import WebVHDID

LOGGER = logging.getLogger(__name__)

@dataclass
class DIDLinkedResourceWithMetadata:
    """Schema for DID Linked Resource with metadata."""

    resource: dict
    metadata: dict


class DIDWebVHResolver(BaseDIDResolver):
    """DID Resolver implementation for did:webvh."""

    def __init__(self):
        """Initialize WebVH Resolver."""
        super().__init__(ResolverType.NATIVE)
    
    def _did_to_url(self, did: str):
        domain = did.split(':')[3]
        path = '/'.join(did.split(':')[4:])
        return f'https://{domain}/{path}/did.json'
    
    def _id_to_url(self, resource_id: str):
        domain = resource_id.split(':')[3]
        path = '/'.join(resource_id.split(':')[4:])
        return f'https://{domain}/{path}'

    async def setup(self, context: InjectionContext):
        """Perform required setup for WebVH DID resolution."""

    @property
    def supported_did_regex(self) -> Pattern:
        """Return supported_did_regex of WebVH DID Resolver."""
        return WebVHDID.PATTERN

    async def _resolve(
        self,
        _profile: Profile,
        did: str,
        service_accept: Optional[Sequence[Text]] = None,
    ) -> dict:
        """Resolve a WebVH DID."""
        did_url = self._did_to_url(did)
        async with ClientSession() as session:
            async with session.get(did_url) as response:
                if response.status == 200:
                    try:
                        # Validate DIDDoc with pyDID
                        resolver_resp = await response.json()
                        did_doc_resp = resolver_resp.get("didDocument")
                        did_doc_metadata = resolver_resp.get("didDocumentMetadata")

                        did_doc = DIDDocument.from_json(json.dumps(did_doc_resp))
                        result = did_doc.serialize()
                        # Check if 'deactivated' field is present in didDocumentMetadata
                        if (
                            did_doc_metadata
                            and did_doc_metadata.get("deactivated") is True
                        ):
                            result["deactivated"] = True
                        return result
                    except Exception as err:
                        raise ResolverError("Response was incorrectly formatted") from err
                if response.status == 404:
                    raise DIDNotFound(f"No document found for {did}")
            raise ResolverError(
                "Could not find doc for {}: {}".format(did, await response.text())
            )

    async def resolve_resource(self, resource_id: str) -> dict:
        """Resolve a WebVH DID Linked Resource and its Metadata."""
        LOGGER.warning("Resolving Resource")
        LOGGER.warning(resource_id)
        resource_url = self._id_to_url(resource_id)
        LOGGER.warning(resource_url)
        async with ClientSession() as session:
            # Fetch the main resource
            async with session.get(resource_url) as response:
                LOGGER.warning(response.status)
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

        # Fetch the metadata
        metadata = {}

        # Validate
        assert resource.get('@context')
        assert resource.get('type')
        assert resource.get('id')
        assert resource.get('resourceContent')
        assert resource.get('resourceMetadata')
        assert resource.get('proof')
    
        attested_resource = resource
        
        proof = resource.pop('proof')
        proof = proof if isinstance(proof, dict) else proof[0]
        
        resource_digest = attested_resource.get('resourceMetadata').get('resourceId')
        assert resource_digest == resource_url.split('/')[-1].split('.')[0]
        
        return attested_resource
    