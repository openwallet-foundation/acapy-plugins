"""DID Resolver for Cheqd."""

import json
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
from pydantic import BaseModel, ValidationError
from pydid import DIDDocument

from ..validation import CheqdDID


@dataclass
class DIDLinkedResourceWithMetadata:
    """Schema for DID Linked Resource with metadata."""

    resource: dict
    metadata: dict


class DIDUrlDereferencingResult(BaseModel):
    """DID Url Dereferencing Result with Metadata."""

    contentStream: dict
    contentMetadata: dict

    class Config:
        """Pydantic config."""

        extra = "allow"


DID_RESOLUTION_HEADER = "application/ld+json;profile=https://w3id.org/did-resolution"
DID_URL_DEREFERENCING_HEADER = (
    "application/ld+json;profile=https://w3id.org/did-url-dereferencing"
)


class CheqdDIDResolver(BaseDIDResolver):
    """DID Resolver implementation for did:cheqd."""

    DID_RESOLVER_BASE_URL = "http://localhost:8080/1.0/identifiers/"

    def __init__(self, resolver_url: str = None):
        """Initialize Cheqd Resolver."""
        super().__init__(ResolverType.NATIVE)
        if resolver_url:
            self.DID_RESOLVER_BASE_URL = resolver_url

    async def setup(self, context: InjectionContext):
        """Perform required setup for Cheqd DID resolution."""

    @property
    def supported_did_regex(self) -> Pattern:
        """Return supported_did_regex of Cheqd DID Resolver."""
        return CheqdDID.PATTERN

    async def _resolve(
        self,
        _profile: Profile,
        did: str,
        service_accept: Optional[Sequence[Text]] = None,
    ) -> dict:
        """Retrieve doc and return with resolver.

        This private method enables the public resolve and resolve_with_metadata
        methods to share the same logic.
        """
        headers = {}
        if service_accept:
            # Convert the Sequence[Text] to a dictionary for headers
            headers = dict(item.split(": ", 1) for item in service_accept)
        async with ClientSession() as session:
            async with session.get(
                self.DID_RESOLVER_BASE_URL + did,
                headers=headers,
            ) as response:
                if response.status == 200:
                    try:
                        resolver_resp = await response.json()
                        return resolver_resp
                    except Exception as err:
                        raise ResolverError("Response was incorrectly formatted") from err
                if response.status == 404:
                    raise DIDNotFound(f"No document found for {did}")
            raise ResolverError(
                "Could not find doc for {}: {}".format(did, await response.text())
            )

    async def resolve(
        self,
        profile: Profile,
        did: str,
        service_accept: Optional[Sequence[Text]] = None,
    ) -> dict:
        """Resolve a DID."""
        resolver_resp = await self._resolve(profile, did, service_accept)

        did_doc_resp = resolver_resp.get("didDocument")
        did_doc_metadata = resolver_resp.get("didDocumentMetadata")

        try:
            did_doc = DIDDocument.from_json(json.dumps(did_doc_resp))
            result = did_doc.serialize()
            # Check if 'deactivated' field is present in didDocumentMetadata
            if did_doc_metadata and did_doc_metadata.get("deactivated") is True:
                result["deactivated"] = True
            return result
        except Exception as err:
            raise ResolverError("Response was incorrectly formatted") from err

    async def dereference_with_metadata(
        self, profile: Profile, did_url: str
    ) -> DIDLinkedResourceWithMetadata:
        """Resolve a Cheqd DID Linked Resource and its Metadata."""
        # Fetch the main resource
        result = await self._resolve(
            profile, did_url, [f"Accept: {DID_URL_DEREFERENCING_HEADER}"]
        )
        try:
            validated_resp = DIDUrlDereferencingResult(**result)
            return DIDLinkedResourceWithMetadata(
                resource=validated_resp.contentStream,
                metadata=validated_resp.contentMetadata,
            )
        except ValidationError:
            raise ResolverError("DidUrlDereferencing result was incorrectly formatted")
