"""DID Resolver for Cheqd."""

import json
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

from cheqd.cheqd.v1_0.validation import CheqdDID


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
        profile: Profile,
        did: str,
        service_accept: Optional[Sequence[Text]] = None,
    ) -> dict:
        """Resolve a Cheqd DID."""
        async with ClientSession() as session:
            async with session.get(
                self.DID_RESOLVER_BASE_URL + did,
            ) as response:
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

    async def resolve_resource(self, did: str) -> dict:
        """Resolve a Cheqd DID Linked Resource."""
        async with ClientSession() as session:
            async with session.get(
                self.DID_RESOLVER_BASE_URL + did,
            ) as response:
                if response.status == 200:
                    try:
                        return await response.json()
                    except Exception as err:
                        raise ResolverError("Response was incorrectly formatted") from err
                if response.status == 404:
                    raise DIDNotFound(f"No resource found for {did}")
            raise ResolverError(
                "Could not find doc for {}: {}".format(did, await response.text())
            )
