"""DID Webvh Registry."""

import re
import logging
import requests
import jcs
from multiformats import multibase, multihash

from typing import Optional, Pattern, Sequence

from acapy_agent.anoncreds.base import (
    AnonCredsResolutionError,
    AnonCredsRegistrationError,
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
)
from acapy_agent.anoncreds.models.credential_definition import (
    CredDef,
    CredDefResult,
    CredDefValue,
    CredDefState,
    GetCredDefResult,
)
from acapy_agent.anoncreds.models.revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevRegDef,
    RevRegDefResult,
    RevRegDefState,
)
from acapy_agent.anoncreds.models.schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)
from acapy_agent.anoncreds.models.schema_info import AnoncredsSchemaInfo
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.vc.data_integrity.manager import (
    DataIntegrityManager,
    DataIntegrityManagerError,
)
from acapy_agent.vc.data_integrity.models.options import DataIntegrityProofOptions
from ..resolver.resolver import DIDWebVHResolver
from ..validation import WebVHDID
# from ..models.resources import AttestedResource

LOGGER = logging.getLogger(__name__)


class DIDWebVHRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """DIDWebvhRegistry."""

    resolver: DIDWebVHResolver

    def __init__(self):
        """Initialize an instance.

        Args:
            None

        """
        self._supported_identifiers_regex = WebVHDID.PATTERN

        self.resolver = DIDWebVHResolver()
        self.service_endpoint = None
        self.proof_options = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "assertionMethod",
        }

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported Identifiers Regular Expression."""
        return WebVHDID.PATTERN

    @staticmethod
    def _digest_multibase(resource_content) -> str:
        """Supported Identifiers Regular Expression."""
        digest_multihash = multihash.digest(
            jcs.canonicalize(resource_content), "sha2-256"
        )
        digest_multibase = multibase.encode(digest_multihash, "base58btc")
        return digest_multibase

    async def setup(self, context: InjectionContext):
        """Setup."""
        print("Successfully registered DIDWebVHRegistry")

    async def get_schema(self, profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        try:
            resource = await self.resolver.resolve_resource(schema_id)
        except:
            raise AnonCredsResolutionError("Error resolving resource")

        try:
            anoncreds_schema = AnonCredsSchema(
                issuer_id=resource["resourceContent"]["issuerId"],
                attr_names=resource["resourceContent"]["attrNames"],
                name=resource["resourceContent"]["name"],
                version=resource["resourceContent"]["version"],
            )
        except:
            raise AnonCredsResolutionError("Resource returned not an anoncreds schema")

        return GetSchemaResult(
            schema_id=schema_id,
            schema=anoncreds_schema,
            schema_metadata=resource["resourceMetadata"],
            resolution_metadata={},
        )

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""

        metadata = {
            "resource_id": self._digest_multibase(schema.serialize()),
            "resource_type": "anonCredsSchema",
            "resource_name": schema.name,
        }

        resource = await self._create_and_publish_resource(
            profile=profile,
            issuer_id=schema.issuer_id,
            resource_metadata=metadata,
            resource_content=schema.serialize(),
            options=options,
        )

        return SchemaResult(
            # job_id=None,
            schema_state=SchemaState(
                state=SchemaState.STATE_FINISHED,
                schema_id=resource.get("id"),
                schema=schema,
            ),
            registration_metadata=metadata,
        )

    async def get_credential_definition(
        self, profile: Profile, credential_definition_id: str
    ) -> GetCredDefResult:
        """Get a credential definition from the registry."""
        resource = await self.resolver.resolve_resource(credential_definition_id)

        anoncreds_credential_definition = CredDef(
            issuer_id=credential_definition_id.split("/")[0],
            schema_id=resource["resourceContent"]["schemaId"],
            type=resource["resourceContent"]["type"],
            tag=resource["resourceContent"]["tag"],
            value=CredDefValue.deserialize(resource["resourceContent"]["value"]),
        )

        return GetCredDefResult(
            credential_definition_id=credential_definition_id,
            credential_definition=anoncreds_credential_definition,
            credential_definition_metadata=resource["resourceMetadata"],
            resolution_metadata={},
        )

    async def register_credential_definition(
        self,
        profile: Profile,
        schema: GetSchemaResult,
        credential_definition: CredDef,
        options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""

        metadata = {
            "resource_id": self._digest_multibase(credential_definition.serialize()),
            "resource_type": "anonCredsCredDef",
            "resource_name": credential_definition.tag,
        }

        resource = await self._create_and_publish_resource(
            profile=profile,
            issuer_id=schema.schema.issuer_id,
            resource_metadata=metadata,
            resource_content=credential_definition.serialize(),
            options=options,
        )

        return CredDefResult(
            # job_id=None,
            credential_definition_state=CredDefState(
                state=CredDefState.STATE_FINISHED,
                credential_definition_id=resource.get("id"),
                credential_definition=credential_definition,
            ),
            registration_metadata=metadata,
            credential_definition_metadata={},
        )

    async def get_revocation_registry_definition(
        self, profile: Profile, revocation_registry_id: str
    ) -> GetRevRegDefResult:
        """Get a revocation registry definition from the registry."""
        resource = await self.resolver.resolve_resource(revocation_registry_id)

        anoncreds_revocation_registry_definition = RevRegDef(
            issuer_id=revocation_registry_id.split("/")[0],
            cred_def_id=resource["resourceContent"]["credDefId"],
            type=resource["resourceContent"]["revocDefType"],
            tag=resource["resourceContent"]["tag"],
            value=resource["resourceContent"]["value"],
        )

        return GetRevRegDefResult(
            revocation_registry_id=revocation_registry_id,
            revocation_registry=anoncreds_revocation_registry_definition,
            revocation_registry_metadata=resource["resourceMetadata"],
            resolution_metadata={},
        )

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""

        metadata = {
            "resource_id": self._digest_multibase(
                revocation_registry_definition.serialize()
            ),
            "resource_type": "anonCredsRevocRegDef",
            "resource_name": revocation_registry_definition.tag,
        }

        resource = await self._create_and_publish_resource(
            profile=profile,
            issuer_id=revocation_registry_definition.issuer_id,
            resource_metadata=metadata,
            resource_content=revocation_registry_definition.serialize(),
            options=options,
        )

        return RevRegDefResult(
            # job_id=None,
            revocation_registry_definition_state=RevRegDefState(
                state=RevRegDefState.STATE_FINISHED,
                revocation_registry_definition_id=resource.get("id"),
                revocation_registry_definition=revocation_registry_definition,
            ),
            registration_metadata=metadata,
            revocation_registry_definition_metadata={},
        )

    async def get_revocation_list(
        self, profile: Profile, revocation_registry_id: str, timestamp: int
    ) -> GetRevListResult:
        """Get a revocation list from the registry."""
        raise NotImplementedError()

    async def register_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_list: RevList,
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""
        raise NotImplementedError()

    async def update_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        prev_list: RevList,
        curr_list: RevList,
        revoked: Sequence[int],
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Update a revocation list on the registry."""
        raise NotImplementedError()

    async def get_schema_info_by_id(
        self, profile: Profile, schema_id: str
    ) -> AnoncredsSchemaInfo:
        """Get a schema info from the registry."""
        resource = await self.resolver.resolve_resource(schema_id)
        schema = resource.get("resourceContent")
        return AnoncredsSchemaInfo(
            issuer_id=schema["issuerId"],
            name=schema["name"],
            version=schema["version"],
        )

    async def _create_and_publish_resource(
        self, profile, issuer_id, resource_content, resource_metadata, options
    ) -> dict:  # AttestedResource:
        """Derive attested resource object from content and publish."""

        # Ensure a service endpoint is set
        if not options.get("serviceEndpoint"):
            raise AnonCredsRegistrationError("Missing service endpoint")
        self.service_endpoint = options.get("serviceEndpoint")

        # Ensure a verification method is set
        if not options.get("verificationMethod"):
            raise AnonCredsRegistrationError("Missing verification method")
        self.proof_options["verificationMethod"] = options.get("verificationMethod")

        # Ensure content digest is accurate
        if resource_metadata.get("resource_id") != self._digest_multibase(
            resource_content
        ):
            raise AnonCredsRegistrationError("Digest mismatch")
        content_digest = resource_metadata.get("resource_id")

        # Create resource object
        resource = {
            "@context": ["https://w3id.org/security/data-integrity/v2"],
            "type": ["AttestedResource"],
            "id": f"{issuer_id}/resources/{content_digest}",
            "resourceContent": resource_content,
            "resourceMetadata": {
                "resourceId": resource_metadata.get("resource_id"),
                "resourceType": resource_metadata.get("resource_type"),
                "resourceName": resource_metadata.get("resource_name"),
            },
        }
        # attested_resource = AttestedResource(
        #         id=f'{issuer_id}/resources/{content_digest}',
        #         resourceContent=resource_content,
        #         resourceMetadata={
        #             'resourceId': content_digest,
        #             'resourceType': resource_type
        #         }
        #     )
        
        # Secure resource with a Data Integrity proof
        try:
            async with profile.session() as session:
                secured_resource = await DataIntegrityManager(session).add_proof(
                    resource, DataIntegrityProofOptions.deserialize(self.proof_options)
                )
            if not secured_resource.get("proof"):
                raise AnonCredsRegistrationError("Unable to attach proof")

            # TODO, server currently expect a proof object, not a proof set (array)
            secured_resource["proof"] = secured_resource["proof"][0]
        except:
            raise AnonCredsRegistrationError("Error securing resource")

        # Upload secured resource to server with metadata
        try:
            r = requests.post(
                self.service_endpoint,
                json={
                    "securedResource": secured_resource,
                    "options": {
                        "resourceId": resource_metadata["resourceId"],
                        "resourceType": resource_metadata["resourceType"],
                    },
                },
            )
            if r.status_code != 201:
                raise AnonCredsRegistrationError(
                    "Invalid status code returned by service endpoint"
                )

        except:
            # raise AnonCredsRegistrationError("Error uploading resource")
            raise AnonCredsRegistrationError(r.text)

        return secured_resource
