"""DID Webvh Registry."""

import re
import requests
import jcs
from multiformats import multibase, multihash

from typing import Optional, Pattern, Sequence

from acapy_agent.anoncreds.base import BaseAnonCredsRegistrar, BaseAnonCredsResolver
from acapy_agent.anoncreds.models.credential_definition import (
    CredDef,
    CredDefResult,
    CredDefValue,
    GetCredDefResult,
)
from acapy_agent.anoncreds.models.revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevList,
    RevListResult,
    RevRegDef,
    RevRegDefResult,
)
from acapy_agent.anoncreds.models.schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState
)
from acapy_agent.anoncreds.models.schema_info import AnoncredsSchemaInfo
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.vc.data_integrity.manager import DataIntegrityManager, DataIntegrityManagerError
from ..resolver.resolver import DIDWebVHResolver
from ..validation import WebVHDID
# from ..models.resources import AttestedResource


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
        self.proof_options = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "proofPurpose": "assertionMethod",
        }

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported Identifiers Regular Expression."""
        return WebVHDID.PATTERN

    @property
    def _digest_multibase(self, resource_content) -> str:
        """Supported Identifiers Regular Expression."""
        digest_multihash = multihash.digest(jcs.canonicalize(resource_content), "sha2-256")
        digest_multibase = multibase.encode(digest_multihash, "base58btc")
        return digest_multibase
        
    @staticmethod
    def publish_attested_resource(
        self, 
        secured_resource, 
        service_endpoint
        ) -> str: # AttestedResource:
        """Publish attested resource object to WebVH Server."""
        service_endpoint += '/resources'
        requests.post(service_endpoint, json=secured_resource)
        # r = requests.post(service_endpoint, json=secured_resource)
        # resource_id = r.json()['resourceId']
        # return resource_id
    
    @staticmethod
    async def sign_attested_resource(self, profile, resource, options) -> dict: #AttestedResource:
        """Secure resource object with Data Integrity Proof."""
        async with profile.session() as session:
            secured_resource = await DataIntegrityManager(session).add_proof(
                resource, options
            )
        return secured_resource
    
    @staticmethod
    async def create_attested_resource(
        self, 
        issuer_id,
        resource_type,
        resource_content,
        options
        ) -> dict: #AttestedResource:
        """Derive attested resource object from content."""
        content_digest = self._digest_multibase(resource_content)
        attested_resource = {
            '@context': ['https://w3id.org/security/data-integrity/v2'],
            'type': ['AttestedResource'],
            'id': f'{issuer_id}/resources/{content_digest}',
            'resourceContent': resource_content,
            'resourceMetadata': {
                'resourceId': content_digest,
                'resourceType': resource_type
            }
        }
        # attested_resource = AttestedResource(
        #         id=f'{issuer_id}/resources/{content_digest}',
        #         resourceContent=resource_content,
        #         resourceMetadata={
        #             'resourceId': content_digest,
        #             'resourceType': resource_type
        #         }
        #     )
        secured_resource = await self.sign_attested_resource(
            attested_resource,
            self.proof_options | {'verificationMethod': options.get('verificationMethod')}
        )
        self.publish_attested_resource(
            secured_resource,
            options.get('serviceEndpoint')
        )
        
        # if resource_id != secured_resource.get('id'):
        #     pass
        
        return secured_resource

    async def setup(self, context: InjectionContext):
        """Setup."""
        print("Successfully registered DIDWebVHRegistry")

    async def get_schema(self, profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        resource = await self.resolver.resolve_resource(schema_id)

        anoncreds_schema = AnonCredsSchema(
            issuer_id=resource['resourceContent']["issuerId"],
            attr_names=resource['resourceContent']["attrNames"],
            name=resource['resourceContent']["name"],
            version=resource['resourceContent']["version"],
        )

        return GetSchemaResult(
            schema_id=schema_id,
            schema=anoncreds_schema,
            schema_metadata=resource['resourceMetadata'],
            resolution_metadata={},
        )

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""
        resource_type = "anonCredsSchema"
        resource_name = schema.name
        resource_version = schema.version
        
        attested_resource = await self.create_attested_resource(
            schema.issuerId,
            resource_type,
            schema.serialize(),
            options
        )
        
        schema_id = attested_resource.get("id")
        resource_id = attested_resource.get("resourceMetadata").get('resourceId')
        return SchemaResult(
            job_id=None,
            schema_state=SchemaState(
                state=SchemaState.STATE_FINISHED,
                schema_id=schema_id,
                schema=schema,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
        )

    async def get_credential_definition(
        self, profile: Profile, credential_definition_id: str
    ) -> GetCredDefResult:
        """Get a credential definition from the registry."""
        resource = await self.resolver.resolve_resource(credential_definition_id)

        anoncreds_credential_definition = CredDef(
            issuer_id=credential_definition_id.split('/')[0],
            schema_id=resource['resourceContent']["schemaId"],
            type=resource['resourceContent']["type"],
            tag=resource['resourceContent']["tag"],
            value=CredDefValue.deserialize(resource['resourceContent']["value"]),
        )

        return GetCredDefResult(
            credential_definition_id=credential_definition_id,
            credential_definition=anoncreds_credential_definition,
            credential_definition_metadata=resource['resourceMetadata'],
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
        raise NotImplementedError()

    async def get_revocation_registry_definition(
        self, profile: Profile, revocation_registry_id: str
    ) -> GetRevRegDefResult:
        """Get a revocation registry definition from the registry."""
        raise NotImplementedError()

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""
        raise NotImplementedError()

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
        return await super().get_schema_info_by_id(schema_id)
