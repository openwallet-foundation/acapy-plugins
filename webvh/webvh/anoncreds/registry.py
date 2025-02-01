"""DID Webvh Registry."""

import logging
import re
import time
from datetime import datetime, timezone
from bitstring import BitArray
import gzip
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
    RevListState,
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
        """Calculate digest."""
        digest_multihash = multihash.digest(
            jcs.canonicalize(resource_content), "sha2-256"
        )
        digest_multibase = multibase.encode(digest_multihash, "base58btc")
        return digest_multibase

    @staticmethod
    def _create_resource_uri(issuer, content_digest) -> str:
        """Create a resource uri."""
        return f"{issuer}/resources/{content_digest}"

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
                issuer_id=resource["content"]["issuerId"],
                attr_names=resource["content"]["attrNames"],
                name=resource["content"]["name"],
                version=resource["content"]["version"],
            )
        except:
            raise AnonCredsResolutionError("Resource returned not an anoncreds schema")

        return GetSchemaResult(
            schema_id=schema_id,
            schema=anoncreds_schema,
            schema_metadata=resource["metadata"],
            resolution_metadata={},
        )

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""

        content = schema.serialize()
        metadata = {
            "resource_id": self._digest_multibase(content),
            "resource_type": "anonCredsSchema",
            "resource_name": schema.name,
        }

        resource = await self._create_and_publish_resource(
            profile=profile,
            issuer=schema.issuer_id,
            metadata=metadata,
            content=content,
            options=options,
        )

        return SchemaResult(
            job_id=None,
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
            schema_id=resource["content"]["schemaId"],
            type=resource["content"]["type"],
            tag=resource["content"]["tag"],
            value=CredDefValue.deserialize(resource["content"]["value"]),
        )

        return GetCredDefResult(
            credential_definition_id=credential_definition_id,
            credential_definition=anoncreds_credential_definition,
            credential_definition_metadata=resource["metadata"],
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

        content = credential_definition.serialize()
        metadata = {
            "resource_id": self._digest_multibase(content),
            "resource_type": "anonCredsCredDef",
            "resource_name": credential_definition.tag,
        }

        resource = await self._create_and_publish_resource(
            profile=profile,
            issuer=schema.schema.issuer_id,
            metadata=metadata,
            content=content,
            options=options,
        )

        return CredDefResult(
            job_id=None,
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
            cred_def_id=resource["content"]["credDefId"],
            type=resource["content"]["revocDefType"],
            tag=resource["content"]["tag"],
            value=resource["content"]["value"],
        )

        return GetRevRegDefResult(
            revocation_registry_id=revocation_registry_id,
            revocation_registry=anoncreds_revocation_registry_definition,
            revocation_registry_metadata=resource["metadata"],
            resolution_metadata={},
        )

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""

        content = revocation_registry_definition.serialize()
        metadata = {
            "resource_id": self._digest_multibase(content),
            "resource_type": "anonCredsRevocRegDef",
            "resource_name": revocation_registry_definition.tag,
        }

        resource = await self._create_and_publish_resource(
            profile=profile,
            issuer=revocation_registry_definition.issuer_id,
            metadata=metadata,
            content=content,
            options=options,
        )

        return RevRegDefResult(
            job_id=None,
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
        
        revocation_registry_resource = await self.resolver.resolve_resource(
            revocation_registry_id
        )
        
        index = sorted(
            revocation_registry_resource.get('links'), 
            key=lambda x: x['timestamp']
        )
        for idx, entry in enumerate(index):
            if entry.get('timestamp') > timestamp:
                status_list_id = index[idx-1].get('id')
        
        status_list_resource = await self.resolver.resolve_resource(
            status_list_id
        )
        
        revocation_list = RevList(
            issuer_id=revocation_registry_id.split('/')[0],
            rev_reg_def_id=revocation_registry_id,
            revocation_list=status_list_resource.get('content').get("revocationList"),
            current_accumulator=status_list_resource.get('content').get("currentAccumulator"),
            timestamp=status_list_resource.get('content').get("timestamp")
        )

        return GetRevListResult(
            revocation_list=revocation_list,
            resolution_metadata={},
            revocation_registry_metadata=status_list_resource.get('metadata'),
        )

    async def register_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_list: RevList,
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""
        
        resource_type = 'anonCredsStatusList'

        content = rev_list.serialize()
        content['timestamp'] = int(time.time())
        metadata = {
            "resource_id": self._digest_multibase(content),
            "resource_type": resource_type,
            "resource_name": rev_reg_def.tag,
        }

        resource = await self._create_and_publish_resource(
            profile=profile,
            issuer=rev_reg_def.issuer_id,
            metadata=metadata,
            content=content,
            options=options,
        )
        
        status_list_entry = {
            'type': resource_type,
            'id': resource.get('id'),
            'timestamp': resource.get('content').get('timestamp')
        }

        rev_reg_def_content = rev_reg_def.serialize()
        rev_reg_def_id = self._create_resource_uri(
            rev_reg_def.issuer_id,
            self._digest_multibase(rev_reg_def_content)
        )
        
        rev_reg_def_resource = await self.resolver.resolve_resource(
            rev_reg_def_id
        )
        rev_reg_def_resource['links'] = [
            status_list_entry
        ]
        rev_reg_def_resource.pop('proof')
        await self._update_and_upload_resource(
            profile=profile,
            resource=rev_reg_def_resource,
            options=options,
        )

        return RevListResult(
            job_id=None,
            revocation_list_state=RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=rev_list,
            ),
            registration_metadata=metadata,
            revocation_list_metadata=metadata,
        )

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
        
        for idx in revoked:
            curr_list.revocationList[idx] = 1
            

        content = curr_list.serialize()
        content['timestamp'] = time.time()
        metadata = {
            "resource_id": self._digest_multibase(content),
            "resource_type": "anonCredsStatusList",
            "resource_name": rev_reg_def.tag,
        }
        
        resource = await self._create_and_publish_resource(
            profile=profile,
            issuer_id=rev_reg_def.issuer_id,
            resource_metadata=metadata,
            resource_content=content,
            options=options,
        )
        
        status_list_entry = {
            'type': 'anonCredsStatusList',
            'id': resource.get('id'),
            'timestamp': resource.get('content').get('timestamp')
        }
        rev_reg_def_content = rev_reg_def.serialize()
        rev_reg_def_id = self._create_resource_uri(
            rev_reg_def.issuer_id,
            self._digest_multibase(rev_reg_def_content)
        )
        
        rev_reg_def_resource = await self.resolver.resolve_resource(
            rev_reg_def_id
        )
        rev_reg_def_resource['links'] = [
            status_list_entry
        ]
        rev_reg_def_resource.pop('proof')
        await self._update_and_upload_resource(
            profile=profile,
            resource=rev_reg_def_resource,
            options=options,
        )

        return RevListResult(
            job_id=None,
            revocation_list_state=RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=curr_list,
            ),
            registration_metadata=metadata,
            revocation_list_metadata=metadata,
        )

    async def get_schema_info_by_id(
        self, profile: Profile, schema_id: str
    ) -> AnoncredsSchemaInfo:
        """Get a schema info from the registry."""
        resource = await self.resolver.resolve_resource(schema_id)
        schema = resource.get("content")
        return AnoncredsSchemaInfo(
            issuer_id=schema["issuerId"],
            name=schema["name"],
            version=schema["version"],
        )

    def _ensure_options(self, options):
        # Ensure a service endpoint is set
        if not options.get("serviceEndpoint"):
            raise AnonCredsRegistrationError("Missing service endpoint")
        self.service_endpoint = options.get("serviceEndpoint")
        # Ensure a verification method is set
        if not options.get("verificationMethod"):
            raise AnonCredsRegistrationError("Missing verification method")
        self.proof_options["verificationMethod"] = options.get("verificationMethod")

    async def _upload(
        self, secured_resource
    ) -> dict:  # AttestedResource:

        # Upload secured resource to server with metadata
        metadata = secured_resource.get('metadata')
        try:
            r = requests.post(
                self.service_endpoint,
                json={
                    "attestedResource": secured_resource,
                    "options": {
                        "resourceId": metadata.get('resourceId'),
                        "resourceType": metadata.get('resourceType'),
                    },
                },
            )
            if r.status_code != 201:
                raise AnonCredsRegistrationError(
                    "Invalid status code returned by service endpoint"
                )

        except:
            raise AnonCredsRegistrationError("Error uploading resource")
            # raise AnonCredsRegistrationError(r.text)

    async def _sign(
        self, profile, document
    ) -> dict:  # AttestedResource:
        try:
            async with profile.session() as session:
                secured_document = await DataIntegrityManager(session).add_proof(
                    document, DataIntegrityProofOptions.deserialize(self.proof_options)
                )
            if not secured_document.get("proof"):
                raise AnonCredsRegistrationError("Unable to attach proof")

            # TODO, server currently expect a proof object, not a proof set (array)
            secured_document["proof"] = secured_document["proof"][0]
            return secured_document
        except:
            raise AnonCredsRegistrationError("Error securing resource")

    async def _update_and_upload_resource(
        self, profile, resource, options
    ) -> dict:  # AttestedResource:
        """Update an existing resource safely."""
        
        self._ensure_options(options)
        if (
            resource.get("id").split('/')[-1] 
            != self._digest_multibase(resource.get("content"))
            ):
            raise AnonCredsRegistrationError("Digest mismatch")
        secured_resource = await self._sign(profile, resource)
        await self._upload(secured_resource)

    async def _create_and_publish_resource(
        self, profile, issuer, content, metadata, options, links=[]
    ) -> dict:  # AttestedResource:
        """Derive attested resource object from content and publish."""

        self._ensure_options(options)

        # Ensure content digest is accurate
        if metadata.get("resource_id") != self._digest_multibase(
            content
        ):
            raise AnonCredsRegistrationError("Digest mismatch")
        
        content_digest = metadata.get("resource_id")

        # Create resource object
        resource = {
            "@context": ["https://w3id.org/security/data-integrity/v2"],
            "type": ["AttestedResource"],
            "id": f"{issuer}/resources/{content_digest}",
            "content": content,
            "metadata": {
                "resourceId": metadata.get("resource_id"),
                "resourceType": metadata.get("resource_type"),
                "resourceName": metadata.get("resource_name"),
            },
            "links": links
        }
        # attested_resource = AttestedResource(
        #         id=f'{issuer_id}/resources/{content_digest}',
        #         content=resource_content,
        #         metadata={
        #             'resourceId': content_digest,
        #             'resourceType': resource_type
        #         }
        #     )
        
        # Secure resource with a Data Integrity proof
        secured_resource = await self._sign(profile, resource)
        
        # Upload resource to server
        await self._upload(secured_resource)

        return secured_resource
