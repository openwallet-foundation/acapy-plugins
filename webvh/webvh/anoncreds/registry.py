"""DID Webvh Registry."""

import asyncio
import logging
import time
from typing import Optional, Pattern, Sequence
import uuid

import jcs
from acapy_agent.anoncreds.base import (
    AnonCredsRegistrationError,
    AnonCredsResolutionError,
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
)
from acapy_agent.anoncreds.models.credential_definition import (
    CredDef,
    CredDefResult,
    CredDefState,
    CredDefValue,
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
    RevRegDefValue,
)
from acapy_agent.anoncreds.models.schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)
from acapy_agent.anoncreds.models.schema_info import AnonCredsSchemaInfo
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.vc.data_integrity.manager import (
    DataIntegrityManager,
)
from acapy_agent.vc.data_integrity.models.options import DataIntegrityProofOptions
from acapy_agent.wallet.askar import CATEGORY_DID
from acapy_agent.wallet.error import WalletError, WalletNotFoundError
from acapy_agent.wallet.keys.manager import verkey_to_multikey
from aiohttp import ClientConnectionError, ClientResponseError, ClientSession
from multiformats import multibase, multihash

from ..resolver.resolver import DIDWebVHResolver
from ..validation import WebVHDID
from ..config.config import get_plugin_config, is_witness
from ..did.server_client import WebVHServerClient
from ..protocols.attested_resource.record import PendingAttestedResourceRecord
from ..protocols.states import WitnessingState
from ..did.witness import WitnessManager
from ..did.manager import ControllerManager
from ..did.utils import add_proof

# from ..models.resources import AttestedResource

LOGGER = logging.getLogger(__name__)

# NOTE, temporary context location
ATTESTED_RESOURCE_CTX = "https://identity.foundation/did-attested-resources/context/v0.1"

PENDING_MESSAGE = {
    "status": WitnessingState.PENDING.value,
    "message": "The witness is pending.",
}
WITNESS_WAIT_TIMEOUT_SECONDS = 2


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
        return multibase.encode(
            multihash.digest(jcs.canonicalize(resource_content), "sha2-256"), "base58btc"
        )

    @staticmethod
    def _derive_upload_endpoint(verification_method) -> str:
        """Derive service upload endpoint."""
        domain = verification_method.split(":")[3]
        namespace = verification_method.split(":")[4]
        identifier = verification_method.split(":")[5]
        return f"https://{domain}/{namespace}/{identifier}/resources"

    @staticmethod
    def _derive_update_endpoint(resource_id) -> str:
        """Derive service update endpoint."""
        url = "/".join(resource_id.split(":")[3:])
        return f"https://{url}"

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
        except Exception:
            raise AnonCredsResolutionError("Error resolving resource")

        try:
            anoncreds_schema = AnonCredsSchema(
                issuer_id=resource["content"]["issuerId"],
                attr_names=resource["content"]["attrNames"],
                name=resource["content"]["name"],
                version=resource["content"]["version"],
            )
        except Exception as e:
            raise AnonCredsResolutionError(
                f"Resource returned not an anoncreds schema: {e}"
            )

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
            value=RevRegDefValue.deserialize(resource["content"]["value"]),
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
        self,
        profile: Profile,
        revocation_registry_id: str,
        timestamp_from: int,
        timestamp_to: int,
    ) -> GetRevListResult:
        """Get a revocation list from the registry."""
        revocation_registry_resource = await self.resolver.resolve_resource(
            revocation_registry_id
        )

        timestamp_to = timestamp_to or int(time.time())
        index = sorted(
            revocation_registry_resource.get("links"), key=lambda x: x["timestamp"]
        )
        for idx, entry in enumerate(index):
            status_list_id = index[idx].get("id")
            if entry.get("timestamp") > timestamp_to and idx > 0:
                status_list_id = index[idx - 1].get("id")
                break

        status_list_resource = await self.resolver.resolve_resource(status_list_id)

        revocation_list = RevList(
            issuer_id=revocation_registry_id.split("/")[0],
            rev_reg_def_id=revocation_registry_id,
            revocation_list=status_list_resource.get("content").get("revocationList"),
            current_accumulator=status_list_resource.get("content").get(
                "currentAccumulator"
            ),
            timestamp=status_list_resource.get("content").get("timestamp"),
        )

        return GetRevListResult(
            revocation_list=revocation_list,
            resolution_metadata={},
            revocation_registry_metadata=status_list_resource.get("metadata"),
        )

    async def register_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_list: RevList,
        options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""

        resource_type = "anonCredsStatusList"

        content = rev_list.serialize()
        content["timestamp"] = int(time.time())
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
            "type": resource_type,
            "id": resource.get("id"),
            "timestamp": resource.get("content").get("timestamp"),
        }

        rev_reg_def_resource = await self.resolver.resolve_resource(
            rev_list.rev_reg_def_id
        )
        rev_reg_def_resource["links"] = [status_list_entry]
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
            curr_list.revocation_list[idx] = 1

        content = curr_list.serialize()
        content["timestamp"] = int(time.time())
        metadata = {
            "resource_id": self._digest_multibase(content),
            "resource_type": "anonCredsStatusList",
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
            "type": "anonCredsStatusList",
            "id": resource.get("id"),
            "timestamp": resource.get("content").get("timestamp"),
        }

        rev_reg_def_resource = await self.resolver.resolve_resource(
            prev_list.rev_reg_def_id
        )
        rev_reg_def_resource["links"].append(status_list_entry)
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
    ) -> AnonCredsSchemaInfo:
        """Get a schema info from the registry."""
        resource = await self.resolver.resolve_resource(schema_id)
        schema = resource.get("content")
        return AnonCredsSchemaInfo(
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

    async def _upload(self, secured_resource) -> dict:  # AttestedResource:
        # Upload secured resource to server with metadata
        metadata = secured_resource.get("metadata")
        async with ClientSession() as http_session:
            try:
                response = await http_session.post(
                    self.service_endpoint,
                    json={
                        "attestedResource": secured_resource,
                        "options": {
                            "resourceId": metadata.get("resourceId"),
                            "resourceType": metadata.get("resourceType"),
                        },
                    },
                )
                if response.status != 201:
                    raise AnonCredsRegistrationError(
                        "Invalid status code returned by service endpoint"
                    )
            except (ClientConnectionError, ClientResponseError) as e:
                raise AnonCredsRegistrationError(f"Error uploading resource: {e}")

    async def _update(self, secured_resource) -> dict:  # AttestedResource:
        # Upload secured resource to server with metadata
        metadata = secured_resource.get("metadata")
        async with ClientSession() as http_session:
            try:
                response = await http_session.put(
                    self.service_endpoint,
                    json={
                        "attestedResource": secured_resource,
                        "options": {
                            "resourceId": metadata.get("resourceId"),
                            "resourceType": metadata.get("resourceType"),
                        },
                    },
                )
                if response.status != 200:
                    raise AnonCredsRegistrationError(
                        "Invalid status code returned by service endpoint"
                    )
            except (ClientConnectionError, ClientResponseError) as e:
                raise AnonCredsRegistrationError(f"Error uploading resource: {e}")

    async def _sign(self, profile, document) -> dict:  # AttestedResource:
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
        except Exception as e:
            raise AnonCredsRegistrationError(f"Error securing resource: {e}")

    async def _update_and_upload_resource(
        self, profile, resource, options
    ) -> dict:  # AttestedResource:
        """Update an existing resource safely."""
        options = options or {}
        proof = resource.pop("proof")
        options["verificationMethod"] = proof.get("verificationMethod")
        options["serviceEndpoint"] = self._derive_update_endpoint(resource.get("id"))
        self._ensure_options(options)
        if resource.get("id").split("/")[-1] != self._digest_multibase(
            resource.get("content")
        ):
            raise AnonCredsRegistrationError("Digest mismatch")
        secured_resource = await self._sign(profile, resource)
        await self._update(secured_resource)

    async def _get_default_verification_method(self, profile, did):
        try:
            async with profile.session() as session:
                did_info = await session.handle.fetch(CATEGORY_DID, did)
            signing_key = verkey_to_multikey(
                did_info.value_json.get("verkey"),
                alg=did_info.value_json.get("key_type"),
            )
            return f"{did}#{signing_key}"
        except (WalletNotFoundError, WalletError):
            raise AnonCredsRegistrationError(f"Error deriving signing key for {did}.")

    async def _create_and_publish_resource(
        self, profile, issuer, content, metadata, options={}, links=None
    ) -> dict:  # AttestedResource:
        """Derive attested resource object from content and publish."""
        # If no verification method set, fetch default signing key from did
        verification_method = options.get(
            "verificationMethod"
        ) or await self._get_default_verification_method(profile, issuer)

        # Ensure content digest is accurate
        if metadata.get("resource_id") != self._digest_multibase(content):
            raise AnonCredsRegistrationError("Digest mismatch")

        content_digest = metadata.get("resource_id")

        # Create resource object
        resource = {
            "@context": [
                ATTESTED_RESOURCE_CTX,
                "https://w3id.org/security/data-integrity/v2",
            ],
            "type": ["AttestedResource"],
            "id": f"{issuer}/resources/{content_digest}",
            "content": content,
            "metadata": {
                "resourceId": metadata.get("resource_id"),
                "resourceType": metadata.get("resource_type"),
                "resourceName": metadata.get("resource_name"),
            },
        }
        if links:
            resource["links"] = links

        # Secure resource with a Data Integrity proof
        secured_resource = await add_proof(profile, resource, verification_method)

        config = await get_plugin_config(profile)
        scid = issuer.split(":")[2]
        namespace = issuer.split(":")[4]
        identifier = issuer.split(":")[5]
        if config.get("endorsement", False):
            # Request witness approval
            witness = WitnessManager(profile)
            controller = ControllerManager(profile)
            witness_request_id = str(uuid.uuid4())
            endorsed_resource = await witness.witness_attested_resource(
                scid, secured_resource, witness_request_id
            )

            if not isinstance(endorsed_resource, dict):
                if await is_witness(profile):
                    pass

                try:
                    LOGGER.info(witness_request_id)
                    await PendingAttestedResourceRecord().set_pending_record_id(
                        profile, witness_request_id
                    )
                    await asyncio.wait_for(
                        controller._wait_for_resource(witness_request_id),
                        WITNESS_WAIT_TIMEOUT_SECONDS,
                    )
                except asyncio.TimeoutError:
                    pass
            else:
                # Upload resource to server
                await WebVHServerClient(profile).upload_attested_resource(
                    namespace, identifier, endorsed_resource
                )
        else:
            # Upload resource to server
            await WebVHServerClient(profile).upload_attested_resource(
                namespace, identifier, secured_resource
            )

        return secured_resource
