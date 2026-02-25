"""DID Webvh Registry."""

import asyncio
import json
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
from acapy_agent.anoncreds.constants import (
    CATEGORY_CRED_DEF,
    CATEGORY_SCHEMA,
    STATE_FINISHED,
)
from acapy_agent.anoncreds.events import CredDefFinishedEvent, RevRegDefFinishedEvent
from acapy_agent.anoncreds.issuer import AnonCredsIssuer
from acapy_agent.anoncreds.revocation import (
    AnonCredsRevocation,
    AnonCredsRevocationError,
)
from acapy_agent.anoncreds.models.schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)
from acapy_agent.anoncreds.models.schema_info import AnonCredsSchemaInfo
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.event_bus import EventBus
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

# Wallet category for rev reg def (same as acapy_agent.anoncreds.revocation)
# Defined here to avoid relying on revocation package exports.
CATEGORY_REV_REG_DEF = "revocation_reg_def"

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

        resource, pub_state = await self._create_and_publish_resource(
            profile=profile,
            issuer=schema.issuer_id,
            metadata=metadata,
            content=content,
            options=options,
        )

        schema_state = (
            SchemaState.STATE_WAIT
            if pub_state == SchemaState.STATE_WAIT
            else SchemaState.STATE_FINISHED
        )
        return SchemaResult(
            job_id=None,
            schema_state=SchemaState(
                state=schema_state,
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

        resource, pub_state = await self._create_and_publish_resource(
            profile=profile,
            issuer=schema.schema.issuer_id,
            metadata=metadata,
            content=content,
            options=options,
        )

        cred_def_state = (
            CredDefState.STATE_WAIT
            if pub_state == CredDefState.STATE_WAIT
            else CredDefState.STATE_FINISHED
        )
        return CredDefResult(
            job_id=None,
            credential_definition_state=CredDefState(
                state=cred_def_state,
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

        resource, pub_state = await self._create_and_publish_resource(
            profile=profile,
            issuer=revocation_registry_definition.issuer_id,
            metadata=metadata,
            content=content,
            options=options,
        )

        rev_reg_def_state = (
            RevRegDefState.STATE_WAIT
            if pub_state == RevRegDefState.STATE_WAIT
            else RevRegDefState.STATE_FINISHED
        )

        return RevRegDefResult(
            job_id=None,
            revocation_registry_definition_state=RevRegDefState(
                state=rev_reg_def_state,
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

        resource, pub_state = await self._create_and_publish_resource(
            profile=profile,
            issuer=rev_reg_def.issuer_id,
            metadata=metadata,
            content=content,
            options=options,
        )

        rev_list_state = (
            RevListState.STATE_WAIT
            if pub_state == RevListState.STATE_WAIT
            else RevListState.STATE_FINISHED
        )

        if pub_state == RevListState.STATE_WAIT:
            # Do not update rev_reg_def with link until witness approves
            return RevListResult(
                job_id=None,
                revocation_list_state=RevListState(
                    state=rev_list_state,
                    revocation_list=rev_list,
                ),
                registration_metadata=metadata,
                revocation_list_metadata=metadata,
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
                state=rev_list_state,
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

        resource, pub_state = await self._create_and_publish_resource(
            profile=profile,
            issuer=rev_reg_def.issuer_id,
            metadata=metadata,
            content=content,
            options=options,
        )

        rev_list_state = (
            RevListState.STATE_WAIT
            if pub_state == RevListState.STATE_WAIT
            else RevListState.STATE_FINISHED
        )

        if pub_state == RevListState.STATE_WAIT:
            return RevListResult(
                job_id=None,
                revocation_list_state=RevListState(
                    state=rev_list_state,
                    revocation_list=curr_list,
                ),
                registration_metadata=metadata,
                revocation_list_metadata=metadata,
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
                state=rev_list_state,
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
            if did_info is None or not getattr(did_info, "value_json", None):
                raise AnonCredsRegistrationError(
                    f"DID not found in wallet: {did}. "
                    "Create the DID (e.g. via /did/webvh/create) before "
                    "registering schemas or other resources with this issuer."
                )
            signing_key = verkey_to_multikey(
                did_info.value_json.get("verkey"),
                alg=did_info.value_json.get("key_type"),
            )
            return f"{did}#{signing_key}"
        except (WalletNotFoundError, WalletError):
            raise AnonCredsRegistrationError(f"Error deriving signing key for {did}.")

    async def add_revocation_list_link(
        self, profile: Profile, attested_resource: dict, options: Optional[dict] = None
    ) -> None:
        """Update the revocation registry definition to include the new status list link.

        Call this when a witness approves a revocation list (anonCredsStatusList) so
        the rev_reg_def is updated with the link to the newly uploaded status list.
        When endorsement is enabled, the rev_reg_def update is also sent for witness
        approval before upload.
        """
        resource_type = attested_resource.get("metadata", {}).get("resourceType", "")
        if resource_type != "anonCredsStatusList":
            return
        content = attested_resource.get("content", {})
        rev_reg_def_id = content.get("rev_reg_def_id") or content.get("revRegDefId")
        if not rev_reg_def_id:
            LOGGER.warning("No rev_reg_def_id in attested resource, skipping link update")
            return
        try:
            rev_reg_def_resource = await self.resolver.resolve_resource(rev_reg_def_id)
        except Exception as e:
            LOGGER.warning(
                "Could not resolve rev_reg_def %s to add link: %s",
                rev_reg_def_id,
                e,
            )
            return
        resource_type_name = "anonCredsStatusList"
        status_list_entry = {
            "type": resource_type_name,
            "id": attested_resource.get("id"),
            "timestamp": content.get("timestamp"),
        }
        links = rev_reg_def_resource.get("links") or []
        if not isinstance(links, list):
            links = []
        links = list(links)
        links.append(status_list_entry)
        rev_reg_def_resource["links"] = links

        config = await get_plugin_config(profile)
        if config.get("endorsement", False):
            # Send rev_reg_def update for witness approval (do not wait)
            try:
                proof = rev_reg_def_resource.pop("proof", None)
                verification_method = None
                if proof:
                    p = proof[0] if isinstance(proof, list) and proof else proof
                    if isinstance(p, dict):
                        verification_method = p.get("verificationMethod")
                if not verification_method:
                    issuer = rev_reg_def_id.split("/")[0]
                    verification_method = await self._get_default_verification_method(
                        profile, issuer
                    )
                self.proof_options["verificationMethod"] = verification_method
                secured_rev_reg_def = await self._sign(profile, rev_reg_def_resource)
                issuer = rev_reg_def_id.split("/")[0]
                scid = issuer.split(":")[2]
                request_id = str(uuid.uuid4())
                controller = ControllerManager(profile)
                witness = WitnessManager(profile)
                pending_records = PendingAttestedResourceRecord()
                witness_connection = await controller._get_active_witness_connection()
                connection_id = (
                    witness_connection.connection_id if witness_connection else ""
                )
                role = "self-witness" if not connection_id else "controller"
                await pending_records.save_pending_record(
                    profile,
                    scid,
                    secured_rev_reg_def,
                    request_id,
                    connection_id,
                    role=role,
                )
                await witness.witness_attested_resource(
                    scid, secured_rev_reg_def, request_id
                )
                LOGGER.info(
                    "Sent rev_reg_def update for witness approval (request_id=%s)",
                    request_id,
                )
            except Exception as e:
                LOGGER.warning("Could not send rev_reg_def update for witness: %s", e)
            return

        try:
            await self._update_and_upload_resource(
                profile, rev_reg_def_resource, options or {}
            )
        except Exception as e:
            LOGGER.warning("Could not update rev_reg_def with status list link: %s", e)

    async def store_attested_resource_after_attestation(
        self, profile: Profile, attested_resource: dict
    ) -> None:
        """Store or update local state when a witness approves an attested resource.

        Dispatches by resourceType from metadata:
        - anonCredsSchema: store in wallet (ACA-Py schema storage)
        - anonCredsCredDef: update cred def record state to finished
        - anonCredsStatusList: update rev_reg_def with the status list link
        Other types are no-ops (can be extended later).
        """
        resource_type = attested_resource.get("metadata", {}).get("resourceType", "")
        if resource_type == "anonCredsSchema":
            await self._store_schema_after_attestation(profile, attested_resource)
        elif resource_type == "anonCredsCredDef":
            await self._store_cred_def_after_attestation(profile, attested_resource)
        elif resource_type == "anonCredsRevocRegDef":
            await self._store_rev_reg_def_after_attestation(profile, attested_resource)
        elif resource_type == "anonCredsStatusList":
            await self.add_revocation_list_link(profile, attested_resource)

    async def _update_schema_state_to_finished(
        self, profile: Profile, schema_id: str
    ) -> bool:
        """Update existing schema record state to STATE_FINISHED (e.g. after witness)."""
        try:
            async with profile.session() as session:
                entry = await session.handle.fetch(CATEGORY_SCHEMA, schema_id)
                if not entry:
                    return False
                tags = dict(entry.tags) if entry.tags else {}
                tags["state"] = STATE_FINISHED
                await session.handle.replace(
                    CATEGORY_SCHEMA,
                    schema_id,
                    entry.value,
                    tags,
                )
                LOGGER.debug("Updated schema state to finished locally: %s", schema_id)
                return True
        except Exception as e:
            LOGGER.warning("Could not update schema state to finished: %s", e)
            return False

    async def _store_schema_after_attestation(
        self, profile: Profile, attested_resource: dict
    ) -> None:
        """Store schema in the wallet (ACA-Py schema storage)."""
        content = attested_resource.get("content", {})
        schema_id = attested_resource.get("id")
        if not schema_id or not content:
            LOGGER.warning(
                "Attested resource missing id or content, skipping schema store"
            )
            return
        try:
            schema = AnonCredsSchema(
                issuer_id=content.get("issuerId", ""),
                attr_names=content.get("attrNames", []),
                name=content.get("name", ""),
                version=content.get("version", ""),
            )
        except Exception as e:
            LOGGER.warning("Could not build schema from attested resource: %s", e)
            return
        result = SchemaResult(
            job_id=None,
            schema_state=SchemaState(
                state=SchemaState.STATE_FINISHED,
                schema_id=schema_id,
                schema=schema,
            ),
            registration_metadata={},
        )
        try:
            issuer = profile.inject(AnonCredsIssuer)
            await issuer.store_schema(result)
            LOGGER.debug("Stored schema locally: %s", schema_id)
        except Exception as e:
            # Record may already exist (stored with STATE_WAIT); update state to FINISHED
            if not await self._update_schema_state_to_finished(profile, schema_id):
                LOGGER.warning("Could not store or update schema locally: %s", e)

    async def _emit_cred_def_finished_for_revocation(
        self,
        profile: Profile,
        tags: dict,
        cred_def_id: str,
        attested_resource: dict,
    ) -> None:
        """Emit CredDefFinishedEvent when tags indicate support_revocation.

        Logs and returns without raising if required tags are missing or notify fails.
        """
        if tags.get("support_revocation", "False") != "True":
            return
        schema_id = tags.get("schema_id")
        issuer_id = tags.get("issuer_id")
        if not schema_id or not issuer_id:
            LOGGER.warning(
                "Cred def %s has support_revocation but missing "
                "schema_id or issuer_id in tags; skipping CredDefFinishedEvent",
                cred_def_id,
            )
            return
        try:
            max_cred_num = int(tags.get("max_cred_num", "0"))
            tag = attested_resource.get("content", {}).get("tag") or tags.get(
                "tag", "default"
            )
            event_bus = profile.inject(EventBus)
            await event_bus.notify(
                profile,
                CredDefFinishedEvent.with_payload(
                    schema_id=schema_id,
                    cred_def_id=cred_def_id,
                    issuer_id=issuer_id,
                    support_revocation=True,
                    max_cred_num=max_cred_num,
                    tag=str(tag) if tag is not None else "default",
                    options={},
                ),
            )
            LOGGER.debug(
                "Emitted CredDefFinishedEvent for cred_def_id=%s "
                "to trigger revocation setup",
                cred_def_id,
            )
        except Exception as e:
            LOGGER.warning("Could not emit CredDefFinishedEvent for rev setup: %s", e)

    async def _store_cred_def_after_attestation(
        self, profile: Profile, attested_resource: dict
    ) -> None:
        """Update cred def record state to finished and trigger revocation setup.

        The issuer only emits CredDefFinishedEvent when state is STATE_FINISHED at store
        time; when we return STATE_WAIT (pending witness), revocation setup never runs.
        After the witness approves we update state here and emit the event so automated
        revocation registry creation is triggered.
        """
        cred_def_id = attested_resource.get("id")
        if not cred_def_id:
            LOGGER.warning("Attested resource missing id, skipping cred def state update")
            return
        try:
            async with profile.session() as session:
                entry = await session.handle.fetch(CATEGORY_CRED_DEF, cred_def_id)
                if not entry:
                    LOGGER.warning(
                        "No local cred def record for %s; issuer may not have stored it",
                        cred_def_id,
                    )
                    return
                tags = dict(entry.tags) if entry.tags else {}
                tags["state"] = STATE_FINISHED
                await session.handle.replace(
                    CATEGORY_CRED_DEF,
                    cred_def_id,
                    entry.value,
                    tags,
                )
                LOGGER.debug(
                    "Updated cred def state to finished locally: %s", cred_def_id
                )
                await self._emit_cred_def_finished_for_revocation(
                    profile, tags, cred_def_id, attested_resource
                )
        except Exception as e:
            LOGGER.warning("Could not update cred def state to finished: %s", e)

    async def _create_revocation_list_after_rev_reg_def(
        self,
        profile: Profile,
        resource_id: str,
        rev_reg_def: RevRegDef,
        tag: str,
    ) -> None:
        """Create and register revocation list after rev reg def is finished.

        Logs and returns without raising on failure (e.g. tails upload error).
        """
        try:
            revoc = AnonCredsRevocation(profile)
            opts = {}
            try:
                await revoc.upload_tails_file(rev_reg_def)
            except AnonCredsRevocationError:
                opts["failed_to_upload"] = True
            await revoc.create_and_register_revocation_list(resource_id, opts)
            LOGGER.info(
                "Created revocation list for rev_reg_def_id=%s tag=%s",
                resource_id,
                tag,
            )
        except Exception as e:
            LOGGER.warning("Revocation list setup failed for %s: %s", resource_id, e)

    async def _store_rev_reg_def_after_attestation(
        self, profile: Profile, attested_resource: dict
    ) -> None:
        """Update rev reg def state to finished and emit event so rev lists created.

        When the registry returns STATE_WAIT (witness pending), the issuer stores the rev
        reg def but does not emit RevRegDefFinishedEvent. The revocation setup manager
        only creates the initial revocation list(s) and sets the active registry when it
        receives that event. After the witness approves we update state here and emit the
        event so the chain runs.
        """
        resource_id = attested_resource.get("id")
        content = attested_resource.get("content", {})
        if not resource_id or not content:
            LOGGER.warning(
                "Attested resource missing id or content, skipping rev reg def state "
                "update"
            )
            return
        cred_def_id = content.get("credDefId", "")
        tag = content.get("tag", "")
        has_links = bool(attested_resource.get("links"))
        LOGGER.info(
            "_store_rev_reg_def_after_attestation: resource_id=%s tag=%s has_links=%s",
            resource_id,
            tag,
            has_links,
        )
        if has_links:
            return  # Update only, list already exists
        try:
            value_obj = RevRegDefValue.deserialize(content.get("value", {}))
            issuer_id = content.get("issuerId") or resource_id.split("/")[0]
            rev_reg_def = RevRegDef(
                issuer_id=issuer_id,
                cred_def_id=cred_def_id,
                type=content.get("revocDefType", "CL_ACCUM"),
                tag=str(tag) if tag is not None else "",
                value=value_obj,
            )
        except Exception:
            return
        try:
            async with profile.session() as session:
                entry = await session.handle.fetch(CATEGORY_REV_REG_DEF, name=resource_id)
                if not entry and cred_def_id and tag is not None:
                    rev_reg_defs = await session.handle.fetch_all(
                        CATEGORY_REV_REG_DEF,
                        {"cred_def_id": cred_def_id},
                    )
                    for e in rev_reg_defs or []:
                        if (e.tags or {}).get("state") != "wait":
                            continue
                        try:
                            raw = getattr(e, "value_json", None) or e.value
                            if isinstance(raw, (str, bytes)):
                                raw = json.loads(raw)
                            if isinstance(raw, dict) and (
                                raw.get("tag") == tag or raw.get("tag") == str(tag)
                            ):
                                entry = e
                                resource_id = entry.name
                                break
                        except Exception:
                            continue
                LOGGER.info(
                    "_store_rev_reg_def_after_attestation: entry_found=%s resource_id=%s",
                    entry is not None,
                    resource_id,
                )
                if not entry and not has_links:
                    LOGGER.warning(
                        "No local rev_reg_def entry for attested resource (tag=%s); "
                        "acapy_agent will store when create_and_register returns",
                        tag,
                    )
                    return  # acapy_agent will store and emit RevRegDefFinishedEvent
                if entry:
                    tags = dict(entry.tags) if entry.tags else {}
                    tags["state"] = STATE_FINISHED
                    # Preserve tag in tags so revocation setup can match
                    if tag is not None:
                        tags["tag"] = str(tag)
                    replace_value = getattr(entry, "value", None) or getattr(
                        entry, "value_json", None
                    )
                    if replace_value is None and hasattr(entry, "raw_value"):
                        replace_value = entry.raw_value
                    if replace_value is None:
                        return
                    await session.handle.replace(
                        CATEGORY_REV_REG_DEF, resource_id, replace_value, tags
                    )
            await profile.inject(EventBus).notify(
                profile,
                RevRegDefFinishedEvent.with_payload(
                    rev_reg_def_id=resource_id,
                    rev_reg_def=rev_reg_def,
                    options={},
                ),
            )
            await self._create_revocation_list_after_rev_reg_def(
                profile, resource_id, rev_reg_def, tag
            )
        except Exception as e:
            LOGGER.warning("Rev reg def store failed for %s: %s", resource_id, e)

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
        server = WebVHServerClient(profile)
        if config.get("endorsement", False):
            # Request witness approval
            witness = WitnessManager(profile)
            controller = ControllerManager(profile)
            pending_records = PendingAttestedResourceRecord()

            # Check for existing pending request - prevents duplicate requests on retry
            # (e.g. revocation list when witness doesn't auto-attest)
            resource_type = secured_resource.get("metadata", {}).get("resourceType", "")
            resource_id = secured_resource.get("id", "")
            content_tag = secured_resource.get("content", {}).get("tag", "")
            existing = await pending_records.get_pending_record_for_resource(
                profile, secured_resource
            )
            LOGGER.info(
                "_create_and_publish_resource: resourceType=%s resource_id=%s "
                "content.tag=%s existing=%s",
                resource_type,
                resource_id,
                content_tag,
                "yes" if existing else "no",
            )
            if existing:
                pending_record, request_id = existing
                LOGGER.info(
                    "Found existing pending request %s for resource, waiting "
                    "(no new request)",
                    request_id,
                )
                try:
                    await asyncio.wait_for(
                        controller._wait_for_resource(request_id),
                        WITNESS_WAIT_TIMEOUT_SECONDS,
                    )
                    # Return the resource from the pending record (actually uploaded)
                    return (
                        pending_record.get("record", secured_resource),
                        STATE_FINISHED,
                    )
                except asyncio.TimeoutError:
                    raise AnonCredsRegistrationError(
                        "Witness approval pending for this resource. "
                        "Please wait for the witness to approve the existing request."
                    )

            request_id = str(uuid.uuid4())
            LOGGER.info(
                "_create_and_publish_resource: sending to witness resourceType=%s "
                "content.tag=%s request_id=%s",
                resource_type,
                content_tag,
                request_id,
            )
            endorsed_resource = await witness.witness_attested_resource(
                scid, secured_resource, request_id
            )

            if not isinstance(endorsed_resource, dict):
                if await is_witness(profile):
                    pass

                # Get witness connection for saving record
                witness_connection = await controller._get_active_witness_connection()
                connection_id = (
                    witness_connection.connection_id if witness_connection else ""
                )
                role = "self-witness" if not connection_id else "controller"

                # Save full pending record
                await pending_records.save_pending_record(
                    profile,
                    scid,
                    secured_resource,
                    request_id,
                    connection_id,
                    role=role,
                )

                # Return immediately with STATE_WAIT so acapy_agent stores the
                # rev_reg_def before set_active_registry runs during rotation.
                # When the witness approves, the handler will update the record.
                return (secured_resource, SchemaState.STATE_WAIT)
            else:
                # Upload resource to server
                await server.upload_attested_resource(endorsed_resource)
                return (endorsed_resource, STATE_FINISHED)
        else:
            # Upload resource to server
            await server.upload_attested_resource(secured_resource)
            return (secured_resource, STATE_FINISHED)
