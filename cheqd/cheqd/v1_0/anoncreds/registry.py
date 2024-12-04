"""DID Cheqd Anoncreds Registry."""

import logging
from typing import Optional, Pattern, Sequence
from uuid import uuid4

from acapy_agent.anoncreds.base import (
    AnonCredsRegistrationError,
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
    RevRegDef,
    RevRegDefResult,
)
from acapy_agent.anoncreds.models.schema import (
    AnonCredsSchema,
    GetSchemaResult,
    SchemaResult,
    SchemaState,
)
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.jwt import dict_to_b64
from aiohttp import web

from cheqd.v1_0.did.manager import CheqdDIDManager
from cheqd.v1_0.did.registrar import CheqdDIDRegistrar

from ..resolver.resolver import CheqdDIDResolver
from ..validation import CheqdDID

LOGGER = logging.getLogger(__name__)


class DIDCheqdRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """DIDCheqdRegistry."""

    registrar: CheqdDIDRegistrar
    resolver: CheqdDIDResolver

    def __init__(self):
        """Initialize an instance.

        Args:
            None

        """

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported Identifiers regex."""
        return CheqdDID.PATTERN

    @staticmethod
    def make_schema_id(schema: AnonCredsSchema, resource_id: str) -> str:
        """Derive the ID for a schema."""
        return f"{schema.issuer_id}/resources/{resource_id}"

    @staticmethod
    def make_credential_definition_id(
        credential_definition: CredDef, resource_id: str
    ) -> str:
        """Derive the ID for a credential definition."""
        return f"{credential_definition.issuer_id}/resources/{resource_id}"

    @staticmethod
    def split_schema_id(schema_id: str) -> (str, str):
        """Derive the ID for a schema."""
        ids = schema_id.split("/")
        return ids[0], ids[2]

    async def setup(self, context: InjectionContext, registrar_url, resolver_url):
        """Setup."""
        self.registrar = CheqdDIDRegistrar(registrar_url)
        self.resolver = CheqdDIDResolver(resolver_url)
        print("Successfully registered DIDCheqdRegistry")

    async def get_schema(self, profile: Profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        schema = await self.resolver.resolve_resource(schema_id)
        (did, resource_id) = self.split_schema_id(schema_id)

        anoncreds_schema = AnonCredsSchema(
            issuer_id=did,
            attr_names=schema["attrNames"],
            name=schema["name"],
            version=schema["version"],
        )

        return GetSchemaResult(
            schema_id=schema_id,
            schema=anoncreds_schema,
            schema_metadata={},
            resolution_metadata={
                "resource_id": resource_id,
                "resource_name": schema.get("name"),
                "resource_type": "anonCredsSchema",
            },
        )

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        _options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""
        resource_type = "anonCredsSchema"
        resource_name = schema.name
        resource_version = schema.version

        LOGGER.debug("Registering schema")
        cheqd_schema = {
            "name": resource_name,
            "type": resource_type,
            "version": resource_version,
            "data": dict_to_b64(
                {
                    "name": schema.name,
                    "version": schema.version,
                    "attrNames": schema.attr_names,
                }
            ),
        }

        LOGGER.debug("schema value: %s", cheqd_schema)
        try:
            resource_state = await self._create_and_publish_resource(
                profile,
                schema.issuer_id,
                cheqd_schema,
            )
            job_id = resource_state.get("jobId")
            resource = resource_state.get("resource")
            resource_id = resource.get("id")
            schema_id = self.make_schema_id(schema, resource_id)
        except Exception as err:
            raise AnonCredsRegistrationError(f"{err}")
        return SchemaResult(
            job_id=job_id,
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
        credential_definition = await self.resolver.resolve_resource(
            credential_definition_id
        )
        (did, resource_id) = self.split_schema_id(credential_definition_id)

        anoncreds_credential_definition = CredDef(
            issuer_id=did,
            schema_id=credential_definition["schemaId"],
            type=credential_definition["type"],
            tag=credential_definition["tag"],
            value=CredDefValue.deserialize(credential_definition["value"]),
        )

        return GetCredDefResult(
            credential_definition_id=credential_definition_id,
            credential_definition=anoncreds_credential_definition,
            credential_definition_metadata={},
            resolution_metadata={
                "resource_id": resource_id,
                "resource_name": credential_definition.get("tag"),
                "resource_type": "anonCredsCredDef",
            },
        )

    async def register_credential_definition(
        self,
        profile: Profile,
        schema: GetSchemaResult,
        credential_definition: CredDef,
        _options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""
        resource_type = "anonCredsCredDef"
        resource_name = credential_definition.tag

        cred_def = {
            "name": resource_name,
            "type": resource_type,
            "data": dict_to_b64(
                {
                    "type": credential_definition.type,
                    "tag": credential_definition.tag,
                    "value": credential_definition.value.serialize(),
                    "schemaId": schema.schema_id,
                }
            ),
            "version": str(uuid4()),
        }

        resource_state = await self._create_and_publish_resource(
            profile, credential_definition.issuer_id, cred_def
        )
        job_id = resource_state.get("jobId")
        resource = resource_state.get("resource")
        resource_id = resource.get("id")

        credential_definition_id = self.make_credential_definition_id(
            credential_definition, resource_id
        )

        return CredDefResult(
            job_id=job_id,
            credential_definition_state=CredDefState(
                state=CredDefState.STATE_FINISHED,
                credential_definition_id=credential_definition_id,
                credential_definition=credential_definition,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
            credential_definition_metadata={},
        )

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
        self,
        profile: Profile,
        revocation_registry_id: str,
        timestamp_from: Optional[int] = 0,
        timestamp_to: Optional[int] = None,
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

    @staticmethod
    async def _create_and_publish_resource(
        profile: Profile, did: str, options: dict
    ) -> dict:
        """Create, Sign and Publish a Resource."""
        cheqd_manager = CheqdDIDManager(profile)
        async with profile.session() as session:
            wallet = session.inject_or(BaseWallet)
            if not wallet:
                raise web.HTTPForbidden(reason="No wallet available")
            try:
                # request create resource operation
                create_request_res = await cheqd_manager.registrar.create_resource(
                    did, options
                )

                job_id: str = create_request_res.get("jobId")
                resource_state = create_request_res.get("resourceState")

                LOGGER.debug("JOBID %s", job_id)
                if resource_state.get("state") == "action":
                    signing_requests: dict = resource_state.get("signingRequest")
                    if not signing_requests:
                        raise Exception("No signing requests available for update.")
                    # sign all requests
                    signed_responses = await CheqdDIDManager.sign_requests(
                        wallet, signing_requests
                    )

                    # publish resource
                    publish_resource_res = await cheqd_manager.registrar.create_resource(
                        did,
                        {
                            "jobId": job_id,
                            "secret": {"signingResponse": signed_responses},
                        },
                    )
                    resource_state = publish_resource_res.get("resourceState")
                    if resource_state.get("state") != "finished":
                        raise AnonCredsRegistrationError(
                            f"Error publishing Resource {resource_state.get("reason")}"
                        )
                    return resource_state
                else:
                    raise AnonCredsRegistrationError(
                        f"Error publishing Resource {resource_state.get("reason")}"
                    )
            except Exception as err:
                raise AnonCredsRegistrationError(f"{err}")
