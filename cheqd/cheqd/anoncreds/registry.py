"""DID Cheqd Anoncreds Registry."""

import logging
import time
from datetime import datetime, timezone
from typing import Optional, Pattern, Sequence, Union
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
from acapy_agent.anoncreds.models.schema_info import AnoncredsSchemaInfo
from acapy_agent.config.injection_context import InjectionContext
from acapy_agent.core.profile import Profile
from acapy_agent.resolver.base import DIDNotFound
from acapy_agent.wallet.base import BaseWallet
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.jwt import dict_to_b64
from pydantic import BaseModel

from ..did.base import (
    DidUrlActionState,
    Options,
    ResourceCreateRequestOptions,
    ResourceUpdateRequestOptions,
    Secret,
    SubmitSignatureOptions,
)
from ..did.helpers import CheqdAnoncredsResourceType
from ..did.manager import CheqdDIDManager
from ..did.registrar import DIDRegistrar
from ..resolver.resolver import CheqdDIDResolver
from ..validation import CheqdDID

LOGGER = logging.getLogger(__name__)


class PublishResourceResponse(BaseModel):
    """Publish Resource Response."""

    did_url: str
    content: Union[dict, str]


class DIDCheqdRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """DIDCheqdRegistry."""

    registrar: DIDRegistrar
    resolver: CheqdDIDResolver

    def __init__(self):
        """Initialize an instance.

        Args:
            None

        """
        self.registrar = DIDRegistrar(method="cheqd")
        self.resolver = CheqdDIDResolver()

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
    def make_revocation_registry_id(
        revocation_registry_definition: RevRegDef, resource_id: str
    ) -> str:
        """Derive the ID for a revocation registry definition."""
        return f"{revocation_registry_definition.issuer_id}/resources/{resource_id}"

    @staticmethod
    def split_did_url(schema_id: str) -> (str, str):
        """Derive the ID for a schema."""
        ids = schema_id.split("/")
        return ids[0], ids[2]

    async def setup(self, _context: InjectionContext, registrar_url, resolver_url):
        """Setup."""
        self.registrar = DIDRegistrar("cheqd", registrar_url)
        self.resolver = CheqdDIDResolver(resolver_url)
        print("Successfully registered DIDCheqdRegistry")

    async def get_schema_info_by_schema_id(
        self, profile: Profile, schema_id: str
    ) -> AnoncredsSchemaInfo:
        """Get the schema info from the registry."""
        schema = self.get_schema(profile, schema_id)
        return {
            "issuer_id": schema.issuer_id,
            "name": schema.name,
            "version": schema.version,
        }

    async def get_schema(self, _profile: Profile, schema_id: str) -> GetSchemaResult:
        """Get a schema from the registry."""
        resource_with_metadata = await self.resolver.dereference_with_metadata(
            _profile, schema_id
        )
        schema = resource_with_metadata.resource
        metadata = resource_with_metadata.metadata

        (did, resource_id) = self.split_did_url(schema_id)

        anoncreds_schema = AnonCredsSchema(
            issuer_id=did,
            attr_names=schema["attrNames"],
            name=schema["name"],
            version=schema["version"],
        )

        return GetSchemaResult(
            schema_id=schema_id,
            schema=anoncreds_schema,
            schema_metadata=metadata,
            resolution_metadata={},
        )

    async def register_schema(
        self,
        profile: Profile,
        schema: AnonCredsSchema,
        _options: Optional[dict] = None,
    ) -> SchemaResult:
        """Register a schema on the registry."""
        resource_type = CheqdAnoncredsResourceType.schema.value
        resource_name = f"{schema.name}"
        resource_version = schema.version

        try:
            # check if schema already exists
            try:
                existing_schema = await self.resolver.dereference_with_metadata(
                    profile,
                    f"{schema.issuer_id}?resourceName={resource_name}&resourceType={resource_type}",
                )
            except DIDNotFound:
                existing_schema = None
            except Exception as ex:
                raise ex

            LOGGER.debug("Existing schema %s", existing_schema)
            # update if schema exists
            if existing_schema is not None:
                cheqd_schema = ResourceUpdateRequestOptions(
                    options=Options(
                        name=resource_name,
                        type=resource_type,
                        versionId=resource_version,
                    ),
                    content=[
                        dict_to_b64(
                            {
                                "name": schema.name,
                                "version": schema.version,
                                "attrNames": schema.attr_names,
                            }
                        )
                    ],
                    did=schema.issuer_id,
                )

                LOGGER.debug("schema value: %s", cheqd_schema)
                publish_resource_res = await self._update_and_publish_resource(
                    profile,
                    self.registrar.DID_REGISTRAR_BASE_URL,
                    self.resolver.DID_RESOLVER_BASE_URL,
                    cheqd_schema,
                )
            else:
                cheqd_schema = ResourceCreateRequestOptions(
                    options=Options(
                        name=resource_name,
                        type=resource_type,
                        versionId=resource_version,
                    ),
                    content=dict_to_b64(
                        {
                            "name": schema.name,
                            "version": schema.version,
                            "attrNames": schema.attr_names,
                        }
                    ),
                    did=schema.issuer_id,
                )

                LOGGER.debug("schema value: %s", cheqd_schema)
                publish_resource_res = await self._create_and_publish_resource(
                    profile,
                    self.registrar.DID_REGISTRAR_BASE_URL,
                    self.resolver.DID_RESOLVER_BASE_URL,
                    cheqd_schema,
                )

            LOGGER.debug("Published resource %s", publish_resource_res)

            schema_id = publish_resource_res.did_url
            (_, resource_id) = self.split_did_url(schema_id)
        except Exception as err:
            raise AnonCredsRegistrationError(f"{err}")
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
        self, _profile: Profile, credential_definition_id: str
    ) -> GetCredDefResult:
        """Get a credential definition from the registry."""
        resource_with_metadata = await self.resolver.dereference_with_metadata(
            _profile, credential_definition_id
        )
        credential_definition = resource_with_metadata.resource
        metadata = resource_with_metadata.metadata
        (did, resource_id) = self.split_did_url(credential_definition_id)

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
            credential_definition_metadata=metadata,
            resolution_metadata={},
        )

    async def register_credential_definition(
        self,
        profile: Profile,
        schema: GetSchemaResult,
        credential_definition: CredDef,
        _options: Optional[dict] = None,
    ) -> CredDefResult:
        """Register a credential definition on the registry."""
        resource_type = CheqdAnoncredsResourceType.credentialDefinition.value
        # TODO: max chars are 31 for resource, on exceeding this should be hashed
        resource_name = f"{schema.schema_value.name}-{credential_definition.tag}"

        cred_def = ResourceCreateRequestOptions(
            options=Options(
                name=resource_name,
                type=resource_type,
                versionId=credential_definition.tag,
            ),
            content=dict_to_b64(
                {
                    "type": credential_definition.type,
                    "tag": credential_definition.tag,
                    "value": credential_definition.value.serialize(),
                    "schemaId": schema.schema_id,
                }
            ),
            did=credential_definition.issuer_id,
        )

        publish_resource_res = await self._create_and_publish_resource(
            profile,
            self.registrar.DID_REGISTRAR_BASE_URL,
            self.resolver.DID_RESOLVER_BASE_URL,
            cred_def,
        )
        credential_definition_id = publish_resource_res.did_url
        (_, resource_id) = self.split_did_url(credential_definition_id)

        return CredDefResult(
            job_id=None,
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
        self, _profile: Profile, revocation_registry_id: str
    ) -> GetRevRegDefResult:
        """Get a revocation registry definition from the registry."""
        resource_with_metadata = await self.resolver.dereference_with_metadata(
            _profile, revocation_registry_id
        )
        revocation_registry_definition = resource_with_metadata.resource
        metadata = resource_with_metadata.metadata

        (did, resource_id) = self.split_did_url(revocation_registry_id)

        anoncreds_revocation_registry_definition = RevRegDef(
            issuer_id=did,
            cred_def_id=revocation_registry_definition["credDefId"],
            type=revocation_registry_definition["revocDefType"],
            tag=revocation_registry_definition["tag"],
            value=RevRegDefValue.deserialize(revocation_registry_definition["value"]),
        )

        return GetRevRegDefResult(
            revocation_registry_id=revocation_registry_id,
            revocation_registry=anoncreds_revocation_registry_definition,
            revocation_registry_metadata=metadata,
            resolution_metadata={},
        )

    async def register_revocation_registry_definition(
        self,
        profile: Profile,
        revocation_registry_definition: RevRegDef,
        _options: Optional[dict] = None,
    ) -> RevRegDefResult:
        """Register a revocation registry definition on the registry."""

        cred_def_result = await self.get_credential_definition(
            profile, revocation_registry_definition.cred_def_id
        )
        cred_def_res = cred_def_result.credential_definition_metadata.get("resourceName")
        # TODO: max chars are 31 for resource name, on exceeding this should be hashed
        resource_name = f"{cred_def_res}-{revocation_registry_definition.tag}"
        resource_type = CheqdAnoncredsResourceType.revocationRegistryDefinition.value

        rev_reg_def = ResourceCreateRequestOptions(
            options=Options(
                name=resource_name,
                type=resource_type,
                versionId=revocation_registry_definition.tag,
            ),
            content=dict_to_b64(
                {
                    "revocDefType": revocation_registry_definition.type,
                    "tag": revocation_registry_definition.tag,
                    "value": revocation_registry_definition.value.serialize(),
                    "credDefId": revocation_registry_definition.cred_def_id,
                }
            ),
            did=revocation_registry_definition.issuer_id,
        )

        publish_resource_res = await self._create_and_publish_resource(
            profile,
            self.registrar.DID_REGISTRAR_BASE_URL,
            self.resolver.DID_RESOLVER_BASE_URL,
            rev_reg_def,
        )
        revocation_registry_definition_id = publish_resource_res.did_url
        (_, resource_id) = self.split_did_url(revocation_registry_definition_id)

        return RevRegDefResult(
            job_id=None,
            revocation_registry_definition_state=RevRegDefState(
                state=RevRegDefState.STATE_FINISHED,
                revocation_registry_definition_id=revocation_registry_definition_id,
                revocation_registry_definition=revocation_registry_definition,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
            revocation_registry_definition_metadata={},
        )

    async def get_revocation_list(
        self,
        profile: Profile,
        revocation_registry_id: str,
        _timestamp_from: Optional[int] = 0,
        timestamp_to: Optional[int] = None,
    ) -> GetRevListResult:
        """Get a revocation list from the registry."""
        revocation_registry_definition = await self.get_revocation_registry_definition(
            profile,
            revocation_registry_id,
        )
        resource_name = revocation_registry_definition.revocation_registry_metadata.get(
            "resourceName"
        )
        (did, resource_id) = self.split_did_url(revocation_registry_id)

        resource_type = CheqdAnoncredsResourceType.revocationStatusList.value
        epoch_time = timestamp_to or int(time.time())
        dt_object = datetime.fromtimestamp(epoch_time, tz=timezone.utc)

        resource_time = dt_object.strftime("%Y-%m-%dT%H:%M:%SZ")
        resource_with_metadata = await self.resolver.dereference_with_metadata(
            profile,
            f"{did}?resourceType={resource_type}&resourceName={resource_name}&resourceVersionTime={resource_time}",
        )
        status_list = resource_with_metadata.resource
        metadata = resource_with_metadata.metadata

        revocation_list = RevList(
            issuer_id=did,
            rev_reg_def_id=revocation_registry_id,
            revocation_list=status_list.get("revocationList"),
            current_accumulator=status_list.get("currentAccumulator"),
            timestamp=epoch_time,  # fix: return timestamp from resolution metadata
        )

        return GetRevListResult(
            revocation_list=revocation_list,
            resolution_metadata={},
            revocation_registry_metadata=metadata,
        )

    async def get_schema_info_by_id(
        self, profile: Profile, schema_id: str
    ) -> AnoncredsSchemaInfo:
        """Get a schema info from the registry."""
        resource_with_metadata = await self.resolver.dereference_with_metadata(
            profile, schema_id
        )
        schema = resource_with_metadata.resource
        (did, resource_id) = self.split_did_url(schema_id)
        anoncreds_schema = AnoncredsSchemaInfo(
            issuer_id=did,
            name=schema["name"],
            version=schema["version"],
        )
        return anoncreds_schema

    async def register_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        rev_list: RevList,
        _options: Optional[dict] = None,
    ) -> RevListResult:
        """Register a revocation list on the registry."""
        revocation_registry_definition = await self.get_revocation_registry_definition(
            profile,
            rev_list.rev_reg_def_id,
        )
        resource_name = revocation_registry_definition.revocation_registry_metadata.get(
            "resourceName"
        )
        resource_type = CheqdAnoncredsResourceType.revocationStatusList.value
        rev_status_list = ResourceCreateRequestOptions(
            options=Options(
                name=resource_name,
                type=resource_type,
                versionId=str(uuid4()),
            ),
            content=dict_to_b64(
                {
                    "revocationList": rev_list.revocation_list,
                    "currentAccumulator": rev_list.current_accumulator,
                    "revRegDefId": rev_list.rev_reg_def_id,
                }
            ),
            did=rev_reg_def.issuer_id,
        )

        publish_resource_res = await self._create_and_publish_resource(
            profile,
            self.registrar.DID_REGISTRAR_BASE_URL,
            self.resolver.DID_RESOLVER_BASE_URL,
            rev_status_list,
        )
        did_url = publish_resource_res.did_url
        (_, resource_id) = self.split_did_url(did_url)

        return RevListResult(
            job_id=None,
            revocation_list_state=RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=rev_list,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
            revocation_list_metadata={},
        )

    async def update_revocation_list(
        self,
        profile: Profile,
        rev_reg_def: RevRegDef,
        _prev_list: RevList,
        curr_list: RevList,
        _revoked: Sequence[int],
        _options: Optional[dict] = None,
    ) -> RevListResult:
        """Update a revocation list on the registry."""
        revocation_registry_definition = await self.get_revocation_registry_definition(
            profile,
            curr_list.rev_reg_def_id,
        )
        resource_name = revocation_registry_definition.revocation_registry_metadata.get(
            "resourceName"
        )
        resource_type = CheqdAnoncredsResourceType.revocationStatusList.value
        rev_status_list = ResourceUpdateRequestOptions(
            options=Options(
                name=resource_name,
                type=resource_type,
                versionId=str(uuid4()),
            ),
            content=[
                dict_to_b64(
                    {
                        "revocationList": curr_list.revocation_list,
                        "currentAccumulator": curr_list.current_accumulator,
                        "revRegDefId": curr_list.rev_reg_def_id,
                    }
                )
            ],
            did=rev_reg_def.issuer_id,
        )

        publish_resource_res = await self._update_and_publish_resource(
            profile,
            self.registrar.DID_REGISTRAR_BASE_URL,
            self.resolver.DID_RESOLVER_BASE_URL,
            rev_status_list,
        )
        did_url = publish_resource_res.did_url
        (_, resource_id) = self.split_did_url(did_url)

        return RevListResult(
            job_id=None,
            revocation_list_state=RevListState(
                state=RevListState.STATE_FINISHED,
                revocation_list=curr_list,
            ),
            registration_metadata={
                "resource_id": resource_id,
                "resource_name": resource_name,
                "resource_type": resource_type,
            },
            revocation_list_metadata={},
        )

    @staticmethod
    async def _create_and_publish_resource(
        profile: Profile,
        registrar_url: str,
        resolver_url: str,
        options: ResourceCreateRequestOptions,
    ) -> PublishResourceResponse:
        """Create, Sign and Publish a Resource."""
        cheqd_manager = CheqdDIDManager(profile, registrar_url, resolver_url)
        async with profile.session() as session:
            wallet = session.inject_or(BaseWallet)
            if not wallet:
                raise WalletError("No wallet available")
            try:
                # request create resource operation
                create_request_res = await cheqd_manager.registrar.create_resource(
                    options
                )
                job_id = create_request_res.jobId
                resource_state = create_request_res.didUrlState
                if not resource_state:
                    raise Exception("No signing requests available for update.")

                LOGGER.debug("JOBID %s", job_id)
                if isinstance(resource_state, DidUrlActionState):
                    signing_requests = resource_state.signingRequest
                    if not signing_requests:
                        raise Exception("No signing requests available for update.")
                    # sign all requests
                    signed_responses = await CheqdDIDManager.sign_requests(
                        wallet, signing_requests
                    )
                    LOGGER.debug("Signed Responses %s", signed_responses)

                    # publish resource
                    publish_resource_res = await cheqd_manager.registrar.create_resource(
                        SubmitSignatureOptions(
                            jobId=job_id,
                            secret=Secret(signingResponse=signed_responses),
                            did=options.did,
                        ),
                    )
                    resource_state = publish_resource_res.didUrlState
                    if resource_state.state != "finished":
                        raise AnonCredsRegistrationError(
                            f"Error publishing Resource {resource_state.reason}"
                        )
                    return PublishResourceResponse(
                        content=resource_state.content,
                        did_url=resource_state.didUrl,
                    )
                else:
                    raise AnonCredsRegistrationError(
                        f"Error publishing Resource {resource_state.reason}"
                    )
            except Exception as err:
                raise AnonCredsRegistrationError(f"{err}")

    @staticmethod
    async def _update_and_publish_resource(
        profile: Profile,
        registrar_url: str,
        resolver_url: str,
        options: ResourceUpdateRequestOptions,
    ) -> PublishResourceResponse:
        """Update, Sign and Publish a Resource."""
        cheqd_manager = CheqdDIDManager(profile, registrar_url, resolver_url)
        async with profile.session() as session:
            wallet = session.inject_or(BaseWallet)
            if not wallet:
                raise WalletError("No wallet available")
            try:
                # request update resource operation
                create_request_res = await cheqd_manager.registrar.update_resource(
                    options
                )

                job_id: str = create_request_res.jobId
                resource_state = create_request_res.didUrlState

                LOGGER.debug("JOBID %s", job_id)
                if isinstance(resource_state, DidUrlActionState):
                    signing_requests = resource_state.signingRequest
                    if not signing_requests:
                        raise Exception("No signing requests available for update.")
                    # sign all requests
                    signed_responses = await CheqdDIDManager.sign_requests(
                        wallet, signing_requests
                    )
                    LOGGER.debug("Signed Responses %s", signed_responses)
                    # publish resource
                    publish_resource_res = await cheqd_manager.registrar.update_resource(
                        SubmitSignatureOptions(
                            jobId=job_id,
                            secret=Secret(signingResponse=signed_responses),
                            did=options.did,
                        ),
                    )
                    resource_state = publish_resource_res.didUrlState
                    if resource_state.state != "finished":
                        raise AnonCredsRegistrationError(
                            f"Error publishing Resource {resource_state.reason}"
                        )
                    return PublishResourceResponse(
                        content=resource_state.content,
                        did_url=resource_state.didUrl,
                    )
                else:
                    raise AnonCredsRegistrationError(
                        f"Error publishing Resource {resource_state.reason}"
                    )
            except Exception as err:
                raise AnonCredsRegistrationError(f"{err}")
