"""AnonCreds Hedera registry."""

import re
import time
from typing import Pattern, cast

from acapy_agent.anoncreds.base import (
    AnonCredsObjectNotFound,
    AnonCredsResolutionError,
    BaseAnonCredsRegistrar,
    BaseAnonCredsResolver,
    CredDefResult,
    GetCredDefResult,
    GetRevListResult,
    GetRevRegDefResult,
    GetSchemaResult,
    RevListResult,
    RevRegDefResult,
    SchemaResult,
)
from acapy_agent.anoncreds.events import RevListFinishedEvent
from acapy_agent.anoncreds.models.schema_info import AnonCredsSchemaInfo
from acapy_agent.core.event_bus import EventBus
from acapy_agent.wallet.base import BaseWallet
from hiero_sdk_python import Client
from hiero_did_sdk_python.anoncreds.hedera_anoncreds_registry import (
    HederaAnonCredsRegistry as SdkHederaAnonCredsRegistry,
)

from ..client import get_client
from ..config import Config
from .types import (
    build_acapy_cred_def_result,
    build_acapy_get_cred_def_result,
    build_acapy_get_rev_list_result,
    build_acapy_get_rev_reg_def_result,
    build_acapy_get_schema_result,
    build_acapy_rev_list_result,
    build_acapy_rev_reg_def_result,
    build_acapy_schema_result,
    build_hedera_anoncreds_schema,
    build_hedera_anoncreds_rev_list,
    build_hedera_anoncreds_rev_reg_def,
    build_hedera_anoncreds_cred_def,
)
from ..utils import get_encoded_private_key_for_did, inject_or_fail


def _validate_resolution_result(hedera_res, attribute_to_check):
    resolution_metadata = hedera_res.resolution_metadata

    if "error" in resolution_metadata:
        error = resolution_metadata.get("error")
        error_message = resolution_metadata.get("message") or "Unknown error"

        if error == "notFound":
            raise AnonCredsObjectNotFound(error_message)
        else:
            raise AnonCredsResolutionError(error_message)

    if getattr(hedera_res, attribute_to_check, None) is None:
        raise AnonCredsResolutionError(f"Failed to retrieve {attribute_to_check}")


class HederaAnonCredsRegistry(BaseAnonCredsResolver, BaseAnonCredsRegistrar):
    """AnonCredsHederaRegistry."""

    def __init__(self):
        """Initializer."""
        self._supported_identifiers_regex = re.compile("^did:hedera:.*$")

    @property
    def supported_identifiers_regex(self) -> Pattern:
        """Supported identifiers regular expression."""
        return self._supported_identifiers_regex

    async def setup(self, context):
        """Setup registry based on current context."""
        settings = Config.from_settings(context.settings)

        network = settings.network
        operator_id = settings.operator_id
        operator_key = settings.operator_key

        client: Client = get_client(network, operator_id, operator_key)

        self._hedera_anoncreds_registry = SdkHederaAnonCredsRegistry(client)

    async def get_schema(self, profile, schema_id) -> GetSchemaResult:
        """Get schema."""
        hedera_res = await self._hedera_anoncreds_registry.get_schema(schema_id)

        _validate_resolution_result(hedera_res, "schema")

        return build_acapy_get_schema_result(hedera_res)

    async def get_credential_definition(
        self, profile, credential_definition_id
    ) -> GetCredDefResult:
        """Get credential definition."""
        hedera_res = await self._hedera_anoncreds_registry.get_cred_def(
            credential_definition_id
        )

        _validate_resolution_result(hedera_res, "credential_definition")

        return build_acapy_get_cred_def_result(hedera_res)

    async def get_revocation_registry_definition(
        self, profile, revocation_registry_id
    ) -> GetRevRegDefResult:
        """Get revocation registry definition."""
        hedera_res = await self._hedera_anoncreds_registry.get_rev_reg_def(
            revocation_registry_id
        )

        _validate_resolution_result(hedera_res, "revocation_registry_definition")

        assert hedera_res.revocation_registry_definition is not None

        return build_acapy_get_rev_reg_def_result(hedera_res)

    async def get_revocation_list(
        self,
        profile,
        revocation_registry_id: str,
        timestamp_from_: int,
        timestamp_to: int,
    ) -> GetRevListResult:
        """Get revocation list."""
        hedera_res = await self._hedera_anoncreds_registry.get_rev_list(
            revocation_registry_id, timestamp_to or int(time.time())
        )

        _validate_resolution_result(hedera_res, "revocation_list")

        assert hedera_res.revocation_list is not None

        return build_acapy_get_rev_list_result(hedera_res)

    async def get_schema_info_by_id(self, profile, schema_id) -> AnonCredsSchemaInfo:
        """Get schema info by schema id."""
        res = await self._hedera_anoncreds_registry.get_schema(schema_id)

        _validate_resolution_result(res, "schema")

        assert res.schema

        return AnonCredsSchemaInfo(
            issuer_id=res.schema.issuer_id,
            name=res.schema.name,
            version=res.schema.version,
        )

    async def register_schema(self, profile, schema, options=None) -> SchemaResult:
        """Register schema."""
        async with profile.session() as session:
            issuer_did = schema.issuer_id

            wallet = inject_or_fail(session, BaseWallet, AnonCredsResolutionError)

            encoded_private_key = await get_encoded_private_key_for_did(
                wallet, issuer_did
            )

            res = await self._hedera_anoncreds_registry.register_schema(
                schema=build_hedera_anoncreds_schema(schema),
                issuer_key_der=encoded_private_key,
            )

            return build_acapy_schema_result(res)

    async def register_credential_definition(
        self, profile, schema, credential_definition, options=None
    ) -> CredDefResult:
        """Register credential definition."""
        async with profile.session() as session:
            issuer_did = schema.schema.issuer_id

            wallet = inject_or_fail(session, BaseWallet, AnonCredsResolutionError)
            encoded_private_key = await get_encoded_private_key_for_did(
                wallet, issuer_did
            )

            res = await self._hedera_anoncreds_registry.register_cred_def(
                cred_def=build_hedera_anoncreds_cred_def(credential_definition),
                issuer_key_der=encoded_private_key,
            )

            return build_acapy_cred_def_result(res)

    async def register_revocation_registry_definition(
        self, profile, revocation_registry_definition, options=None
    ) -> RevRegDefResult:
        """Register revocation registry definition."""
        async with profile.session() as session:
            issuer_did = revocation_registry_definition.issuer_id

            wallet = inject_or_fail(session, BaseWallet, AnonCredsResolutionError)

            encoded_private_key = await get_encoded_private_key_for_did(
                wallet, issuer_did
            )

            hedera_res = await self._hedera_anoncreds_registry.register_rev_reg_def(
                rev_reg_def=build_hedera_anoncreds_rev_reg_def(
                    revocation_registry_definition
                ),
                issuer_key_der=encoded_private_key,
            )

            assert (
                hedera_res.revocation_registry_definition_state.revocation_registry_definition_id
                is not None
            )

            return build_acapy_rev_reg_def_result(hedera_res)

    async def register_revocation_list(
        self, profile, rev_reg_def, rev_list, options=None
    ) -> RevListResult:
        """Register revocation list."""
        async with profile.session() as session:
            issuer_did = rev_reg_def.issuer_id

            wallet = inject_or_fail(
                session,
                BaseWallet,
                AnonCredsResolutionError,
            )

            encoded_private_key = await get_encoded_private_key_for_did(
                wallet, issuer_did
            )

            hedera_res = await self._hedera_anoncreds_registry.register_rev_list(
                build_hedera_anoncreds_rev_list(rev_list), encoded_private_key
            )

            return build_acapy_rev_list_result(hedera_res)

    async def update_revocation_list(
        self, profile, rev_reg_def, prev_list, curr_list, revoked, options=None
    ) -> RevListResult:
        """Update revocation list."""
        async with profile.session() as session:
            issuer_did = rev_reg_def.issuer_id

            wallet = inject_or_fail(session, BaseWallet, AnonCredsResolutionError)
            event_bus = inject_or_fail(session, EventBus, AnonCredsResolutionError)

            encoded_private_key = await get_encoded_private_key_for_did(
                wallet, issuer_did
            )

            hedera_res = await self._hedera_anoncreds_registry.update_rev_list(
                build_hedera_anoncreds_rev_list(prev_list),
                build_hedera_anoncreds_rev_list(curr_list),
                revoked,
                encoded_private_key,
            )

            await event_bus.notify(
                profile,
                RevListFinishedEvent.with_payload(
                    curr_list.rev_reg_def_id, cast(list, revoked)
                ),
            )

            return build_acapy_rev_list_result(hedera_res)
