"""Helpers fpr mapping AnonCreds-related data classes."""

from acapy_agent.anoncreds.base import (
    AnonCredsSchema as AcapyAnonCredsSchema,
    CredDef as AcapyAnonCredsCredDef,
    CredDefResult as AcapyCredDefResult,
    GetRevListResult as AcapyGetRevListResult,
    GetRevRegDefResult as AcapyGetRevRegDefResult,
    GetSchemaResult as AcapyGetSchemaResult,
    RevList as AcapyRevList,
    RevListResult as AcapyRevListResult,
    RevRegDef as AcapyRevRegDef,
    RevRegDefResult as AcapyRevRegDefResult,
    SchemaResult as AcapySchemaResult,
)
from acapy_agent.anoncreds.models.credential_definition import (
    CredDefState as AcapyCredDefState,
    CredDefValue as AcapyCredDefValue,
    CredDefValuePrimary as AcapyCredDefValuePrimary,
    CredDefValueRevocation as AcapyCredDefValueRevocation,
    GetCredDefResult as AcapyGetCredDefResult,
)
from acapy_agent.anoncreds.models.revocation import (
    RevListState as AcapyRevListState,
    RevRegDefState as AcapyRevRegDefState,
    RevRegDefValue as AcapyRevRegDefValue,
)
from acapy_agent.anoncreds.models.schema import SchemaState as AcapySchemaState
from hiero_did_sdk_python.anoncreds.models import (
    CredDefValue as HederaCredDefValue,
    CredDefValuePrimary as HederaCredDefValuePrimary,
    CredDefValueRevocation as HederaCredDefValueRevocation,
    AnonCredsRevRegDef as HederaAnonCredsRevRegDef,
    RevRegDefValue as HederaRevRegDefValue,
    AnonCredsSchema as HederaAnonCredsSchema,
)
from hiero_did_sdk_python.anoncreds.types import (
    AnonCredsCredDef as HederaAnonCredsCredDef,
    AnonCredsRevList as HederaAnonCredsRevList,
    GetCredDefResult as HederaGetCredDefResult,
    GetRevListResult as HederaGetRevListResult,
    GetRevRegDefResult as HederaGetRevRegDefResult,
    GetSchemaResult as HederaGetSchemaResult,
    RegisterCredDefResult as HederaCredDefResult,
    RegisterRevListResult as HederaRegisterRevListResult,
    RegisterRevRegDefResult as HederaRegisterRevRegDefResult,
    RegisterSchemaResult as HederaSchemaResult,
)


def build_hedera_anoncreds_schema(schema: AcapyAnonCredsSchema) -> HederaAnonCredsSchema:
    """Map object."""
    return HederaAnonCredsSchema(
        name=schema.name,
        issuer_id=schema.issuer_id,
        attr_names=schema.attr_names,
        version=schema.version,
    )


def build_hedera_anoncreds_cred_def(
    cred_def: AcapyAnonCredsCredDef,
) -> HederaAnonCredsCredDef:
    """Map object."""
    revocation = (
        HederaCredDefValueRevocation(
            g=cred_def.value.revocation.g,
            g_dash=cred_def.value.revocation.g_dash,
            h=cred_def.value.revocation.h,
            h0=cred_def.value.revocation.h0,
            h1=cred_def.value.revocation.h1,
            h2=cred_def.value.revocation.h2,
            htilde=cred_def.value.revocation.htilde,
            h_cap=cred_def.value.revocation.h_cap,
            u=cred_def.value.revocation.u,
            pk=cred_def.value.revocation.pk,
            y=cred_def.value.revocation.y,
        )
        if cred_def.value.revocation
        else None
    )

    return HederaAnonCredsCredDef(
        issuer_id=cred_def.issuer_id,
        schema_id=cred_def.schema_id,
        tag=cred_def.tag,
        value=HederaCredDefValue(
            HederaCredDefValuePrimary(
                n=cred_def.value.primary.n,
                s=cred_def.value.primary.s,
                r=cred_def.value.primary.r,
                rctxt=cred_def.value.primary.rctxt,
                z=cred_def.value.primary.z,
            ),
            revocation,
        ),
    )


def build_hedera_anoncreds_rev_reg_def(
    revocation_registry_definition: AcapyRevRegDef,
) -> HederaAnonCredsRevRegDef:
    """Map object."""
    return HederaAnonCredsRevRegDef(
        issuer_id=revocation_registry_definition.issuer_id,
        cred_def_id=revocation_registry_definition.cred_def_id,
        tag=revocation_registry_definition.tag,
        value=HederaRevRegDefValue(
            public_keys=revocation_registry_definition.value.public_keys,
            max_cred_num=revocation_registry_definition.value.max_cred_num,
            tails_location=revocation_registry_definition.value.tails_location,
            tails_hash=revocation_registry_definition.value.tails_hash,
        ),
    )


def build_hedera_anoncreds_rev_list(rev_list: AcapyRevList) -> HederaAnonCredsRevList:
    """Map object."""
    return HederaAnonCredsRevList(
        issuer_id=rev_list.issuer_id,
        rev_reg_def_id=rev_list.rev_reg_def_id,
        revocation_list=rev_list.revocation_list,
        current_accumulator=rev_list.current_accumulator,
        timestamp=rev_list.timestamp,
    )


def build_acapy_get_schema_result(
    hedera_res: HederaGetSchemaResult,
) -> AcapyGetSchemaResult:
    """Map object."""
    assert hedera_res.schema

    return AcapyGetSchemaResult(
        schema=AcapyAnonCredsSchema(
            issuer_id=hedera_res.schema.issuer_id,
            attr_names=hedera_res.schema.attr_names,
            name=hedera_res.schema.name,
            version=hedera_res.schema.version,
        ),
        schema_id=hedera_res.schema_id,
        resolution_metadata=hedera_res.resolution_metadata,
        schema_metadata=hedera_res.schema_metadata,
    )


def build_acapy_get_cred_def_result(
    hedera_res: HederaGetCredDefResult,
) -> AcapyGetCredDefResult:
    """Map object."""
    assert hedera_res.credential_definition

    revocation = (
        AcapyCredDefValueRevocation(
            g=hedera_res.credential_definition.value.revocation.g,
            g_dash=hedera_res.credential_definition.value.revocation.g_dash,
            h=hedera_res.credential_definition.value.revocation.h,
            h0=hedera_res.credential_definition.value.revocation.h0,
            h1=hedera_res.credential_definition.value.revocation.h1,
            h2=hedera_res.credential_definition.value.revocation.h2,
            htilde=hedera_res.credential_definition.value.revocation.htilde,
            h_cap=hedera_res.credential_definition.value.revocation.h_cap,
            u=hedera_res.credential_definition.value.revocation.u,
            pk=hedera_res.credential_definition.value.revocation.pk,
            y=hedera_res.credential_definition.value.revocation.y,
        )
        if hedera_res.credential_definition.value.revocation
        else None
    )

    return AcapyGetCredDefResult(
        credential_definition_id=hedera_res.credential_definition_id,
        credential_definition=AcapyAnonCredsCredDef(
            issuer_id=hedera_res.credential_definition.issuer_id,
            schema_id=hedera_res.credential_definition.schema_id,
            type="CL",
            tag=hedera_res.credential_definition.tag,
            value=AcapyCredDefValue(
                AcapyCredDefValuePrimary(
                    n=hedera_res.credential_definition.value.primary.n,
                    s=hedera_res.credential_definition.value.primary.s,
                    r=hedera_res.credential_definition.value.primary.r,
                    rctxt=hedera_res.credential_definition.value.primary.rctxt,
                    z=hedera_res.credential_definition.value.primary.z,
                ),
                revocation,
            ),
        ),
        resolution_metadata=hedera_res.resolution_metadata,
        credential_definition_metadata=hedera_res.credential_definition_metadata,
    )


def build_acapy_get_rev_reg_def_result(
    hedera_res: HederaGetRevRegDefResult,
) -> AcapyGetRevRegDefResult:
    """Map object."""
    assert hedera_res.revocation_registry_definition is not None

    return AcapyGetRevRegDefResult(
        revocation_registry=AcapyRevRegDef(
            issuer_id=hedera_res.revocation_registry_definition.issuer_id,
            type="CL_ACCUM",
            cred_def_id=hedera_res.revocation_registry_definition.cred_def_id,
            tag=hedera_res.revocation_registry_definition.tag,
            value=AcapyRevRegDefValue(
                hedera_res.revocation_registry_definition.value.public_keys,
                hedera_res.revocation_registry_definition.value.max_cred_num,
                hedera_res.revocation_registry_definition.value.tails_location,
                hedera_res.revocation_registry_definition.value.tails_hash,
            ),
        ),
        revocation_registry_id=hedera_res.revocation_registry_definition_id,
        resolution_metadata=hedera_res.resolution_metadata,
        revocation_registry_metadata=hedera_res.revocation_registry_definition_metadata,
    )


def build_acapy_get_rev_list_result(
    hedera_res: HederaGetRevListResult,
) -> AcapyGetRevListResult:
    """Map object."""
    assert hedera_res.revocation_list is not None

    return AcapyGetRevListResult(
        revocation_list=AcapyRevList(
            issuer_id=hedera_res.revocation_list.issuer_id,
            rev_reg_def_id=hedera_res.revocation_list.rev_reg_def_id,
            revocation_list=hedera_res.revocation_list.revocation_list,
            current_accumulator=hedera_res.revocation_list.current_accumulator,
            timestamp=hedera_res.revocation_list.timestamp,
        ),
        resolution_metadata=hedera_res.resolution_metadata,
        revocation_registry_metadata=hedera_res.revocation_list_metadata,
    )


def build_acapy_schema_result(
    res: HederaSchemaResult, *, job_id=None
) -> AcapySchemaResult:
    """Map object."""
    return AcapySchemaResult(
        job_id=job_id,
        schema_state=AcapySchemaState(
            state=res.schema_state.state,
            schema_id=res.schema_state.schema_id or "",
            schema=AcapyAnonCredsSchema(
                res.schema_state.schema.issuer_id,
                res.schema_state.schema.attr_names,
                res.schema_state.schema.name,
                res.schema_state.schema.version,
            ),
        ),
        registration_metadata=res.registration_metadata,
        schema_metadata=res.schema_metadata,
    )


def build_acapy_cred_def_result(
    hedera_res: HederaCredDefResult, *, job_id=None
) -> AcapyCredDefResult:
    """Map object."""
    state = hedera_res.credential_definition_state
    cred_def = state.credential_definition
    value = cred_def.value
    schema_id = state.credential_definition.schema_id
    primary = value.primary

    revocation = (
        AcapyCredDefValueRevocation(
            g=value.revocation.g,
            g_dash=value.revocation.g_dash,
            h=value.revocation.h,
            h0=value.revocation.h0,
            h1=value.revocation.h1,
            h2=value.revocation.h2,
            htilde=value.revocation.htilde,
            h_cap=value.revocation.h_cap,
            u=value.revocation.u,
            pk=value.revocation.pk,
            y=value.revocation.y,
        )
        if value.revocation
        else None
    )

    return AcapyCredDefResult(
        job_id,
        AcapyCredDefState(
            state.state,
            hedera_res.credential_definition_state.credential_definition_id,
            AcapyAnonCredsCredDef(
                cred_def.issuer_id,
                schema_id,
                "CL",
                cred_def.tag,
                AcapyCredDefValue(
                    AcapyCredDefValuePrimary(
                        n=primary.n,
                        s=primary.s,
                        r=primary.r,
                        rctxt=primary.rctxt,
                        z=primary.z,
                    ),
                    revocation,
                ),
            ),
        ),
        registration_metadata=hedera_res.registration_metadata,
        credential_definition_metadata=hedera_res.credential_definition_metadata,
    )


def build_acapy_rev_reg_def_result(
    hedera_res: HederaRegisterRevRegDefResult, *, job_id=None
) -> AcapyRevRegDefResult:
    """Map object."""
    assert (
        hedera_res.revocation_registry_definition_state.revocation_registry_definition_id
        is not None
    )

    return AcapyRevRegDefResult(
        job_id=job_id,
        revocation_registry_definition_state=AcapyRevRegDefState(
            state=hedera_res.revocation_registry_definition_state.state,
            revocation_registry_definition_id=hedera_res.revocation_registry_definition_state.revocation_registry_definition_id,
            revocation_registry_definition=AcapyRevRegDef(
                issuer_id=hedera_res.revocation_registry_definition_state.revocation_registry_definition.issuer_id,
                type="CL_ACCUM",
                cred_def_id=hedera_res.revocation_registry_definition_state.revocation_registry_definition.cred_def_id,
                tag=hedera_res.revocation_registry_definition_state.revocation_registry_definition.tag,
                value=AcapyRevRegDefValue(
                    hedera_res.revocation_registry_definition_state.revocation_registry_definition.value.public_keys,
                    hedera_res.revocation_registry_definition_state.revocation_registry_definition.value.max_cred_num,
                    hedera_res.revocation_registry_definition_state.revocation_registry_definition.value.tails_location,
                    hedera_res.revocation_registry_definition_state.revocation_registry_definition.value.tails_hash,
                ),
            ),
        ),
        registration_metadata=hedera_res.registration_metadata,
        revocation_registry_definition_metadata=hedera_res.revocation_registry_definition_metadata,
    )


def build_acapy_rev_list_result(
    hedera_res: HederaRegisterRevListResult, *, job_id=None
) -> AcapyRevListResult:
    """Map object."""
    return AcapyRevListResult(
        job_id=job_id,
        revocation_list_state=AcapyRevListState(
            state=hedera_res.revocation_list_state.state,
            revocation_list=AcapyRevList(
                issuer_id=hedera_res.revocation_list_state.revocation_list.issuer_id,
                rev_reg_def_id=hedera_res.revocation_list_state.revocation_list.rev_reg_def_id,
                revocation_list=hedera_res.revocation_list_state.revocation_list.revocation_list,
                current_accumulator=hedera_res.revocation_list_state.revocation_list.current_accumulator,
                timestamp=hedera_res.revocation_list_state.revocation_list.timestamp,
            ),
        ),
        registration_metadata=hedera_res.registration_metadata,
        revocation_list_metadata=hedera_res.revocation_list_metadata,
    )
