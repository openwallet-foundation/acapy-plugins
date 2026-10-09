"""Credential exchange admin routes."""

import logging
import re
from typing import Mapping

from acapy_agent.admin.decorators.auth import tenant_authentication
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.anoncreds.models.issuer_cred_rev_record import IssuerCredRevRecord
from acapy_agent.core.event_bus import EventBus, EventWithMetadata
from acapy_agent.core.profile import Profile
from acapy_agent.messaging.decorators.attach_decorator import AttachDecorator
from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.messaging.valid import UUID4_EXAMPLE
from acapy_agent.protocols.issue_credential.v2_0.formats.ld_proof.models.cred_detail import (
    LDProofVCDetailSchema,
)
from acapy_agent.protocols.issue_credential.v2_0.messages.cred_format import V20CredFormat
from acapy_agent.protocols.issue_credential.v2_0.messages.cred_proposal import (
    V20CredProposal,
)
from acapy_agent.protocols.issue_credential.v2_0.messages.inner.cred_preview import (
    V20CredPreview,
    V20CredPreviewSchema,
)
from acapy_agent.protocols.issue_credential.v2_0.models.cred_ex_record import (
    V20CredExRecord,
    V20CredExRecordSchema,
)
from acapy_agent.protocols.issue_credential.v2_0.routes import (
    V20CredFilterAnonCredsSchema,
    credential_exchange_create_free_offer,
    credential_exchange_issue,
    credential_exchange_list,
    credential_exchange_problem_report,
    credential_exchange_remove,
    credential_exchange_retrieve,
    credential_exchange_send,
    credential_exchange_send_bound_offer,
    credential_exchange_send_bound_request,
    credential_exchange_send_free_offer,
    credential_exchange_send_free_request,
    credential_exchange_send_proposal,
    credential_exchange_store,
)
from acapy_agent.storage.error import StorageError, StorageNotFoundError
from acapy_agent.utils.tracing import AdminAPIMessageTracingSchema, get_timer, trace_event
from aiohttp import web
from aiohttp_apispec import (
    docs,
    request_schema,
    response_schema,
)
from marshmallow import ValidationError, fields, validates_schema

from .manager import IndyV20CredManager
from .message_types import ATTACHMENT_FORMAT, CRED_20_PROPOSAL, SPEC_URI

LOGGER = logging.getLogger(__name__)


def _formats_filters(filt_spec: Mapping) -> Mapping:
    """Break out formats and filters for v2.0 cred proposal messages."""
    return (
        {
            "formats": [
                V20CredFormat(
                    attach_id=fmt_api,
                    format_=ATTACHMENT_FORMAT[CRED_20_PROPOSAL][fmt_api],
                )
                for fmt_api in filt_spec
            ],
            "filters_attach": [
                AttachDecorator.data_base64(filt_by_fmt, ident=fmt_api)
                for (fmt_api, filt_by_fmt) in filt_spec.items()
            ],
        }
        if filt_spec
        else {}
    )


class IndyV20CredFilterSchema(OpenAPISchema):
    """Credential filtration criteria."""

    anoncreds = fields.Nested(
        V20CredFilterAnonCredsSchema,
        required=False,
        metadata={"description": "Credential filter for anoncreds"},
    )
    ld_proof = fields.Nested(
        LDProofVCDetailSchema,
        required=False,
        metadata={"description": "Credential filter for linked data proof"},
    )

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """Validate schema fields.

        Data must have anoncreds, ld_proof.

        Args:
            data: The data to validate
            kwargs: Additional keyword arguments

        Raises:
            ValidationError: if data has neither anoncreds nor ld_proof

        """
        if not any(f.api in data for f in V20CredFormat.Format):
            raise ValidationError(
                "V20CredFilterSchema requires anoncreds, ld_proof, or both"
            )


class IndyV20IssueCredSchemaCore(AdminAPIMessageTracingSchema):
    """Filter, auto-remove, comment, trace."""

    filter_ = fields.Nested(
        IndyV20CredFilterSchema,
        required=True,
        data_key="filter",
        metadata={"description": "Credential specification criteria by format"},
    )
    auto_remove = fields.Bool(
        required=False,
        metadata={
            "description": (
                "Whether to remove the credential exchange record on completion"
                " (overrides --preserve-exchange-records configuration setting)"
            )
        },
    )
    auto_remove_on_failure = fields.Bool(
        required=False,
        metadata={
            "description": (
                "Whether to remove the credential exchange record on failure"
                " (overrides --no-preserve-failed-exchange-records configuration setting)"
            )
        },
    )
    comment = fields.Str(
        required=False,
        allow_none=True,
        metadata={"description": "Human-readable comment"},
    )

    credential_preview = fields.Nested(V20CredPreviewSchema, required=False)

    replacement_id = fields.Str(
        required=False,
        allow_none=True,
        metadata={
            "description": "Optional identifier used to manage credential replacement",
            "example": UUID4_EXAMPLE,
        },
    )


@docs(
    tags=["issue-credential v2.0"],
    summary=(
        "Create a credential record without sending (generally for use with Out-Of-Band)"
    ),
)
@request_schema(IndyV20IssueCredSchemaCore())
@response_schema(V20CredExRecordSchema(), 200, description="")
@tenant_authentication
async def credential_exchange_create(request: web.BaseRequest):
    """Request handler for creating a credential from attr values.

    The internal credential record will be created without the credential
    being sent to any connection. This can be used in conjunction with
    the `oob` protocols to bind messages to an out of band message.

    Args:
        request: aiohttp request object

    Returns:
        The credential exchange record

    """
    r_time = get_timer()

    context: AdminRequestContext = request["context"]
    profile = context.profile
    body = await request.json()

    comment = body.get("comment")
    preview_spec = body.get("credential_preview")
    filt_spec = body.get("filter")
    auto_remove = body.get(
        "auto_remove", not profile.settings.get("preserve_exchange_records")
    )
    auto_remove_on_failure = body.get(
        "auto_remove_on_failure",
        profile.settings.get("no_preserve_failed_exchange_records"),
    )
    if not filt_spec:
        raise web.HTTPBadRequest(reason="Missing filter")
    trace_msg = body.get("trace")

    try:
        # Not all formats use credential preview
        cred_preview = V20CredPreview.deserialize(preview_spec) if preview_spec else None
        cred_proposal = V20CredProposal(
            comment=comment,
            credential_preview=cred_preview,
            **_formats_filters(filt_spec),
        )
        cred_proposal.assign_trace_decorator(
            context.settings,
            trace_msg,
        )

        trace_event(
            context.settings,
            cred_proposal,
            outcome="credential_exchange_create.START",
        )

        cred_manager = IndyV20CredManager(context.profile)
        (cred_ex_record, cred_offer_message) = await cred_manager.prepare_send(
            connection_id=None,
            cred_proposal=cred_proposal,
            auto_remove=auto_remove,
            auto_remove_on_failure=auto_remove_on_failure,
        )
    except (StorageError, BaseModelError) as err:
        raise web.HTTPBadRequest(reason=err.roll_up) from err

    trace_event(
        context.settings,
        cred_offer_message,
        outcome="credential_exchange_create.END",
        perf_counter=r_time,
    )

    return web.json_response(cred_ex_record.serialize())


async def register(app: web.Application):
    """Register routes."""
    app.add_routes(
        [
            web.get(
                "/issue-credential-2.0/records",
                credential_exchange_list,
                allow_head=False,
            ),
            web.post(
                "/issue-credential-2.0/create-offer",
                credential_exchange_create_free_offer,
            ),
            web.get(
                "/issue-credential-2.0/records/{cred_ex_id}",
                credential_exchange_retrieve,
                allow_head=False,
            ),
            web.post("/issue-credential-2.0/create", credential_exchange_create),
            web.post("/issue-credential-2.0/send", credential_exchange_send),
            web.post(
                "/issue-credential-2.0/send-proposal", credential_exchange_send_proposal
            ),
            web.post(
                "/issue-credential-2.0/send-offer", credential_exchange_send_free_offer
            ),
            web.post(
                "/issue-credential-2.0/send-request",
                credential_exchange_send_free_request,
            ),
            web.post(
                "/issue-credential-2.0/records/{cred_ex_id}/send-offer",
                credential_exchange_send_bound_offer,
            ),
            web.post(
                "/issue-credential-2.0/records/{cred_ex_id}/send-request",
                credential_exchange_send_bound_request,
            ),
            web.post(
                "/issue-credential-2.0/records/{cred_ex_id}/issue",
                credential_exchange_issue,
            ),
            web.post(
                "/issue-credential-2.0/records/{cred_ex_id}/store",
                credential_exchange_store,
            ),
            web.post(
                "/issue-credential-2.0/records/{cred_ex_id}/problem-report",
                credential_exchange_problem_report,
            ),
            web.delete(
                "/issue-credential-2.0/records/{cred_ex_id}",
                credential_exchange_remove,
            ),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""
    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "issue-credential v2.0",
            "description": "Credential issue v2.0",
            "externalDocs": {"description": "Specification", "url": SPEC_URI},
        }
    )


def register_events(bus: EventBus):
    """Register event listeners."""
    bus.subscribe(re.compile(r"^acapy::cred-revoked$"), cred_revoked)


async def cred_revoked(profile: Profile, event: EventWithMetadata):
    """Handle cred revoked event."""
    assert isinstance(event.payload, IssuerCredRevRecord)
    rev_rec: IssuerCredRevRecord = event.payload

    if rev_rec.cred_ex_id is None:
        return

    if (
        rev_rec.cred_ex_version
        and rev_rec.cred_ex_version != IssuerCredRevRecord.VERSION_2
    ):
        return

    async with profile.transaction() as txn:
        try:
            cred_ex_record = await V20CredExRecord.retrieve_by_id(
                txn, rev_rec.cred_ex_id, for_update=True
            )
            cred_ex_record.state = V20CredExRecord.STATE_CREDENTIAL_REVOKED
            await cred_ex_record.save(txn, reason="revoke credential")
            await txn.commit()
        except StorageNotFoundError:
            # ignore if no such record
            pass
