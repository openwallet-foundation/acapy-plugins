"""Presentation model for OID4VP."""

from typing import Any, Dict, List, Optional

from acapy_agent.core.profile import ProfileSession
from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields


class OID4VPPresentation(BaseRecord):
    """OID4VP Presentation."""

    REQUEST_CREATED = "request-created"
    REQUEST_RETRIEVED = "request-retrieved"
    PRESENTATION_INVALID = "presentation-invalid"
    PRESENTATION_VALID = "presentation-valid"
    RECORD_TOPIC = "oid4vp"
    RECORD_TYPE = "oid4vp"
    STATES = (
        REQUEST_CREATED,
        REQUEST_RETRIEVED,
        PRESENTATION_INVALID,
        PRESENTATION_VALID,
    )

    RECORD_ID_NAME = "presentation_id"
    TAG_NAMES = {"pres_def_id", "state", "request_id", "dcql_query_id"}

    class Meta:
        """OID4VP Presentation Metadata."""

        schema_class = "OID4VPPresentationSchema"

    def __init__(
        self,
        *,
        presentation_id: Optional[str] = None,
        state: str,
        pres_def_id: Optional[str] = None,
        dcql_query_id: Optional[str] = None,
        errors: Optional[List[str]] = None,
        matched_credentials: Optional[Dict[str, Any]] = None,
        verified: Optional[bool] = None,
        request_id: str,
        nonce: Optional[str] = None,
        **kwargs,
    ) -> None:
        """Initialize an OID4VP Presentation instance."""

        super().__init__(presentation_id, state, **kwargs)

        self.pres_def_id = pres_def_id
        self.errors = errors
        self.matched_credentials = matched_credentials
        self.verified = verified
        self.request_id = request_id
        self.dcql_query_id = dcql_query_id
        self.nonce = nonce  # in request

    @property
    def presentation_id(self) -> str:
        """Accessor for the ID associated with this presentation record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the exchange record for storage."""
        return {
            prop: getattr(self, prop)
            for prop in (
                "errors",
                "matched_credentials",
                "verified",
                "nonce",
            )
        }

    @classmethod
    async def retrieve_by_request_id(
        cls, session: ProfileSession, request_id: str
    ) -> "OID4VPPresentation":
        """Retrieve a Presentation by Request ID."""

        return await cls.retrieve_by_tag_filter(
            session=session, tag_filter={"request_id": request_id}
        )


class OID4VPPresentationSchema(BaseRecordSchema):
    """OID4VP Presentation Schema."""

    class Meta:
        """OID4VP Presentation Schema Metadata."""

        model_class = "OID4VPPresentation"

    presentation_id = fields.Str(
        required=False,
        metadata={
            "description": "Presentation identifier",
        },
    )

    pres_def_id = fields.Str(
        required=False,
        metadata={
            "description": "Identifier used to identify presentation defintion",
        },
    )

    dcql_query_id = fields.Str(
        required=False,
        metadata={
            "description": "Identifier used to identify dcql query",
        },
    )

    request_id = fields.Str(
        required=True,
        metadata={
            "description": "Identifier used to identify presentation request",
        },
    )

    nonce = fields.Str(
        required=False,
    )

    errors = fields.List(
        fields.Str,
        required=False,
        metadata={
            "description": "Errors raised during validation, if present",
        },
    )

    matched_credentials = fields.Dict(
        required=False,
        metadata={
            "description": "Verified claims from the presentation, if present",
        },
    )

    verified = fields.Bool(
        required=False,
        metadata={
            "description": "Whether or not the presentation was successfully verified"
        },
    )
