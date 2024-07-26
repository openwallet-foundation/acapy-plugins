"""Presentation model for OID4VP."""

from typing import Any, Dict, List
from aries_cloudagent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields


class OID4VPPresentation(BaseRecord):
    """OID4VP Presentation."""

    REQUEST_CREATED = "request-created"
    REQUEST_RETRIEVED = "request-retrieved"
    PRESENTATION_RECEIVED = "presentation-received"
    PRESENTATION_INVALID = "presentation-invalid"
    PRESENTATION_VALID = "presentation-valid"
    STATES = (
        REQUEST_CREATED,
        REQUEST_RETRIEVED,
        PRESENTATION_RECEIVED,
        PRESENTATION_INVALID,
        PRESENTATION_VALID,
    )

    RECORD_ID_NAME = "presentation_id"
    TAG_NAMES = {"pres_def_id", "state"}

    class Meta:
        """OID4VP Presentation Metadata."""

        schema_class = "OID4VPPresentationSchema"

    def __init__(
        self,
        id: str,
        state: str,
        pres_def_id: str,
        errors: List[str],
        verified_claims: Dict[str, Any],
        verified: bool,
    ) -> None:
        """Initialize an OID4VP Presentation instance."""

        super().__init__(id, state)

        self.pres_def_id = pres_def_id
        self.errors = errors
        self.verified_claims = verified_claims
        self.verified = verified

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
                "verified_claims",
                "verified",
            )
        }


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
        required=True,
        metadata={
            "description": "Identifier used to identify presentation defintion",
        },
    )

    errors = fields.List(
        fields.Str,
        required=False,
        metadata={
            "description": "Errors raised during validation, if present",
        },
    )

    verified_claims = fields.Dict(
        required=False,
        metadata={
            "description": "Verified claims from the presentation, if present",
        },
    )

    verified = fields.Bool(
        required=True,
        metadata={
            "description": "Whether or not the presentation was successfully verified"
        },
    )
