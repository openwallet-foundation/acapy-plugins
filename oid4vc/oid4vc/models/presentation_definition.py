"""Presentation definition model for OID4VP."""

from typing import Any, Dict, Optional

from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields


class OID4VPPresDef(BaseRecord):
    """OID4VP Presentation."""

    RECORD_TYPE = "oid4vp-pres-def"
    RECORD_ID_NAME = "pres_def_id"

    class Meta:
        """OID4VP Presentation Metadata."""

        schema_class = "OID4VPPresDefSchema"

    def __init__(
        self,
        *,
        pres_def_id: Optional[str] = None,
        pres_def: Dict[str, Any],
        **kwargs,
    ) -> None:
        """Initialize an OID4VP Presentation instance."""

        super().__init__(pres_def_id, **kwargs)

        self.pres_def = pres_def

    @property
    def pres_def_id(self) -> str:
        """Accessor for the ID associated with this presentation definition record."""
        return self._id

    @property
    def record_value(self) -> dict:
        """Return dict representation of the exchange record for storage."""
        return {prop: getattr(self, prop) for prop in ("pres_def",)}


class OID4VPPresDefSchema(BaseRecordSchema):
    """OID4VP Presentation Schema."""

    class Meta:
        """OID4VP Presentation Schema Metadata."""

        model_class = "OID4VPPresDef"

    pres_def_id = fields.Str(
        required=False,
        metadata={
            "description": "Presentation definition identifier",
        },
    )

    pres_def = fields.Dict(
        required=False,
        metadata={
            "description": "Presentation definition",
        },
    )
