"""AttestedResource model for WebVH."""

from typing import Any, Dict, List, Optional, Union

# from acapy_agent.core.profile import ProfileSession
from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields

# class ResourceMetadata:
#     pass

class AttestedResource(BaseRecord):
    """WebVH AttestedResource."""

    class Meta:
        """WebVH AttestedResource Metadata."""

        schema_class = "AttestedResourceSchema"

    def __init__(
        self,
        *,
        context: List[str] = None,
        id: str,
        type: Union[str, List[str]],
        resourceContent: Optional[Dict[str, Any]] = None,
        resourceMetadata: Optional[Dict[str, str]] = None,
        relatedResource: Optional[List[Dict[str, str]]] = None,
        proof: Union[dict, List[dict]],
        **kwargs,
    ) -> None:
        """Initialize an WebVH AttestedResource instance."""

        super().__init__(**kwargs)

        self.context = context
        self.id = id
        self.type = type
        self.resourceContent = resourceContent
        self.resourceMetadata = resourceMetadata
        self.relatedResource = relatedResource
        self.proof = proof


class AttestedResourceSchema(BaseRecordSchema):
    """WebVH AttestedResource Schema."""

    class Meta:
        """WebVH AttestedResource Schema Metadata."""

        model_class = "AttestedResource"

    context = fields.List(
        required=True,
        metadata={
            "description": "Context",
        },
    )

    id = fields.Str(
        required=True,
        metadata={
            "description": "Id",
        },
    )

    type = fields.List(
        required=True,
        metadata={
            "description": "Type",
        },
    )

    resourceContent = fields.Dict(
        required=True,
        metadata={
            "description": "Content",
        },
    )

    resourceMetadata = fields.Dict(
        required=True,
        metadata={
            "description": "Metadata",
        },
    )

    relatedResource = fields.List(
        fields.Dict,
        required=False,
        metadata={
            "description": "Related resource",
        },
    )

    proof = fields.List(
        required=False,
        metadata={
            "description": "Data integrity Proof",
        },
    )