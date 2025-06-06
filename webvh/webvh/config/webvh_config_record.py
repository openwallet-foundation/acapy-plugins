"""Webvh configuration record."""

from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from marshmallow import fields
from marshmallow.utils import EXCLUDE


class WebvhConfig(BaseRecord):
    """Webvh configuration."""

    class Meta:
        """Webvh configuration metadata."""

        schema_class = "WebvhConfigSchema"


class WebvhConfigSchema(BaseRecordSchema):
    """Webvh configuration schema."""

    class Meta:
        """Webvh configuration schema metadata."""

        model_class = WebvhConfig
        unkown = EXCLUDE

    role = fields.Str(
        required=True,
        description="Role",
    )

    server_url = fields.Str(
        required=True,
        description="WebVH Server",
    )

    notify_watchers = fields.Bool(
        required=True,
        description="Notify watchers",
    )

    witnesses = fields.List(
        fields.Str(),
        required=False,
        description="Witnesses",
    )

    scids = fields.Dict(
        required=False,
        description="Scid to DID mappings",
    )


class WebvhConfigRecord(BaseRecord):
    """Webvh configuration record."""

    class Meta:
        """Webvh configuration metadata."""

        schema_class = "WebvhConfigRecordSchema"

    RECORD_TYPE = "webvh_config"
    RECORD_ID_NAME = "record_id"

    def __init__(self, *, record_id: str = None, config: dict, **kwargs):
        """Initialize a new WebvhConfigRecord."""
        super().__init__(id=record_id, state=None, **kwargs)
        self.config = config

    @property
    def record_id(self) -> str:
        """Accessor for the ID associated with this record."""
        return self._id


class WebvhConfigRecordSchema(BaseRecordSchema):
    """Webvh configuration record schema."""

    class Meta:
        """Webvh configuration record schema metadata."""

        model_class = WebvhConfigRecord
        unkown = EXCLUDE

    record_id = fields.Str(required=True, metadata={"description": "Record identifier"})

    config = fields.Dict(
        required=True,
        description="Webvh configuration",
        example={"server_url": "http://localhost:8080", "role": "controller"},
    )
