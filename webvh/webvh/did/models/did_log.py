"""Model for webvh DID log entry."""

from acapy_agent.messaging.models.openapi import OpenAPISchema
from marshmallow import fields, validate


class WitnessSchema(OpenAPISchema):
    """Witness object."""

    id = fields.str(
        required=True,
        metadata={"description": "did:key value for the witness"},
    )


class WitnessParameterSchema(OpenAPISchema):
    """Parameters for the witness feature."""

    threshold = fields.Int(
        required=True,
        metadata={
            "description": "Witness treshold",
            "example": 1,
        },
    )
    witnesses = fields.List(
        fields.Nested(WitnessSchema()), required=True, validate=validate.Length(min=1)
    )


class InitialParametersSchema(OpenAPISchema):
    """Parameters for a initial Webvh DID request."""

    method = fields.Str(
        required=True,
        metadata={
            "description": "The didwebvh method version",
            "example": "did:webvh:0.1",
        },
        default="did:webvh:0.1",
    )

    scid = fields.Str(
        required=True,
        metadata={
            "description": "The calculated SCID",
        },
    )

    updateKeys = fields.List(
        fields.Str(),
        required=True,
        validate=validate.Length(min=1),
        metadata={
            "description": "A list of authorized keys",
        },
    )

    portable = fields.Bool(
        required=False,
        metadata={
            "description": "Portable flag",
            "example": False,
        },
        default=False,
    )

    nextKeyHashes = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "A list of the key hashes authorized for pre-rotation",
        },
    )

    watchers = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "Watchers list.",
        },
    )

    witness = fields.Nested(
        WitnessParameterSchema(),
        required=False,
        metadata={
            "description": "Witness configuration",
        },
    )

    ttl = fields.Int(
        required=False,
        metadata={
            "description": "Cache ttl in seconds.",
            "example": 10000,
        },
    )


class ParametersSchema(OpenAPISchema):
    """Parameters for a Webvh DID request."""

    method = fields.Str(
        required=False,
        metadata={
            "description": "The didwebvh method version",
        },
    )

    scid = fields.Str(
        required=False,
        metadata={
            "description": "The calculated SCID",
        },
    )

    updateKeys = fields.List(
        fields.Str(),
        required=False,
        validate=validate.Length(min=1),
        metadata={
            "description": "A list of authorized keys",
        },
    )

    portable = fields.Bool(
        required=False,
        metadata={
            "description": "Portable flag",
            "example": False,
        },
    )

    nextKeyHashes = fields.List(
        fields.Str(),
        required=False,
        metadata={
            "description": "A list of the key hashes authorized for pre-rotation",
        },
    )

    witness = fields.Nested(
        WitnessParameterSchema(),
        required=False,
        metadata={
            "description": "Witness configuration",
        },
    )

    deactivated = fields.Bool(
        required=False,
        metadata={
            "description": "Deactivated flag.",
        },
    )

    ttl = fields.Int(
        required=False,
        metadata={
            "description": "Cache ttl in seconds.",
            "example": 10000,
        },
    )
