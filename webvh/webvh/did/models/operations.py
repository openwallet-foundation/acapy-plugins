"""DID operations models."""

import enum
from collections import Counter

from acapy_agent.messaging.models.openapi import OpenAPISchema
from acapy_agent.vc.vc_ld.models.presentation import PresentationSchema
from marshmallow import fields, validates, validate, ValidationError


class ConfigureWebvhSchema(OpenAPISchema):
    """Request model for configuring a Webvh agent."""

    server_url = fields.Str(
        required=False,
        metadata={
            "description": "URL of the webvh server",
            "example": "http://localhost:8000",
        },
    )
    notify_watchers = fields.Boolean(
        required=False,
        metadata={
            "description": "Notify watchers on DID updates",
            "example": "false",
        },
        default=False,
    )
    witness = fields.Boolean(
        required=False,
        metadata={
            "description": "Enable the witness role",
            "example": "false",
        },
        default=False,
    )
    witness_key = fields.Str(
        required=False,
        metadata={
            "description": "Existing key to use as witness key",
            "example": "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i",
        },
    )
    auto_attest = fields.Bool(
        required=False,
        metadata={
            "description": "Auto sign witness requests",
            "example": "false",
        },
        default=False,
    )
    endorsement = fields.Bool(
        required=False,
        metadata={
            "description": "Require witness approval for creating attested resources.",
            "example": False,
        },
        default=False,
    )
    witness_invitation = fields.Str(
        required=False,
        metadata={
            "description": "An invitation from a witness, required for a controller",
            "example": "http://localhost:3000?oob=eyJAdHlwZSI6ICJodHRwczovL2RpZGNvbW0ub3JnL291dC1vZi1iYW5kLzEuMS9pbnZpdGF0aW9uIiwgIkBpZCI6ICJlMzI5OGIyNS1mZjRlLTRhZmItOTI2Yi03ZDcyZmVlMjQ1ODgiLCAibGFiZWwiOiAid2VidmgtZW5kb3JzZXIiLCAiaGFuZHNoYWtlX3Byb3RvY29scyI6IFsiaHR0cHM6Ly9kaWRjb21tLm9yZy9kaWRleGNoYW5nZS8xLjAiXSwgInNlcnZpY2VzIjogW3siaWQiOiAiI2lubGluZSIsICJ0eXBlIjogImRpZC1jb21tdW5pY2F0aW9uIiwgInJlY2lwaWVudEtleXMiOiBbImRpZDprZXk6ejZNa3FDQ1pxNURSdkdMcDV5akhlZlZTa2JhN0tYWlQ1Nld2SlJacEQ2Z3RvRzU0I3o2TWtxQ0NacTVEUnZHTHA1eWpIZWZWU2tiYTdLWFpUNTZXdkpSWnBENmd0b0c1NCJdLCAic2VydmljZUVuZHBvaW50IjogImh0dHA6Ly9sb2NhbGhvc3Q6MzAwMCJ9XX0",
        },
    )


class WebvhCreateWitnessInvitationSchema(OpenAPISchema):
    """Request model for creating a witness invitation."""

    alias = fields.Str(
        required=False,
        metadata={
            "description": "Optional alias for the connection.",
            "example": "Issuer 01",
        },
        default=None,
    )

    label = fields.Str(
        required=False,
        metadata={
            "description": "Optional label for the connection recipient.",
            "example": "Witnessing Service",
        },
        default=None,
    )

    multi = fields.Bool(
        required=False,
        metadata={
            "description": "Create a multi use witness invitation.",
            "example": True,
        },
        default=False,
    )


class WebvhUpdateSchema(OpenAPISchema):
    """Request model for updating a Webvh DID."""

    # class UpdateStateSchema(OpenAPISchema):
    #     "Webvh DID state update schema."""

    class UpdateParametersSchema(OpenAPISchema):
        """Webvh DID parameters update schema."""

        portable = fields.Bool(
            required=False,
            metadata={
                "description": "Portable flag",
                "example": False,
            },
        )
        prerotation = fields.Bool(
            required=False,
            metadata={
                "description": "Prerotation flag",
                "example": False,
            },
        )
        witnessThreshold = fields.Int(
            required=False,
            metadata={
                "description": "The witness threshold",
                "example": 1,
            },
        )

    # state = fields.Nested(UpdateStateSchema())
    parameters = fields.Nested(UpdateParametersSchema())


class WebvhCreateSchema(OpenAPISchema):
    """Request model for creating a Webvh DID."""

    class CreateOptionsSchema(OpenAPISchema):
        """Options for a Webvh DID request."""

        server_url = fields.Str(
            required=False,
            metadata={
                "description": "Optional DID WebVH server url.",
                "example": "https://id.test-suite.app",
            },
            default=None,
        )
        namespace = fields.Str(
            required=False,
            metadata={
                "description": "Namespace for the DID",
                "example": "default",
            },
            default="default",
        )
        identifier = fields.Str(
            required=False,
            metadata={
                "description": "Identifier for the DID.",
                "example": "1",
            },
        )
        version_time = fields.Str(
            required=False,
            metadata={
                "description": "Optional timestamp for the initial versionTime.",
                "example": "2025-07-28T21:47:32Z",
            },
            default=None,
        )
        watchers = fields.List(
            fields.Str(),
            required=False,
            metadata={
                "description": "List of watchers for this DID.",
                "example": ["https://watcher.webvh.test-suite.app"],
            },
        )
        portable = fields.Bool(
            required=False,
            metadata={
                "description": "Enable DID portability.",
                "example": False,
            },
            default=False,
        )
        prerotation = fields.Bool(
            required=False,
            metadata={
                "description": "Enable key pre-rotation on DID updates.",
                "example": False,
            },
            default=False,
        )
        witness_threshold = fields.Int(
            required=False,
            metadata={
                "description": "The witness treshold.",
                "example": 1,
            },
        )
        apply_policy = fields.Bool(
            required=False,
            metadata={
                "description": "Apply policies from server.",
                "example": True,
            },
            default=True,
        )

    options = fields.Nested(CreateOptionsSchema())


class WebvhDIDQueryStringSchema(OpenAPISchema):
    """Query model for providing a DID."""

    did = fields.Str(
        required=True,
        metadata={"description": "DID of interest", "example": ""},
    )


class WebvhSCIDQueryStringSchema(OpenAPISchema):
    """Query model for providing a SCID."""

    scid = fields.Str(
        required=True,
        metadata={"description": "SCID of interest", "example": ""},
    )


class WebvhRecordIdQueryStringSchema(OpenAPISchema):
    """Query model for providing a SCID."""

    record_id = fields.Str(
        required=True,
        metadata={
            "description": "Record ID for the witness request.",
            "example": "eb3f768d-08fa-4622-88b0-dfcd0f1ddebb",
        },
    )


class WebvhAddVMSchema(OpenAPISchema):
    """Request model for adding a Webvh Verification Method."""

    class RelationshipsEnum(enum.Enum):
        """Relationships for a Webvh verification method."""

        keyAgreement = "keyAgreement"
        authentication = "authentication"
        assertionMethod = "assertionMethod"
        capabilityInvocation = "capabilityInvocation"
        capabilityDelegation = "capabilityDelegation"

    id = fields.Str(
        required=False,
        metadata={
            "description": "An user provided verification method ID",
            "example": "key-01",
        },
    )

    type = fields.Str(
        validate=validate.OneOf(["Multikey", "JsonWebKey"]),
        required=False,
        metadata={"description": ""},
    )

    relationships = fields.List(
        fields.Enum(RelationshipsEnum),
        required=False,
        metadata={"description": ""},
        default=["assertionMethod"],
    )

    multikey = fields.Str(
        required=False,
        metadata={"description": "An existing multikey to bind.", "example": ""},
    )

    @validates("id")
    def validate_key_id(self, value):
        """Relationship validator."""
        if "#" in value:
            raise ValidationError("Forbidden character in id.")

    @validates("relationships")
    def validate_relationships(self, value):
        """Relationship validator."""
        if [k for k, v in Counter(value).items() if v > 1]:
            raise ValidationError("Duplicate relationship.")


class WebvhDeactivateSchema(OpenAPISchema):
    """Request model for deactivating a Webvh DID."""

    id = fields.Str(
        required=True,
        metadata={
            "description": "ID of the DID to deactivate",
            "example": "did:webvh:scid:example.com:prod:1",
        },
    )


class IdRequestParamSchema(OpenAPISchema):
    """Request model for creating a Webvh DID."""

    entry_id = fields.Str(
        required=True,
        metadata={
            "description": "ID of the DID to attest",
            "example": "did:web:server.localhost%3A8000:prod:1",
        },
    )


class WebvhUpdateWhoisSchema(OpenAPISchema):
    """Request model for updating a whois VP."""

    presentation = fields.Nested(PresentationSchema, required=True)
