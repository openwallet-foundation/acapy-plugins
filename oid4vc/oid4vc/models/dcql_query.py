"""Models for DCQL queries."""

from marshmallow import ValidationError, fields, validates_schema
from marshmallow.validate import OneOf
from typing import Any, List, Mapping, Optional
from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from acapy_agent.messaging.models.base import BaseModel, BaseModelSchema


ClaimsPath = List[str | int | None]


# class JsonClaimsQuery:
#     """A DCQL claims query for JSON based structures."""

#     id: Optional[str] = None
#     values: Optional[List[str | int | bool]] = None


# class MdocClaimsQuery:
#     """A DCQL claims query for mdoc based structures."""


class ClaimsQuery:
    """A DCQL claims query."""

    id: Optional[str] = None
    namespace: Optional[str] = None
    claim_name: Optional[str] = None
    path: Optional[ClaimsPath] = None
    values: Optional[List[str | int | bool]] = None


class ClaimsQuerySchema:
    """A DCQL claims query."""

    id = fields.Str(
        required=False, metadata={"description": "Identifier for this claims query."}
    )
    namespace = fields.Str(
        required=False,
        metadata={
            "description": "",  # TODO: Add description
        },
    )
    claim_name = fields.Str(
        required=False,
        metadata={
            "description": "",  # TODO: Add description
        },
    )
    path = fields.List(
        fields.Raw,
        required=False,
        metadata={
            "description": "",  # TODO: Add description
        },
    )
    values = fields.List(
        fields.Raw,
        required=False,
        metadata={
            "description": "Values of the claims query.",
        },
    )

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """Validate schema fields."""
        namespace = data.get("namespace")
        claim_name = data.get("claim_name")

        if namespace and not claim_name:
            raise ValidationError("Cannot have namespace without claim_name.")
        if claim_name and not namespace:
            raise ValidationError("Cannot have claim_name without namespace.")

        path = data.get("path")
        if path and namespace or path and claim_name:
            raise ValidationError("Cannot have path and namespace or claim_name.")

        if path:
            for p in path:
                if not (
                    isinstance(p, str) or isinstance(p, int) or p is None
                ):  # TODO: check logic here
                    raise ValidationError("Path elements must be string, int, or None.")

        values = data.get("values")
        if values:
            for v in values:
                if not (
                    isinstance(v, str) or isinstance(v, int) or isinstance(v, bool)
                ):  # TODO: check logic here
                    raise ValidationError(
                        "Values elements must be string, int, or bool."
                    )


ClaimQueryID = str


class CredentialMeta(BaseModel):
    """Metadata for credential query."""

    query_type: Optional[str] = None
    doctype_values: Optional[List[str]] = None
    vct_values: Optional[List[str]] = None


class CredentialMetaSchema(BaseModelSchema):
    """Schema for credential query metadata."""

    query_type = fields.Str(
        required=False,
        validate=OneOf(
            [
                "SdJwtVcMeta",
                "MdocMeta",
            ]
        ),
    )

    doctype_values = fields.List(
        fields.Str,
        required=False,
    )

    vct_values = fields.List(
        fields.Str,
        required=False,
    )

    @validates_schema
    def validate_fields(self, data, **kwargs):
        """Validate CredentialMeta object."""

        query_type = data.get("query_type")
        doctype_values = data.get("doctype_values")
        vct_values = data.get("vct_values")

        if query_type == "SdJwtVcMeta" and doctype_values:
            raise ValidationError("SdJwtVc Meta cannot contain `doctype_values`")

        if query_type == "MdocMeta" and vct_values:
            raise ValidationError("Mdoc Meta cannot contain `vct_values`")


class CredentialQuery(BaseModel):
    """A DCQL Credential Query."""

    class Meta:
        """Credential Query Metadata."""

        schema_class = "CredentialQuerySchema"

    def __init__(
        self,
        *,
        id: str,
        format: str,
        meta: Optional[CredentialMeta] = None,
        claims: Optional[List[ClaimsQuery]] = None,  # min_length of 1
        claim_sets: Optional[List[List[ClaimQueryID]]] = None,  # min_length of 1
        **kwargs,
    ) -> None:
        """Initialize a CredentialQuery object."""

        self.id = id
        self.format = format
        self.meta = meta
        self.claims = claims
        self.claim_sets = claim_sets

        # TODO: add serialize/deserialize
        # (probably use BaseModel/BaseSchema? that provides ser/deser)
        # https://github.com/openwallet-foundation/acapy/blob/main/acapy_agent/protocols/present_proof/v2_0/models/pres_exchange.py#L211-L239


class CredentialQuerySchema(BaseModelSchema):
    """Schema for Credential Queries."""

    class Meta:
        """Credential Query Schema Metadata."""

        model_class = "CredentialQuery"

    credential_query_id = fields.Str(
        required=True, metadata={"description": "Identifier of the credential query."}
    )
    format = fields.Str(
        required=True,
        metadata={
            "description": "Credential format specified by the credential query.",
            "example": "jwt_vc_json",
        },
    )

    claims = fields.List(
        ClaimsQuerySchema,  # TODO: Schema or model?
        required=False,
        metadata={"description": ""},
    )
    claim_sets = fields.List(
        fields.List(fields.Str), required=False, metadata={"description": ""}
    )

    # TODO: is this the way to do this? Is there a better way?
    @validates_schema
    def validate_fields(self, data):
        """Validate schema fields."""

        meta = data.get("meta")
        if meta and not isinstance(meta, CredentialMeta):
            raise ValidationError(
                "Credential query metadata must be a CredentialMeta object."
            )


CredentialQueryID = str


class CredentialSetQuery(BaseModel):
    """A DCQL credential set query."""

    class Meta:
        """Metadata for CredentialSetQuery."""

        schema_class = "CredentialSetQuerySchema"

    def __init__(
        self,
        options: List[List[CredentialQueryID]],  # min_length of 1
        required: Optional[bool] = None,
        purpose: Optional[str | int | Any] = None,
    ) -> None:
        """Initialize a CredentialSetQuery object."""

        self.options = options
        self.required = required
        self.purpose = purpose


class CredentialSetQuerySchema(BaseModelSchema):
    """A DCQL credential set query."""

    class Meta:
        """Metadata for CredentialSetQuerySchema."""

        model_class = "CredentialSetQuery"

    options = fields.List(
        fields.List(fields.Str),
        required=True,
        metadata={
            "description": "",  # TODO IDK lol
        },
    )

    required = fields.Bool(
        required=False,
        metadata={
            "description": "Whether the credential sets being queried are required.",
        },
    )

    purpose = fields.Raw(
        required=False,
        metadata={
            "description": "The purpose for this credential set.",
        },
    )


class DCQLQuery(BaseRecord):
    """A DCQL Query."""

    class Meta:
        """Metadata for DCQLQuery."""

        schema_class = "DCQLQuerySchema"

    RECORD_ID_NAME = "dcql_query_id"

    def __init__(
        self,
        *,
        dcql_query_id: Optional[str] = None,
        credentials: List[CredentialQuery],  # min_length of 1
        credential_sets: Optional[List[CredentialSetQuery]] = None,  # min_length of 1
        **kwargs,
    ):
        """Initialize a new DCQL Credential Query Record."""
        super().__init__(dcql_query_id, **kwargs)
        self.credentials = credentials
        self.credential_set = credential_sets

    @property
    def dcql_query_id(self) -> str:
        """Accessor for the ID associated with this DCQL query record."""
        return self._id

    # TODO: double check that this works the way I think it does
    @property
    def record_value(self) -> Mapping:
        """Accessor for the JSON record value generated for this DCQL query."""
        val = {
            "dcql_query_id": getattr(self, "dcql_query_id"),
            "credentials": [cred.serialize() for cred in self.credentials],
        }
        if self.credential_set is not None:
            val["credential_sets"] = [set.serialize() for set in self.credential_set]

        return val


# TODO: Add Schema for DCQLQuery


class DCQLQuerySchema(BaseRecordSchema):
    """Schema for DCQLQuery class."""

    class Meta:
        """Metadata for DCQLQuery."""

        model_class = "DCQLQuery"

    credentials = fields.List(
        CredentialQuerySchema,  # TODO: Schema or regular?
        required=True,
        metadata={
            "description": "A list of credential query objects",
        },
    )
    credential_sets = fields.List(
        CredentialSetQuerySchema,  # TODO: Schema or regular?
        required=False,
        metadata={
            "description": "A list of credential set query objects",
        },
    )
