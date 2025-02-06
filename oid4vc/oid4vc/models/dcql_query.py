"""Models for DCQL queries."""

from marshmallow import ValidationError, fields, validates_schema
from marshmallow.validate import OneOf
from typing import Any, List, Mapping, Optional, Union
from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema
from acapy_agent.messaging.models.base import BaseModel, BaseModelSchema


ClaimsPath = List[str | int | None]


# class JsonClaimsQuery:
#     """A DCQL claims query for JSON based structures."""

#     id: Optional[str] = None
#     values: Optional[List[str | int | bool]] = None


# class MdocClaimsQuery:
#     """A DCQL claims query for mdoc based structures."""


class ClaimsQuery(BaseModel):
    """A DCQL claims query."""

    class Meta:
        """Metadata for Claims Query Model."""

        schema_class = "ClaimsQuerySchema"

    def __init__(
        self,
        id: Optional[str] = None,
        namespace: Optional[str] = None,
        claim_name: Optional[str] = None,
        path: Optional[ClaimsPath] = None,
        values: Optional[List[str | int | bool]] = None,
    ):
        """Initialize a ClaimsQuery model."""

        self.id = id
        self.namespace = namespace
        self.claim_name = claim_name
        self.path = path
        self.values = values


class ClaimsQuerySchema(BaseModelSchema):
    """A DCQL claims query."""

    class Meta:
        """Metadata for Claims Query Schema."""

        model_class = "ClaimsQuery"

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

    class Meta:
        """Credential Meta Schema Metadata."""

        schema_class = "CredentialMetaSchema"

    def __init__(
        self,
        query_type: Optional[str] = None,
        doctype_values: Optional[List[str]] = None,
        vct_values: Optional[List[str]] = None,
    ):
        """Initialize a CredentialMeta model."""
        super().__init__()

        self.query_type = query_type
        self.doctype_values = doctype_values
        self.vct_values = vct_values


class CredentialMetaSchema(BaseModelSchema):
    """Schema for credential query metadata."""

    class Meta:
        """Credential Meta Schema Metadata."""

        model_class = "CredentialMeta"

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

        if vct_values and doctype_values:
            raise ValidationError(
                "Credential Metadata cannot have both vct_values and doctype_values."
            )


class CredentialQuery(BaseModel):
    """A DCQL Credential Query."""

    class Meta:
        """Credential Query Metadata."""

        schema_class = "CredentialQuerySchema"

    def __init__(
        self,
        *,
        credential_query_id: str,
        format: str,
        meta: Optional[CredentialMeta] = None,
        claims: Optional[List[ClaimsQuery]] = None,  # min_length of 1
        claim_sets: Optional[List[List[ClaimQueryID]]] = None,  # min_length of 1
        **kwargs,
    ) -> None:
        """Initialize a CredentialQuery object."""

        self.credential_query_id = credential_query_id
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
        required=True,
        metadata={"description": "Identifier of the credential query."},
        data_key="id",
    )
    format = fields.Str(
        required=True,
        metadata={
            "description": "Credential format specified by the credential query.",
            "example": "jwt_vc_json",
        },
    )

    claims = fields.List(
        fields.Nested(ClaimsQuerySchema),
        required=False,
        metadata={"description": ""},
    )
    claim_sets = fields.List(
        fields.List(fields.Str), required=False, metadata={"description": ""}
    )

    meta = fields.Nested(
        CredentialMetaSchema(),
        required=False,
        metadata={"description": "Metadata about the Credential Query"},
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
    RECORD_TOPIC = "oid4vp"
    RECORD_TYPE = "oid4vp"

    def __init__(
        self,
        *,
        dcql_query_id: Optional[str] = None,
        credentials: Union[List[Mapping], List[CredentialQuery]],  # min_length of 1
        credential_sets: Optional[
            Union[List[Mapping], List[CredentialSetQuery]]
        ] = None,  # min_length of 1
        **kwargs,
    ):
        """Initialize a new DCQL Credential Query Record."""
        super().__init__(dcql_query_id, **kwargs)

        self._credentials = [CredentialQuery.serde(cred) for cred in credentials]
        self._credential_set = (
            [CredentialSetQuery.serde(cred) for cred in credential_sets]
            if credential_sets
            else None
        )

    @property
    def dcql_query_id(self) -> str:
        """Accessor for the ID associated with this DCQL query record."""
        return self._id

    @property
    def credentials(self) -> List[CredentialQuery]:
        """Accessor for CredentialQuery list; deserialized view."""
        return [cred.de for cred in self._credentials if cred is not None]

    @credentials.setter
    def credentials(self, value):
        self._credentials = [CredentialQuery.serde(cred) for cred in value]

    @property
    def credential_set(self) -> Union[List[CredentialQuery], None]:
        """Accessor for CredentialQuery list; deserialized view."""

        if self._credential_set is not None:
            return [cred.de for cred in self._credential_set if cred is not None]
        return None

    @credential_set.setter
    def credential_set(self, value):
        self._credential_set = [CredentialQuery.serde(cred) for cred in value]

    @property
    def record_value(self) -> Mapping:
        """Accessor for the JSON record value generated for this DCQL query."""
        val = {
            "credentials": [cred.ser for cred in self._credentials if cred is not None],
        }
        if self._credential_set is not None:
            val["credential_sets"] = [
                set.ser for set in self._credential_set if set is not None
            ]

        return val


# TODO: Add Schema for DCQLQuery


class DCQLQuerySchema(BaseRecordSchema):
    """Schema for DCQLQuery class."""

    class Meta:
        """Metadata for DCQLQuery."""

        model_class = "DCQLQuery"

    credentials = fields.List(
        fields.Nested(CredentialQuerySchema),
        required=True,
        metadata={
            "description": "A list of credential query objects",
        },
    )
    credential_sets = fields.List(
        fields.Nested(CredentialSetQuerySchema),
        required=False,
        metadata={
            "description": "A list of credential set query objects",
        },
    )
