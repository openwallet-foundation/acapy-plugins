"""Models for DCQL queries."""

from typing import Any, List, Mapping, Optional
from acapy_agent.messaging.models.base_record import BaseRecord, BaseRecordSchema


ClaimsPath = List[str | int | None]


class JsonClaimsQuery:
    """A DCQL claims query for JSON based structures."""

    id: str | None = None
    path: ClaimsPath
    values: List[str | int | bool] | None = None


class MdocClaimsQuery:
    """A DCQL claims query for mdoc based structures."""

    id: str | None = None
    namespace: str
    claim_name: str
    values: List[str | int | bool] | None = None


ClaimsQuery = JsonClaimsQuery | MdocClaimsQuery
ClaimQueryID = str


class SdJwtVcMeta:
    """SD-JWT VC Metadata for credential query."""

    vct_values: List[str] | None = None


class MdocMeta:
    """mdoc Metadata for credential query."""

    doctype_values: List[str] | None = None


CredentialMeta = SdJwtVcMeta | MdocMeta


class CredentialQuery:
    """A DCQL Credential Query."""

    def __init__(
        self,
        *,
        id: str,
        fmt: str,
        meta: CredentialMeta | None = None,
        claims: List[ClaimsQuery] | None = None,  # min_length of 1
        claim_sets: List[List[ClaimQueryID]] | None = None,  # min_length of 1
        **kwargs,
    ) -> None:
        """Initialize a CredentialQuery object."""

        self.id = id
        self.fmt = fmt
        self.meta = meta
        self.claims = claims
        self.claim_sets = claim_sets


CredentialQueryID = str


class CredentialSetQuery:
    """A DCQL credential set query."""

    def __init__(
        self,
        options: List[List[CredentialQueryID]],  # min_length of 1
        required: bool | None = None,
        purpose: str | int | Any | None = None,
    ) -> None:
        """Initialize a CredentialSetQuery object."""

        self.options = options
        self.required = required
        self.purpose = purpose


class DCQLQuery(BaseRecord):
    """A DCQL Query."""

    RECORD_ID_NAME = "dcql_query_id"

    def __init__(
        self,
        *,
        dcql_query_id: Optional[str] = None,
        credentials: List[CredentialQuery],  # min_length of 1
        credential_sets: List[CredentialSetQuery] | None = None,  # min_length of 1
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


# TODO: Add Schema for DCQLQuery
