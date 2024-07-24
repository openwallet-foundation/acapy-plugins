"""CredProcessor interface and exception."""

from abc import ABC, abstractmethod

from aries_cloudagent.core.error import BaseError
from aries_cloudagent.admin.request_context import AdminRequestContext

from .models.exchange import OID4VCIExchangeRecord
from .models.supported_cred import SupportedCredential
from .pop_result import PopResult


class ICredProcessor(ABC):
    """Returns singed credential payload."""

    @abstractmethod
    def issue_cred(
        self,
        body: any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ):
        """Method signature.

        Args:
            body: any
            supported: SupportedCredential
            ex_record: OID4VCIExchangeRecord
            pop: PopResult
            context: AdminRequestContext
        Returns:
            encoded: signed credential payload.
        """


class CredIssueError(BaseError):
    """Base class for CredProcessor errors."""
