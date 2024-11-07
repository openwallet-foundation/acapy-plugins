"""CredProcessor interface and exception."""

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.core.error import BaseError
from acapy_agent.core.profile import Profile

from .models.exchange import OID4VCIExchangeRecord
from .models.presentation import OID4VPPresentation
from .models.supported_cred import SupportedCredential
from .pop_result import PopResult


@dataclass
class VerifyResult:
    """Result of verification."""

    verified: bool
    payload: Any


class Issuer(Protocol):
    """Issuer protocol."""

    async def issue(
        self,
        body: Any,
        supported: SupportedCredential,
        ex_record: OID4VCIExchangeRecord,
        pop: PopResult,
        context: AdminRequestContext,
    ) -> Any:
        """Issue a credential."""
        ...

    def validate_credential_subject(self, supported: SupportedCredential, subject: dict):
        """Validate the credential subject."""
        ...

    def validate_supported_credential(self, supported: SupportedCredential):
        """Validate the credential."""
        ...


class CredVerifier(Protocol):
    """Credential verifier protocol."""

    async def verify_credential(
        self,
        profile: Profile,
        credential: Any,
    ) -> VerifyResult:
        """Verify credential."""
        ...


class PresVerifier(Protocol):
    """Presentation verifier protocol."""

    async def verify_presentation(
        self,
        profile: Profile,
        presentation: Any,
        presentation_record: OID4VPPresentation,
    ) -> VerifyResult:
        """Verify presentation."""
        ...


class CredProcessorError(BaseError):
    """Base class for CredProcessor errors."""


class IssuerError(CredProcessorError):
    """Raised on issuer errors."""


class CredVerifeirError(CredProcessorError):
    """Raised on credential verifier errors."""


class PresVerifeirError(CredProcessorError):
    """Raised on presentation verifier errors."""


class CredProcessors:
    """Registry for credential format processors."""

    def __init__(
        self,
        issuers: Optional[Mapping[str, Issuer]] = None,
        cred_verifiers: Optional[Mapping[str, CredVerifier]] = None,
        pres_verifiers: Optional[Mapping[str, PresVerifier]] = None,
    ):
        """Initialize the processor registry."""
        self.issuers = dict(issuers) if issuers else {}
        self.cred_verifiers = dict(cred_verifiers) if cred_verifiers else {}
        self.pres_verifiers = dict(pres_verifiers) if pres_verifiers else {}

    def issuer_for_format(self, format: str) -> Issuer:
        """Return the processor to handle the given format."""
        processor = self.issuers.get(format)
        if not processor:
            raise CredProcessorError(f"No loaded issuer for format {format}")
        return processor

    def cred_verifier_for_format(self, format: str) -> CredVerifier:
        """Return the processor to handle the given format."""
        processor = self.cred_verifiers.get(format)
        if not processor:
            raise CredProcessorError(f"No loaded credential verifier for format {format}")
        return processor

    def pres_verifier_for_format(self, format: str) -> PresVerifier:
        """Return the processor to handle the given format."""
        processor = self.pres_verifiers.get(format)
        if not processor:
            raise CredProcessorError(
                f"No loaded presentation verifier for format {format}"
            )
        return processor

    def register_issuer(self, format: str, processor: Issuer):
        """Register a new processor for a format."""
        self.issuers[format] = processor

    def register_cred_verifier(self, format: str, processor: CredVerifier):
        """Register a new processor for a format."""
        self.cred_verifiers[format] = processor

    def register_pres_verifier(self, format: str, processor: PresVerifier):
        """Register a new processor for a format."""
        self.pres_verifiers[format] = processor
