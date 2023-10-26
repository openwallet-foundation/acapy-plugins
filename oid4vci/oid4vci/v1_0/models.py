from typing import Any, Dict, Optional
from aries_cloudagent.messaging.models.base_record import BaseExchangeRecord, BaseRecord


class OID4VCICredentialExchangeRecord(BaseExchangeRecord):
    def __init__(
        self,
        credential_supported_id=None,
        credential_subject: Optional[Dict[str, Any]] = None,
        nonce=None,
        pin=None,
        token=None,
    ):
        self.credential_supported_id = credential_supported_id
        self.credential_subject = credential_subject  # (received from submit)
        self.nonce = nonce  # in offer
        self.pin = pin  # (when relevant)
        self.token = token
    
    @property
    def credential_exchange_id(self) -> str:
        """Accessor for the ID associated with this exchange."""
        return self._id


class CredentialOfferRecord(BaseExchangeRecord):  # TODO: do we need this?
    def __init__(
        self,
        credential_issuer,
        credentials,
        grants,
    ):
        self.credential_issuer = credential_issuer
        self.credentials = credentials
        self.grants = grants


class OID4VCICredentialSupported(BaseRecord):
    def __init__(
        self,
        credential_definition_id,
        format,
        types,
        cryptographic_binding_methods_supported,
        cryptographic_suites_supported,
        display,
        credentialSubject,
        scope,
    ):
        self.credential_definition_id = credential_definition_id
        self.format = format
        self.types = types
        self.cryptographic_binding_methods_supported = (
            cryptographic_binding_methods_supported
        )
        self.cryptographic_suites_supported = cryptographic_suites_supported
        self.display = display
        self.credentialSubject = credentialSubject
        self.scope = scope

    TAG_NAMES = {"credential_definition_id", "types", "scope"}

    def web_serialize(self) -> dict:
        return self.serialize()
