from typing import Any, Dict, Optional
from aries_cloudagent.messaging.models.base_record import BaseExchangeRecord, BaseRecord



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
