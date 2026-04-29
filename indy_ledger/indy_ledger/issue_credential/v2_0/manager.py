"""Credential manager for Indy-based credentials."""

import logging
from typing import Optional

from acapy_agent.protocols.issue_credential.v2_0.manager import (
    V20CredManager,
    V20CredManagerError,
)
from acapy_agent.protocols.issue_credential.v2_0.messages.cred_issue import V20CredIssue
from acapy_agent.protocols.issue_credential.v2_0.models.cred_ex_record import (
    V20CredExRecord,
)

from .messages.cred_format import V20CredFormat

LOGGER = logging.getLogger(__name__)


class IndyV20CredManager(V20CredManager):
    """Credential manager for Indy-based credentials."""

    def __init__(self, *args, **kwargs):
        """Initialize an Indy V2.0 Credential Manager."""
        super().__init__(*args, **kwargs)

    async def receive_credential(
        self, cred_issue_message: V20CredIssue, connection_id: Optional[str]
    ) -> V20CredExRecord:
        """Receive a credential issue message from an issuer.

        Hold cred in storage potentially to be processed by controller before storing.

        Returns:
            Credential exchange record, retrieved and updated

        """
        assert cred_issue_message.credentials_attach

        # FIXME use transaction, fetch for_update
        async with self._profile.session() as session:
            cred_ex_record = await V20CredExRecord.retrieve_by_conn_and_thread(
                session,
                connection_id,
                cred_issue_message._thread_id,
                role=V20CredExRecord.ROLE_HOLDER,
            )

        cred_request_message = cred_ex_record.cred_request
        req_formats = [
            V20CredFormat.Format.get(fmt.format)
            for fmt in cred_request_message.formats
            if V20CredFormat.Format.get(fmt.format)
        ]
        issue_formats = [
            V20CredFormat.Format.get(fmt.format)
            for fmt in cred_issue_message.formats
            if V20CredFormat.Format.get(fmt.format)
        ]
        handled_formats = []

        def _check_formats():
            """Allow anoncreds req format or matching formats."""
            return (req_formats == [V20CredFormat.Format.ANONCREDS]) or len(
                set(issue_formats) - set(req_formats)
            ) == 0

        if not _check_formats():
            raise V20CredManagerError(
                "Received issue credential format(s) not present in credential "
                f"request: {set(issue_formats) - set(req_formats)}"
            )

        for issue_format in issue_formats:
            await issue_format.handler(self.profile).receive_credential(
                cred_ex_record, cred_issue_message
            )
            handled_formats.append(issue_format)

        if len(handled_formats) == 0:
            raise V20CredManagerError("No supported credential formats received.")

        cred_ex_record.cred_issue = cred_issue_message
        cred_ex_record.state = V20CredExRecord.STATE_CREDENTIAL_RECEIVED

        async with self._profile.session() as session:
            await cred_ex_record.save(session, reason="receive v2.0 credential issue")
        return cred_ex_record
