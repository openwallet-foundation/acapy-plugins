from unittest import TestCase, mock

import pytest

from acapy_agent.messaging.models.base import BaseModelError
from acapy_agent.protocols.didcomm_prefix import DIDCommPrefix
from ...message_types import CREDENTIAL_PROBLEM_REPORT, PROTOCOL_PACKAGE
from .. import credential_problem_report as test_module
from ..credential_problem_report import (
    CredentialProblemReport,
    CredentialProblemReportSchema,
    ProblemReportReason,
    ValidationError,
)


class TestCredentialProblemReport(TestCase):
    """Problem report tests."""

    def test_init_type(self):
        """Test initializer."""

        prob = CredentialProblemReport(
            description={
                "en": "oh no",
                "code": ProblemReportReason.ISSUANCE_ABANDONED.value,
            }
        )
        assert prob._type == DIDCommPrefix.qualify_current(CREDENTIAL_PROBLEM_REPORT)

    @mock.patch.object(CredentialProblemReportSchema, "load")
    def test_deserialize(self, mock_load):
        """Test deserialization."""

        obj = CredentialProblemReport(
            description={
                "en": "oh no",
                "code": ProblemReportReason.ISSUANCE_ABANDONED.value,
            }
        )

        prob = CredentialProblemReport.deserialize(obj)
        mock_load.assert_called_once_with(obj)

        assert prob is mock_load.return_value

    @mock.patch.object(CredentialProblemReportSchema, "dump")
    def test_serialize(self, mock_dump):
        """Test serialization."""

        obj = CredentialProblemReport(
            description={
                "en": "oh no",
                "code": ProblemReportReason.ISSUANCE_ABANDONED.value,
            }
        )

        ser = obj.serialize()
        mock_dump.assert_called_once_with(obj)

        assert ser is mock_dump.return_value

    def test_make_model(self):
        """Test making model."""

        prob = CredentialProblemReport(
            description={
                "en": "oh no",
                "code": ProblemReportReason.ISSUANCE_ABANDONED.value,
            }
        )
        data = prob.serialize()
        model_instance = CredentialProblemReport.deserialize(data)
        assert isinstance(model_instance, CredentialProblemReport)

        prob = CredentialProblemReport()
        data = prob.serialize()
        with pytest.raises(BaseModelError):
            CredentialProblemReport.deserialize(data)

    def test_validate_x(self):
        """Exercise validation requirements."""
        schema = CredentialProblemReportSchema()
        with pytest.raises(ValidationError):
            schema.validate_fields({})

    def test_validate_and_logger(self):
        """Capture ValidationError and Logs."""
        data = CredentialProblemReport(
            description={
                "en": "oh no",
                "code": "invalid_code",
            },
        ).serialize()
        with mock.patch.object(test_module, "LOGGER", autospec=True) as mock_logger:
            CredentialProblemReportSchema().validate_fields(data)
        assert mock_logger.warning.call_count == 1
