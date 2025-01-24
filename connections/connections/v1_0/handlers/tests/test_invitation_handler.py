import pytest

from acapy_agent.messaging.request_context import RequestContext
from acapy_agent.messaging.responder import MockResponder
from acapy_agent.transport.inbound.receipt import MessageReceipt
from acapy_agent.utils.testing import create_test_profile
from ...handlers.connection_invitation_handler import ConnectionInvitationHandler
from ...messages.connection_invitation import ConnectionInvitation
from ...messages.problem_report import ConnectionProblemReport, ProblemReportReason


@pytest.fixture()
async def request_context():
    ctx = RequestContext.test_context(await create_test_profile())
    ctx.message_receipt = MessageReceipt()
    yield ctx


class TestInvitationHandler:
    @pytest.mark.asyncio
    async def test_problem_report(self, request_context):
        request_context.message = ConnectionInvitation()
        handler = ConnectionInvitationHandler()
        responder = MockResponder()
        await handler.handle(request_context, responder)
        messages = responder.messages
        assert len(messages) == 1
        result, target = messages[0]
        assert (
            isinstance(result, ConnectionProblemReport)
            and result.description
            and (
                result.description["code"]
                == ProblemReportReason.INVITATION_NOT_ACCEPTED.value
            )
        )
        assert not target
