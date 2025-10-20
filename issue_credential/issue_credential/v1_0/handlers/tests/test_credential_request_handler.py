from unittest import IsolatedAsyncioTestCase

from acapy_agent.core.oob_processor import OobMessageProcessor
from acapy_agent.messaging.request_context import RequestContext
from acapy_agent.messaging.responder import MockResponder
from acapy_agent.tests import mock
from acapy_agent.transport.inbound.receipt import MessageReceipt
from acapy_agent.utils.testing import create_test_profile
from ...messages.credential_request import CredentialRequest
from ...messages.inner.credential_preview import CredAttrSpec, CredentialPreview
from ...models.credential_exchange import V10CredentialExchange
from .. import credential_request_handler as test_module

CD_ID = "LjgpST2rjsoxYegQDRm7EL:3:CL:18:tag"


class TestCredentialRequestHandler(IsolatedAsyncioTestCase):
    async def test_called(self):
        profile = await create_test_profile()
        request_context = RequestContext.test_context(profile)
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        oob_record = mock.MagicMock()
        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=oob_record
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with mock.patch.object(
            test_module, "CredentialManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_request = mock.CoroutineMock(
                return_value=mock.MagicMock()
            )
            mock_cred_mgr.return_value.receive_request.return_value.auto_issue = False
            request_context.message = CredentialRequest()
            request_context.connection_ready = True
            handler = test_module.CredentialRequestHandler()
            responder = MockResponder()
            await handler.handle(request_context, responder)

        mock_cred_mgr.assert_called_once_with(request_context.profile)
        mock_cred_mgr.return_value.receive_request.assert_called_once_with(
            request_context.message, request_context.connection_record, oob_record
        )
        mock_oob_processor.find_oob_record_for_inbound_message.assert_called_once_with(
            request_context
        )
        assert not responder.messages

    async def test_called_auto_issue(self):
        profile = await create_test_profile()
        request_context = RequestContext.test_context(profile)
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        oob_record = mock.MagicMock()
        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=oob_record
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        ATTR_DICT = {"test": "123", "hello": "world"}
        cred_ex_rec = V10CredentialExchange(
            credential_proposal_dict={
                "credential_proposal": CredentialPreview(
                    attributes=(CredAttrSpec.list_plain(ATTR_DICT))
                ).serialize(),
                "cred_def_id": CD_ID,
            },
        )

        with mock.patch.object(
            test_module, "CredentialManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_request = mock.CoroutineMock(
                return_value=cred_ex_rec
            )
            mock_cred_mgr.return_value.receive_request.return_value.auto_issue = True
            mock_cred_mgr.return_value.issue_credential = mock.CoroutineMock(
                return_value=(None, "credential_issue_message")
            )
            request_context.message = CredentialRequest()
            request_context.connection_ready = True
            handler = test_module.CredentialRequestHandler()
            responder = MockResponder()
            await handler.handle(request_context, responder)
            mock_cred_mgr.return_value.issue_credential.assert_called_once_with(
                cred_ex_record=cred_ex_rec, comment=None
            )

        mock_cred_mgr.assert_called_once_with(request_context.profile)
        mock_cred_mgr.return_value.receive_request.assert_called_once_with(
            request_context.message, request_context.connection_record, oob_record
        )
        mock_oob_processor.find_oob_record_for_inbound_message.assert_called_once_with(
            request_context
        )
        messages = responder.messages
        assert len(messages) == 1
        (result, target) = messages[0]
        assert result == "credential_issue_message"
        assert target == {}

    async def test_called_auto_issue_x(self):
        profile = await create_test_profile()
        request_context = RequestContext.test_context(profile)
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        oob_record = mock.MagicMock()
        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=oob_record
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        ATTR_DICT = {"test": "123", "hello": "world"}
        cred_ex_rec = V10CredentialExchange(
            credential_proposal_dict={
                "credential_proposal": CredentialPreview(
                    attributes=(CredAttrSpec.list_plain(ATTR_DICT))
                ).serialize(),
                "cred_def_id": CD_ID,
            },
        )

        with (
            mock.patch.object(
                test_module, "CredentialManager", autospec=True
            ) as mock_cred_mgr,
            mock.patch.object(cred_ex_rec, "save_error_state", mock.CoroutineMock()),
        ):
            mock_cred_mgr.return_value.receive_request = mock.CoroutineMock(
                return_value=cred_ex_rec
            )
            mock_cred_mgr.return_value.receive_request.return_value.auto_issue = True
            mock_cred_mgr.return_value.issue_credential = mock.CoroutineMock(
                side_effect=test_module.IndyIssuerError()
            )

            request_context.message = CredentialRequest()
            request_context.connection_ready = True
            handler = test_module.CredentialRequestHandler()
            responder = MockResponder()

            with (
                mock.patch.object(responder, "send_reply", mock.CoroutineMock()),
                mock.patch.object(
                    handler._logger, "exception", mock.MagicMock()
                ) as mock_log_exc,
            ):
                await handler.handle(request_context, responder)
                mock_log_exc.assert_called_once()

    async def test_called_auto_issue_no_preview(self):
        profile = await create_test_profile()
        request_context = RequestContext.test_context(profile)
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        oob_record = mock.MagicMock()
        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=oob_record
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        cred_ex_rec = V10CredentialExchange(
            credential_proposal_dict={"cred_def_id": CD_ID}
        )

        with mock.patch.object(
            test_module, "CredentialManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_request = mock.CoroutineMock(
                return_value=cred_ex_rec
            )
            mock_cred_mgr.return_value.receive_request.return_value.auto_issue = True
            mock_cred_mgr.return_value.issue_credential = mock.CoroutineMock(
                return_value=(None, "credential_issue_message")
            )

            request_context.message = CredentialRequest()
            request_context.connection_ready = True
            handler = test_module.CredentialRequestHandler()
            responder = MockResponder()
            await handler.handle(request_context, responder)
            mock_cred_mgr.return_value.issue_credential.assert_not_called()

        mock_cred_mgr.assert_called_once_with(request_context.profile)
        mock_cred_mgr.return_value.receive_request.assert_called_once_with(
            request_context.message, request_context.connection_record, oob_record
        )
        mock_oob_processor.find_oob_record_for_inbound_message.assert_called_once_with(
            request_context
        )
        assert not responder.messages

    async def test_called_not_ready(self):
        profile = await create_test_profile()
        request_context = RequestContext.test_context(profile)
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        with mock.patch.object(
            test_module, "CredentialManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_request = mock.CoroutineMock()
            request_context.message = CredentialRequest()
            request_context.connection_ready = False
            handler = test_module.CredentialRequestHandler()
            responder = MockResponder()
            with self.assertRaises(test_module.HandlerException) as err:
                await handler.handle(request_context, responder)
            assert (
                err.exception.message
                == "Connection used for credential request not ready"
            )

        assert not responder.messages

    async def test_called_no_connection_no_oob(self):
        profile = await create_test_profile()
        request_context = RequestContext.test_context(profile)
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = None
        request_context.connection_ready = False

        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=None
        )

        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with mock.patch.object(
            test_module, "CredentialManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_request = mock.CoroutineMock()
            request_context.message = CredentialRequest()
            handler = test_module.CredentialRequestHandler()
            responder = MockResponder()
            with self.assertRaises(test_module.HandlerException) as err:
                await handler.handle(request_context, responder)
            assert (
                err.exception.message
                == "No connection or associated connectionless exchange found for credential request"
            )

        assert not responder.messages
