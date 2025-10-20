from unittest import IsolatedAsyncioTestCase

from acapy_agent.core.oob_processor import OobMessageProcessor
from acapy_agent.messaging.request_context import RequestContext
from acapy_agent.messaging.responder import MockResponder
from acapy_agent.tests import mock
from acapy_agent.transport.inbound.receipt import MessageReceipt
from acapy_agent.utils.testing import create_test_profile
from ...messages.credential_offer import CredentialOffer
from .. import credential_offer_handler as test_module


class TestCredentialOfferHandler(IsolatedAsyncioTestCase):
    async def test_called(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.settings["debug.auto_respond_credential_offer"] = False
        request_context.connection_record = mock.MagicMock()

        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=mock.MagicMock()
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with mock.patch.object(
            test_module, "CredentialManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_offer = mock.CoroutineMock()
            request_context.message = CredentialOffer()
            request_context.connection_ready = True
            handler = test_module.CredentialOfferHandler()
            responder = MockResponder()
            await handler.handle(request_context, responder)

        mock_cred_mgr.assert_called_once_with(request_context.profile)
        mock_cred_mgr.return_value.receive_offer.assert_called_once_with(
            request_context.message, request_context.connection_record.connection_id
        )
        mock_oob_processor.find_oob_record_for_inbound_message.assert_called_once_with(
            request_context
        )
        assert not responder.messages

    async def test_called_auto_request(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.settings["debug.auto_respond_credential_offer"] = True
        request_context.connection_record = mock.MagicMock()
        request_context.connection_record.my_did = "dummy"

        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=mock.MagicMock()
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with mock.patch.object(
            test_module, "CredentialManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_offer = mock.CoroutineMock()
            mock_cred_mgr.return_value.create_request = mock.CoroutineMock(
                return_value=(None, "credential_request_message")
            )
            request_context.message = CredentialOffer()
            request_context.connection_ready = True
            handler = test_module.CredentialOfferHandler()
            responder = MockResponder()
            await handler.handle(request_context, responder)

        mock_cred_mgr.assert_called_once_with(request_context.profile)
        mock_cred_mgr.return_value.receive_offer.assert_called_once_with(
            request_context.message, request_context.connection_record.connection_id
        )
        mock_oob_processor.find_oob_record_for_inbound_message.assert_called_once_with(
            request_context
        )
        messages = responder.messages
        assert len(messages) == 1
        (result, target) = messages[0]
        assert result == "credential_request_message"
        assert target == {}

    async def test_called_auto_request_x(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.settings["debug.auto_respond_credential_offer"] = True
        request_context.connection_record = mock.MagicMock()
        request_context.connection_record.my_did = "dummy"

        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=mock.MagicMock()
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with mock.patch.object(
            test_module, "CredentialManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_offer = mock.CoroutineMock(
                return_value=mock.MagicMock(save_error_state=mock.CoroutineMock())
            )
            mock_cred_mgr.return_value.create_request = mock.CoroutineMock(
                side_effect=test_module.IndyHolderError()
            )

            request_context.message = CredentialOffer()
            request_context.connection_ready = True
            handler = test_module.CredentialOfferHandler()
            responder = MockResponder()

            with (
                mock.patch.object(responder, "send_reply", mock.CoroutineMock()),
                mock.patch.object(
                    handler._logger, "exception", mock.MagicMock()
                ) as mock_log_exc,
            ):
                await handler.handle(request_context, responder)
                mock_log_exc.assert_called_once()

    async def test_called_not_ready(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()
        request_context.connection_record = mock.MagicMock()

        with mock.patch.object(
            test_module, "CredentialManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_offer = mock.CoroutineMock()
            request_context.message = CredentialOffer()
            request_context.connection_ready = False
            handler = test_module.CredentialOfferHandler()
            responder = MockResponder()
            with self.assertRaises(test_module.HandlerException) as err:
                await handler.handle(request_context, responder)
            assert (
                err.exception.message == "Connection used for credential offer not ready"
            )

        assert not responder.messages

    async def test_no_conn_no_oob(self):
        request_context = RequestContext.test_context(await create_test_profile())
        request_context.message_receipt = MessageReceipt()

        mock_oob_processor = mock.MagicMock(OobMessageProcessor, autospec=True)
        mock_oob_processor.find_oob_record_for_inbound_message = mock.CoroutineMock(
            return_value=None
        )
        request_context.injector.bind_instance(OobMessageProcessor, mock_oob_processor)

        with mock.patch.object(
            test_module, "CredentialManager", autospec=True
        ) as mock_cred_mgr:
            mock_cred_mgr.return_value.receive_offer = mock.CoroutineMock()
            request_context.message = CredentialOffer()
            request_context.connection_ready = False
            handler = test_module.CredentialOfferHandler()
            responder = MockResponder()
            with self.assertRaises(test_module.HandlerException) as err:
                await handler.handle(request_context, responder)
            assert (
                err.exception.message
                == "No connection or associated connectionless exchange found for credential offer"
            )

        assert not responder.messages
