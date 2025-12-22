import importlib
from unittest import IsolatedAsyncioTestCase

from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.anoncreds.models.presentation_request import (
    AnonCredsPresentationReqAttrSpecSchema,
)
from acapy_agent.indy.holder import IndyHolder
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from marshmallow import ValidationError

from .. import routes as test_module
from ..models.presentation_exchange import V10PresentationExchange


class TestProofRoutes(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile(
            settings={
                "admin.admin_api_key": "secret-key",
            }
        )
        self.context = AdminRequestContext.test_context({}, profile=self.profile)
        self.request_dict = {
            "context": self.context,
            "outbound_message_router": mock.CoroutineMock(),
        }
        self.request = mock.MagicMock(
            app={},
            match_info={},
            query={},
            __getitem__=lambda _, k: self.request_dict[k],
            headers={"x-api-key": "secret-key"},
        )

    async def test_validate_proof_req_attr_spec(self):
        aspec = AnonCredsPresentationReqAttrSpecSchema()
        aspec.validate_fields({"name": "attr0"})
        aspec.validate_fields(
            {
                "names": ["attr0", "attr1"],
                "restrictions": [{"attr::attr1::value": "my-value"}],
            }
        )
        aspec.validate_fields(
            {"name": "attr0", "restrictions": [{"schema_name": "preferences"}]}
        )
        with self.assertRaises(ValidationError):
            aspec.validate_fields({})
        with self.assertRaises(ValidationError):
            aspec.validate_fields({"name": "attr0", "names": ["attr1", "attr2"]})
        with self.assertRaises(ValidationError):
            aspec.validate_fields({"names": ["attr1", "attr2"]})
        with self.assertRaises(ValidationError):
            aspec.validate_fields({"names": ["attr0", "attr1"], "restrictions": []})
        with self.assertRaises(ValidationError):
            aspec.validate_fields({"names": ["attr0", "attr1"], "restrictions": [{}]})

    async def test_presentation_exchange_list(self):
        self.request.query = {
            "thread_id": "thread_id_0",
            "connection_id": "conn_id_0",
            "role": "dummy",
            "state": "dummy",
        }

        with mock.patch.object(
            V10PresentationExchange,
            "query",
            mock.CoroutineMock(
                return_value=[V10PresentationExchange(thread_id="sample-thread-id")]
            ),
        ):
            with mock.patch.object(test_module.web, "json_response") as mock_response:
                await test_module.presentation_exchange_list(self.request)
                mock_response.assert_called_once_with(
                    {
                        "results": [
                            V10PresentationExchange(
                                thread_id="sample-thread-id"
                            ).serialize()
                        ]
                    }
                )

    async def test_presentation_exchange_list_x(self):
        self.request.query = {
            "thread_id": "thread_id_0",
            "connection_id": "conn_id_0",
            "role": "dummy",
            "state": "dummy",
        }

        with mock.patch.object(
            V10PresentationExchange,
            "query",
            mock.CoroutineMock(side_effect=test_module.StorageError()),
        ):
            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_list(self.request)

    async def test_presentation_exchange_credentials_list_not_found(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with mock.patch.object(
            V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(side_effect=StorageNotFoundError),
        ):
            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.presentation_exchange_credentials_list(self.request)

    async def test_presentation_exchange_credentials_x(self):
        self.request.match_info = {
            "pres_ex_id": "123-456-789",
            "referent": "myReferent1",
        }
        self.request.query = {"extra_query": {}}
        mock_holder = mock.MagicMock(IndyHolder, autospec=True)
        mock_holder.get_credentials_for_presentation_request_by_referent = (
            mock.CoroutineMock(side_effect=test_module.IndyHolderError())
        )
        self.profile.context.injector.bind_instance(IndyHolder, mock_holder)
        mock_px_rec = mock.MagicMock(save_error_state=mock.CoroutineMock())

        with mock.patch.object(
            V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(return_value=mock_px_rec),
        ):
            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_credentials_list(self.request)

    async def test_presentation_exchange_credentials_list_single_referent(self):
        self.request.match_info = {
            "pres_ex_id": "123-456-789",
            "referent": "myReferent1",
        }
        self.request.query = {"extra_query": {}}

        returned_credentials = [{"name": "Credential1"}, {"name": "Credential2"}]
        mock_holder = mock.MagicMock(IndyHolder, autospec=True)
        mock_holder.get_credentials_for_presentation_request_by_referent = (
            mock.CoroutineMock(return_value=returned_credentials)
        )
        self.profile.context.injector.bind_instance(IndyHolder, mock_holder)

        with mock.patch.object(
            V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(return_value=mock.MagicMock()),
        ):
            with mock.patch.object(test_module.web, "json_response") as mock_response:
                await test_module.presentation_exchange_credentials_list(self.request)
                mock_response.assert_called_once_with(returned_credentials)

    async def test_presentation_exchange_credentials_list_multiple_referents(self):
        self.request.match_info = {
            "pres_ex_id": "123-456-789",
            "referent": "myReferent1,myReferent2",
        }
        self.request.query = {"extra_query": {}}

        returned_credentials = [{"name": "Credential1"}, {"name": "Credential2"}]
        mock_holder = mock.MagicMock(IndyHolder, autospec=True)
        mock_holder.get_credentials_for_presentation_request_by_referent = (
            mock.CoroutineMock(return_value=returned_credentials)
        )
        self.profile.context.injector.bind_instance(IndyHolder, mock_holder)

        with mock.patch.object(
            V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(return_value=mock.MagicMock()),
        ):
            with mock.patch.object(test_module.web, "json_response") as mock_response:
                await test_module.presentation_exchange_credentials_list(self.request)
                mock_response.assert_called_once_with(returned_credentials)

    async def test_presentation_exchange_retrieve_not_found(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with mock.patch.object(
            V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(side_effect=StorageNotFoundError),
        ):
            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.presentation_exchange_retrieve(self.request)

    async def test_presentation_exchange_retrieve_x(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with (
            mock.patch.object(
                V10PresentationExchange,
                "retrieve_by_id",
                mock.CoroutineMock(
                    return_value=V10PresentationExchange(
                        connection_id="abc123", thread_id="thid123"
                    )
                ),
            ),
            mock.patch.object(
                V10PresentationExchange,
                "serialize",
                mock.MagicMock(side_effect=test_module.BaseModelError()),
            ),
        ):
            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_retrieve(self.request)

    async def test_presentation_exchange_send_proposal_no_conn_record(self):
        self.request.json = mock.CoroutineMock()

        with mock.patch(
            "acapy_agent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record:
            # Since we are mocking import
            importlib.reload(test_module)

            # Emulate storage not found (bad connection id)
            mock_connection_record.retrieve_by_id = mock.CoroutineMock(
                side_effect=StorageNotFoundError
            )

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_proposal(self.request)

    async def test_presentation_exchange_send_free_request_not_found(self):
        self.request.json = mock.CoroutineMock(return_value={"connection_id": "dummy"})

        with mock.patch(
            "acapy_agent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record:
            # Since we are mocking import
            importlib.reload(test_module)

            mock_connection_record.retrieve_by_id = mock.CoroutineMock()
            mock_connection_record.retrieve_by_id.side_effect = StorageNotFoundError

            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_free_request(self.request)

    async def test_presentation_exchange_send_free_request_not_ready(self):
        self.request.json = mock.CoroutineMock(
            return_value={"connection_id": "dummy", "proof_request": {}}
        )

        with mock.patch(
            "acapy_agent.connections.models.conn_record.ConnRecord",
            autospec=True,
        ) as mock_connection_record:
            # Since we are mocking import
            importlib.reload(test_module)

            mock_connection_record.is_ready = False
            mock_connection_record.retrieve_by_id = mock.CoroutineMock(
                return_value=mock_connection_record
            )

            with self.assertRaises(test_module.web.HTTPForbidden):
                await test_module.presentation_exchange_send_free_request(self.request)

    async def test_presentation_exchange_send_bound_request_px_rec_not_found(self):
        self.request.json = mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        with mock.patch.object(
            test_module.V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(),
        ) as mock_retrieve:
            mock_retrieve.side_effect = StorageNotFoundError("no such record")
            with self.assertRaises(test_module.web.HTTPNotFound) as context:
                await test_module.presentation_exchange_send_bound_request(self.request)
            assert "no such record" in str(context.exception)

    async def test_presentation_exchange_send_bound_request_bad_state(self):
        self.request.json = mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        with mock.patch.object(
            V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(
                return_value=V10PresentationExchange(
                    state=V10PresentationExchange.STATE_PRESENTATION_ACKED,
                    connection_id="dummy",
                )
            ),
        ) as mock_presentation_exchange:
            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_bound_request(self.request)

    async def test_presentation_exchange_send_presentation_px_rec_not_found(self):
        self.request.json = mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        with mock.patch.object(
            test_module.V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(),
        ) as mock_retrieve:
            mock_retrieve.side_effect = StorageNotFoundError("no such record")
            with self.assertRaises(test_module.web.HTTPNotFound) as context:
                await test_module.presentation_exchange_send_presentation(self.request)
            assert "no such record" in str(context.exception)

    async def test_presentation_exchange_send_presentation_bad_state(self):
        self.request.json = mock.CoroutineMock()
        self.request.match_info = {"pres_ex_id": "dummy"}

        with mock.patch.object(
            V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(
                return_value=V10PresentationExchange(
                    state=V10PresentationExchange.STATE_PRESENTATION_ACKED
                )
            ),
        ) as mock_presentation_exchange:
            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_send_presentation(self.request)

    async def test_presentation_exchange_verify_presentation_px_rec_not_found(self):
        self.request.json = mock.CoroutineMock(return_value={"trace": False})
        self.request.match_info = {"pres_ex_id": "dummy"}

        with mock.patch.object(
            test_module.V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(),
        ) as mock_retrieve:
            mock_retrieve.side_effect = StorageNotFoundError("no such record")
            with self.assertRaises(test_module.web.HTTPNotFound) as context:
                await test_module.presentation_exchange_verify_presentation(self.request)
            assert "no such record" in str(context.exception)

    async def test_presentation_exchange_verify_presentation_bad_state(self):
        self.request.json = mock.CoroutineMock()
        self.request.match_info = {"pres_ex_id": "dummy"}

        with mock.patch.object(
            V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(
                return_value=mock.MagicMock(
                    state=V10PresentationExchange.STATE_PRESENTATION_ACKED
                )
            ),
        ):
            with self.assertRaises(test_module.web.HTTPBadRequest):
                await test_module.presentation_exchange_verify_presentation(self.request)

    async def test_presentation_exchange_problem_report(self):
        self.request.json = mock.CoroutineMock()
        self.request.match_info = {"pres_ex_id": "dummy"}
        magic_report = mock.MagicMock()

        with (
            mock.patch.object(
                V10PresentationExchange,
                "retrieve_by_id",
                mock.CoroutineMock(
                    return_value=mock.MagicMock(save_error_state=mock.CoroutineMock())
                ),
            ) as mock_pres_ex,
            mock.patch.object(
                test_module, "problem_report_for_record", mock.MagicMock()
            ) as mock_problem_report,
            mock.patch.object(test_module.web, "json_response") as mock_response,
        ):
            mock_problem_report.return_value = magic_report

            await test_module.presentation_exchange_problem_report(self.request)

            self.request["outbound_message_router"].assert_awaited_once()
            mock_response.assert_called_once_with({})

    async def test_presentation_exchange_problem_report_bad_pres_ex_id(self):
        self.request.json = mock.CoroutineMock(
            return_value={"description": "Did I say no problem? I meant 'no: problem.'"}
        )
        self.request.match_info = {"pres_ex_id": "dummy"}

        with (
            mock.patch.object(
                V10PresentationExchange,
                "retrieve_by_id",
                mock.CoroutineMock(side_effect=test_module.StorageNotFoundError()),
            ) as mock_pres_ex,
        ):
            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.presentation_exchange_problem_report(self.request)

    async def test_presentation_exchange_remove(self):
        self.request.match_info = {"pres_ex_id": "dummy"}

        with mock.patch.object(
            V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(
                return_value=V10PresentationExchange(
                    state=V10PresentationExchange.STATE_VERIFIED,
                    connection_id="dummy",
                )
            ),
        ):
            with mock.patch.object(test_module.web, "json_response") as mock_response:
                await test_module.presentation_exchange_remove(self.request)
                mock_response.assert_called_once_with({})

    async def test_presentation_exchange_remove_not_found(self):
        self.request.json = mock.CoroutineMock()
        self.request.match_info = {"pres_ex_id": "dummy"}

        with mock.patch.object(
            V10PresentationExchange,
            "retrieve_by_id",
            mock.CoroutineMock(side_effect=StorageNotFoundError),
        ):
            with self.assertRaises(test_module.web.HTTPNotFound):
                await test_module.presentation_exchange_remove(self.request)

    async def test_register(self):
        mock_app = mock.MagicMock()
        mock_app.add_routes = mock.MagicMock()

        await test_module.register(mock_app)
        mock_app.add_routes.assert_called_once()

    async def test_post_process_routes(self):
        mock_app = mock.MagicMock(_state={"swagger_dict": {}})
        test_module.post_process_routes(mock_app)
        assert "tags" in mock_app._state["swagger_dict"]
