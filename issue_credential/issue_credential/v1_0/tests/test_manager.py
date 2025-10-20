import json
from copy import deepcopy
from time import time
from unittest import IsolatedAsyncioTestCase

from acapy_agent.cache.base import BaseCache
from acapy_agent.cache.in_memory import InMemoryCache
from acapy_agent.indy.holder import IndyHolder
from acapy_agent.indy.issuer import IndyIssuer
from acapy_agent.ledger.base import BaseLedger
from acapy_agent.ledger.multiple_ledger.ledger_requests_executor import (
    IndyLedgerRequestsExecutor,
)
from acapy_agent.messaging.credential_definitions.util import CRED_DEF_SENT_RECORD_TYPE
from acapy_agent.messaging.decorators.thread_decorator import ThreadDecorator
from acapy_agent.messaging.responder import BaseResponder, MockResponder
from acapy_agent.multitenant.base import BaseMultitenantManager
from acapy_agent.multitenant.manager import MultitenantManager
from acapy_agent.storage.base import BaseStorage, StorageRecord
from acapy_agent.storage.error import StorageNotFoundError
from acapy_agent.tests import mock
from acapy_agent.utils.testing import create_test_profile
from .. import manager as test_module
from ..manager import CredentialManager, CredentialManagerError
from ..messages.credential_ack import CredentialAck
from ..messages.credential_issue import CredentialIssue
from ..messages.credential_offer import CredentialOffer
from ..messages.credential_problem_report import CredentialProblemReport
from ..messages.credential_proposal import CredentialProposal
from ..messages.credential_request import CredentialRequest
from ..messages.inner.credential_preview import CredAttrSpec, CredentialPreview
from ..models.credential_exchange import V10CredentialExchange
from . import (
    CRED_DEF,
    CRED_DEF_ID,
    INDY_CRED,
    INDY_CRED_INFO,
    INDY_CRED_REQ,
    INDY_OFFER,
    REV_REG_DEF,
    REV_REG_ID,
    SCHEMA,
    SCHEMA_ID,
    TEST_DID,
)


class TestCredentialManager(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.profile = await create_test_profile()

        self.ledger = mock.MagicMock(BaseLedger, autospec=True)
        self.ledger.get_schema = mock.CoroutineMock(return_value=SCHEMA)
        self.ledger.get_credential_definition = mock.CoroutineMock(return_value=CRED_DEF)
        self.ledger.get_revoc_reg_def = mock.CoroutineMock(return_value=REV_REG_DEF)
        self.ledger.credential_definition_id2schema_id = mock.CoroutineMock(
            return_value=SCHEMA_ID
        )
        self.profile.context.injector.bind_instance(BaseLedger, self.ledger)
        mock_executor = mock.MagicMock(IndyLedgerRequestsExecutor, autospec=True)
        mock_executor.get_ledger_for_identifier = mock.CoroutineMock(
            return_value=(None, self.ledger)
        )
        self.profile.context.injector.bind_instance(
            IndyLedgerRequestsExecutor, mock_executor
        )
        self.manager = CredentialManager(self.profile)
        assert self.manager.profile

    async def test_record_eq(self):
        same = [
            V10CredentialExchange(
                credential_exchange_id="dummy-0",
                thread_id="thread-0",
                credential_definition_id=CRED_DEF_ID,
                role=V10CredentialExchange.ROLE_ISSUER,
            )
        ] * 2
        diff = [
            V10CredentialExchange(
                credential_exchange_id="dummy-1",
                credential_definition_id=CRED_DEF_ID,
                role=V10CredentialExchange.ROLE_ISSUER,
            ),
            V10CredentialExchange(
                credential_exchange_id="dummy-0",
                thread_id="thread-1",
                credential_definition_id=CRED_DEF_ID,
                role=V10CredentialExchange.ROLE_ISSUER,
            ),
            V10CredentialExchange(
                credential_exchange_id="dummy-1",
                thread_id="thread-0",
                credential_definition_id=f"{CRED_DEF_ID}_distinct_tag",
                role=V10CredentialExchange.ROLE_ISSUER,
            ),
        ]

        for i in range(len(same) - 1):
            for j in range(i, len(same)):
                assert same[i] == same[j]

        for i in range(len(diff) - 1):
            for j in range(i, len(diff)):
                assert diff[i] == diff[j] if i == j else diff[i] != diff[j]

    async def test_prepare_send(self):
        connection_id = "test_conn_id"
        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )
        proposal = CredentialProposal(
            credential_proposal=preview, cred_def_id=CRED_DEF_ID, schema_id=SCHEMA_ID
        )
        with mock.patch.object(
            self.manager, "create_offer", autospec=True
        ) as create_offer:
            create_offer.return_value = (mock.MagicMock(), mock.MagicMock())
            ret_exchange, _ = await self.manager.prepare_send(connection_id, proposal)
            create_offer.assert_called_once()
            assert ret_exchange is create_offer.return_value[0]
            arg_exchange = create_offer.call_args[1]["cred_ex_record"]
            assert arg_exchange.auto_issue
            assert arg_exchange.connection_id == connection_id
            assert arg_exchange.schema_id is None
            assert arg_exchange.credential_definition_id is None
            assert arg_exchange.role == V10CredentialExchange.ROLE_ISSUER
            assert arg_exchange.credential_proposal_dict == proposal

    async def test_create_proposal(self):
        connection_id = "test_conn_id"
        comment = "comment"
        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )

        self.ledger.credential_definition_id2schema_id = mock.CoroutineMock(
            return_value=SCHEMA_ID
        )

        with mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex:
            exchange: V10CredentialExchange = await self.manager.create_proposal(
                connection_id,
                auto_offer=True,
                comment=comment,
                credential_preview=preview,
                cred_def_id=CRED_DEF_ID,
            )
            save_ex.assert_called_once()

            await self.manager.create_proposal(
                connection_id,
                auto_offer=True,
                comment=comment,
                credential_preview=preview,
                cred_def_id=None,
            )  # OK to leave underspecified until offer

        proposal = exchange.credential_proposal_dict

        assert exchange.auto_offer
        assert exchange.connection_id == connection_id
        assert not exchange.credential_definition_id  # leave underspecified until offer
        assert not exchange.schema_id  # leave underspecified until offer
        assert exchange.thread_id == proposal._thread_id
        assert exchange.role == exchange.ROLE_HOLDER
        assert exchange.state == V10CredentialExchange.STATE_PROPOSAL_SENT

    async def test_create_proposal_no_preview(self):
        connection_id = "test_conn_id"
        comment = "comment"

        self.ledger.credential_definition_id2schema_id = mock.CoroutineMock(
            return_value=SCHEMA_ID
        )

        with mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex:
            exchange: V10CredentialExchange = await self.manager.create_proposal(
                connection_id,
                auto_offer=True,
                comment=comment,
                credential_preview=None,
                cred_def_id=CRED_DEF_ID,
            )
            save_ex.assert_called_once()

        proposal = exchange.credential_proposal_dict

        assert exchange.auto_offer
        assert exchange.connection_id == connection_id
        assert not exchange.credential_definition_id  # leave underspecified until offer
        assert not exchange.schema_id  # leave underspecified until offer
        assert exchange.thread_id == proposal._thread_id
        assert exchange.role == exchange.ROLE_HOLDER
        assert exchange.state == V10CredentialExchange.STATE_PROPOSAL_SENT

    async def test_receive_proposal(self):
        connection_id = "test_conn_id"

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )

        with mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex:
            proposal = CredentialProposal(
                credential_proposal=preview, cred_def_id=CRED_DEF_ID, schema_id=None
            )

            exchange = await self.manager.receive_proposal(proposal, connection_id)
            save_ex.assert_called_once()

            assert exchange.connection_id == connection_id
            assert exchange.credential_definition_id is None
            assert exchange.role == V10CredentialExchange.ROLE_ISSUER
            assert exchange.state == V10CredentialExchange.STATE_PROPOSAL_RECEIVED
            assert exchange.schema_id is None
            assert exchange.thread_id == proposal._thread_id

            ret_proposal: CredentialProposal = exchange.credential_proposal_dict
            attrs = ret_proposal.credential_proposal.attributes
            assert attrs == preview.attributes

            self.profile.context.message = CredentialProposal(
                credential_proposal=preview, cred_def_id=None, schema_id=None
            )
            await self.manager.receive_proposal(
                proposal, connection_id
            )  # OK to leave open until offer

    async def test_create_free_offer(self):
        comment = "comment"
        schema_id_parts = SCHEMA_ID.split(":")

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )
        proposal = CredentialProposal(
            credential_proposal=preview, cred_def_id=CRED_DEF_ID, schema_id=None
        )

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            credential_definition_id=CRED_DEF_ID,
            role=V10CredentialExchange.ROLE_ISSUER,
            credential_proposal_dict=proposal.serialize(),
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        with mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex:
            self.cache = InMemoryCache()
            self.profile.context.injector.bind_instance(BaseCache, self.cache)

            issuer = mock.MagicMock(IndyIssuer, autospec=True)
            issuer.create_credential_offer = mock.CoroutineMock(
                return_value=json.dumps(INDY_OFFER)
            )
            self.profile.context.injector.bind_instance(IndyIssuer, issuer)

            cred_def_record = StorageRecord(
                CRED_DEF_SENT_RECORD_TYPE,
                CRED_DEF_ID,
                {
                    "schema_id": SCHEMA_ID,
                    "schema_issuer_did": schema_id_parts[0],
                    "schema_name": schema_id_parts[-2],
                    "schema_version": schema_id_parts[-1],
                    "issuer_did": TEST_DID,
                    "cred_def_id": CRED_DEF_ID,
                    "epoch": str(int(time())),
                },
            )
            async with self.profile.session() as session:
                storage = session.inject(BaseStorage)
                await storage.add_record(cred_def_record)

            (ret_exchange, ret_offer) = await self.manager.create_offer(
                cred_ex_record=stored_exchange,
                counter_proposal=None,
                comment=comment,
            )
            assert ret_exchange is stored_exchange
            save_ex.assert_called_once()

            issuer.create_credential_offer.assert_called_once_with(CRED_DEF_ID)

            assert (
                stored_exchange.credential_exchange_id == ret_exchange._id
            )  # cover property
            assert stored_exchange.thread_id == ret_offer._thread_id
            assert stored_exchange.credential_definition_id == CRED_DEF_ID
            assert stored_exchange.role == V10CredentialExchange.ROLE_ISSUER
            assert stored_exchange.schema_id == SCHEMA_ID
            assert stored_exchange.state == V10CredentialExchange.STATE_OFFER_SENT
            assert stored_exchange._credential_offer.ser == INDY_OFFER

            await self.manager.create_offer(
                cred_ex_record=stored_exchange,
                counter_proposal=None,
                comment=comment,
            )  # once more to cover case where offer is available in cache

    async def test_create_free_offer_attr_mismatch(self):
        comment = "comment"
        schema_id_parts = SCHEMA_ID.split(":")

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legal name", value="value"),
                CredAttrSpec(name="jurisdiction id", value="value"),
                CredAttrSpec(name="incorporation date", value="value"),
            )
        )
        proposal = CredentialProposal(
            credential_proposal=preview, cred_def_id=CRED_DEF_ID, schema_id=None
        )

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            credential_definition_id=CRED_DEF_ID,
            role=V10CredentialExchange.ROLE_ISSUER,
            credential_proposal_dict=proposal.serialize(),
            new_with_id=True,
        )
        self.profile.context.injector.bind_instance(
            BaseMultitenantManager,
            mock.MagicMock(MultitenantManager, autospec=True),
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        with mock.patch.object(V10CredentialExchange, "save", autospec=True):
            self.cache = InMemoryCache()
            self.profile.context.injector.bind_instance(BaseCache, self.cache)

            issuer = mock.MagicMock(IndyIssuer, autospec=True)
            issuer.create_credential_offer = mock.CoroutineMock(
                return_value=json.dumps(INDY_OFFER)
            )
            self.profile.context.injector.bind_instance(IndyIssuer, issuer)

            cred_def_record = StorageRecord(
                CRED_DEF_SENT_RECORD_TYPE,
                CRED_DEF_ID,
                {
                    "schema_id": SCHEMA_ID,
                    "schema_issuer_did": schema_id_parts[0],
                    "schema_name": schema_id_parts[-2],
                    "schema_version": schema_id_parts[-1],
                    "issuer_did": TEST_DID,
                    "cred_def_id": CRED_DEF_ID,
                    "epoch": str(int(time())),
                },
            )
            async with self.profile.session() as session:
                storage = session.inject(BaseStorage)
                await storage.add_record(cred_def_record)

            with self.assertRaises(CredentialManagerError):
                await self.manager.create_offer(
                    cred_ex_record=stored_exchange,
                    counter_proposal=None,
                    comment=comment,
                )

    async def test_create_bound_offer(self):
        TEST_DID = "LjgpST2rjsoxYegQDRm7EL"
        schema_id_parts = SCHEMA_ID.split(":")
        comment = "comment"

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )
        proposal = CredentialProposal(credential_proposal=preview)
        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            credential_proposal_dict=proposal.serialize(),
            role=V10CredentialExchange.ROLE_ISSUER,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        with (
            mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex,
            mock.patch.object(
                V10CredentialExchange, "get_cached_key", autospec=True
            ) as get_cached_key,
            mock.patch.object(V10CredentialExchange, "set_cached_key", autospec=True),
        ):
            get_cached_key.return_value = None
            issuer = mock.MagicMock(IndyIssuer, autospec=True)
            issuer.create_credential_offer = mock.CoroutineMock(
                return_value=json.dumps(INDY_OFFER)
            )
            self.profile.context.injector.bind_instance(IndyIssuer, issuer)

            cred_def_record = StorageRecord(
                CRED_DEF_SENT_RECORD_TYPE,
                CRED_DEF_ID,
                {
                    "schema_id": SCHEMA_ID,
                    "schema_issuer_did": schema_id_parts[0],
                    "schema_name": schema_id_parts[-2],
                    "schema_version": schema_id_parts[-1],
                    "issuer_did": TEST_DID,
                    "cred_def_id": CRED_DEF_ID,
                    "epoch": str(int(time())),
                },
            )
            async with self.profile.session() as session:
                storage = session.inject(BaseStorage)
                await storage.add_record(cred_def_record)

            (ret_exchange, ret_offer) = await self.manager.create_offer(
                cred_ex_record=stored_exchange,
                counter_proposal=None,
                comment=comment,
            )
            assert ret_exchange is stored_exchange
            save_ex.assert_called_once()

            issuer.create_credential_offer.assert_called_once_with(CRED_DEF_ID)

            assert stored_exchange.thread_id == ret_offer._thread_id
            assert stored_exchange.schema_id == SCHEMA_ID
            assert stored_exchange.credential_definition_id == CRED_DEF_ID
            assert stored_exchange.role == V10CredentialExchange.ROLE_ISSUER
            assert stored_exchange.state == V10CredentialExchange.STATE_OFFER_SENT
            assert stored_exchange._credential_offer.ser == INDY_OFFER

            # additionally check that credential preview was passed through
            assert ret_offer.credential_preview.attributes == preview.attributes

    async def test_create_bound_offer_no_cred_def(self):
        comment = "comment"

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )
        proposal = CredentialProposal(credential_proposal=preview)
        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            credential_proposal_dict=proposal.serialize(),
            role=V10CredentialExchange.ROLE_ISSUER,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        with (
            mock.patch.object(V10CredentialExchange, "save", autospec=True),
            mock.patch.object(
                V10CredentialExchange, "get_cached_key", autospec=True
            ) as get_cached_key,
            mock.patch.object(V10CredentialExchange, "set_cached_key", autospec=True),
        ):
            get_cached_key.return_value = None
            issuer = mock.MagicMock()
            issuer.create_credential_offer = mock.CoroutineMock(return_value=INDY_OFFER)
            self.profile.context.injector.bind_instance(IndyIssuer, issuer)

            with self.assertRaises(CredentialManagerError):
                await self.manager.create_offer(
                    cred_ex_record=stored_exchange,
                    counter_proposal=None,
                    comment=comment,
                )

    async def test_receive_offer_proposed(self):
        connection_id = "test_conn_id"
        thread_id = "thread-id"

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )
        proposal = CredentialProposal(credential_proposal=preview)

        offer = CredentialOffer(
            credential_preview=preview,
            offers_attach=[CredentialOffer.wrap_indy_offer(INDY_OFFER)],
        )
        offer.assign_thread_id(thread_id)

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_proposal_dict=proposal.serialize(),
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_PROPOSAL_SENT,
            schema_id=SCHEMA_ID,
            thread_id=thread_id,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        with (
            mock.patch.object(V10CredentialExchange, "save", autospec=True),
            mock.patch.object(
                V10CredentialExchange,
                "retrieve_by_connection_and_thread",
                mock.CoroutineMock(return_value=stored_exchange),
            ),
        ):
            exchange = await self.manager.receive_offer(offer, connection_id)

            assert exchange.connection_id == connection_id
            assert exchange.credential_definition_id == CRED_DEF_ID
            assert exchange.schema_id == SCHEMA_ID
            assert exchange.thread_id == offer._thread_id
            assert exchange.role == V10CredentialExchange.ROLE_HOLDER
            assert exchange.state == V10CredentialExchange.STATE_OFFER_RECEIVED
            assert exchange._credential_offer.ser == INDY_OFFER
            assert exchange.credential_offer_dict == offer

            proposal = exchange.credential_proposal_dict
            assert proposal.credential_proposal.attributes == preview.attributes

    async def test_receive_free_offer(self):
        connection_id = "test_conn_id"
        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(name="legalName", value="value"),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )

        offer = CredentialOffer(
            credential_preview=preview,
            offers_attach=[CredentialOffer.wrap_indy_offer(INDY_OFFER)],
        )
        self.profile.context.message = offer
        self.profile.context.connection_record = mock.MagicMock()
        self.profile.context.connection_record.connection_id = connection_id

        with (
            mock.patch.object(V10CredentialExchange, "save", autospec=True),
            mock.patch.object(
                V10CredentialExchange,
                "retrieve_by_connection_and_thread",
                mock.CoroutineMock(side_effect=StorageNotFoundError),
            ),
        ):
            exchange = await self.manager.receive_offer(offer, connection_id)

            assert exchange.connection_id == connection_id
            assert exchange.credential_definition_id == CRED_DEF_ID
            assert exchange.schema_id == SCHEMA_ID
            assert exchange.thread_id == offer._thread_id
            assert exchange.role == V10CredentialExchange.ROLE_HOLDER
            assert exchange.state == V10CredentialExchange.STATE_OFFER_RECEIVED
            assert exchange._credential_offer.ser == INDY_OFFER
            assert exchange.credential_proposal_dict
            assert exchange.credential_offer_dict == offer

    async def test_create_request(self):
        connection_id = "test_conn_id"
        thread_id = "thread-id"
        holder_did = "did"

        credential_offer_dict = CredentialOffer(
            "thread-id",
        )
        credential_offer_dict._thread = ThreadDecorator(pthid="some-pthid")

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_OFFER_RECEIVED,
            credential_offer_dict=credential_offer_dict,
            schema_id=SCHEMA_ID,
            thread_id=thread_id,
            new_with_id=True,
        )

        async with self.profile.session() as session:
            await stored_exchange.save(session)

        self.cache = InMemoryCache()
        self.profile.context.injector.bind_instance(BaseCache, self.cache)

        with mock.patch.object(V10CredentialExchange, "save", autospec=True):
            cred_def = {"cred": "def"}
            self.ledger.get_credential_definition = mock.CoroutineMock(
                return_value=cred_def
            )

            cred_req_meta = {}
            holder = mock.MagicMock(IndyHolder, autospec=True)
            holder.create_credential_request = mock.CoroutineMock(
                return_value=(json.dumps(INDY_CRED_REQ), json.dumps(cred_req_meta))
            )
            self.profile.context.injector.bind_instance(IndyHolder, holder)

            ret_exchange, ret_request = await self.manager.create_request(
                stored_exchange, holder_did
            )

            holder.create_credential_request.assert_called_once_with(
                INDY_OFFER, cred_def, holder_did
            )

            assert ret_request.indy_cred_req() == INDY_CRED_REQ
            assert ret_request._thread_id == thread_id

            assert ret_exchange.state == V10CredentialExchange.STATE_REQUEST_SENT

            # cover case with request in cache
            stored_exchange.credential_request = None
            stored_exchange.state = V10CredentialExchange.STATE_OFFER_RECEIVED
            await self.manager.create_request(stored_exchange, holder_did)

            # cover case with existing cred req
            (
                ret_existing_exchange,
                ret_existing_request,
            ) = await self.manager.create_request(ret_exchange, holder_did)
            assert ret_existing_exchange == ret_exchange
            assert ret_existing_request._thread_id == thread_id
            assert ret_existing_request._thread.pthid == "some-pthid"

    async def test_create_request_no_cache(self):
        connection_id = "test_conn_id"
        thread_id = "thread-id"
        holder_did = "did"

        credential_offer_dict = CredentialOffer(
            "thread-id",
        )
        credential_offer_dict._thread = ThreadDecorator(pthid="some-pthid")

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            credential_offer_dict=credential_offer_dict,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_OFFER_RECEIVED,
            schema_id=SCHEMA_ID,
            thread_id=thread_id,
            new_with_id=True,
        )
        self.profile.context.injector.bind_instance(
            BaseMultitenantManager,
            mock.MagicMock(MultitenantManager, autospec=True),
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        with mock.patch.object(V10CredentialExchange, "save", autospec=True):
            cred_def = {"cred": "def"}
            self.ledger.get_credential_definition = mock.CoroutineMock(
                return_value=cred_def
            )

            cred_req_meta = {}
            holder = mock.MagicMock(IndyHolder, autospec=True)
            holder.create_credential_request = mock.CoroutineMock(
                return_value=(json.dumps(INDY_CRED_REQ), json.dumps(cred_req_meta))
            )
            self.profile.context.injector.bind_instance(IndyHolder, holder)

            ret_exchange, ret_request = await self.manager.create_request(
                stored_exchange, holder_did
            )

            holder.create_credential_request.assert_called_once_with(
                INDY_OFFER, cred_def, holder_did
            )

            assert ret_request.indy_cred_req() == INDY_CRED_REQ
            assert ret_request._thread_id == thread_id
            assert ret_request._thread.pthid == "some-pthid"

            assert ret_exchange.state == V10CredentialExchange.STATE_REQUEST_SENT

    async def test_create_request_bad_state(self):
        connection_id = "test_conn_id"
        thread_id = "thread-id"
        holder_did = "did"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_PROPOSAL_SENT,
            schema_id=SCHEMA_ID,
            thread_id=thread_id,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        with self.assertRaises(CredentialManagerError):
            await self.manager.create_request(stored_exchange, holder_did)

    async def test_receive_request(self):
        mock_conn = mock.MagicMock(connection_id="test_conn_id")

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=mock_conn.connection_id,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_OFFER_SENT,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

            request = CredentialRequest(
                requests_attach=[CredentialRequest.wrap_indy_cred_req(INDY_CRED_REQ)]
            )

            with (
                mock.patch.object(
                    V10CredentialExchange, "save", autospec=True
                ) as save_ex,
                mock.patch.object(
                    V10CredentialExchange,
                    "retrieve_by_connection_and_thread",
                    mock.CoroutineMock(return_value=stored_exchange),
                ) as retrieve_ex,
            ):
                exchange = await self.manager.receive_request(request, mock_conn, None)

            retrieve_ex.assert_called()
            save_ex.assert_called_once()

            assert exchange.state == V10CredentialExchange.STATE_REQUEST_RECEIVED
            assert exchange._credential_request.ser == INDY_CRED_REQ

    async def test_receive_request_no_connection_cred_request(self):
        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_OFFER_SENT,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        request = CredentialRequest(
            requests_attach=[CredentialRequest.wrap_indy_cred_req(INDY_CRED_REQ)]
        )

        mock_conn = mock.MagicMock(
            connection_id="test_conn_id",
        )
        mock_oob = mock.MagicMock()

        with (
            mock.patch.object(V10CredentialExchange, "save", autospec=True) as mock_save,
            mock.patch.object(
                V10CredentialExchange,
                "retrieve_by_connection_and_thread",
                mock.CoroutineMock(),
            ) as mock_retrieve,
        ):
            mock_retrieve.return_value = stored_exchange
            cx_rec = await self.manager.receive_request(request, mock_conn, mock_oob)

            mock_retrieve.assert_called()
            mock_save.assert_called_once()
            assert cx_rec.state == V10CredentialExchange.STATE_REQUEST_RECEIVED
            assert cx_rec._credential_request.ser == INDY_CRED_REQ
            assert cx_rec.connection_id == "test_conn_id"

    async def test_receive_request_no_cred_ex_with_offer_found(self):
        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_OFFER_SENT,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        request = CredentialRequest(
            requests_attach=[CredentialRequest.wrap_indy_cred_req(INDY_CRED_REQ)]
        )

        mock_conn = mock.MagicMock(
            connection_id="test_conn_id",
        )

        with (
            mock.patch.object(V10CredentialExchange, "save", autospec=True),
            mock.patch.object(
                V10CredentialExchange,
                "retrieve_by_connection_and_thread",
                mock.CoroutineMock(),
            ) as mock_retrieve,
        ):
            mock_retrieve.side_effect = (StorageNotFoundError(),)
            with self.assertRaises(StorageNotFoundError):
                await self.manager.receive_request(request, mock_conn, None)

                mock_retrieve.assert_called()

    async def test_issue_credential_revocable(self):
        connection_id = "test_conn_id"
        comment = "comment"
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            credential_request=INDY_CRED_REQ,
            credential_proposal_dict=CredentialProposal(
                credential_proposal=CredentialPreview.deserialize(
                    {"attributes": [{"name": "attr", "value": "value"}]}
                ),
                cred_def_id=CRED_DEF_ID,
                schema_id=SCHEMA_ID,
            ).serialize(),
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_REQUEST_RECEIVED,
            thread_id=thread_id,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        issuer = mock.MagicMock(IndyIssuer, autospec=True)
        cred = {"indy": "credential"}
        cred_rev_id = "1000"
        issuer.create_credential = mock.CoroutineMock(
            return_value=(json.dumps(cred), cred_rev_id)
        )
        self.profile.context.injector.bind_instance(IndyIssuer, issuer)

        with (
            mock.patch.object(test_module, "IndyRevocation", autospec=True) as revoc,
            mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex,
        ):
            revoc.return_value.get_or_create_active_registry = mock.CoroutineMock(
                return_value=(
                    mock.MagicMock(  # active_rev_reg_rec
                        revoc_reg_id=REV_REG_ID,
                    ),
                    mock.MagicMock(  # rev_reg
                        registry_id=REV_REG_ID,
                        tails_local_path="dummy-path",
                        get_or_fetch_local_tails_path=mock.CoroutineMock(),
                        max_creds=10,
                    ),
                )
            )
            (ret_exchange, ret_cred_issue) = await self.manager.issue_credential(
                stored_exchange, comment=comment, retries=1
            )

            save_ex.assert_called_once()

            issuer.create_credential.assert_called()

            assert ret_exchange._credential.ser == cred
            assert ret_cred_issue.indy_credential() == cred
            assert ret_exchange.state == V10CredentialExchange.STATE_ISSUED
            assert ret_cred_issue._thread_id == thread_id

            # cover case with existing cred
            (
                ret_existing_exchange,
                ret_existing_cred,
            ) = await self.manager.issue_credential(
                ret_exchange, comment=comment, retries=0
            )
            assert ret_existing_exchange == ret_exchange
            assert ret_existing_cred._thread_id == thread_id

    async def test_issue_credential_non_revocable(self):
        CRED_DEF_NR = deepcopy(CRED_DEF)
        CRED_DEF_NR["value"]["revocation"] = None
        connection_id = "test_conn_id"
        comment = "comment"
        cred_values = {"attr": "value"}
        thread_id = "thread-id"
        self.profile.context.injector.bind_instance(
            BaseMultitenantManager,
            mock.MagicMock(MultitenantManager, autospec=True),
        )
        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            credential_request=INDY_CRED_REQ,
            credential_proposal_dict=CredentialProposal(
                credential_proposal=CredentialPreview.deserialize(
                    {"attributes": [{"name": "attr", "value": "value"}]}
                ),
                cred_def_id=CRED_DEF_ID,
                schema_id=SCHEMA_ID,
            ).serialize(),
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_REQUEST_RECEIVED,
            thread_id=thread_id,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        issuer = mock.MagicMock(IndyIssuer, autospec=True)
        cred = {"indy": "credential"}
        issuer.create_credential = mock.CoroutineMock(
            return_value=(json.dumps(cred), None)
        )
        self.profile.context.injector.bind_instance(IndyIssuer, issuer)

        self.ledger = mock.MagicMock(BaseLedger, autospec=True)
        self.ledger.get_schema = mock.CoroutineMock(return_value=SCHEMA)
        self.ledger.get_credential_definition = mock.CoroutineMock(
            return_value=CRED_DEF_NR
        )
        self.ledger.__aenter__ = mock.CoroutineMock(return_value=self.ledger)
        self.profile.context.injector.clear_binding(BaseLedger)
        self.profile.context.injector.bind_instance(BaseLedger, self.ledger)
        with (
            mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex,
            mock.patch.object(
                IndyLedgerRequestsExecutor,
                "get_ledger_for_identifier",
                mock.CoroutineMock(return_value=("test_ledger_id", self.ledger)),
            ),
        ):
            (ret_exchange, ret_cred_issue) = await self.manager.issue_credential(
                stored_exchange, comment=comment, retries=0
            )

            save_ex.assert_called_once()

            issuer.create_credential.assert_called_once_with(
                SCHEMA,
                INDY_OFFER,
                INDY_CRED_REQ,
                cred_values,
                None,
                None,
            )

            assert ret_exchange._credential.ser == cred
            assert ret_cred_issue.indy_credential() == cred
            assert ret_exchange.state == V10CredentialExchange.STATE_ISSUED
            assert ret_cred_issue._thread_id == thread_id

    async def test_issue_credential_fills_rr(self):
        connection_id = "test_conn_id"
        comment = "comment"
        cred_values = {"attr": "value"}
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            credential_request=INDY_CRED_REQ,
            credential_proposal_dict=CredentialProposal(
                credential_proposal=CredentialPreview.deserialize(
                    {"attributes": [{"name": "attr", "value": "value"}]}
                ),
                cred_def_id=CRED_DEF_ID,
                schema_id=SCHEMA_ID,
            ).serialize(),
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_REQUEST_RECEIVED,
            thread_id=thread_id,
            revocation_id="1000",
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        issuer = mock.MagicMock(IndyIssuer, autospec=True)
        cred = {"indy": "credential"}
        issuer.create_credential = mock.CoroutineMock(
            return_value=(json.dumps(cred), stored_exchange.revocation_id)
        )
        self.profile.context.injector.bind_instance(IndyIssuer, issuer)

        with (
            mock.patch.object(test_module, "IndyRevocation", autospec=True) as revoc,
            mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex,
        ):
            revoc.return_value = mock.MagicMock(
                get_or_create_active_registry=(
                    mock.CoroutineMock(
                        return_value=(
                            mock.MagicMock(  # active_rev_reg_rec
                                revoc_reg_id=REV_REG_ID,
                                set_state=mock.CoroutineMock(),
                            ),
                            mock.MagicMock(  # rev_reg
                                registry_id=REV_REG_ID,
                                tails_local_path="dummy-path",
                                max_creds=1000,
                                get_or_fetch_local_tails_path=(mock.CoroutineMock()),
                            ),
                        )
                    )
                ),
                handle_full_registry=mock.CoroutineMock(),
            )
            (ret_exchange, ret_cred_issue) = await self.manager.issue_credential(
                stored_exchange, comment=comment, retries=0
            )

            save_ex.assert_called_once()

            issuer.create_credential.assert_called_once_with(
                SCHEMA,
                INDY_OFFER,
                INDY_CRED_REQ,
                cred_values,
                REV_REG_ID,
                "dummy-path",
            )

            revoc.return_value.handle_full_registry.assert_awaited_once_with(REV_REG_ID)

            assert ret_exchange._credential.ser == cred
            assert ret_cred_issue.indy_credential() == cred
            assert ret_exchange.state == V10CredentialExchange.STATE_ISSUED
            assert ret_cred_issue._thread_id == thread_id

    async def test_issue_credential_request_bad_state(self):
        connection_id = "test_conn_id"
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_PROPOSAL_SENT,
            schema_id=SCHEMA_ID,
            thread_id=thread_id,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        with self.assertRaises(CredentialManagerError):
            await self.manager.issue_credential(stored_exchange)

    async def test_issue_credential_no_active_rr_no_retries(self):
        connection_id = "test_conn_id"
        comment = "comment"
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            credential_request=INDY_CRED_REQ,
            credential_proposal_dict=CredentialProposal(
                credential_proposal=CredentialPreview.deserialize(
                    {"attributes": [{"name": "attr", "value": "value"}]}
                ),
                cred_def_id=CRED_DEF_ID,
                schema_id=SCHEMA_ID,
            ).serialize(),
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_REQUEST_RECEIVED,
            thread_id=thread_id,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        issuer = mock.MagicMock(IndyIssuer, autospec=True)
        cred = {"indy": "credential"}
        cred_rev_id = "1"
        issuer.create_credential = mock.CoroutineMock(
            return_value=(json.dumps(cred), cred_rev_id)
        )
        self.profile.context.injector.bind_instance(IndyIssuer, issuer)
        executor = mock.MagicMock(IndyLedgerRequestsExecutor, autospec=True)
        executor.get_ledger_for_identifier = mock.CoroutineMock(
            return_value=("test_ledger_id", self.ledger)
        )
        self.profile.context.injector.bind_instance(IndyLedgerRequestsExecutor, executor)
        with mock.patch.object(test_module, "IndyRevocation", autospec=True) as revoc:
            revoc.return_value.get_or_create_active_registry = mock.CoroutineMock(
                side_effect=[
                    None,
                    (
                        mock.MagicMock(  # active_rev_reg_rec
                            revoc_reg_id=REV_REG_ID,
                            set_state=mock.CoroutineMock(),
                        ),
                        mock.MagicMock(  # rev_reg
                            tails_local_path="dummy-path",
                            get_or_fetch_local_tails_path=(mock.CoroutineMock()),
                        ),
                    ),
                ]
            )
            with self.assertRaises(CredentialManagerError):
                await self.manager.issue_credential(
                    stored_exchange, comment=comment, retries=0
                )

    async def test_issue_credential_no_active_rr_retry(self):
        connection_id = "test_conn_id"
        comment = "comment"
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_offer=INDY_OFFER,
            credential_request=INDY_CRED_REQ,
            credential_proposal_dict=CredentialProposal(
                credential_proposal=CredentialPreview.deserialize(
                    {"attributes": [{"name": "attr", "value": "value"}]}
                ),
                cred_def_id=CRED_DEF_ID,
                schema_id=SCHEMA_ID,
            ).serialize(),
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            state=V10CredentialExchange.STATE_REQUEST_RECEIVED,
            thread_id=thread_id,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        issuer = mock.MagicMock(IndyIssuer, autospec=True)
        cred = {"indy": "credential"}
        cred_rev_id = "1"
        issuer.create_credential = mock.CoroutineMock(
            return_value=(json.dumps(cred), cred_rev_id)
        )
        self.profile.context.injector.bind_instance(IndyIssuer, issuer)
        executor = mock.MagicMock(IndyLedgerRequestsExecutor, autospec=True)
        executor.get_ledger_for_identifier = mock.CoroutineMock(
            return_value=("test_ledger_id", self.ledger)
        )
        self.profile.context.injector.bind_instance(IndyLedgerRequestsExecutor, executor)
        with mock.patch.object(test_module, "IndyRevocation", autospec=True) as revoc:
            revoc.return_value.get_or_create_active_registry = mock.CoroutineMock(
                return_value=None
            )
            with self.assertRaises(CredentialManagerError):
                await self.manager.issue_credential(
                    stored_exchange, comment=comment, retries=1
                )

    async def test_receive_credential(self):
        connection_id = "test_conn_id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_REQUEST_SENT,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        issue = CredentialIssue(
            credentials_attach=[CredentialIssue.wrap_indy_credential(INDY_CRED)]
        )

        with (
            mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex,
            mock.patch.object(
                V10CredentialExchange,
                "retrieve_by_connection_and_thread",
                mock.CoroutineMock(return_value=stored_exchange),
            ) as retrieve_ex,
        ):
            exchange = await self.manager.receive_credential(issue, connection_id)

            assert retrieve_ex.call_args.args[1] == connection_id
            assert retrieve_ex.call_args.args[2] == issue._thread_id
            assert (
                retrieve_ex.call_args.kwargs["role"] == V10CredentialExchange.ROLE_HOLDER
            )
            assert retrieve_ex.call_args.kwargs["for_update"] is True
            save_ex.assert_called_once()

            assert exchange._raw_credential.ser == INDY_CRED
            assert exchange.state == V10CredentialExchange.STATE_CREDENTIAL_RECEIVED

    async def test_store_credential(self):
        connection_id = "test_conn_id"
        cred_req_meta = {"req": "meta"}
        thread_id = "thread-id"

        preview = CredentialPreview(
            attributes=(
                CredAttrSpec(
                    name="legalName", value="value", mime_type="text/plain;lang=en-ca"
                ),
                CredAttrSpec(name="jurisdictionId", value="value"),
                CredAttrSpec(name="incorporationDate", value="value"),
            )
        )
        proposal = CredentialProposal(
            credential_proposal=preview, cred_def_id=CRED_DEF_ID, schema_id=SCHEMA_ID
        )

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_request_metadata=cred_req_meta,
            credential_proposal_dict=proposal,
            raw_credential=INDY_CRED,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_CREDENTIAL_RECEIVED,
            thread_id=thread_id,
            auto_remove=True,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        cred_id = "cred-id"
        holder = mock.MagicMock(IndyHolder, autospec=True)
        holder.store_credential = mock.CoroutineMock(return_value=cred_id)
        holder.get_credential = mock.CoroutineMock(
            return_value=json.dumps(INDY_CRED_INFO)
        )
        self.profile.context.injector.bind_instance(IndyHolder, holder)
        executor = mock.MagicMock(IndyLedgerRequestsExecutor, autospec=True)
        executor.get_ledger_for_identifier = mock.CoroutineMock(
            return_value=("test_ledger_id", self.ledger)
        )
        self.profile.context.injector.bind_instance(IndyLedgerRequestsExecutor, executor)
        with (
            mock.patch.object(
                test_module, "RevocationRegistry", autospec=True
            ) as mock_rev_reg,
            mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex,
            mock.patch.object(V10CredentialExchange, "delete_record", autospec=True),
        ):
            mock_rev_reg.from_definition = mock.MagicMock(
                return_value=mock.MagicMock(
                    get_or_fetch_local_tails_path=mock.CoroutineMock()
                )
            )
            ret_exchange = await self.manager.store_credential(
                stored_exchange, credential_id=cred_id
            )

            save_ex.assert_called_once()

            self.ledger.get_credential_definition.assert_called_once_with(CRED_DEF_ID)

            holder.store_credential.assert_called_once_with(
                CRED_DEF,
                INDY_CRED,
                cred_req_meta,
                {"legalName": "text/plain;lang=en-ca"},
                credential_id=cred_id,
                rev_reg_def=REV_REG_DEF,
            )

            holder.get_credential.assert_called_once_with(cred_id)

            assert ret_exchange.credential_id == cred_id
            assert ret_exchange._credential.ser == INDY_CRED_INFO
            assert ret_exchange.state == V10CredentialExchange.STATE_CREDENTIAL_RECEIVED

    async def test_store_credential_bad_state(self):
        connection_id = "test_conn_id"
        cred_req_meta = {"req": "meta"}
        thread_id = "thread-id"

        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_request_metadata=cred_req_meta,
            credential_proposal_dict=None,
            raw_credential=INDY_CRED,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_OFFER_RECEIVED,
            thread_id=thread_id,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)
        cred_id = "cred-id"

        with self.assertRaises(CredentialManagerError):
            await self.manager.store_credential(stored_exchange, credential_id=cred_id)

    async def test_store_credential_no_preview(self):
        connection_id = "test_conn_id"
        cred_req_meta = {"req": "meta"}
        thread_id = "thread-id"
        self.profile.context.injector.bind_instance(
            BaseMultitenantManager,
            mock.MagicMock(MultitenantManager, autospec=True),
        )
        cred_no_rev = {**INDY_CRED}
        cred_no_rev["rev_reg_id"] = None
        cred_no_rev["rev_reg"] = None
        cred_no_rev["witness"] = None
        cred_info_no_rev = {**INDY_CRED_INFO}
        cred_info_no_rev["rev_reg_id"] = None
        cred_info_no_rev["cred_rev_id"] = None
        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_request_metadata=cred_req_meta,
            credential_proposal_dict=None,
            raw_credential=cred_no_rev,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_CREDENTIAL_RECEIVED,
            thread_id=thread_id,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        cred_def = mock.MagicMock()
        self.ledger.get_credential_definition = mock.CoroutineMock(return_value=cred_def)

        cred_id = "cred-id"
        holder = mock.MagicMock(IndyHolder, autospec=True)
        holder.store_credential = mock.CoroutineMock(return_value=cred_id)
        holder.get_credential = mock.CoroutineMock(
            return_value=json.dumps(cred_info_no_rev)
        )
        self.profile.context.injector.bind_instance(IndyHolder, holder)
        executor = mock.MagicMock(IndyLedgerRequestsExecutor, autospec=True)
        executor.get_ledger_for_identifier = mock.CoroutineMock(
            return_value=("test_ledger_id", self.ledger)
        )
        self.profile.context.injector.bind_instance(IndyLedgerRequestsExecutor, executor)
        with (
            mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex,
            mock.patch.object(V10CredentialExchange, "delete_record", autospec=True),
        ):
            ret_exchange = await self.manager.store_credential(stored_exchange)

            save_ex.assert_called_once()

            self.ledger.get_credential_definition.assert_called_once_with(CRED_DEF_ID)

            holder.store_credential.assert_called_once_with(
                cred_def,
                cred_no_rev,
                cred_req_meta,
                None,
                credential_id=None,
                rev_reg_def=None,
            )

            holder.get_credential.assert_called_once_with(cred_id)

            assert ret_exchange.credential_id == cred_id
            assert ret_exchange._credential.ser == cred_info_no_rev
            assert ret_exchange.state == V10CredentialExchange.STATE_CREDENTIAL_RECEIVED

    async def test_store_credential_holder_store_indy_error(self):
        connection_id = "test_conn_id"
        cred_req_meta = {"req": "meta"}
        thread_id = "thread-id"

        cred_no_rev = {**INDY_CRED}
        cred_no_rev["rev_reg_id"] = None
        cred_no_rev["rev_reg"] = None
        cred_no_rev["witness"] = None
        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            credential_definition_id=CRED_DEF_ID,
            credential_request_metadata=cred_req_meta,
            credential_proposal_dict=None,
            raw_credential=cred_no_rev,
            initiator=V10CredentialExchange.INITIATOR_EXTERNAL,
            role=V10CredentialExchange.ROLE_HOLDER,
            state=V10CredentialExchange.STATE_CREDENTIAL_RECEIVED,
            thread_id=thread_id,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        cred_def = mock.MagicMock()
        self.ledger.get_credential_definition = mock.CoroutineMock(return_value=cred_def)

        cred_id = "cred-id"
        holder = mock.MagicMock(IndyHolder, autospec=True)
        holder.store_credential = mock.CoroutineMock(
            side_effect=test_module.IndyHolderError("Problem", {"message": "Nope"})
        )
        self.profile.context.injector.bind_instance(IndyHolder, holder)

        mock_executor = mock.MagicMock(IndyLedgerRequestsExecutor, autospec=True)
        mock_executor.get_ledger_for_identifier = mock.CoroutineMock(
            return_value=("test_ledger_id", self.ledger)
        )
        self.profile.context.injector.bind_instance(
            IndyLedgerRequestsExecutor, mock_executor
        )
        with self.assertRaises(test_module.IndyHolderError):
            await self.manager.store_credential(
                cred_ex_record=stored_exchange, credential_id=cred_id
            )

    async def test_send_credential_ack(self):
        connection_id = "connection-id"
        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            state=V10CredentialExchange.STATE_CREDENTIAL_RECEIVED,
            thread_id="thid",
            parent_thread_id="pthid",
            role=V10CredentialExchange.ROLE_ISSUER,
            trace=False,
            auto_remove=True,
            new_with_id=True,
        )

        async with self.profile.session() as session:
            await stored_exchange.save(session)

        with (
            mock.patch.object(V10CredentialExchange, "save", autospec=True),
            mock.patch.object(
                V10CredentialExchange, "delete_record", autospec=True
            ) as mock_delete_ex,
            mock.patch.object(
                test_module.LOGGER, "exception", mock.MagicMock()
            ) as mock_log_exception,
            mock.patch.object(
                test_module.LOGGER, "warning", mock.MagicMock()
            ) as mock_log_warning,
        ):
            mock_delete_ex.side_effect = test_module.StorageError()
            (exch, ack) = await self.manager.send_credential_ack(stored_exchange)
            assert ack._thread
            mock_log_exception.assert_called_once()  # cover exception log-and-continue
            mock_log_warning.assert_called_once()  # no BaseResponder
            assert exch.state == V10CredentialExchange.STATE_ACKED

            mock_responder = MockResponder()  # cover with responder
            self.profile.context.injector.bind_instance(BaseResponder, mock_responder)
            (exch, ack) = await self.manager.send_credential_ack(stored_exchange)
            assert ack._thread
            assert exch.state == V10CredentialExchange.STATE_ACKED

    async def test_receive_credential_ack(self):
        connection_id = "connection-id"
        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)

        ack = CredentialAck()

        with (
            mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex,
            mock.patch.object(
                V10CredentialExchange, "delete_record", autospec=True
            ) as delete_ex,
            mock.patch.object(
                V10CredentialExchange,
                "retrieve_by_connection_and_thread",
                mock.CoroutineMock(),
            ) as retrieve_ex,
        ):
            retrieve_ex.return_value = stored_exchange
            ret_exchange = await self.manager.receive_credential_ack(ack, connection_id)

            assert retrieve_ex.call_args.args[1] == connection_id
            assert retrieve_ex.call_args.args[2] == ack._thread_id
            assert (
                retrieve_ex.call_args.kwargs["role"] == V10CredentialExchange.ROLE_ISSUER
            )
            assert retrieve_ex.call_args.kwargs["for_update"] is True
            save_ex.assert_called_once()

            assert ret_exchange.state == V10CredentialExchange.STATE_ACKED
            delete_ex.assert_called_once()

    async def test_receive_problem_report(self):
        connection_id = "connection-id"
        stored_exchange = V10CredentialExchange(
            credential_exchange_id="dummy-cxid",
            connection_id=connection_id,
            initiator=V10CredentialExchange.INITIATOR_SELF,
            role=V10CredentialExchange.ROLE_ISSUER,
            new_with_id=True,
        )
        async with self.profile.session() as session:
            await stored_exchange.save(session)
        problem = CredentialProblemReport(
            description={
                "code": test_module.ProblemReportReason.ISSUANCE_ABANDONED.value,
                "en": "Insufficient privilege",
            }
        )

        with (
            mock.patch.object(V10CredentialExchange, "save", autospec=True) as save_ex,
            mock.patch.object(
                V10CredentialExchange,
                "retrieve_by_connection_and_thread",
                mock.CoroutineMock(),
            ) as retrieve_ex,
        ):
            retrieve_ex.return_value = stored_exchange

            ret_exchange = await self.manager.receive_problem_report(
                problem, connection_id
            )
            assert retrieve_ex.call_args.args[1] == connection_id
            assert retrieve_ex.call_args.args[2] == problem._thread_id
            assert retrieve_ex.call_args.kwargs["for_update"] is True

            save_ex.assert_called_once()

            assert ret_exchange.state == V10CredentialExchange.STATE_ABANDONED

    async def test_receive_problem_report_x(self):
        connection_id = "connection-id"
        problem = CredentialProblemReport(
            description={
                "code": test_module.ProblemReportReason.ISSUANCE_ABANDONED.value,
                "en": "Insufficient privilege",
            }
        )

        with mock.patch.object(
            V10CredentialExchange,
            "retrieve_by_connection_and_thread",
            mock.CoroutineMock(),
        ) as retrieve_ex:
            retrieve_ex.side_effect = test_module.StorageNotFoundError("No such record")

            exch = await self.manager.receive_problem_report(problem, connection_id)
            assert exch is None

    async def test_retrieve_records(self):
        self.cache = InMemoryCache()
        self.profile.context.injector.bind_instance(BaseCache, self.cache)

        for index in range(2):
            exchange_record = V10CredentialExchange(
                connection_id=str(index),
                thread_id=str(1000 + index),
                initiator=V10CredentialExchange.INITIATOR_SELF,
                role=V10CredentialExchange.ROLE_ISSUER,
            )
            async with self.profile.session() as session:
                await exchange_record.save(session)

                for _ in range(2):  # second pass gets from cache
                    ret_ex = (
                        await V10CredentialExchange.retrieve_by_connection_and_thread(
                            session, str(index), str(1000 + index)
                        )
                    )
                    assert ret_ex.connection_id == str(index)
                    assert ret_ex.thread_id == str(1000 + index)
