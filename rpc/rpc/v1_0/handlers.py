"""Message handlers for DIDComm RPC v1.0."""

import json

from acapy_agent.messaging.base_handler import (
    BaseHandler,
    BaseResponder,
    RequestContext,
)
from acapy_agent.storage.base import BaseStorage
from acapy_agent.storage.record import StorageRecord

from rpc.v1_0.messages import DRPCRequestMessage, DRPCResponseMessage
from rpc.v1_0.models import DRPCRecord


class DRPCRequestHandler(BaseHandler):
    """Handler class for DRPCRequestMessage."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler implementation."""

        self._logger.debug("DRPCRequestHandler called with context %s", context)
        assert isinstance(context.message, DRPCRequestMessage)

        self._logger.info("Received RPC request: %s", context.message.request)

        connection_id = context.connection_record.connection_id
        thread_id = context.message._id

        async with context.session() as session:
            request_record = DRPCRecord(
                request=context.message.request, state=DRPCRecord.STATE_REQUEST_RECEIVED
            )
            serialized_request_record = request_record.serialize()

            storage = session.inject(BaseStorage)
            record = StorageRecord(
                type=DRPCRecord.RECORD_TYPE,
                value=json.dumps(serialized_request_record),
                tags={
                    "connection_id": connection_id,
                    "thread_id": thread_id,
                },
            )
            await storage.add_record(record)

        notification = {
            "connection_id": connection_id,
            "thread_id": thread_id,
            "request": serialized_request_record,
        }

        await context.profile.notify("drpc::request::received", notification)
        await context.profile.notify("acapy::webhook::drpc_request", notification)


class DRPCResponseHandler(BaseHandler):
    """Handler class for DRPCResponseMessage."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler implementation."""

        self._logger.debug("DRPCResponseHandler called with context %s", context)
        assert isinstance(context.message, DRPCResponseMessage)

        self._logger.info("Received RPC response: %s", context.message.response)

        connection_id = context.connection_record.connection_id
        thread_id = context.message._thread_id

        async with context.session() as session:
            response_record = await DRPCRecord.retrieve_by_connection_and_thread(
                session, connection_id, thread_id
            )
            response_record.response = context.message.response
            response_record.state = DRPCRecord.STATE_COMPLETED
            serialized_response_record = response_record.serialize()

            storage = session.inject(BaseStorage)
            await storage.update_record(
                response_record.storage_record,
                json.dumps(serialized_response_record),
                {
                    "connection_id": connection_id,
                    "thread_id": thread_id,
                },
            )

        notification = {
            "connection_id": connection_id,
            "thread_id": thread_id,
            "response": serialized_response_record,
        }

        await context.profile.notify("drpc::response::received", notification)
        await context.profile.notify("acapy::webhook::drpc_response", notification)
