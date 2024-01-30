"""Message handlers for DIDComm RPC v1.0."""

import json
from aries_cloudagent.messaging.base_handler import (
    BaseResponder,
    BaseHandler,
    RequestContext,
)
from aries_cloudagent.storage.base import BaseStorage
from aries_cloudagent.storage.record import StorageRecord

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
            storage = session.inject(BaseStorage)
            record = StorageRecord(
                type=DRPCRecord.RECORD_TYPE,
                value=json.dumps(request_record.serialize()),
                tags={
                    "connection_id": connection_id,
                    "thread_id": thread_id,
                },
            )
            await storage.add_record(record)

        await context.profile.notify(
            "drpc::request::received",
            {
                "connection_id": connection_id,
                "thread_id": thread_id,
                "request": request_record.serialize(),
            },
        )


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
            response_record.response = context.message.response.serialize()
            response_record.state = DRPCRecord.STATE_COMPLETED

            storage = session.inject(BaseStorage)
            await storage.update_record(
                response_record.storage_record,
                json.dumps(response_record.serialize()),
                {
                    "connection_id": connection_id,
                    "thread_id": thread_id,
                },
            )

        await context.profile.notify(
            "drpc::response::received",
            {
                "connection_id": connection_id,
                "thread_id": thread_id,
                "request": response_record.serialize(),
            },
        )
