from aries_cloudagent.messaging.base_handler import (
    BaseResponder,
    BaseHandler,
    RequestContext
)

from rpc.v1_0.messages import DRPCRequestMessage, DRPCResponseMessage


class DRPCRequestHandler(BaseHandler):
    """Handler class for DRPCRequestMessage."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler implementation."""

        self._logger.debug("DRPCRequestHandler called with context %s", context)
        assert isinstance(context.message, DRPCRequestMessage)

        self._logger.info("Received RPC request: %s", context.message.request)

        pass


class DRPCResponseHandler(BaseHandler):
    """Handler class for DRPCResponseMessage."""

    async def handle(self, context: RequestContext, responder: BaseResponder):
        """Message handler implementation."""

        self._logger.debug("DRPCResponseHandler called with context %s", context)
        assert isinstance(context.message, DRPCResponseMessage)

        self._logger.info("Received RPC response: %s", context.message.response)

        pass