"""Routes for DIDComm Resolver."""

from aiohttp import web
from aiohttp_apispec import docs, response_schema
from aries_cloudagent.admin.request_context import AdminRequestContext
from aries_cloudagent.messaging.models.base import BaseModelError
from aries_cloudagent.messaging.models.openapi import OpenAPISchema
from aries_cloudagent.storage.error import StorageError
from marshmallow import fields
from kafka_events import teardown, start


class StopKafkaSchema(OpenAPISchema):
    """Stop Kafka request expected response."""

    result = fields.Str(
        description="Result of the operation", example="Kafka plugin stopped"
    )


class StartKafkaSchema(OpenAPISchema):
    """Start Kafka request expected response."""

    result = fields.Str(
        description="Result of the operation", example="Kafka plugin started"
    )


@docs(
    tags=["kafka-bus"],
    summary="Stop the kafka consumer & producer.",
)
@response_schema(StopKafkaSchema(), 200, description="Stop Kafka Consumer/Producer")
async def stop_kafka(request: web.Request):
    """
    Request handler to stop the kafka consume & produce.

    Args:
        request: aiohttp request object

    Returns:
        The connection list response

    """
    context: AdminRequestContext = request["context"]
    async with context.session():
        try:
            await teardown(context)
        except Exception as err:
            raise web.HTTPBadRequest(reason=err) from err

    return web.json_response({"result": "Kafka plugin stopped"})


@docs(
    tags=["kafka-bus"],
    summary="Start the kafka consumer & producer.",
)
@response_schema(StartKafkaSchema(), 200, description="")
async def start_kafka(request: web.Request):
    """
    Request handler for listing resolver connections.

    Args:
        request: aiohttp request object

    Returns:
        The connection list response

    """
    context: AdminRequestContext = request["context"]
    async with context.session():
        try:
            await start(context)
        except (StorageError, BaseModelError) as err:
            raise web.HTTPBadRequest(reason=err) from err

    return web.json_response({"result": "Kafka plugin started"})


async def register(app: web.Application):
    """Register routes."""

    app.add_routes(
        [
            web.get("/kafka/stop", stop_kafka, allow_head=False),
            web.get("/kafka/start", start_kafka, allow_head=False),
        ]
    )


def post_process_routes(app: web.Application):
    """Amend swagger API."""

    # Add top-level tags description
    if "tags" not in app._state["swagger_dict"]:
        app._state["swagger_dict"]["tags"] = []
    app._state["swagger_dict"]["tags"].append(
        {
            "name": "kafka-bus",
            "description": "Kafka commands to stop/start the interfaces.",
            "externalDocs": {
                "description": "Specification",
                "url": "https://hackmd.io/ZjsDJg_8Ta6rsbq5ZSgHxA",
            },
        }
    )
