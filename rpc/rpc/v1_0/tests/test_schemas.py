from marshmallow import ValidationError
import pytest

from aries_cloudagent.messaging.valid import UUID4_EXAMPLE

from rpc.v1_0.messages import DRPCRequestMessageSchema, DRPCResponseMessageSchema
from rpc.v1_0.routes import DRPCRequestSchema, DRPCResponseSchema


def test_valid_drpc_request():
    """Test the DRPCRequestSchema schema."""

    data = {
        "connection_id": UUID4_EXAMPLE,
        "request": {
            "jsonrpc": "2.0",
            "method": "test.method",
            "id": "1",
            "params": {"one": "1"},
        },
    }

    schema = DRPCRequestSchema()
    result = schema.load(data)
    assert result.connection_id == UUID4_EXAMPLE
    assert result.request.jsonrpc == "2.0"
    assert result.request.method == "test.method"
    assert result.request.id == "1"
    assert result.request.params == {"one": "1"}


def test_invalid_drpc_request():
    """Test the DRPCRequestSchema schema."""

    data = {
        "connection_id": UUID4_EXAMPLE,
        "request": {"method": "test.method", "id": "1", "params": {"one": "1"}},
    }

    schema = DRPCRequestSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(data)

    assert "request" in exc_info.value.messages
    assert "jsonrpc" in exc_info.value.messages["request"]
    assert (
        "Missing data for required field."
        in exc_info.value.messages["request"]["jsonrpc"]
    )


def test_valid_drpc_request_message():
    """Test the DRPCRequesMessageSchema schema."""

    data = {
        "connection_id": UUID4_EXAMPLE,
        "request": {
            "jsonrpc": "2.0",
            "method": "test.method",
            "id": "1",
            "params": {"one": "1"},
        },
        "state": "request-sent",
    }

    schema = DRPCRequestMessageSchema()
    result = schema.load(data)
    assert result._id is not None
    assert result._type is not None
    assert result.connection_id == UUID4_EXAMPLE
    assert result.request.jsonrpc == "2.0"
    assert result.request.method == "test.method"
    assert result.request.id == "1"
    assert result.request.params == {"one": "1"}


def test_valid_drpc_response():
    """Test the DRPCResponseSchema schema."""

    data = {
        "connection_id": UUID4_EXAMPLE,
        "response": {"jsonrpc": "2.0", "result": "test result", "id": "1"},
        "thread_id": UUID4_EXAMPLE,
    }

    schema = DRPCResponseSchema()
    result = schema.load(data)
    assert result.connection_id == UUID4_EXAMPLE
    assert result.response.jsonrpc == "2.0"
    assert result.response.result == "test result"
    assert result.response.id == "1"


def test_invalid_drpc_response():
    """Test the DRPCResponseSchema schema."""

    data = {
        "connection_id": UUID4_EXAMPLE,
        "response": {"result": "test result", "id": "1"},
    }

    schema = DRPCResponseSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(data)

    assert "response" in exc_info.value.messages
    assert "jsonrpc" in exc_info.value.messages["response"]
    assert (
        "Missing data for required field."
        in exc_info.value.messages["response"]["jsonrpc"]
    )


def test_valid_drpc_response_message():
    """Test the DRPCResponseMessageSchema schema."""

    data = {
        "connection_id": UUID4_EXAMPLE,
        "response": {"jsonrpc": "2.0", "result": "test result", "id": "1"},
        "state": "completed",
    }

    schema = DRPCResponseMessageSchema()
    result = schema.load(data)
    assert result._id is not None
    assert result._type is not None
    assert result.connection_id == UUID4_EXAMPLE
    assert result.response.jsonrpc == "2.0"
    assert result.response.result == "test result"
    assert result.response.id == "1"
