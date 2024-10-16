import pytest
from acapy_agent.messaging.valid import UUID4_EXAMPLE
from marshmallow import ValidationError

from rpc.v1_0.messages import DRPCRequestMessageSchema, DRPCResponseMessageSchema
from rpc.v1_0.routes import DRPCRequestJSONSchema, DRPCResponseJSONSchema


def test_valid_drpc_request():
    """Test the DRPCRequestJSONSchema schema."""

    data = {
        "request": {
            "jsonrpc": "2.0",
            "method": "test.method",
            "id": "1",
            "params": {"one": "1"},
        },
    }

    schema = DRPCRequestJSONSchema()
    result = schema.load(data)
    assert result.request.jsonrpc == "2.0"
    assert result.request.method == "test.method"
    assert result.request.id == "1"
    assert result.request.params == {"one": "1"}


def test_invalid_drpc_request():
    """Test the DRPCRequestJSONSchema schema."""

    data = {
        "connection_id": UUID4_EXAMPLE,
        "request": {"method": "test.method", "id": "1", "params": {"one": "1"}},
    }

    schema = DRPCRequestJSONSchema()

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
        "request": {
            "jsonrpc": "2.0",
            "method": "test.method",
            "id": "1",
            "params": {"one": "1"},
        },
    }

    schema = DRPCRequestMessageSchema()
    result = schema.load(data)
    assert result._id is not None
    assert result._type is not None
    assert result.request.jsonrpc == "2.0"
    assert result.request.method == "test.method"
    assert result.request.id == "1"
    assert result.request.params == {"one": "1"}


def test_valid_drpc_response():
    """Test the DRPCResponseJSONSchema schema."""

    data = {
        "response": {"jsonrpc": "2.0", "result": "test result", "id": "1"},
        "thread_id": UUID4_EXAMPLE,
    }

    schema = DRPCResponseJSONSchema()
    result = schema.load(data)
    assert result.response.jsonrpc == "2.0"
    assert result.response.result == "test result"
    assert result.response.id == "1"


def test_invalid_drpc_response():
    """Test the DRPCResponseJSONSchema schema."""

    data = {
        "connection_id": UUID4_EXAMPLE,
        "response": {"result": "test result", "id": "1"},
    }

    schema = DRPCResponseJSONSchema()

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

    data = {"response": {"jsonrpc": "2.0", "result": "test result", "id": "1"}}

    schema = DRPCResponseMessageSchema()
    result = schema.load(data)
    assert result._id is not None
    assert result._type is not None
    assert result.response.jsonrpc == "2.0"
    assert result.response.result == "test result"
    assert result.response.id == "1"
