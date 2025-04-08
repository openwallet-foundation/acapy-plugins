import pytest
from marshmallow import ValidationError

from rpc.v1_0.models import (
    DRPCRecordSchema,
    RPCBaseModelSchema,
    RPCErrorModelSchema,
    RPCRequestModelSchema,
    RPCResponseModelSchema,
)

rpc_base = {"jsonrpc": "2.0"}


@pytest.mark.parametrize("test_input", [rpc_base])
def test_valid_rpc_base(test_input):
    schema = RPCBaseModelSchema()
    result = schema.load(test_input)

    assert result.jsonrpc == "2.0"


@pytest.mark.parametrize("test_input", [{}])
def test_invalid_rpc_base_jsonrpc_missing(test_input):
    schema = RPCBaseModelSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "jsonrpc" in exc_info.value.messages
    assert "Missing data for required field." in exc_info.value.messages["jsonrpc"]


@pytest.mark.parametrize(
    "test_input",
    [
        {**rpc_base, "method": "test.method", "id": 123},
        {**rpc_base, "method": "test.method", "id": "123"},
        {**rpc_base, "method": "test.notification", "id": None},
        {**rpc_base, "method": "test.notification"},
        {**rpc_base, "method": "test.method", "params": ["1", "2", "3"], "id": 123},
        {**rpc_base, "method": "test.method", "params": {"test": "params"}, "id": 123},
        {**rpc_base, "method": "test.method", "params": [], "id": 123},
        {**rpc_base, "method": "test.method", "params": {}, "id": 123},
        {**rpc_base, "method": "test.method", "params": None, "id": 123},
        {**rpc_base, "method": "test.notification", "params": ["1", "2", "3"]},
        {**rpc_base, "method": "test.notification", "params": {"test": "params"}},
        {**rpc_base, "method": "test.notification", "params": []},
        {**rpc_base, "method": "test.notification", "params": {}},
        {**rpc_base, "method": "test.notification", "params": None},
    ],
)
def test_valid_rpc_request(test_input):
    schema = RPCRequestModelSchema()
    result = schema.load(test_input)

    assert result.jsonrpc == "2.0"
    assert result.method == test_input["method"]
    # Test optional fields
    if "id" in test_input:
        assert result.id == test_input["id"]


@pytest.mark.parametrize("test_input", [{**rpc_base, "method": "rpc.test.method"}])
def test_invalid_rpc_request_internal_method(test_input):
    schema = RPCRequestModelSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "method" in exc_info.value.messages
    assert (
        "Method name cannot be internal RPC method." in exc_info.value.messages["method"]
    )


@pytest.mark.parametrize(
    "test_input", [{**rpc_base, "method": "test.method", "id": 12.34}]
)
def test_invalid_rpc_request_id_float(test_input):
    schema = RPCRequestModelSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "id" in exc_info.value.messages
    assert "ID must be an integer, string, or null." in exc_info.value.messages["id"]


@pytest.mark.parametrize(
    "test_input",
    [
        {**rpc_base, "method": "test.method", "params": "test params", "id": 123},
        {**rpc_base, "method": "test.method", "params": 123, "id": 123},
    ],
)
def test_invalid_rpc_request_params_type(test_input):
    schema = RPCRequestModelSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "params" in exc_info.value.messages
    assert (
        "Params must be an array, object, or null." in exc_info.value.messages["params"]
    )


@pytest.mark.parametrize(
    "test_input",
    [
        {"code": -123, "message": "Test error message"},
        {"code": 123, "message": "Test error message"},
        {"code": "-123", "message": "Test error message"},
        {"code": "123", "message": "Test error message"},
        {"code": 123, "message": "Test error message", "data": "abc"},
        {"code": 123, "message": "Test error message", "data": {"test": "abc"}},
    ],
)
def test_valid_rpc_error(test_input):
    schema = RPCErrorModelSchema()
    result = schema.load(test_input)

    assert result.code == int(test_input["code"])
    assert result.message == test_input["message"]
    # Test optional fields
    if "data" in test_input:
        assert result.data == test_input["data"]


@pytest.mark.parametrize(
    "test_input",
    [
        {"message": "Test error message"},
        {"message": "Test error message", "data": "abc"},
    ],
)
def test_invalid_rpc_error_code_missing(test_input):
    schema = RPCErrorModelSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "code" in exc_info.value.messages
    assert "Missing data for required field." in exc_info.value.messages["code"]


@pytest.mark.parametrize("test_input", [{"code": 123}, {"code": "123", "data": "abc"}])
def test_invalid_rpc_error_message_missing(test_input):
    schema = RPCErrorModelSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "message" in exc_info.value.messages
    assert "Missing data for required field." in exc_info.value.messages["message"]


@pytest.mark.parametrize(
    "test_input",
    [
        {"code": "abc", "message": "Test error message"},
        {"code": "abc", "message": "Test error message", "data": "abc"},
    ],
)
def test_invalid_rpc_error_code_type(test_input):
    schema = RPCErrorModelSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "code" in exc_info.value.messages
    assert "Not a valid integer." in exc_info.value.messages["code"]


@pytest.mark.parametrize(
    "test_input",
    [
        {**rpc_base, "result": "test result", "id": 123},
        {**rpc_base, "result": "test result", "id": "123"},
        {**rpc_base, "result": {"test": "result"}, "id": 123},
        {
            **rpc_base,
            "error": {"code": -123, "message": "Test error message"},
            "id": None,
        },
        {
            **rpc_base,
            "error": {"code": -123, "message": "Test error message"},
            "id": 123,
        },
        {
            **rpc_base,
            "error": {"code": "-123", "message": "Test error message"},
            "id": None,
        },
        {
            **rpc_base,
            "error": {"code": "-123", "message": "Test error message"},
            "id": "123",
        },
    ],
)
def test_valid_rpc_response(test_input):
    schema = RPCResponseModelSchema()
    result = schema.load(test_input)

    assert result.jsonrpc == "2.0"
    assert result.id == test_input["id"]
    if "result" in test_input:
        assert result.result is not None
        assert result.error is None
    if "error" in test_input:
        assert result.error is not None
        assert result.result is None


@pytest.mark.parametrize(
    "test_input",
    [{**rpc_base, "id": 123}, {**rpc_base, "id": "123"}, {**rpc_base, "id": None}],
)
def test_invalid_rpc_response_result_or_error_missing(test_input):
    schema = RPCResponseModelSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "_schema" in exc_info.value.messages
    assert (
        "RPC response must have either result or error."
        in exc_info.value.messages["_schema"]
    )


@pytest.mark.parametrize(
    "test_input",
    [
        {
            **rpc_base,
            "result": "test result",
            "error": {"code": -123, "message": "Test error message"},
            "id": 123,
        }
    ],
)
def test_invalid_rpc_response_result_and_error_present(test_input):
    schema = RPCResponseModelSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "_schema" in exc_info.value.messages
    assert (
        "RPC response cannot have both result and error."
        in exc_info.value.messages["_schema"]
    )


@pytest.mark.parametrize("test_input", [{**rpc_base, "result": "test result"}])
def test_invalid_rpc_response_result_id_missing(test_input):
    schema = RPCResponseModelSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "id" in exc_info.value.messages
    assert "Missing data for required field." in exc_info.value.messages["id"]


@pytest.mark.parametrize(
    "test_input", [{**rpc_base, "result": "test result", "id": None}]
)
def test_invalid_rpc_response_result_id_null(test_input):
    schema = RPCResponseModelSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "_schema" in exc_info.value.messages
    assert (
        "RPC response with result must have an ID." in exc_info.value.messages["_schema"]
    )


@pytest.mark.parametrize(
    "test_input",
    [
        {
            "state": "request-sent",
            "request": {**rpc_base, "method": "test.method", "id": 123},
        },
        {
            "state": "request-sent",
            "request": [
                {**rpc_base, "method": "test.method", "id": 123},
                {**rpc_base, "method": "test.method.2", "id": "123"},
            ],
        },
        {
            "state": "request-sent",
            "request": {**rpc_base, "method": "test.notification", "id": None},
        },
        {
            "state": "request-sent",
            "request": [
                {**rpc_base, "method": "test.method", "id": 123},
                {**rpc_base, "method": "test.notification", "id": None},
            ],
        },
    ],
)
def test_valid_drpc_request_record_request_sent(test_input):
    schema = DRPCRecordSchema()
    result = schema.load(test_input)

    if isinstance(test_input["request"], list):
        assert isinstance(result.request, list)
        requests = result.request
        for i in range(len(requests)):
            assert requests[i].jsonrpc == "2.0"
            assert requests[i].method == test_input["request"][i]["method"]
            assert requests[i].id == test_input["request"][i]["id"]
    else:
        assert result.request.jsonrpc == "2.0"
        assert result.request.method == test_input["request"]["method"]
        assert result.request.id == test_input["request"]["id"]


@pytest.mark.parametrize(
    "test_input",
    [
        {"request": {}},
        {"request": []},
        {"request": None},
    ],
)
def test_invalid_drpc_record_request_empty(test_input):
    schema = DRPCRecordSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "request" in exc_info.value.messages
    assert "RPC request cannot be empty." in exc_info.value.messages["request"]


@pytest.mark.parametrize(
    "test_input",
    [
        {
            "state": "completed",
            "request": {**rpc_base, "method": "test.method", "id": 123},
            "response": {**rpc_base, "result": "test result", "id": 123},
        },
        {
            "state": "completed",
            "request": [
                {**rpc_base, "method": "test.method", "id": 123},
                {**rpc_base, "method": "test.method.2", "id": "123"},
            ],
            "response": [
                {**rpc_base, "result": "test result", "id": 123},
                {**rpc_base, "result": "test result 2", "id": "123"},
            ],
        },
        {
            "state": "completed",
            "request": {**rpc_base, "method": "test.erroneous.method", "id": 123},
            "response": {
                **rpc_base,
                "error": {"code": -123, "message": "Test error message"},
                "id": 123,
            },
        },
        {
            "state": "completed",
            "request": [
                {**rpc_base, "method": "test.erroneous.method", "id": 123},
                {**rpc_base, "method": "test.erroneous.method.2", "id": None},
            ],
            "response": [
                {
                    **rpc_base,
                    "error": {"code": -123, "message": "Test error message"},
                    "id": 123,
                },
                {
                    **rpc_base,
                    "error": {"code": -123, "message": "Test error message 2"},
                    "id": None,
                },
            ],
        },
        {
            "state": "completed",
            "request": [
                {**rpc_base, "method": "test.method", "id": 123},
                {**rpc_base, "method": "test.erroneous.method.2", "id": None},
            ],
            "response": [
                {**rpc_base, "result": "test result", "id": 123},
                {
                    **rpc_base,
                    "error": {"code": -123, "message": "Test error message 2"},
                    "id": None,
                },
            ],
        },
        {
            "state": "completed",
            "request": {**rpc_base, "method": "test.notification", "id": None},
            "response": {},
        },
        {
            "state": "completed",
            "request": [
                {**rpc_base, "method": "test.notification", "id": None},
                {**rpc_base, "method": "test.notification.2", "id": None},
            ],
            "response": [],
        },
    ],
)
def test_valid_drpc_record_completed(test_input):
    schema = DRPCRecordSchema()
    result = schema.load(test_input)

    if isinstance(test_input["response"], list):
        assert isinstance(result.response, list)
        responses = result.response
        for i in range(len(responses)):
            assert responses[i].jsonrpc == "2.0"
            assert responses[i].id == test_input["response"][i]["id"]
            if "error" in test_input["response"][i]:
                # Check for error
                assert (
                    responses[i].error.code == test_input["response"][i]["error"]["code"]
                )
                assert (
                    responses[i].error.message
                    == test_input["response"][i]["error"]["message"]
                )
            else:
                # Check for result
                assert responses[i].result == test_input["response"][i]["result"]
    else:
        if "result" in test_input["response"] or "error" in test_input["response"]:
            assert result.response.jsonrpc == "2.0"
            assert result.response.id == test_input["response"]["id"]
        if "result" in test_input["response"]:
            # Check for result
            assert result.response.result == test_input["response"]["result"]
        if "error" in test_input["response"]:
            # Check for error
            assert result.response.error.code == test_input["response"]["error"]["code"]
            assert (
                result.response.error.message
                == test_input["response"]["error"]["message"]
            )


@pytest.mark.parametrize(
    "test_input",
    [
        {
            "state": "request-received",
            "request": {},
        },
        {
            "state": "request-received",
            "request": [],
        },
        {
            "state": "request-received",
            "request": None,
        },
        {
            "state": "completed",
            "request": {},
        },
        {
            "state": "completed",
            "request": [],
        },
        {
            "state": "completed",
            "request": None,
        },
    ],
)
def test_invalid_drpc_response_record_request_missing(test_input):
    schema = DRPCRecordSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "request" in exc_info.value.messages
    assert "RPC request cannot be empty." in exc_info.value.messages["request"]


@pytest.mark.parametrize(
    "test_input",
    [
        {
            "state": "completed",
            "request": {**rpc_base, "method": "test.method", "id": 123},
            "response": None,
        },
    ],
)
def test_invalid_drpc_response_record_completed_response_is_null(test_input):
    schema = DRPCRecordSchema()

    with pytest.raises(ValidationError) as exc_info:
        schema.load(test_input)

    assert "_schema" in exc_info.value.messages
    assert (
        "RPC response cannot be null if state is 'completed'."
        in exc_info.value.messages["_schema"]
    )


@pytest.mark.parametrize(
    "test_input",
    [
        {
            "jsonrpc": "2.0",
            "method": "test.method",
            "params": {"one": "1"},
            "id": "1",
        },
        [
            {
                "jsonrpc": "2.0",
                "method": "test.method",
                "params": {"one": "1"},
                "id": "1",
            },
            {
                "jsonrpc": "2.0",
                "method": "test.method.2",
                "params": {"two": "2"},
                "id": "2",
            },
        ],
    ],
)
def test_rpc_request_serializes(test_input):
    if isinstance(test_input, list):
        rpc_requests = [RPCRequestModelSchema().load(request) for request in test_input]
        assert [request.serialize() for request in rpc_requests] == test_input
    else:
        rpc_request = RPCRequestModelSchema().load(test_input)
        assert rpc_request.serialize() == test_input
