import pytest
from marshmallow import ValidationError

from rpc.v1_0.messages import DRPCResponseMessageSchema


def test_drpc_response_message_validation_error():
    with pytest.raises(ValidationError) as exc_info:
        schema = DRPCResponseMessageSchema()
        msg = schema.load(
            {
                "response": {
                    "jsonrpc": "2.0",
                    "id": "1",
                    "result": {"one": "1"},
                },
            }
        )

        schema.dump(msg)

    assert "Missing required field(s) in thread decorator" in exc_info.value.messages
