from rpc.v1_0.errors import RPCError


def test_server_error_code():
    CODE = -32050

    assert CODE in RPCError
    assert "message" in RPCError[CODE]
    assert RPCError[CODE]["message"] == "Server error"
