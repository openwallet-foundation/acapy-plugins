"""JSON-RPC Defined Error Codes."""

_SERVER_ERROR_RANGE = range(-32099, -32000)

RPCError = {
    -32700: {
        "message": "Parse error",
        "description": (
            "Invalid JSON was received by the server. "
            "An error occurred on the server while parsing the JSON text."
        ),
    },
    -32600: {
        "message": "Invalid Request",
        "description": "The JSON sent is not a valid Request object.",
    },
    -32601: {
        "message": "Method not found",
        "description": "The method does not exist / is not available.",
    },
    -32602: {
        "message": "Invalid params",
        "description": "Invalid method parameter(s).",
    },
    -32603: {"message": "Internal error", "description": "Internal JSON-RPC error."},
    **dict(
        zip(
            _SERVER_ERROR_RANGE,
            [
                {
                    "message": "Server error",
                    "description": "Reserved for implementation-defined server-errors.",
                }
                for _ in _SERVER_ERROR_RANGE
            ],
        )
    ),
}
