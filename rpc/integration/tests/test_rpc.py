import time

import pytest

from . import ALICE, BOB, Agent

rpc_request = {"jsonrpc": "2.0", "method": "add", "params": [1, 2], "id": 1}
rpc_response = {"jsonrpc": "2.0", "result": 3, "id": 1}
rpc_error = {
    "jsonrpc": "2.0",
    "error": {"code": -32601, "message": "Method not found"},
    "id": 1,
}


@pytest.fixture(scope="session")
def bob():
    """bob agent fixture."""
    yield Agent(BOB)


@pytest.fixture(scope="session")
def alice():
    """resolver agent fixture."""
    yield Agent(ALICE)


@pytest.fixture(scope="session", autouse=True)
def established_connection(bob, alice):
    """Established connection filter."""
    invite = bob.create_invitation(
        {
            "handshake_protocols": ["https://didcomm.org/didexchange/1.1"],
        },
        auto_accept="true",
    )["invitation"]
    resp = alice.receive_invite(invite, auto_accept="true")
    yield resp["connection_id"]


def test_drpc_request(bob, alice, established_connection):
    # make sure connection is active...
    time.sleep(1)

    alice_drpc_request = alice.send_drpc_request(
        connection_id=established_connection,
        request=rpc_request,
    )
    assert True

    # make sure messages are exchanged...
    time.sleep(1)

    bob_drpc_request_records = bob.get_drpc_records(thread_id=alice_drpc_request["@id"])
    bob_drpc_request_record = bob_drpc_request_records["results"][0]
    tags = bob_drpc_request_record["tags"]
    assert len(bob_drpc_request_records["results"]) == 1
    assert bob_drpc_request_record["state"] == "request-received"
    assert tags["thread_id"] == alice_drpc_request["@id"]
    assert "request" in bob_drpc_request_record
    assert bob_drpc_request_record["request"] == rpc_request


def test_drpc_response(bob, alice, established_connection):
    # make sure connection is active...
    time.sleep(1)

    alice_drpc_request = alice.send_drpc_request(
        connection_id=established_connection,
        request=rpc_request,
    )
    assert True

    # make sure messages are exchanged...
    time.sleep(1)

    bob_connections = bob.get_connections(state="active")
    bob_connection = bob_connections["results"][0]
    bob_connection_id = bob_connection["connection_id"]
    bob_drpc_response = bob.send_drpc_response(
        connection_id=bob_connection_id,
        thread_id=alice_drpc_request["@id"],
        response=rpc_response,
    )
    assert True

    # make sure messages are exchanged...
    time.sleep(1)

    alice_drpc_response_records = alice.get_drpc_records(
        connection_id=established_connection, thread_id=alice_drpc_request["@id"]
    )
    alice_drpc_response_record = alice_drpc_response_records["results"][0]
    alice_tags = alice_drpc_response_record["tags"]
    alice_thread_id = alice_tags["thread_id"]

    bob_drpc_request_records = bob.get_drpc_records(
        connection_id=bob_connection_id, thread_id=alice_drpc_request["@id"]
    )
    bob_drpc_request_record = bob_drpc_request_records["results"][0]
    bob_tags = bob_drpc_request_record["tags"]
    bob_thread_id = bob_tags["thread_id"]

    assert len(alice_drpc_response_records["results"]) == 1
    assert alice_thread_id == bob_drpc_response["~thread"]["thid"]
    assert alice_drpc_response_record["state"] == "completed"
    assert "request" in alice_drpc_response_record
    assert "response" in alice_drpc_response_record
    assert alice_drpc_response_record["request"] == rpc_request
    assert alice_drpc_response_record["response"] == rpc_response

    assert len(bob_drpc_request_records["results"]) == 1
    assert bob_thread_id == alice_drpc_request["@id"]
    assert bob_drpc_request_record["state"] == "completed"
    assert "request" in bob_drpc_request_record
    assert "response" in bob_drpc_request_record
    assert bob_drpc_request_record["request"] == rpc_request
    assert bob_drpc_request_record["response"] == rpc_response


def test_drpc_response_error(bob, alice, established_connection):
    # make sure connection is active...
    time.sleep(1)

    alice_drpc_request = alice.send_drpc_request(
        connection_id=established_connection,
        request=rpc_request,
    )
    assert True

    # make sure messages are exchanged...
    time.sleep(1)

    bob_connections = bob.get_connections(state="active")
    bob_connection = bob_connections["results"][0]
    bob_connection_id = bob_connection["connection_id"]
    bob_drpc_response = bob.send_drpc_response(
        connection_id=bob_connection_id,
        thread_id=alice_drpc_request["@id"],
        response=rpc_error,
    )
    assert True

    # make sure messages are exchanged...
    time.sleep(1)

    alice_drpc_response_records = alice.get_drpc_records(
        connection_id=established_connection, thread_id=alice_drpc_request["@id"]
    )
    alice_drpc_response_record = alice_drpc_response_records["results"][0]
    alice_tags = alice_drpc_response_record["tags"]
    alice_thread_id = alice_tags["thread_id"]

    bob_drpc_request_records = bob.get_drpc_records(
        connection_id=bob_connection_id, thread_id=alice_drpc_request["@id"]
    )
    bob_drpc_request_record = bob_drpc_request_records["results"][0]
    bob_tags = bob_drpc_request_record["tags"]
    bob_thread_id = bob_tags["thread_id"]

    assert len(alice_drpc_response_records["results"]) == 1
    assert alice_thread_id == bob_drpc_response["~thread"]["thid"]
    assert alice_drpc_response_record["state"] == "completed"
    assert "request" in alice_drpc_response_record
    assert "response" in alice_drpc_response_record
    assert alice_drpc_response_record["request"] == rpc_request
    assert alice_drpc_response_record["response"] == rpc_error

    assert len(bob_drpc_request_records["results"]) == 1
    assert bob_thread_id == alice_drpc_request["@id"]
    assert bob_drpc_request_record["state"] == "completed"
    assert "request" in bob_drpc_request_record
    assert "response" in bob_drpc_request_record
    assert bob_drpc_request_record["request"] == rpc_request
    assert bob_drpc_request_record["response"] == rpc_error
