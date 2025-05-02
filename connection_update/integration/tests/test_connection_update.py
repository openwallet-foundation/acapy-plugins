"""Integration tests for Basic Message Storage."""

# pylint: disable=redefined-outer-name

import time

import pytest

from . import ALICE, BOB, Agent


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


def test_send_message(bob, alice, established_connection):
    # make sure connection is active...
    time.sleep(2)

    test_alias = "test-alias"
    update_response = alice.connections_update(established_connection, alias=test_alias)
    get_response = alice.get_connection(established_connection)

    assert update_response["alias"] == test_alias
    assert get_response["alias"] == test_alias
