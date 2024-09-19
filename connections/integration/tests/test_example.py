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
def established_connection(bob: Agent, alice: Agent):
    """Established connection filter."""
    invite = bob.create_invitation(auto_accept="true")["invitation"]
    resp = alice.receive_invite(invite, auto_accept="true")
    yield resp["connection_id"]


def test_send_message(bob, alice, established_connection):
    # make sure connection is active...
    time.sleep(1)

    alice.send_message(established_connection, "hello bob")
