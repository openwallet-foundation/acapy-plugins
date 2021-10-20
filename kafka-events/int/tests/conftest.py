"""Common fixtures for testing."""

import asyncio
import hashlib
from os import getenv
from typing import Iterator, Optional

from aiokafka.consumer.consumer import AIOKafkaConsumer
from aiokafka.producer.producer import AIOKafkaProducer
import pytest

from acapy_client import Client
from acapy_client.api.connection import create_static, delete_connection, set_metadata
from acapy_client.models import (
    ConnectionMetadataSetRequest,
    ConnectionStaticRequest,
    ConnectionStaticResult,
)
from acapy_client.models.conn_record import ConnRecord
from echo_agent import EchoClient


@pytest.fixture(scope="session")
def event_loop():
    """Create a session scoped event loop.
    pytest.asyncio plugin provides a default function scoped event loop
    which cannot be used as a dependency to session scoped fixtures.
    """
    return asyncio.get_event_loop()


@pytest.fixture(scope="session")
def host():
    """Hostname of agent under test."""
    return getenv("AGENT_HOST", "localhost")


@pytest.fixture(scope="session")
def port():
    """Port of agent under test."""
    return getenv("AGENT_PORT", 3000)


@pytest.fixture(scope="session")
def backchannel_port():
    """Port of agent under test backchannel."""
    return getenv("AGENT_BACKCHANNEL_PORT", 3001)


@pytest.fixture(scope="session")
def echo_endpoint():
    return getenv("ECHO_ENDPOINT", "http://localhost:4000")


@pytest.fixture(scope="session")
def backchannel(host, backchannel_port):
    """Yield backchannel client."""
    yield Client(base_url="http://{}:{}".format(host, backchannel_port))


@pytest.fixture(scope="session")
def suite_seed():
    yield hashlib.sha256(b"acapy-plugin-toolbox-int-test-runner").hexdigest()[:32]


@pytest.fixture(scope="session")
def agent_seed():
    yield hashlib.sha256(b"acapy-plugin-toolbox-int-test-runner").hexdigest()[:32]


@pytest.fixture(scope="session")
def agent_endpoint(host, port):
    yield "http://{}:{}".format(host, port)


@pytest.fixture(scope="session")
def agent_connection(
    suite_seed, agent_seed, backchannel, echo_endpoint
) -> Iterator[ConnectionStaticResult]:
    """Yield agent's representation of this connection."""

    # Create connection in agent under test
    create_result: Optional[ConnectionStaticResult] = create_static.sync(
        client=backchannel,
        json_body=ConnectionStaticRequest.from_dict(
            {
                "my_seed": agent_seed,
                "their_seed": suite_seed,
                "their_endpoint": echo_endpoint,
                "their_label": "test-runner",
            }
        ),
    )
    if not create_result:
        raise RuntimeError("Could not create static connection with agent under test")

    # Set admin metadata to enable access to admin protocols
    set_result = set_metadata.sync(
        client=backchannel,
        conn_id=create_result.record.connection_id,
        json_body=ConnectionMetadataSetRequest.from_dict(
            {"metadata": {"group": "admin"}}
        ),
    )
    if not set_result:
        raise RuntimeError("Could not set metadata on static connection")

    yield create_result

    delete_connection.sync(
        client=backchannel, conn_id=create_result.record.connection_id
    )


@pytest.fixture(scope="session")
def conn_record(agent_connection: ConnectionStaticResult):
    yield agent_connection.record


@pytest.fixture(scope="session")
def connection_id(conn_record: ConnRecord):
    yield conn_record.connection_id


@pytest.fixture(scope="session")
def echo_agent(echo_endpoint: str):
    yield EchoClient(base_url=echo_endpoint)


@pytest.fixture
async def echo(echo_agent: EchoClient):
    async with echo_agent as client:
        yield client


@pytest.fixture(scope="session")
async def connection(
    agent_connection: ConnectionStaticResult, echo_agent: EchoClient, suite_seed: str
):
    """Yield static connection to agent under test."""
    # Create and yield static connection
    async with echo_agent as echo:
        conn = await echo.new_connection(
            seed=suite_seed,
            endpoint=agent_connection.my_endpoint,
            their_vk=agent_connection.my_verkey,
        )
    yield conn


@pytest.fixture
def consumer():
    def _consumer(topic: str):
        return AIOKafkaConsumer(topic, bootstrap_servers="kafka", group_id="test")

    yield _consumer


@pytest.fixture
async def producer():
    producer = AIOKafkaProducer(bootstrap_servers="kafka")

    async with producer:
        yield producer
