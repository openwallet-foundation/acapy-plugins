"""Common fixtures for testing."""

from redis import asyncio as aioredis
import asyncio
import hashlib
import logging
import os
import pytest

from acapy_client import Client
from acapy_client.api.connection import create_static, delete_connection, set_metadata
from acapy_client.models import (
    ConnectionMetadataSetRequest,
    ConnectionStaticRequest,
    ConnectionStaticResult,
)
from acapy_client.models.conn_record import ConnRecord
from acapy_client.api.schema import publish_schema
from acapy_client.models.schema_send_request import SchemaSendRequest
from echo_agent.client import EchoClient
from typing import Iterator, Optional


LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def event_loop():
    """Create a session scoped event loop.
    pytest.asyncio plugin provides a default function scoped event loop
    which cannot be used as a dependency to session scoped fixtures.
    """
    return asyncio.get_event_loop()


@pytest.fixture(scope="session")
def echo_seed():
    yield hashlib.sha256(b"acapy-pickup-int-test-runner").hexdigest()[:32]


@pytest.fixture(scope="session")
def agent_seed():
    yield hashlib.sha256(b"acapy-pickup-agent").hexdigest()[:32]


@pytest.fixture(scope="session")
def backchannel_endpoint():
    yield os.environ.get("ADMIN_ENDPOINT")


@pytest.fixture(scope="session")
def echo_endpoint():
    yield os.environ.get("ECHO_ENDPOINT")


@pytest.fixture(scope="session")
def backchannel(backchannel_endpoint):
    """Yield backchannel client."""
    yield Client(base_url=backchannel_endpoint)


@pytest.fixture(scope="session")
async def redis_client():
    """Yield aioredis client."""
    redis = aioredis.from_url("redis://redis-host:6379/0")
    yield redis
    await redis.close()


@pytest.fixture(scope="session")
def agent_connection(
    echo_seed, agent_seed, echo_endpoint, backchannel
) -> Iterator[ConnectionStaticResult]:
    """Yield agent's representation of this connection."""

    # Create connection in agent under test
    create_result: Optional[ConnectionStaticResult] = create_static.sync(
        client=backchannel,
        json_body=ConnectionStaticRequest.from_dict(
            {
                "my_seed": agent_seed,
                "their_seed": echo_seed,
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
def echo_agent(echo_endpoint: str):
    yield EchoClient(base_url=echo_endpoint)


@pytest.fixture
async def echo(echo_agent: EchoClient):
    async with echo_agent as client:
        yield client


@pytest.fixture(scope="session")
def conn_record(agent_connection: ConnectionStaticResult):
    yield agent_connection.record


@pytest.fixture(scope="session")
def connection_id(conn_record: ConnRecord):
    yield conn_record.connection_id


@pytest.fixture(scope="session", autouse=True)
async def connection(
    agent_connection: ConnectionStaticResult, echo_agent: EchoClient, echo_seed: str
):
    """Yield static connection to agent under test."""
    # Create and yield static connection
    async with echo_agent as echo:
        conn = await echo.new_connection(
            seed=echo_seed,
            endpoint=agent_connection.my_endpoint,
            their_vk=agent_connection.my_verkey,
        )
    yield conn


@pytest.fixture(scope="module")
async def create_schema(backchannel: Client):
    """Schema factory fixture."""

    async def _create_schema(version):
        return await publish_schema.asyncio(
            client=backchannel.with_timeout(60),
            json_body=SchemaSendRequest(
                attributes=["attr_1_0", "attr_1_1", "attr_1_2"],
                schema_name="Test Schema",
                schema_version=version,
            ),
        )

    yield _create_schema


# @pytest.fixture(autouse=True)
# async def clear_questions(backchannel_endpoint: str):
#     yield
#     r = httpx.get(f"{backchannel_endpoint}/qa/get-questions")
#     assert r.status_code == 200
#     results = r.json()["results"]

#     for thread_id in [result["thread_id"] for result in results]:
#         r = httpx.delete(f"{backchannel_endpoint}/qa/{thread_id}")
#         assert r.status_code == 200
