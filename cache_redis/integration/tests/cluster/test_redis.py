"""Status Request and response tests"""

import httpx
import logging
import pytest
import json


LOGGER = logging.getLogger(__name__)


@pytest.mark.asyncio
async def test_send_cred_def(
    connection, backchannel_endpoint: str, redis_cluster_client, echo_endpoint
):
    """Create a credential definition"""

    # Attempt to create a schema (No ledger, won't work)
    # schema = await create_schema(version="1.0")

    # Get the list of connections
    r = httpx.get(f"{backchannel_endpoint}/connections")
    assert r.status_code == 200

    # Get our echo agent connection info
    response = r.json()["results"][0]
    connection_id = response["connection_id"]

    # Get our echo agent info from the cache using info from ACA-Py
    raw_connection_info = await redis_cluster_client.get(
        f"ACA-Py:connection_target::{connection_id}"
    )

    # Ensure that we were able to retrieve the info from redis and parse it
    assert raw_connection_info
    connection_info = json.loads(raw_connection_info)

    # Validate that the info matches
    assert connection_info[0]["endpoint"] == echo_endpoint
    assert connection_info[0]["did"] == f"did:sov:{response['their_did']}"
    assert connection_info[0]["label"] == response["their_label"]
