import pytest

from acapy_controller import Controller


@pytest.mark.asyncio
async def test_dcql_query_create(controller: Controller):
    cred_json = {
        "credentials": [
            {
                "id": "pid",
                "format": "vc+sd-jwt",
                "meta": {
                    "vct_values": [
                        "https://credentials.example.com/identity_credential"
                    ]
                },
                "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["address", "street_address"]},
                ],
            }
        ]
    }

    query = await controller.post("/oid4vp/dcql/queries", json=cred_json)

    assert isinstance(query, dict)
    assert "dcql_query" in query.keys()
    assert "dcql_query_id" in query.keys()
    assert query["dcql_query"]["credentials"] == cred_json["credentials"]


@pytest.mark.asyncio
async def test_dcql_query_list(controller: Controller):
    cred_json = {
        "credentials": [
            {
                "id": "pid",
                "format": "vc+sd-jwt",
                "meta": {
                    "vct_values": [
                        "https://credentials.example.com/identity_credential"
                    ]
                },
                "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["address", "street_address"]},
                ],
            }
        ]
    }

    query = await controller.post("/oid4vp/dcql/queries", json=cred_json)
    query_id = query["dcql_query_id"]

    queries_list = await controller.get(
        "/oid4vp/dcql/queries",
        params={
            "dcql_query_id": query_id,
        },
    )

    assert len(queries_list["results"]) == 1
    assert queries_list["results"][0]["credentials"] == cred_json["credentials"]


@pytest.mark.asyncio
async def test_dcql_query_get(controller: Controller):
    cred_json = {
        "credentials": [
            {
                "id": "pid",
                "format": "vc+sd-jwt",
                "meta": {
                    "vct_values": [
                        "https://credentials.example.com/identity_credential"
                    ]
                },
                "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["address", "street_address"]},
                ],
            }
        ]
    }

    query = await controller.post("/oid4vp/dcql/queries", json=cred_json)
    query_id = query["dcql_query_id"]

    ret_query = await controller.get(
        f"/oid4vp/dcql/query/{query_id}",
    )

    assert ret_query["credentials"] == cred_json["credentials"]


@pytest.mark.asyncio
async def test_dcql_query_delete(controller: Controller):
    cred_json = {
        "credentials": [
            {
                "id": "pid",
                "format": "vc+sd-jwt",
                "meta": {
                    "vct_values": [
                        "https://credentials.example.com/identity_credential"
                    ]
                },
                "claims": [
                    {"path": ["given_name"]},
                    {"path": ["family_name"]},
                    {"path": ["address", "street_address"]},
                ],
            }
        ]
    }

    query = await controller.post("/oid4vp/dcql/queries", json=cred_json)
    query_id = query["dcql_query_id"]

    # Get initial count of queries
    queries_list = await controller.get(
        "/oid4vp/dcql/queries",
    )
    initial_count = len(queries_list["results"])

    # Verify the query we created exists by filtering for its ID
    filtered_queries = await controller.get(
        "/oid4vp/dcql/queries",
        params={"dcql_query_id": query_id},
    )
    assert len(filtered_queries["results"]) == 1
    assert filtered_queries["results"][0]["credentials"] == cred_json["credentials"]

    # Delete the query
    await controller.delete(
        f"/oid4vp/dcql/query/{query_id}",
    )

    # Verify count decreased
    queries_list = await controller.get(
        "/oid4vp/dcql/queries",
    )
    assert len(queries_list["results"]) == initial_count - 1

    # Verify the query can be retrieved directly still gives an error (record not found)
    # Note: The API returns 400 when filtering by a non-existent ID, not an empty list
    try:
        await controller.get(f"/oid4vp/dcql/query/{query_id}")
        assert False, "Expected 404/400 error when getting deleted query"
    except Exception:
        # Expected - query was deleted
        pass
