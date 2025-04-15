import pytest

from acapy_controller.controller import Controller


@pytest.mark.asyncio
async def test_dcql_query_create(controller: Controller):
    cred_json = {
        "credentials": [
            {
                "id": "pid",
                "format": "vc+sd-jwt",
                "meta": {
                    "vct_values": ["https://credentials.example.com/identity_credential"]
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
                    "vct_values": ["https://credentials.example.com/identity_credential"]
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
                    "vct_values": ["https://credentials.example.com/identity_credential"]
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
                    "vct_values": ["https://credentials.example.com/identity_credential"]
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
    )

    length = len(queries_list["results"])
    assert queries_list["results"][0]["credentials"] == cred_json["credentials"]

    queries_list = await controller.delete(
        f"/oid4vp/dcql/query/{query_id}",
    )

    queries_list = await controller.get(
        "/oid4vp/dcql/queries",
    )

    assert len(queries_list["results"]) == length - 1
