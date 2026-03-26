"""Tests for supported credential admin routes."""

import copy

from unittest.mock import AsyncMock, MagicMock

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from aiohttp import web

from oid4vc.models.supported_cred import SupportedCredential
from oid4vc.routes.supported_credential import (
    get_supported_credential_by_id,
    supported_credential_create,
    supported_credential_create_jwt,
    supported_credential_list,
    supported_credential_remove,
    update_supported_credential_jwt_vc,
)


def _make_request(context, *, json_data=None, match_info=None, query=None):
    """Build a mock aiohttp request with the given context and data.

    Returns a deep copy of json_data on each call to request.json() so that
    in-place mutations (e.g. body.pop) don't leak between calls.
    """
    items = {"context": context}
    mock = MagicMock()
    mock.__getitem__ = lambda _, k: items[k]
    mock.match_info = match_info or {}
    mock.query = query or {}
    source = json_data or {}
    mock.json = AsyncMock(side_effect=lambda: copy.deepcopy(source))
    mock.headers = {"x-api-key": "admin_api_key"}
    return mock


# -- Generic create ----------------------------------------------------------


@pytest.mark.asyncio
async def test_supported_credential_create(context: AdminRequestContext):
    """Test the generic supported_credential_create handler."""
    body = {
        "format": "jwt_vc_json",
        "id": "GenericCred",
        "format_data": {
            "credentialSubject": {"name": "alice"},
            "type": ["VerifiableCredential", "GenericCred"],
        },
        "cryptographic_binding_methods_supported": ["did"],
        "credential_signing_alg_values_supported": ["ES256"],
        "display": [{"name": "Generic Credential", "locale": "en-US"}],
    }
    request = _make_request(context, json_data=body)

    response = await supported_credential_create(request)
    assert response.status == 200

    async with context.session() as session:
        records = await SupportedCredential.query(session, {"identifier": "GenericCred"})

    assert len(records) == 1
    record = records[0]
    assert record.format == "jwt_vc_json"
    assert record.identifier == "GenericCred"
    assert record.credential_signing_alg_values_supported == ["ES256"]


@pytest.mark.asyncio
async def test_supported_credential_create_duplicate(context: AdminRequestContext):
    """Creating a credential with an existing identifier should 400."""
    body = {
        "format": "jwt_vc_json",
        "id": "DupCred",
        "credential_signing_alg_values_supported": ["ES256"],
    }
    request = _make_request(context, json_data=body)
    await supported_credential_create(request)

    request2 = _make_request(context, json_data=body)
    with pytest.raises(web.HTTPBadRequest, match="already exists"):
        await supported_credential_create(request2)


# -- JWT create ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_supported_credential_create_jwt(context: AdminRequestContext):
    """Test the JWT-specific create handler with credential_definition."""
    body = {
        "format": "jwt_vc_json",
        "id": "JwtCred",
        "cryptographic_binding_methods_supported": ["did"],
        "credential_signing_alg_values_supported": ["ES256"],
        "credential_definition": {
            "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
        },
        "credential_metadata": {
            "display": [{"name": "University Credential", "locale": "en-US"}],
            "claims": [
                {
                    "path": ["given_name"],
                    "display": [{"name": "Given Name", "locale": "en-US"}],
                },
            ],
        },
    }
    request = _make_request(context, json_data=body)

    response = await supported_credential_create_jwt(request)
    assert response.status == 200

    async with context.session() as session:
        records = await SupportedCredential.query(session, {"identifier": "JwtCred"})

    assert len(records) == 1
    record = records[0]
    assert record.format == "jwt_vc_json"
    assert record.identifier == "JwtCred"
    assert record.format_data["types"] == [
        "VerifiableCredential",
        "UniversityDegreeCredential",
    ]
    assert record.format_data["context"] == [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1",
    ]
    assert record.vc_additional_data["type"] == [
        "VerifiableCredential",
        "UniversityDegreeCredential",
    ]
    assert record.credential_metadata["claims"][0]["path"] == ["given_name"]


@pytest.mark.asyncio
async def test_supported_credential_create_jwt_ignores_unknown_fields(
    context: AdminRequestContext,
):
    """JWT create should ignore unknown fields (schema uses exclude, matching upstream)."""
    body = {
        "format": "jwt_vc_json",
        "id": "BadCred",
        "credential_signing_alg_values_supported": ["ES256"],
        "totally_bogus_field": "should be ignored",
    }
    request = _make_request(context, json_data=body)

    # Should succeed — unknown fields are excluded, not rejected
    response = await supported_credential_create_jwt(request)
    assert response.status == 200


# -- List ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_supported_credential_list(context: AdminRequestContext):
    """Test listing supported credentials."""
    # Create two records
    for cred_id in ("ListCred1", "ListCred2"):
        body = {
            "format": "jwt_vc_json",
            "id": cred_id,
            "credential_signing_alg_values_supported": ["ES256"],
        }
        req = _make_request(context, json_data=body)
        await supported_credential_create(req)

    request = _make_request(context, query={})
    response = await supported_credential_list(request)
    assert response.status == 200

    import json

    data = json.loads(response.body)
    assert len(data["results"]) >= 2


# -- Get by ID ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_supported_credential_by_id(context: AdminRequestContext):
    """Test retrieving a supported credential by ID."""
    body = {
        "format": "jwt_vc_json",
        "id": "GetByIdCred",
        "credential_signing_alg_values_supported": ["ES256"],
    }
    req = _make_request(context, json_data=body)
    create_resp = await supported_credential_create(req)

    import json

    created = json.loads(create_resp.body)
    record_id = created["supported_cred_id"]

    request = _make_request(context, match_info={"supported_cred_id": record_id})
    response = await get_supported_credential_by_id(request)
    assert response.status == 200

    data = json.loads(response.body)
    assert data["identifier"] == "GetByIdCred"


@pytest.mark.asyncio
async def test_get_supported_credential_not_found(context: AdminRequestContext):
    """Getting a non-existent credential should 404."""
    request = _make_request(context, match_info={"supported_cred_id": "nonexistent-id"})
    with pytest.raises(web.HTTPNotFound):
        await get_supported_credential_by_id(request)


# -- JWT update ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_supported_credential_jwt_vc(context: AdminRequestContext):
    """Test updating a JWT supported credential."""
    # Create first
    create_body = {
        "format": "jwt_vc_json",
        "id": "UpdateCred",
        "credential_signing_alg_values_supported": ["ES256"],
        "credential_definition": {
            "type": ["VerifiableCredential", "OldType"],
            "@context": ["https://www.w3.org/2018/credentials/v1"],
        },
    }
    req = _make_request(context, json_data=create_body)
    create_resp = await supported_credential_create_jwt(req)

    import json

    created = json.loads(create_resp.body)
    record_id = created["supported_cred_id"]

    # Update with new type
    update_body = {
        "format": "jwt_vc_json",
        "id": "UpdateCred",
        "credential_signing_alg_values_supported": ["ES256K"],
        "credential_definition": {
            "type": ["VerifiableCredential", "NewType"],
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://www.w3.org/2018/credentials/examples/v1",
            ],
        },
        "credential_metadata": {
            "display": [{"name": "Updated Credential", "locale": "en-US"}],
        },
    }
    request = _make_request(
        context,
        json_data=update_body,
        match_info={"supported_cred_id": record_id},
    )
    response = await update_supported_credential_jwt_vc(request)
    assert response.status == 200

    data = json.loads(response.body)
    assert data["credential_signing_alg_values_supported"] == ["ES256K"]
    assert data["format_data"]["types"] == ["VerifiableCredential", "NewType"]


# -- Delete -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_supported_credential_remove(context: AdminRequestContext):
    """Test removing a supported credential."""
    body = {
        "format": "jwt_vc_json",
        "id": "DeleteCred",
        "credential_signing_alg_values_supported": ["ES256"],
    }
    req = _make_request(context, json_data=body)
    create_resp = await supported_credential_create(req)

    import json

    created = json.loads(create_resp.body)
    record_id = created["supported_cred_id"]

    request = _make_request(context, match_info={"supported_cred_id": record_id})
    response = await supported_credential_remove(request)
    assert response.status == 200

    # Verify it's gone
    get_req = _make_request(context, match_info={"supported_cred_id": record_id})
    with pytest.raises(web.HTTPNotFound):
        await get_supported_credential_by_id(get_req)
