import json
from os import getenv
from urllib.parse import quote, urlencode
from uuid import uuid4

from acapy_controller.controller import Controller
import pytest
import pytest_asyncio

from oid4vci_client.client import OpenID4VCIClient

ISSUER_ADMIN_ENDPOINT = getenv("ISSUER_ADMIN_ENDPOINT", "http://localhost:3001")


@pytest_asyncio.fixture
async def controller():
    """Connect to Issuer."""
    controller = Controller(ISSUER_ADMIN_ENDPOINT)
    async with controller:
        yield controller


@pytest.fixture
def test_client():
    client = OpenID4VCIClient()
    yield client


@pytest_asyncio.fixture
async def issuer_did(controller: Controller):
    result = await controller.post(
        "/did/jwk/create",
        json={
            "key_type": "p256",
        },
    )
    assert "did" in result
    did = result["did"]
    yield did


@pytest_asyncio.fixture
async def supported_cred_id(controller: Controller, issuer_did: str):
    """Create a supported credential."""
    supported = await controller.post(
        "/oid4vci/credential-supported/create",
        json={
            "cryptographic_binding_methods_supported": ["did"],
            "cryptographic_suites_supported": ["ES256"],
            "format": "jwt_vc_json",
            "id": "UniversityDegreeCredential",
            "format_data": {
                "types": ["VerifiableCredential", "UniversityDegreeCredential"],
            },
            "vc_additional_data": {
                "@context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1",
                ],
                "type": ["VerifiableCredential", "UniversityDegreeCredential"],
            },
        },
    )
    yield supported["supported_cred_id"]


@pytest_asyncio.fixture
async def offer(controller: Controller, issuer_did: str, supported_cred_id: str):
    """Create a credential offer."""
    exchange = await controller.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": supported_cred_id,
            "credential_subject": {"name": "alice"},
            "verification_method": issuer_did + "#0",
        },
    )
    offer = await controller.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    offer_uri = "openid-credential-offer://?" + urlencode(
        {"credential_offer": json.dumps(offer)}, quote_via=quote
    )
    yield offer_uri


@pytest_asyncio.fixture
async def sdjwt_supported_cred_id(controller: Controller, issuer_did: str):
    """Create an SD-JWT VC supported credential."""
    supported = await controller.post(
        "/oid4vci/credential-supported/create",
        json={
            "format": "vc+sd-jwt",
            "id": "IDCard",
            "cryptographic_binding_methods_supported": ["jwk"],
            "display": [
                {
                    "name": "ID Card",
                    "locale": "en-US",
                    "background_color": "#12107c",
                    "text_color": "#FFFFFF"
                }
            ],
            "format_data": {
                "vct": "ExampleIDCard",
                "claims": {
                    "given_name": {
                        "mandatory": True,
                        "value_type": "string",
                    },
                    "family_name": {
                        "mandatory": True,
                        "value_type": "string",
                    },
                    "age_equal_or_over": {
                        "12": {
                            "mandatory": True,
                            "value_type": "boolean",
                        },
                        "14": {
                            "mandatory": True,
                            "value_type": "boolean",
                        },
                        "16": {
                            "mandatory": True,
                            "value_type": "boolean",
                        },
                        "18": {
                            "mandatory": True,
                            "value_type": "boolean",
                        },
                        "21": {
                            "mandatory": True,
                            "value_type": "boolean",
                        },
                        "65": {
                            "mandatory": True,
                            "value_type": "boolean",
                        },
                    }
                }
            },
            "vc_additional_data": {
                "sd_list": [
                    "/given_name",
                    "/family_name",
                    "/age_equal_or_over/12",
                    "/age_equal_or_over/14",
                    "/age_equal_or_over/16",
                    "/age_equal_or_over/18",
                    "/age_equal_or_over/21",
                    "/age_equal_or_over/65"
                ]
            }
        },
    )
    yield supported["supported_cred_id"]


@pytest_asyncio.fixture
async def sdjwt_offer(controller: Controller, issuer_did: str, sdjwt_supported_cred_id: str):
    """Create a cred offer for an SD-JWT VC."""
    exchange = await controller.post(
        "/oid4vci/exchange/create",
        json={
            "supported_cred_id": sdjwt_supported_cred_id,
            "credential_subject": {
                "given_name": "Erika",
                "family_name": "Mustermann",
                "source_document_type": "id_card",
                "age_equal_or_over": {
                    "12": True,
                    "14": True,
                    "16": True,
                    "18": True,
                    "21": True,
                    "65": False
                }
            },
            "verification_method": issuer_did + "#0",
        },
    )
    offer = await controller.get(
        "/oid4vci/credential-offer",
        params={"exchange_id": exchange["exchange_id"]},
    )
    offer_uri = "openid-credential-offer://?" + urlencode(
        {"credential_offer": json.dumps(offer)}, quote_via=quote
    )
    yield offer_uri


@pytest_asyncio.fixture
async def presentation_definition_id(controller: Controller, issuer_did: str):
    """Create a supported credential."""
    record = await controller.post(
        "/oid4vp/presentation-definition",
        json={
            "pres_def": {
                "id": str(uuid4()),
                "purpose": "Present basic profile info",
                "format": {
                    "jwt_vc_json": {"alg": ["ES256"]},
                    "jwt_vp_json": {"alg": ["ES256"]},
                    "jwt_vc": {"alg": ["ES256"]},
                    "jwt_vp": {"alg": ["ES256"]},
                },
                "input_descriptors": [
                    {
                        "id": "4ce7aff1-0234-4f35-9d21-251668a60950",
                        "name": "Profile",
                        "purpose": "Present basic profile info",
                        "constraints": {
                            "fields": [
                                {
                                    "name": "name",
                                    "path": [
                                        "$.vc.credentialSubject.name",
                                        "$.credentialSubject.name",
                                    ],
                                    "filter": {"type": "string", "pattern": "^.{1,64}$"},
                                },
                            ]
                        },
                    }
                ],
            }
        },
    )
    yield record["pres_def_id"]


@pytest_asyncio.fixture
async def request_uri(
    controller: Controller, issuer_did: str, presentation_definition_id: str
):
    """Create a credential offer."""
    exchange = await controller.post(
        "/oid4vp/request",
        json={
            "pres_def_id": presentation_definition_id,
            "vp_formats": {
				"jwt_vc_json": { "alg": [ "ES256", "EdDSA" ] },
				"jwt_vp_json": { "alg": [ "ES256", "EdDSA" ] },
				"jwt_vc": { "alg": [ "ES256", "EdDSA" ] },
				"jwt_vp": { "alg": [ "ES256", "EdDSA" ] },
			},
        },
    )
    yield exchange["request_uri"]
