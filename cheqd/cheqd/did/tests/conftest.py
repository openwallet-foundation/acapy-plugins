import pytest
from acapy_agent.cache.base import BaseCache
from acapy_agent.cache.in_memory import InMemoryCache
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.key_type import KeyTypes
from yarl import URL

from ...did_method import CHEQD
from ...did.base import (
    DidCreateRequestOptions,
    DidDeactivateRequestOptions,
    DidUpdateRequestOptions,
    ResourceCreateRequestOptions,
    ResourceUpdateRequestOptions,
)
from ..registrar import DIDRegistrar


@pytest.fixture
async def profile():
    did_methods = DIDMethods()
    did_methods.register(CHEQD)
    profile = await create_test_profile(
        settings={"wallet.type": "askar-anoncreds"},
    )
    profile.context.injector.bind_instance(DIDMethods, did_methods)
    profile.context.injector.bind_instance(KeyTypes, KeyTypes())
    profile.context.injector.bind_instance(BaseCache, InMemoryCache())
    return profile


@pytest.fixture
def registrar_url():
    return "http://localhost:9080/1.0/"


@pytest.fixture
def registrar(registrar_url):
    return DIDRegistrar(method="cheqd", registrar_url=registrar_url)


@pytest.fixture
def mock_did_document_url(registrar_url):
    return URL(registrar_url + "did-document").with_query(
        {
            "methodSpecificIdAlgo": "uuid",
            "network": "testnet",
            "publicKeyHex": "abc123",
            "verificationMethod": "Ed25519VerificationKey2020",
        }
    )


@pytest.fixture
def mock_options():
    return {"MOCK_KEY": "MOCK_VALUE"}


@pytest.fixture
def mock_did_create_options():
    return DidCreateRequestOptions()


@pytest.fixture
def mock_did_update_options():
    return DidUpdateRequestOptions(did="MOCK_VALUE", didDocument=[])


@pytest.fixture
def mock_did_deactivate_options():
    return DidDeactivateRequestOptions(did="MOCK_VALUE")


@pytest.fixture
def mock_resource_create_options():
    return ResourceCreateRequestOptions(
        did="MOCK_VALUE", content="MOCK_VALUE", name="MOCK_VALUE", type="MOCK_VALUE"
    )


@pytest.fixture
def mock_resource_update_options():
    return ResourceUpdateRequestOptions(
        did="MOCK_VALUE", content=["MOCK_VALUE"], name="MOCK_VALUE", type="MOCK_VALUE"
    )


@pytest.fixture
def mock_did_response():
    return {
        "jobId": "6d85bcd0-2ea3-4288-ab00-15afadd8a156",
        "didState": {
            "state": "finished",
            "did": "string",
            "didDocument": {
                "id": "did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09",
                "controller": ["did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09"],
                "verificationMethod": [
                    {
                        "id": "did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09#key-1",
                        "type": "Ed25519VerificationKey2020",
                        "controller": "did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09",
                        "publicKeyMultibase": "z6Mkt9Vg1a1Jbg5a1NkToUeWH23Z33TwGUua5MrqAYUz2AL3",
                    }
                ],
                "authentication": [
                    "did:cheqd:testnet:ca9ff47c-0286-4614-a4be-8ffa83911e09#key-1"
                ],
            },
        },
        "didRegistrationMetadata": {},
        "didDocumentMetadata": {},
    }


@pytest.fixture
def mock_did_invalid_response():
    return {
        # missing jobId, didDocument etc.
        "didState": {"state": "finished", "did": "string"},
        "didRegistrationMetadata": {},
        "didDocumentMetadata": {},
    }


@pytest.fixture
def mock_resource_response():
    return {
        "jobId": "6d85bcd0-2ea3-4288-ab00-15afadd8a156",
        "didUrlState": {
            "didUrl": "string",
            "state": "finished",
            "name": "name",
            "type": "type",
            "version": "version",
            "secret": {"seed": "72WGp7NgFR1Oqdi8zlt7jQQ434XR0cNQ"},
            "content": "string",
        },
        "didRegistrationMetadata": {},
        "contentMetadata": {},
    }


@pytest.fixture
def mock_response():
    return {"MOCK_KEY": "MOCK_VALUE"}


@pytest.fixture
def did():
    return "did:cheqd:testnet:123456"


@pytest.fixture
def did_doc():
    return {"MOCK_KEY": "MOCK_VALUE"}
