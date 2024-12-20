import pytest
from acapy_agent.cache.base import BaseCache
from acapy_agent.cache.in_memory import InMemoryCache
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.key_type import KeyTypes
from yarl import URL

from ...did_method import CHEQD
from ..registrar import CheqdDIDRegistrar


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
    return "http://localhost:3000/1.0/"


@pytest.fixture
def registrar(registrar_url):
    return CheqdDIDRegistrar(registrar_url=registrar_url)


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
def mock_response():
    return {"MOCK_KEY": "MOCK_VALUE"}


@pytest.fixture
def did():
    return "did:cheqd:testnet:123456"


@pytest.fixture
def did_doc():
    return {"MOCK_KEY": "MOCK_VALUE"}
