import pytest
from yarl import URL

from ..registrar import CheqdDIDRegistrar


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
