import pytest

from ..resolver import CheqdDIDResolver


@pytest.fixture
def resolver_url():
    return "http://localhost:8080/1.0/identifiers/"


@pytest.fixture
def did():
    return "did:cheqd:testnet:123"


@pytest.fixture
def resolve_url(resolver_url, did):
    return resolver_url + did


@pytest.fixture
def resolve_resource_url(resolver_url, did):
    return resolver_url + did


@pytest.fixture
def resolver(resolver_url):
    return CheqdDIDResolver(resolver_url=resolver_url)
