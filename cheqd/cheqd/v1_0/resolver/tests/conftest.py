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


@pytest.fixture(
    params=[
        ("did:cheqd:testnet:123/resources/456", "/metadata"),
        (
            "did:cheqd:testnet:123?resourceName=test&resourceType=anoncredsRevRegEntry",
            "&resourceMetadata=true",
        ),
    ]
)
def resolve_resource_params(resolver_url, request):
    did_resource, metadata_suffix = request.param

    return (
        did_resource,
        resolver_url + did_resource,
        resolver_url + did_resource + metadata_suffix,
    )


@pytest.fixture
def resolver(resolver_url):
    return CheqdDIDResolver(resolver_url=resolver_url)
