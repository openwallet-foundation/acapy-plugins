from acapy_agent.resolver.base import ResolutionMetadata, ResolutionResult, ResolverType
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.tests import mock


SCID_PLACEHOLDER = "{SCID}"
TEST_DOMAIN = "sandbox.bcvh.vonx.io"
TEST_SERVER_URL = f"https://{TEST_DOMAIN}"
TEST_WITNESS_SEED = "00000000000000000000000000000000"
TEST_WITNESS_KEY = "z6MkgKA7yrw5kYSiDuQFcye4bMaJpcfHFry3Bx45pdWh3s8i"
TEST_NAMESPACE = "test"
TEST_RESOLVER = mock.MagicMock(DIDResolver, autospec=True)
TEST_RESOLVER.resolve_with_metadata = mock.AsyncMock(
    return_value=ResolutionResult(
        did_document={},
        metadata=ResolutionMetadata(
            resolver_type=ResolverType.NATIVE,
            resolver="resolver",
            retrieved_time="retrieved_time",
            duration=0,
        ),
    )
)
