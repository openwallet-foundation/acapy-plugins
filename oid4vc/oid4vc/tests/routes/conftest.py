from unittest.mock import MagicMock

import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.core.profile import Profile
from acapy_agent.resolver.did_resolver import DIDResolver

from jwt_vc_json import JwtVcJsonCredProcessor
from oid4vc.cred_processor import CredProcessors
from oid4vc.jwk_resolver import JwkResolver


@pytest.fixture
def resolver():
    """Test DIDResolver."""
    yield DIDResolver([JwkResolver()])


@pytest.fixture
async def profile(resolver: DIDResolver):
    """Test Profile."""
    processors = CredProcessors(
        {"jwt_vc_json": JwtVcJsonCredProcessor()},
        {"jwt_vc_json": JwtVcJsonCredProcessor()},
        {"jwt_vc_json": JwtVcJsonCredProcessor()},
    )
    profile = await create_test_profile(
        {
            "admin.admin_insecure_mode": True,
            "plugin_config": {
                "oid4vci": {
                    "endpoint": "http://localhost:8020",
                    "host": "0.0.0.0",
                    "port": 8020,
                }
            },
        }
    )

    profile.context.injector.bind_instance(DIDResolver, resolver)
    profile.context.injector.bind_instance(CredProcessors, processors)

    yield profile


@pytest.fixture
def context(profile: Profile):
    """Test AdminRequestContext."""
    yield AdminRequestContext(profile)


@pytest.fixture
def req(context: AdminRequestContext):
    """Test web.Request."""
    items = {"context": context}
    mock = MagicMock()
    mock.__getitem__ = lambda _, k: items[k]
    yield mock
