import pytest
from acapy_agent.admin.request_context import AdminRequestContext
from acapy_agent.config.settings import Settings
from acapy_agent.core.profile import Profile
from acapy_agent.resolver.did_resolver import DIDResolver
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.default_verification_key_strategy import (
    BaseVerificationKeyStrategy,
    DefaultVerificationKeyStrategy,
)

from jwt_vc_json import JwtVcJsonCredProcessor
from oid4vc.config import Config
from oid4vc.cred_processor import CredProcessors
from oid4vc.jwk_resolver import JwkResolver
from sd_jwt_vc.cred_processor import SdJwtCredIssueProcessor


@pytest.fixture
def settings():
    return {
        "admin.admin_insecure_mode": True,
        "wallet.id": "538451fa-11ab-41de-b6e3-7ae3df7356d6",
        "plugin_config": {
            "oid4vci": {
                "host": "localhost",
                "port": 8020,
                "endpoint": "http://localhost:8020",
                "auth_server_url": "http://localhost:9001",
                "auth_server_client": '{"auth_type": "client_secret_basic","client_id": "client_id","client_secret": "client_secret"}',
            }
        },
    }


@pytest.fixture
def config(settings):
    config = Config.from_settings(Settings(settings))
    yield config


@pytest.fixture
def resolver():
    """Test DIDResolver."""
    yield DIDResolver([JwkResolver()])


@pytest.fixture
async def profile(resolver: DIDResolver, settings):
    """Test Profile."""
    processors = CredProcessors(
        {"jwt_vc_json": JwtVcJsonCredProcessor()},
        {"sd_jwt_vc": SdJwtCredIssueProcessor()},
    )
    profile = await create_test_profile(settings)
    profile.context.injector.bind_instance(DIDResolver, resolver)
    profile.context.injector.bind_instance(
        BaseVerificationKeyStrategy, DefaultVerificationKeyStrategy()
    )
    profile.context.injector.bind_instance(CredProcessors, processors)

    yield profile


@pytest.fixture
def context(profile: Profile):
    """Test AdminRequestContext."""
    yield AdminRequestContext(profile)


@pytest.fixture
def dummy_request(context):
    class DummyRequest:
        def __init__(
            self, json_data=None, headers=None, path="/dummy-path", match_info=None
        ):
            self._json = json_data or {}
            self.headers = headers or {"Authorization": "Bearer testtoken"}
            self.path = path
            self.match_info = match_info or {}

        async def json(self):
            return self._json

        def __getitem__(self, key):
            if key == "context":
                return context
            raise KeyError(key)

    return DummyRequest
