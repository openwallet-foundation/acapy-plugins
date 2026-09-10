import pytest
from pydantic import ValidationError

from tenant.config import Settings


@pytest.mark.parametrize(
    ("enabled", "required"),
    [(False, False), (True, False), (True, True)],
)
def test_attestation_config_accepts_valid_states(enabled, required):
    config = Settings(
        _env_file=None,
        ATTESTATION_ENABLED=enabled,
        ATTESTATION_REQUIRED=required,
    )

    assert config.ATTESTATION_ENABLED is enabled
    assert config.ATTESTATION_REQUIRED is required


def test_attestation_config_rejects_required_when_disabled():
    with pytest.raises(ValidationError, match="ATTESTATION_REQUIRED"):
        Settings(
            _env_file=None,
            ATTESTATION_ENABLED=False,
            ATTESTATION_REQUIRED=True,
        )
