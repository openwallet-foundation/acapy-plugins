"""Tests for Diff-1: InputDescriptorMapping.id is now optional (waltid compat)."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from oid4vc.cred_processor import CredProcessors
from oid4vc.pex import (
    InputDescriptorMapping,
    InputDescriptorMappingSchema,
    PresentationExchangeEvaluator,
)


# ---------------------------------------------------------------------------
# Schema-level tests – id field optionality
# ---------------------------------------------------------------------------


class TestInputDescriptorMappingSchemaDiff1:
    """Diff-1: id field must be optional (required=False, load_default=None)."""

    def test_missing_id_loads_to_none(self):
        """Schema must not raise when 'id' is absent; loaded value must be None."""
        schema = InputDescriptorMappingSchema()
        loaded = schema.load({"format": "jwt_vc_json", "path": "$"})
        assert isinstance(loaded, InputDescriptorMapping)
        assert loaded.id is None
        assert loaded.fmt == "jwt_vc_json"
        assert loaded.path == "$"

    def test_explicit_id_still_loaded(self):
        """Schema must still accept and preserve an explicit id when provided."""
        schema = InputDescriptorMappingSchema()
        loaded = schema.load(
            {"id": "descriptor-first", "format": "jwt_vc_json", "path": "$"}
        )
        assert loaded.id == "descriptor-first"

    def test_null_id_loads_to_none(self):
        """Explicit null value for id should load as None without error."""
        schema = InputDescriptorMappingSchema()
        loaded = schema.load({"id": None, "format": "jwt_vc_json", "path": "$"})
        assert loaded.id is None


# ---------------------------------------------------------------------------
# Evaluator-level tests – positional fallback when id is absent
# ---------------------------------------------------------------------------

_SIMPLE_DEF = {
    "id": "4f5d6e7a-1234-4abc-8def-000000000001",
    "input_descriptors": [
        {
            "id": "desc-0",
            "constraints": {"fields": [{"path": ["$.type"]}]},
        }
    ],
}


@pytest.fixture
def mock_processors():
    """CredProcessors mock whose verifier returns verified=True."""
    mock_verifier = MagicMock()
    mock_verifier.verify_credential = AsyncMock(
        return_value=MagicMock(
            verified=True,
            payload={"type": ["VerifiableCredential"]},
        )
    )
    processors = MagicMock(spec=CredProcessors)
    processors.cred_verifier_for_format.return_value = mock_verifier
    return processors


@pytest.mark.asyncio
async def test_evaluator_rejects_unknown_id(profile, mock_processors):
    """Baseline: unknown id still produces an unverified result."""
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(_SIMPLE_DEF)

    submission = {
        "id": "4f5d6e7a-1234-4abc-8def-000000000002",
        "definition_id": "4f5d6e7a-1234-4abc-8def-000000000001",
        "descriptor_map": [{"id": "no-such-id", "format": "jwt_vc_json", "path": "$"}],
    }
    result = await evaluator.verify(
        profile, submission, {"type": ["VerifiableCredential"]}
    )
    assert result.verified is False
    assert "no-such-id" in (result.details or "")


@pytest.mark.asyncio
async def test_evaluator_positional_match_when_id_absent(profile, mock_processors):
    """Diff-1 evaluator: waltid omits descriptor id; positional matching must succeed.

    A submission whose descriptor_map entry has no 'id' field should fall back
    to the input descriptor at the same index (index 0 → 'desc-0').
    """
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(_SIMPLE_DEF)

    # No 'id' key — matches waltid's actual submission format
    submission = {
        "id": "4f5d6e7a-1234-4abc-8def-000000000003",
        "definition_id": "4f5d6e7a-1234-4abc-8def-000000000001",
        "descriptor_map": [{"format": "jwt_vc_json", "path": "$"}],
    }

    result = await evaluator.verify(
        profile, submission, {"type": ["VerifiableCredential"]}
    )
    assert result.verified is True, (
        "Positional matching must succeed when descriptor_map entry omits 'id'. "
        f"Got: verified={result.verified}, details={result.details!r}"
    )


@pytest.mark.asyncio
async def test_evaluator_named_id_still_takes_priority(profile, mock_processors):
    """Diff-1: when id IS provided and matches, named lookup is used normally."""
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(_SIMPLE_DEF)

    submission = {
        "id": "4f5d6e7a-1234-4abc-8def-000000000004",
        "definition_id": "4f5d6e7a-1234-4abc-8def-000000000001",
        "descriptor_map": [{"id": "desc-0", "format": "jwt_vc_json", "path": "$"}],
    }

    result = await evaluator.verify(
        profile, submission, {"type": ["VerifiableCredential"]}
    )
    assert result.verified is True


@pytest.mark.asyncio
async def test_evaluator_positional_out_of_bounds_returns_unverified(
    profile, mock_processors
):
    """Diff-1 evaluator: more submissions than descriptors must still fail cleanly.

    Two entries without id, but only one input descriptor → second entry has no
    positional match and must produce an unverified result.
    """
    profile.context.injector.bind_instance(CredProcessors, mock_processors)
    evaluator = PresentationExchangeEvaluator.compile(_SIMPLE_DEF)  # 1 descriptor

    submission = {
        "id": "4f5d6e7a-1234-4abc-8def-000000000005",
        "definition_id": "4f5d6e7a-1234-4abc-8def-000000000001",
        "descriptor_map": [
            {"format": "jwt_vc_json", "path": "$"},  # idx 0 → positional match OK
            {"format": "jwt_vc_json", "path": "$"},  # idx 1 → out of bounds
        ],
    }

    result = await evaluator.verify(
        profile, submission, {"type": ["VerifiableCredential"]}
    )
    assert result.verified is False, (
        "A submission with more entries than descriptors must not succeed."
    )
