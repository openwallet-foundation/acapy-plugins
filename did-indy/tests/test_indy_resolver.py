"""Test Indy Resolver."""

import pytest

from acapy_plugin_did_indy.resolver import INDY_DID_PATTERN


@pytest.mark.parametrize(
    ("did", "namespace"),
    [
        ("did:indy:indicio:test:As728S9715ppSToDurKnvT", "indicio:test"),
        ("did:indy:indicio:demo:As728S9715ppSToDurKnvT", "indicio:demo"),
        ("did:indy:indicio:main:As728S9715ppSToDurKnvT", "indicio:main"),
        ("did:indy:indicio:As728S9715ppSToDurKnvT", "indicio"),
        ("did:indy:sovrin:As728S9715ppSToDurKnvT", "sovrin"),
    ],
)
def test_pattern(did: str, namespace: str):
    """Test the did:indy pattern."""
    match = INDY_DID_PATTERN.fullmatch(did)
    assert match
    assert match.group("namespace") == namespace


@pytest.mark.parametrize(
    "did",
    [
        "did:sov:As728S9715ppSToDurKnvT",
        "did:indy:As728S9715ppSToDurKnvT",
        "did:example:123did:indy:indicio:123",
    ],
)
def test_pattern_x(did: str):
    """Test negative cases."""
    match = INDY_DID_PATTERN.fullmatch(did)
    assert not match
