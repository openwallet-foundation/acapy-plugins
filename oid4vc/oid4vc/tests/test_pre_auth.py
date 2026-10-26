from unittest.mock import MagicMock

import pytest

from oid4vc import pre_auth
from oid4vc.models.exchange import OID4VCIExchangeRecord
from oid4vc.pre_auth import (
    PreAuthCodeError,
    lookup_pre_auth_code,
    redeem_pre_auth_code,
)


async def _record(profile, code="code-1", pin=None, state=None):
    record = OID4VCIExchangeRecord(
        state=state or OID4VCIExchangeRecord.STATE_OFFER_CREATED,
        verification_method="did:example:123#k",
        issuer_id="did:example:123",
        supported_cred_id="cred-id",
        credential_subject={"name": "alice"},
        code=code,
        pin=pin,
    )
    async with profile.session() as session:
        await record.save(session, reason="test")
    return record


async def _reload(profile, record):
    async with profile.session() as session:
        return await OID4VCIExchangeRecord.retrieve_by_id(session, record.exchange_id)


@pytest.mark.asyncio
async def test_redeem_success_and_single_use(profile):
    record = await _record(profile)
    redeemed = await redeem_pre_auth_code(profile, "code-1", None)
    assert redeemed.exchange_id == record.exchange_id
    assert (await _reload(profile, record)).code_redeemed_at

    with pytest.raises(PreAuthCodeError) as exc:
        await redeem_pre_auth_code(profile, "code-1", None)
    assert exc.value.error == "invalid_grant"
    assert "already been used" in exc.value.description


@pytest.mark.asyncio
async def test_redeem_unknown_code(profile):
    with pytest.raises(PreAuthCodeError) as exc:
        await redeem_pre_auth_code(profile, "nope", None)
    assert exc.value.error == "invalid_grant"


@pytest.mark.asyncio
async def test_redeem_missing_code(profile):
    with pytest.raises(PreAuthCodeError) as exc:
        await redeem_pre_auth_code(profile, None, None)
    assert exc.value.error == "invalid_request"


@pytest.mark.asyncio
async def test_redeem_rejects_issued_exchange(profile):
    await _record(profile, state=OID4VCIExchangeRecord.STATE_ISSUED)
    with pytest.raises(PreAuthCodeError):
        await redeem_pre_auth_code(profile, "code-1", None)


@pytest.mark.asyncio
async def test_tx_code_required(profile):
    await _record(profile, pin="123456")
    with pytest.raises(PreAuthCodeError) as exc:
        await redeem_pre_auth_code(profile, "code-1", None)
    assert exc.value.error == "invalid_request"
    # A missing tx_code is not counted as a guess
    await redeem_pre_auth_code(profile, "code-1", "123456")


@pytest.mark.asyncio
async def test_tx_code_lockout(profile):
    record = await _record(profile, pin="123456")
    for attempt in range(1, 6):
        with pytest.raises(PreAuthCodeError) as exc:
            await redeem_pre_auth_code(profile, "code-1", "000000")
        assert exc.value.description == "tx_code is invalid"
        assert (await _reload(profile, record)).pin_attempts == attempt

    # Locked: even the right tx_code is refused now
    with pytest.raises(PreAuthCodeError) as exc:
        await redeem_pre_auth_code(profile, "code-1", "123456")
    assert "locked" in exc.value.description
    assert (await _reload(profile, record)).code_redeemed_at is None


@pytest.mark.asyncio
async def test_tx_code_lockout_is_configurable(profile, monkeypatch):
    monkeypatch.setattr(
        pre_auth.Config, "from_settings", lambda _: MagicMock(max_tx_code_attempts=1)
    )
    await _record(profile, pin="123456")
    with pytest.raises(PreAuthCodeError):
        await redeem_pre_auth_code(profile, "code-1", "000000")
    with pytest.raises(PreAuthCodeError) as exc:
        await redeem_pre_auth_code(profile, "code-1", "123456")
    assert "locked" in exc.value.description


@pytest.mark.asyncio
async def test_tx_code_correct_after_failures(profile):
    await _record(profile, pin="123456")
    with pytest.raises(PreAuthCodeError):
        await redeem_pre_auth_code(profile, "code-1", "000000")
    record = await redeem_pre_auth_code(profile, "code-1", "123456")
    assert record.code_redeemed_at


@pytest.mark.asyncio
async def test_lookup_does_not_redeem(profile):
    record = await _record(profile)
    found = await lookup_pre_auth_code(profile, "code-1")
    assert found.exchange_id == record.exchange_id
    assert (await _reload(profile, record)).code_redeemed_at is None
    with pytest.raises(PreAuthCodeError) as exc:
        await lookup_pre_auth_code(profile, "nope")
    assert exc.value.error == "invalid_grant"
    with pytest.raises(PreAuthCodeError) as exc:
        await lookup_pre_auth_code(profile, None)
    assert exc.value.error == "invalid_request"


@pytest.mark.asyncio
async def test_finalize_is_stored_with_the_redemption(profile):
    record = await _record(profile, pin="1234")

    def store(rec):
        rec.token = "tok"

    # A rejected tx_code never reaches finalize; nothing is stored.
    with pytest.raises(PreAuthCodeError):
        await redeem_pre_auth_code(profile, "code-1", "0000", finalize=store)
    reloaded = await _reload(profile, record)
    assert reloaded.token is None and reloaded.code_redeemed_at is None

    await redeem_pre_auth_code(profile, "code-1", "1234", finalize=store)
    reloaded = await _reload(profile, record)
    assert reloaded.token == "tok" and reloaded.code_redeemed_at
