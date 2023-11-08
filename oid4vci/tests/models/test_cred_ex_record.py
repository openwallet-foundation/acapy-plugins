from oid4vci.v1_0.models.cred_ex_record import OID4VCICredentialExchangeRecord


def test_serde():
    record = OID4VCICredentialExchangeRecord(
        exchange_id="123",
        credential_supported_id="456",
        credential_subject={"name": "alice"},
        nonce="789",
        pin="000",
        code="111",
        token="222",
    )
    serialized = record.serialize()
    print(serialized)
    deserialized = OID4VCICredentialExchangeRecord.deserialize(serialized)
    assert record == deserialized
