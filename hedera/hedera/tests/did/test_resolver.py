from unittest.mock import AsyncMock, patch

from acapy_agent.resolver.did_resolver import ResolverError
from hedera.did import HederaDIDResolver
from pydid.did import InvalidDIDError
import pytest


class TestDidResolver:
    @patch("hedera.did.resolver.SdkHederaDidResolver")
    async def test_resolve_success(self, mock_hedera_did_resolver, profile, context):
        did = (
            "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574"
        )
        did_document = {
            "didDocumentMetadata": {
                "versionId": "1734001354.326604",
                "created": "2024-12-12",
                "updated": "2024-12-12",
            },
            "didResolutionMetadata": {"contentType": "application/did+ld+json"},
            "didDocument": {
                "@context": "https://www.w3.org/ns/did/v1",
                "id": "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574",
                "verificationMethod": [
                    {
                        "id": "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574#did-root-key",
                        "type": "Ed25519VerificationKey2018",
                        "controller": "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574",
                        "publicKeyBase58": "HNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ",
                    }
                ],
                "assertionMethod": [
                    "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574#did-root-key"
                ],
                "authentication": [
                    "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574#did-root-key"
                ],
            },
        }

        resolver = HederaDIDResolver()
        await resolver.setup(context)

        mock_hedera_did_resolver.return_value.resolve = AsyncMock(
            return_value=did_document
        )

        resp = await resolver.resolve(profile, did)

        assert resp == did_document

    @patch("hedera.did.resolver.SdkHederaDidResolver")
    async def test_resolve_invalid_hedera_network(
        self, mock_hedera_did_resolver, profile, context
    ):
        did = "did:hedera:invalidNetwork:nNCTE5bZdRmjm2obqJwS892jVLakafasdfasdfasffwvdasdfasqqwe_0.0.1"
        did_document = {
            "didDocument": None,
            "didDocumentMetadata": {},
            "didResolutionMetadata": {
                "error": "unknownNetwork",
                "message": "DID string is invalid. Invalid Hedera network.",
            },
        }

        resolver = HederaDIDResolver()
        await resolver.setup(context)

        mock_hedera_did_resolver.return_value.resolve = AsyncMock(
            return_value=did_document
        )

        with pytest.raises(
            ResolverError, match="DID string is invalid. Invalid Hedera network."
        ):
            await resolver.resolve(profile, did)

    async def test_resolve_topic_id_missing(self, profile):
        did = ""

        resolver = HederaDIDResolver()

        with pytest.raises(InvalidDIDError):
            await resolver.resolve(profile, did)

    @patch("hedera.did.resolver.SdkHederaDidResolver")
    async def test_resolve_success_deactivated_document(
        self, mock_hedera_did_resolver, profile, context
    ):
        did = (
            "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574"
        )
        did_document = {
            "didDocument": {
                "@context": "https://www.w3.org/ns/did/v1",
                "assertionMethod": [],
                "authentication": [],
                "id": did,
                "verificationMethod": [],
            },
            "didDocumentMetadata": {
                "versionId": None,
                "deactivated": True,
            },
            "didResolutionMetadata": {
                "contentType": "application/did+ld+json",
            },
        }

        resolver = HederaDIDResolver()
        await resolver.setup(context)

        mock_hedera_did_resolver.return_value.resolve = AsyncMock(
            return_value=did_document
        )

        resp = await resolver.resolve(profile, did)

        assert resp == did_document

    @patch("hedera.did.resolver.SdkHederaDidResolver")
    async def test_resolve_no_medatada(self, mock_hedera_did_resolver, profile, context):
        did = (
            "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574"
        )
        did_document = {
            "didDocument": None,
            "didDocumentMetadata": {},
        }

        resolver = HederaDIDResolver()
        await resolver.setup(context)

        mock_hedera_did_resolver.return_value.resolve = AsyncMock(
            return_value=did_document
        )

        with pytest.raises(ResolverError, match="Unknown error"):
            await resolver.resolve(profile, did)

    @patch("hedera.did.resolver.SdkHederaDidResolver")
    async def test_resolve_no_error_message(
        self, mock_hedera_did_resolver, profile, context
    ):
        did = (
            "did:hedera:testnet:zHNJ37tiLbGxD7XPvnTkaZCAV3PCe5P4HJFGMGUkVVZAJ_0.0.5254574"
        )
        did_document = {
            "didDocument": None,
            "didDocumentMetadata": {},
            "didResolutionMetadata": {
                "error": "unknownNetwork",
            },
        }

        resolver = HederaDIDResolver()
        await resolver.setup(context)

        mock_hedera_did_resolver.return_value.resolve = AsyncMock(
            return_value=did_document
        )

        with pytest.raises(ResolverError, match="Unknown error"):
            await resolver.resolve(profile, did)
