"""Tests for verified resolution of did:webvh Attested Resources."""

from copy import deepcopy
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

from acapy_agent.resolver.base import DIDNotFound, ResolverError
from did_webvh.askar import AskarSigningKey
from did_webvh.core.proof import di_jcs_sign
from did_webvh.core.resolver import ResolutionResult

from ...anoncreds.registry import DIDWebVHRegistry
from ..resolver import DIDWebVHResolver, digest_multibase

DID = "did:webvh:QmScid:example.com:issuer:01"
FILES_URL = "https://example.com/issuer/01/"
SCHEMA = {"issuerId": DID, "attrNames": ["name"], "name": "s", "version": "1.0"}


def did_document(*keys, assertion=True) -> dict:
    methods = [
        {
            "id": f"{DID}#{key.multikey}",
            "type": "Multikey",
            "controller": DID,
            "publicKeyMultibase": str(key.multikey),
        }
        for key in keys
    ]
    return {
        "id": DID,
        "verificationMethod": methods,
        "assertionMethod": [m["id"] for m in methods] if assertion else [],
        "service": [
            {"id": f"{DID}#files", "type": "relativeRef", "serviceEndpoint": FILES_URL}
        ],
    }


def attested_resource(content: dict, resource_type="anonCredsSchema") -> dict:
    digest = digest_multibase(content)
    return {
        "@context": [
            "https://identity.foundation/did-attested-resources/context/v0.1",
            "https://w3id.org/security/data-integrity/v2",
        ],
        "type": ["AttestedResource"],
        "id": f"{DID}/resources/{digest}",
        "content": content,
        "metadata": {
            "resourceId": digest,
            "resourceType": resource_type,
            "resourceName": "s",
        },
    }


def signed(resource: dict, key, kid=None, purpose="assertionMethod") -> dict:
    resource = deepcopy(resource)
    proof = di_jcs_sign(
        resource, key, kid=kid or f"{DID}#{key.multikey}", purpose=purpose
    )
    resource["proof"] = [proof]
    return resource


class TestResolveResource(IsolatedAsyncioTestCase):
    def setUp(self):
        self.issuer_key = AskarSigningKey.generate("ed25519")
        self.other_key = AskarSigningKey.generate("ed25519")
        self.document = did_document(self.issuer_key)
        self.resource = signed(attested_resource(SCHEMA), self.issuer_key)
        self.resource_id = self.resource["id"]

    async def resolve(self, served, resource_id=None, resource_type="anonCredsSchema"):
        with (
            patch(
                "webvh.resolver.resolver.resolve_did",
                AsyncMock(return_value=ResolutionResult(document=self.document)),
            ),
            patch.object(
                DIDWebVHResolver, "_fetch", AsyncMock(return_value=served)
            ) as fetch,
        ):
            result = await DIDWebVHResolver().resolve_resource(
                resource_id or self.resource_id, resource_type
            )
        return result, fetch

    async def test_resolve(self):
        result, fetch = await self.resolve(self.resource)

        assert result == self.resource
        fetch.assert_awaited_once_with(
            self.resource_id,
            f"{FILES_URL}resources/{self.resource['metadata']['resourceId']}",
        )

    async def test_resolve_without_expected_type(self):
        result, _ = await self.resolve(self.resource, resource_type=None)
        assert result == self.resource

    async def test_resolve_with_witness_proof(self):
        witness_key = AskarSigningKey.generate("ed25519")
        resource = deepcopy(self.resource)
        resource["proof"].insert(
            0,
            di_jcs_sign(
                attested_resource(SCHEMA),
                witness_key,
                kid=f"did:key:{witness_key.multikey}#{witness_key.multikey}",
            ),
        )

        result, _ = await self.resolve(resource)
        assert result == resource

    async def test_resolve_single_proof_object(self):
        resource = deepcopy(self.resource)
        resource["proof"] = resource["proof"][0]

        result, _ = await self.resolve(resource)
        assert result == resource

    async def test_x_substituted_content(self):
        forged = deepcopy(self.resource)
        forged["content"]["attrNames"] = ["name", "admin"]

        with self.assertRaisesRegex(ResolverError, "does not match its digest"):
            await self.resolve(forged)

    async def test_x_self_consistent_resource_signed_by_other_key(self):
        content = {**SCHEMA, "attrNames": ["name", "admin"]}
        forged = signed(attested_resource(content), self.other_key)

        with self.assertRaisesRegex(ResolverError, "not signed by an assertion method"):
            await self.resolve(forged, resource_id=forged["id"])

    async def test_x_proof_by_did_key_only(self):
        forged = signed(
            attested_resource(SCHEMA),
            self.other_key,
            kid=f"did:key:{self.other_key.multikey}#{self.other_key.multikey}",
        )

        with self.assertRaisesRegex(ResolverError, "not signed by an assertion method"):
            await self.resolve(forged)

    async def test_x_key_not_assertion_method(self):
        self.document = did_document(self.issuer_key, assertion=False)

        with self.assertRaisesRegex(ResolverError, "not signed by an assertion method"):
            await self.resolve(self.resource)

    async def test_x_wrong_proof_purpose(self):
        resource = signed(
            attested_resource(SCHEMA), self.issuer_key, purpose="authentication"
        )

        with self.assertRaisesRegex(ResolverError, "not signed by an assertion method"):
            await self.resolve(resource)

    async def test_x_tampered_proof_value(self):
        forged = deepcopy(self.resource)
        value = forged["proof"][0]["proofValue"]
        forged["proof"][0]["proofValue"] = value[:-2] + (
            "11" if value[-2:] != "11" else "22"
        )

        with self.assertRaisesRegex(ResolverError, "not signed by an assertion method"):
            await self.resolve(forged)

    async def test_x_tampered_metadata(self):
        forged = deepcopy(self.resource)
        forged["metadata"]["resourceName"] = "other"

        with self.assertRaisesRegex(ResolverError, "not signed by an assertion method"):
            await self.resolve(forged)

    async def test_x_missing_proof(self):
        forged = deepcopy(self.resource)
        forged.pop("proof")

        with self.assertRaisesRegex(ResolverError, "missing required fields"):
            await self.resolve(forged)

    async def test_x_wrong_resource_id(self):
        forged = deepcopy(self.resource)
        forged["metadata"]["resourceId"] = digest_multibase({"other": 1})

        with self.assertRaisesRegex(ResolverError, "resourceId does not match"):
            await self.resolve(forged)

    async def test_x_wrong_id(self):
        forged = deepcopy(self.resource)
        forged["id"] = f"{DID}/resources/other"

        with self.assertRaisesRegex(ResolverError, "id does not match"):
            await self.resolve(forged)

    async def test_x_wrong_type(self):
        with self.assertRaisesRegex(ResolverError, "is not 'anonCredsCredDef'"):
            await self.resolve(self.resource, resource_type="anonCredsCredDef")

    async def test_x_not_attested_resource(self):
        forged = deepcopy(self.resource)
        forged["type"] = ["Other"]

        with self.assertRaisesRegex(ResolverError, "not an AttestedResource"):
            await self.resolve(forged)

    async def test_x_did_not_found(self):
        with patch(
            "webvh.resolver.resolver.resolve_did",
            AsyncMock(
                return_value=ResolutionResult(resolution_metadata={"error": "notFound"})
            ),
        ):
            with self.assertRaises(DIDNotFound):
                await DIDWebVHResolver().resolve_resource(self.resource_id)

    async def test_x_resolved_document_id_mismatch(self):
        for doc_id in ("did:webvh:QmScid:example.com:issuer:02", None):
            with self.subTest(doc_id=doc_id):
                document = {**self.document, "id": doc_id}
                with (
                    patch(
                        "webvh.resolver.resolver.resolve_did",
                        AsyncMock(return_value=ResolutionResult(document=document)),
                    ),
                    patch.object(DIDWebVHResolver, "_fetch", AsyncMock()) as fetch,
                ):
                    with self.assertRaisesRegex(
                        ResolverError, "does not match issuer DID"
                    ):
                        await DIDWebVHResolver().resolve_resource(self.resource_id)
                fetch.assert_not_awaited()

    async def test_x_invalid_resource_id(self):
        for resource_id in (DID, "did:web:example.com/resources/z", "not a did"):
            with self.subTest(resource_id=resource_id):
                with self.assertRaisesRegex(ResolverError, "Invalid resource identifier"):
                    await DIDWebVHResolver().resolve_resource(resource_id)

    async def test_x_files_service_not_https(self):
        self.document["service"][0]["serviceEndpoint"] = "http://example.com/issuer/01/"

        with self.assertRaisesRegex(ResolverError, "No usable files service"):
            await self.resolve(self.resource)

    async def test_x_resource_path_outside_files_service(self):
        resource_id = (
            f"{DID}/../../other/resources/{self.resource['metadata']['resourceId']}"
        )

        with self.assertRaisesRegex(ResolverError, "outside the files service"):
            await self.resolve(self.resource, resource_id=resource_id)

    async def test_x_other_dids_resource_served_under_issuer_id(self):
        # Another tenant's correctly signed resource, served for this DID's id
        other_did = "did:webvh:QmOther:example.com:attacker:01"
        content = {**SCHEMA, "version": "1.0-other"}
        resource = attested_resource(content)
        resource["id"] = f"{other_did}/resources/{resource['metadata']['resourceId']}"
        resource = signed(
            resource,
            self.other_key,
            kid=f"{other_did}#{self.other_key.multikey}",
        )
        requested_id = f"{DID}/resources/{resource['metadata']['resourceId']}"

        with self.assertRaisesRegex(ResolverError, "id does not match"):
            await self.resolve(resource, resource_id=requested_id)

        # Even with the id rewritten, the proof is not by this DID
        resource["id"] = requested_id
        with self.assertRaisesRegex(ResolverError, "not signed by an assertion method"):
            await self.resolve(resource, resource_id=requested_id)


class TestRegistryIssuerBinding(IsolatedAsyncioTestCase):
    async def test_x_schema_issuer_id_not_resource_did(self):
        registry = DIDWebVHRegistry()
        content = {**SCHEMA, "issuerId": "did:webvh:QmOther:example.com:other"}
        resource = attested_resource(content)

        with patch.object(
            registry.resolver, "resolve_resource", AsyncMock(return_value=resource)
        ):
            with self.assertRaisesRegex(ResolverError, "issuerId does not match"):
                await registry._resolve(resource["id"], "anonCredsSchema")

    async def test_schema_issuer_id_is_resource_did(self):
        registry = DIDWebVHRegistry()
        resource = attested_resource(SCHEMA)

        with patch.object(
            registry.resolver, "resolve_resource", AsyncMock(return_value=resource)
        ) as resolve:
            assert await registry._resolve(resource["id"], "anonCredsSchema") == resource
        resolve.assert_awaited_once_with(resource["id"], "anonCredsSchema")
