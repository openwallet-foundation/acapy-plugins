"""Simple connectivity test to verify Docker network communication."""

import httpx
import pytest


@pytest.mark.asyncio
async def test_docker_network_connectivity():
    """Test that services can communicate within Docker network."""

    # Test Credo agent service
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get("http://credo-agent:3021/health")
        assert response.status_code == 200
        print(f"✅ Credo agent health: {response.json()}")

    # Test ACA-Py issuer admin service
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get("http://acapy-issuer:8021/status/live")
        assert response.status_code == 200
        print(f"✅ ACA-Py issuer health: {response.json()}")

    # Test ACA-Py verifier admin service
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get("http://acapy-verifier:8031/status/live")
        assert response.status_code == 200
        print(f"✅ ACA-Py verifier health: {response.json()}")


@pytest.mark.asyncio
async def test_oid4vci_well_known_endpoint():
    """Test OID4VCI well-known endpoint accessibility."""

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            "http://acapy-issuer:8022/.well-known/openid-credential-issuer"
        )

        assert response.status_code == 200
        metadata = response.json()
        assert "credential_issuer" in metadata
        assert "credential_endpoint" in metadata

        print("✅ OID4VCI metadata endpoint accessible:")
        print(f"   Issuer: {metadata['credential_issuer']}")
        if "credential_configurations_supported" in metadata:
            print(
                f"   Supported configurations: {list(metadata['credential_configurations_supported'].keys())}"
            )
