"""Simple mock ACA-Py controller for integration testing."""

from typing import Any

import httpx


class Controller:
    """Simple HTTP client wrapper for ACA-Py admin API."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Content-Type": "application/json"}

    async def get(self, path: str, params: dict | None = None) -> dict[str, Any]:
        """Make GET request to ACA-Py admin API."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}{path}",
                params=params,
                headers=self.headers,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def post(self, path: str, json: dict | None = None) -> dict[str, Any]:
        """Make POST request to ACA-Py admin API."""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}{path}", json=json, headers=self.headers, timeout=30.0
            )
            response.raise_for_status()
            return response.json()

    async def patch(self, path: str, json: dict | None = None) -> dict[str, Any]:
        """Make PATCH request to ACA-Py admin API."""
        async with httpx.AsyncClient() as client:
            response = await client.patch(
                f"{self.base_url}{path}", json=json, headers=self.headers, timeout=30.0
            )
            response.raise_for_status()
            return response.json()

    async def put(self, path: str, json: dict | None = None) -> dict[str, Any]:
        """Make PUT request to ACA-Py admin API."""
        async with httpx.AsyncClient() as client:
            response = await client.put(
                f"{self.base_url}{path}", json=json, headers=self.headers, timeout=30.0
            )
            response.raise_for_status()
            return response.json()

    async def delete(self, path: str, params: dict | None = None) -> dict[str, Any]:
        """Make DELETE request to ACA-Py admin API."""
        async with httpx.AsyncClient() as client:
            response = await client.delete(
                f"{self.base_url}{path}",
                params=params,
                headers=self.headers,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def event_with_values(self, topic: str, **kwargs) -> dict[str, Any]:
        """Mock event waiting - simplified for testing."""
        # In real implementation, this would wait for webhooks
        # For now, just return success
        return {"topic": topic, "values": kwargs, "status": "received"}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
