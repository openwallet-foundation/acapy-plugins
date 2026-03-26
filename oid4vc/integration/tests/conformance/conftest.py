"""
Shared fixtures for OpenID Foundation conformance suite pytest tests.

These fixtures connect to the OIDF conformance suite (which must already be
running) and to the ACA-Py services whose setup output was produced by
``conformance/setup_acapy.py``.

Environment variables (with defaults used inside Docker):
  CONFORMANCE_SUITE_URL        — base URL of the conformance suite
  CONFORMANCE_SETUP_OUTPUT     — path to the JSON output of setup_acapy.py
"""

import asyncio
import json
import logging
import os
import time
from typing import Any

import httpx
import pytest
import pytest_asyncio

logger = logging.getLogger(__name__)

CONFORMANCE_SUITE_URL = os.environ.get(
    "CONFORMANCE_SUITE_URL", "http://conformance-server:8080"
)
CONFORMANCE_SETUP_OUTPUT = os.environ.get(
    "CONFORMANCE_SETUP_OUTPUT", "/tmp/conformance-setup.json"
)

# How long to poll for a test module to complete
MODULE_TIMEOUT_S = int(os.environ.get("CONFORMANCE_TEST_TIMEOUT", "120"))
POLL_INTERVAL_S = float(os.environ.get("CONFORMANCE_POLL_INTERVAL", "2.0"))
RUNNING_STATUSES = {"RUNNING", "CREATED", "WAITING"}


# ── Low-level helpers ─────────────────────────────────────────────────────────


async def _wait_for_suite(
    client: httpx.AsyncClient, base_url: str, max_attempts: int = 60
) -> None:
    for attempt in range(1, max_attempts + 1):
        try:
            resp = await client.get(f"{base_url}/api/availabletestplans")
            if resp.status_code < 500:
                return
        except httpx.ConnectError:
            # Connection refused — conformance server is not running at all.
            # Skip immediately rather than waiting the full timeout.
            pytest.skip(
                f"Conformance suite is not reachable at {base_url} "
                "(connection refused) — skipping all conformance tests. "
                "Run with --profile conformance to enable the suite."
            )
        except httpx.RequestError:
            pass
        if attempt < max_attempts:
            await asyncio.sleep(5)
    pytest.skip(
        f"Conformance suite at {base_url} did not become ready in time — "
        "skipping all conformance tests (run with --profile conformance to enable)"
    )


async def _create_plan(
    client: httpx.AsyncClient,
    base_url: str,
    plan_name: str,
    variant: dict,
    config: dict,
    alias: str,
) -> str:
    body = {"planName": plan_name, "variant": variant, "body": config, "alias": alias}
    resp = await client.post(f"{base_url}/api/plan", json=body)
    resp.raise_for_status()
    data = resp.json()
    plan_id = data.get("id") or data.get("plan_id")
    assert plan_id, f"No plan ID in response: {data}"
    logger.info(f"Created plan '{plan_name}' (alias={alias}) → {plan_id}")
    return plan_id


async def _get_plan_modules(
    client: httpx.AsyncClient, base_url: str, plan_id: str
) -> list[dict]:
    resp = await client.get(f"{base_url}/api/plan/{plan_id}")
    resp.raise_for_status()
    data = resp.json()
    return data.get("modules", []) or data.get("module", [])


async def _start_module(
    client: httpx.AsyncClient, base_url: str, plan_id: str, module_name: str
) -> str:
    body = {"test": {"name": module_name}, "planId": plan_id}
    resp = await client.post(f"{base_url}/api/runner", json=body)
    resp.raise_for_status()
    data = resp.json()
    test_id = data.get("id") or data.get("testId")
    assert test_id, f"No test ID in response: {data}"
    return test_id


async def _wait_for_module(
    client: httpx.AsyncClient, base_url: str, test_id: str, module_name: str
) -> dict:
    deadline = time.monotonic() + MODULE_TIMEOUT_S
    while True:
        resp = await client.get(f"{base_url}/api/info/{test_id}")
        resp.raise_for_status()
        info = resp.json()
        status = info.get("status", "UNKNOWN")
        if status not in RUNNING_STATUSES:
            return info
        if time.monotonic() > deadline:
            return {"status": "INTERRUPTED", "result": "FAILED", "error": "timeout"}
        await asyncio.sleep(POLL_INTERVAL_S)


async def _get_module_log(
    client: httpx.AsyncClient, base_url: str, test_id: str
) -> list[dict]:
    resp = await client.get(f"{base_url}/api/log/{test_id}")
    resp.raise_for_status()
    return resp.json() if isinstance(resp.json(), list) else []


async def run_plan(
    client: httpx.AsyncClient,
    base_url: str,
    plan_name: str,
    variant: dict,
    config: dict,
    alias: str,
) -> list[dict[str, Any]]:
    """Run all modules in a test plan and return per-module result dicts."""
    plan_id = await _create_plan(client, base_url, plan_name, variant, config, alias)
    modules = await _get_plan_modules(client, base_url, plan_id)

    results = []
    for mod in modules:
        module_name = mod.get("testModule") or mod.get("name", "")
        if not module_name:
            continue
        start = time.monotonic()
        try:
            test_id = await _start_module(client, base_url, plan_id, module_name)
            info = await _wait_for_module(client, base_url, test_id, module_name)
            log = await _get_module_log(client, base_url, test_id)
        except Exception as exc:
            info = {"status": "INTERRUPTED", "result": "FAILED"}
            log = []
            logger.error(f"Module '{module_name}' raised: {exc}")

        passed = info.get("result") in ("PASSED", "WARNING", "REVIEW")
        errors = [e.get("msg", "") for e in log if e.get("result") == "FAILURE"]
        results.append(
            {
                "module": module_name,
                "result": info.get("result", "FAILED"),
                "status": info.get("status", "INTERRUPTED"),
                "passed": passed,
                "errors": errors,
                "duration_s": time.monotonic() - start,
            }
        )
        icon = "✅" if passed else "❌"
        logger.info(f"  {icon} {module_name}: {info.get('result', 'FAILED')}")

    return results


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture(scope="session")
async def conformance_suite_client():
    """Session-scoped async HTTP client for the OIDF conformance suite."""
    async with httpx.AsyncClient(
        verify=False,
        timeout=httpx.Timeout(30.0),
        headers={"Accept": "application/json"},
    ) as client:
        await _wait_for_suite(client, CONFORMANCE_SUITE_URL)
        yield client


@pytest.fixture(scope="session")
def conformance_setup() -> dict:
    """Load the ACA-Py setup output generated by setup_acapy.py."""
    try:
        with open(CONFORMANCE_SETUP_OUTPUT) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        pytest.skip(f"Conformance setup file not found or invalid: {exc}")
