"""
OpenID Conformance Suite Test Runner for ACA-Py OID4VC.

Drives the OIDF conformance suite via its REST API to run:
  - OID4VCI 1.0 Issuer test plan (oid4vci-1_0-issuer-test-plan)
  - OID4VP 1.0 Final Verifier test plan (oid4vp-1final-verifier-test-plan)
    - SD-JWT VC credential format
    - ISO mDL (mDOC) credential format

Usage:
    python run_conformance.py [--suite-url URL] [--output-xml FILE]
                              [--scope {issuer,verifier,all}]

Exit codes:
    0  All selected tests passed
    1  One or more tests failed
    2  Setup or connectivity error
"""

import argparse
import asyncio
import base64
import json
import logging
import os
import ssl
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key as ec_generate_private_key,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Environment configuration ────────────────────────────────────────────────

CONFORMANCE_SUITE_URL = os.environ.get(
    "CONFORMANCE_SUITE_URL", "https://conformance-suite:8443"
)
CONFORMANCE_SETUP_OUTPUT = os.environ.get(
    "CONFORMANCE_SETUP_OUTPUT", "/tmp/conformance-setup.json"
)
CONFORMANCE_OUTPUT_XML = os.environ.get(
    "CONFORMANCE_OUTPUT_XML", "/usr/src/app/test-results/conformance-junit.xml"
)
CONFORMANCE_SCOPE = os.environ.get(
    "CONFORMANCE_SCOPE", "all"
)  # issuer | verifier | all
# ACA-Py issuer admin API base URL (used to create fresh offers per test module)
ACAPY_ISSUER_ADMIN_URL = os.environ.get(
    "ACAPY_ISSUER_ADMIN_URL", "http://acapy-issuer:8021"
)

# How long to wait for a single test module to complete (seconds)
TEST_TIMEOUT = int(os.environ.get("CONFORMANCE_TEST_TIMEOUT", "120"))
POLL_INTERVAL = float(os.environ.get("CONFORMANCE_POLL_INTERVAL", "2.0"))

# Conformance suite readiness
SUITE_POLL_INTERVAL = 5.0
SUITE_POLL_MAX_ATTEMPTS = 60

# ── ACA-Py offer factory ─────────────────────────────────────────────────────


async def create_fresh_offer(
    admin_url: str,
    supported_cred_id: str,
    issuer_did: str,
    pin: str | None = None,
) -> str:
    """Create a fresh ACA-Py pre-authorized credential offer and return its deeplink URI.

    Each call creates a new exchange record in ACA-Py with a new one-time-use
    pre-authorized code, so individual test modules each receive a usable offer.
    """
    exchange_body: dict = {
        "supported_cred_id": supported_cred_id,
        "credential_subject": {
            "given_name": "Alice",
            "family_name": "Smith",
            "email": "alice@example.com",
            "birthdate": "1990-01-15",
        },
        # Pass the DID directly — ACA-Py resolves the verification method
        # (for did:jwk it appends #0 automatically, avoiding manual URI construction).
        "did": issuer_did,
    }
    if pin is not None:
        exchange_body["pin"] = pin

    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        resp = await client.post(
            f"{admin_url}/oid4vci/exchange/create",
            json=exchange_body,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        exchange = resp.json()
        exchange_id = exchange.get("exchange_id") or exchange.get("id")
        if not exchange_id:
            raise RuntimeError(f"No exchange_id in response: {exchange}")

        resp = await client.get(
            f"{admin_url}/oid4vci/credential-offer",
            params={"exchange_id": exchange_id},
        )
        resp.raise_for_status()
        offer = resp.json()
        offer_uri = offer.get("offer_uri") or offer.get("credential_offer")
        if not offer_uri:
            raise RuntimeError(f"No offer_uri in response: {offer}")

    logger.info(f"  Created fresh offer for {supported_cred_id}: {offer_uri[:80]}...")
    return offer_uri


# ── Result constants ─────────────────────────────────────────────────────────

RESULT_PASSED = "PASSED"
RESULT_WARNING = "WARNING"
RESULT_REVIEW = "REVIEW"
RESULT_SKIPPED = "SKIPPED"
RESULT_FAILED = "FAILED"

# Statuses that indicate the test is still in-flight
RUNNING_STATUSES = {"RUNNING", "CREATED", "WAITING"}


# ── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class TestResult:
    plan_id: str
    plan_name: str
    module_name: str
    module_id: str
    status: str  # FINISHED | INTERRUPTED | ...
    result: str  # PASSED | FAILED | WARNING | REVIEW | SKIPPED
    duration_ms: int
    logs: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.result in (RESULT_PASSED, RESULT_WARNING, RESULT_REVIEW)


@dataclass
class PlanSummary:
    plan_name: str
    plan_id: str
    modules_total: int
    modules_passed: int
    modules_failed: int
    modules_skipped: int
    results: list[TestResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.modules_failed == 0


# ── Conformance Suite API client ──────────────────────────────────────────────


class ConformanceSuiteClient:
    """Async HTTP client for the OIDF Conformance Suite REST API."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        # Use an unverified SSL context so self-signed certs work in Docker
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        self._client = httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(30.0),
            headers={"Accept": "application/json"},
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def wait_until_ready(self) -> None:
        """Poll the suite until it responds to /api/runner/available."""
        url = f"{self.base_url}/api/runner/available"
        logger.info(f"Waiting for conformance suite at {self.base_url} ...")
        for attempt in range(1, SUITE_POLL_MAX_ATTEMPTS + 1):
            try:
                resp = await self._client.get(url)
                if resp.status_code < 500:
                    logger.info(f"Conformance suite ready after {attempt} attempt(s)")
                    return
            except httpx.RequestError:
                pass
            if attempt < SUITE_POLL_MAX_ATTEMPTS:
                await asyncio.sleep(SUITE_POLL_INTERVAL)
        raise RuntimeError("Conformance suite did not become ready in time")

    async def available_test_plans(self) -> list[str]:
        """Return available test module names from /api/runner/available."""
        resp = await self._client.get(f"{self.base_url}/api/runner/available")
        resp.raise_for_status()
        modules = resp.json()
        # Each module object contains a testModule or testName field
        names: list[str] = []
        for m in modules:
            if isinstance(m, dict):
                name = m.get("testModule") or m.get("testName") or m.get("name", "")
                if name:
                    names.append(name)
            elif isinstance(m, str):
                names.append(m)
        return names

    async def create_plan(
        self,
        plan_name: str,
        variant: dict[str, str],
        config: dict,
        *,
        alias: str | None = None,
    ) -> str:
        """Create a test plan and return its plan ID."""
        # The OIDF conformance suite API requires planName/variant as query
        # params and the configuration object as the raw JSON request body.
        params: dict[str, str] = {"planName": plan_name}
        if variant:
            params["variant"] = json.dumps(variant)

        resp = await self._client.post(
            f"{self.base_url}/api/plan",
            params=params,
            content=json.dumps(config),
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code not in (200, 201):
            logger.error(f"Failed to create plan {plan_name}: {resp.text}")
            resp.raise_for_status()
        data = resp.json()
        plan_id = data.get("id") or data.get("plan_id")
        if not plan_id:
            raise RuntimeError(f"No plan ID in response: {data}")
        logger.info(f"Created test plan '{plan_name}' → plan_id={plan_id}")
        return plan_id

    async def get_plan_modules(self, plan_id: str) -> list[dict]:
        """Return the list of test modules defined for a plan."""
        resp = await self._client.get(f"{self.base_url}/api/plan/{plan_id}")
        resp.raise_for_status()
        data = resp.json()
        return data.get("modules", []) or data.get("module", [])

    async def start_module(self, plan_id: str, module_name: str) -> str:
        """Start a test module and return the test (runner) ID."""
        # The OIDF API expects test (module name) and plan (plan ID) as query params
        params = {"test": module_name, "plan": plan_id}
        resp = await self._client.post(
            f"{self.base_url}/api/runner",
            params=params,
        )
        if resp.status_code not in (200, 201):
            logger.error(f"Failed to start module {module_name}: {resp.text}")
            resp.raise_for_status()
        data = resp.json()
        test_id = data.get("id") or data.get("testId")
        if not test_id:
            raise RuntimeError(f"No test ID in response: {data}")
        logger.info(f"  Started module '{module_name}' → test_id={test_id}")
        return test_id

    async def get_module_status(self, test_id: str) -> dict:
        resp = await self._client.get(f"{self.base_url}/api/info/{test_id}")
        resp.raise_for_status()
        return resp.json()

    async def get_module_log(self, test_id: str) -> list[dict]:
        resp = await self._client.get(f"{self.base_url}/api/log/{test_id}")
        resp.raise_for_status()
        return resp.json() if isinstance(resp.json(), list) else []

    async def trigger_oid4vci_offer(
        self,
        test_id: str,
        openid_offer_deeplink: str,
    ) -> bool:
        """Deliver a credential offer to the conformance suite's mock wallet.

        The conformance suite for OID4VCI issuer tests acts as a mock wallet at:
            {base_url}/test/{testId}/credential_offer
        It enters WAITING state after setup and waits for the issuer to deliver
        a credential offer.  We parse the openid-credential-offer:// deep link
        and forward the inner credential_offer / credential_offer_uri to the
        suite's endpoint.
        """
        parsed = urlparse(openid_offer_deeplink)
        params = parse_qs(parsed.query)

        # Prefer credential_offer_uri (HTTP URL that the suite fetches)
        # over credential_offer (inline JSON)
        trigger_params: dict[str, str] = {}
        if "credential_offer_uri" in params:
            trigger_params["credential_offer_uri"] = params["credential_offer_uri"][0]
        elif "credential_offer" in params:
            trigger_params["credential_offer"] = params["credential_offer"][0]
        else:
            # Fallback: pass the entire deep link through (some ACA-Py builds
            # embed the offer inline)
            logger.warning(
                f"  Cannot parse OID4VCI deeplink, using raw URI: {openid_offer_deeplink[:100]}"
            )
            trigger_params["credential_offer_uri"] = openid_offer_deeplink

        offer_endpoint = f"{self.base_url}/test/{test_id}/credential_offer"
        logger.info(
            f"  Triggering conformance wallet (OID4VCI offer): GET {offer_endpoint}"
        )
        for k, v in trigger_params.items():
            logger.info(f"    {k}={v[:120]}")

        try:
            resp = await self._client.get(
                offer_endpoint,
                params=trigger_params,
                follow_redirects=True,
            )
            logger.info(f"  OID4VCI offer trigger HTTP {resp.status_code}")
            return resp.status_code < 500
        except Exception as exc:
            logger.error(f"  OID4VCI offer trigger error: {exc}")
            return False

    async def wait_for_waiting(self, test_id: str, timeout: float = 30.0) -> None:
        """Poll until a test module reaches WAITING state (ready for wallet interaction)."""
        deadline = time.monotonic() + timeout
        while True:
            info = await self.get_module_status(test_id)
            status = info.get("status", "UNKNOWN")
            if status == "WAITING":
                logger.info(f"  Module {test_id} is in WAITING state")
                return
            # If module already finished/interrupted, no need to wait
            if status not in ("CREATED", "CONFIGURED", "RUNNING", "WAITING"):
                logger.warning(
                    f"  Module {test_id} reached unexpected state {status} while "
                    "waiting for WAITING"
                )
                return
            if time.monotonic() > deadline:
                logger.warning(f"  Module {test_id} didn't reach WAITING in {timeout}s")
                return
            await asyncio.sleep(0.5)

    async def trigger_oid4vp_wallet(
        self,
        test_id: str,
        openid_deeplink: str,
    ) -> bool:
        """Deliver an OID4VP authorization request to the conformance suite's mock wallet.

        The conformance suite for OID4VP verifier tests acts as a mock wallet at:
            {base_url}/test/{testId}/authorize
        It enters WAITING state after setup and requires the verifier to deliver the
        authorization request (client_id + request_uri) to this wallet endpoint.
        """
        parsed = urlparse(openid_deeplink)
        params = parse_qs(parsed.query)
        client_id = params.get("client_id", [""])[0]
        request_uri = params.get("request_uri", [""])[0]

        if not client_id or not request_uri:
            logger.error(
                f"  Cannot parse OID4VP deeplink for wallet trigger: {openid_deeplink[:100]}"
            )
            return False

        wallet_url = f"{self.base_url}/test/{test_id}/authorize"
        logger.info(f"  Triggering conformance wallet: GET {wallet_url}")
        logger.info(f"    client_id={client_id[:80]}...")
        logger.info(f"    request_uri={request_uri}")

        # In OID4VP Final spec, client_id_scheme was removed from authorization
        # request URL query parameters (removed in draft ID3).  The scheme is
        # communicated inside the signed JAR only.  Omit client_id_scheme here.
        try:
            resp = await self._client.get(
                wallet_url,
                params={
                    "client_id": client_id,
                    "request_uri": request_uri,
                },
                follow_redirects=True,
            )
            logger.info(f"  Wallet trigger HTTP {resp.status_code}")
            return resp.status_code < 500
        except Exception as exc:
            logger.error(f"  Wallet trigger error: {exc}")
            return False

    async def wait_for_module(self, test_id: str, module_name: str) -> dict:
        """Poll until a module finishes and return its final status dict."""
        deadline = time.monotonic() + TEST_TIMEOUT
        while True:
            info = await self.get_module_status(test_id)
            status = info.get("status", "UNKNOWN")

            if status not in RUNNING_STATUSES:
                logger.info(
                    f"  Module '{module_name}' finished: "
                    f"status={status}, result={info.get('result', 'N/A')}"
                )
                return info

            if time.monotonic() > deadline:
                logger.warning(
                    f"  Module '{module_name}' (test_id={test_id}) timed out "
                    f"after {TEST_TIMEOUT}s — marking as FAILED"
                )
                return {"status": "INTERRUPTED", "result": "FAILED", "error": "timeout"}

            await asyncio.sleep(POLL_INTERVAL)

    async def run_plan(
        self,
        plan_id: str,
        plan_name: str,
        *,
        oid4vp_deeplinks: dict[str, str] | None = None,
        oid4vci_offers: dict[str, str] | None = None,
        oid4vci_offer_factory: Any | None = None,
    ) -> list[TestResult]:
        """Run all modules in a plan sequentially and return results.

        Args:
            plan_id: The conformance suite plan ID.
            plan_name: Human-readable plan name for logging.
            oid4vp_deeplinks: For OID4VP verifier test plans, a mapping from
                module name to the openid:// deeplink that should be delivered
                to the conformance suite's mock wallet after the module enters
                WAITING state.  If provided, each module with a matching entry
                will be triggered via the wallet endpoint before polling.
            oid4vci_offers: For OID4VCI issuer test plans, a mapping from module
                name to the openid-credential-offer:// deeplink that should be
                delivered to the conformance suite's mock wallet (credential_offer
                endpoint) after the module enters WAITING state.
            oid4vci_offer_factory: An async callable () -> str that creates a fresh
                ACA-Py credential offer for each test module.  Takes priority over
                oid4vci_offers when both are provided.
        """
        modules = await self.get_plan_modules(plan_id)
        if not modules:
            logger.warning(f"Plan {plan_id} has no modules — skipping")
            return []

        results: list[TestResult] = []
        for module_def in modules:
            module_name = module_def.get("testModule") or module_def.get("name", "")
            if not module_name:
                continue

            start_ts = time.monotonic()
            try:
                test_id = await self.start_module(plan_id, module_name)

                # OID4VP verifier tests require a wallet-trigger step after the
                # module enters WAITING state (the suite acts as a mock wallet
                # and waits for the verifier to deliver the authorization request).
                #
                # OID4VCI issuer tests require a credential-offer trigger step after
                # the module enters WAITING state (the suite acts as a mock wallet
                # and waits for the issuer to deliver a credential offer).
                if oid4vp_deeplinks and module_name in oid4vp_deeplinks:
                    await self.wait_for_waiting(test_id)
                    deeplink = oid4vp_deeplinks[module_name]
                    if deeplink:
                        await self.trigger_oid4vp_wallet(test_id, deeplink)
                    else:
                        logger.warning(
                            f"  No deeplink for module '{module_name}' — skipping trigger"
                        )
                elif oid4vci_offers or oid4vci_offer_factory:
                    # wait_for_waiting returns immediately if the module exits
                    # without entering WAITING (negative-test modules).
                    await self.wait_for_waiting(test_id, timeout=15.0)
                    # Only trigger offer if the module is ACTUALLY waiting for
                    # one — modules like the metadata test derive the issuer
                    # URL from the plan-level credential_offer config and don't
                    # need a module-level offer trigger.  Sending one causes the
                    # suite to reject it with "unexpected credential_offer".
                    info_check = await self.get_module_status(test_id)
                    is_metadata_module = "metadata" in module_name
                    if is_metadata_module:
                        logger.info(
                            f"  Module '{module_name}' is a metadata-only module "
                            "— skipping offer trigger"
                        )
                    elif info_check.get("status") != "WAITING":
                        logger.info(
                            f"  Module '{module_name}' is not in WAITING state "
                            f"(status={info_check.get('status')}) — skipping offer trigger"
                        )
                    else:
                        if oid4vci_offer_factory:
                            # Fresh offer per module — each call creates a new one-time
                            # pre-authorized code in ACA-Py so every module can redeem it.
                            try:
                                offer_deeplink = await oid4vci_offer_factory()
                            except Exception as exc:
                                logger.error(
                                    f"  Failed to create fresh offer for '{module_name}': {exc}"
                                )
                                offer_deeplink = ""
                        else:
                            # Fall back to static dict (wildcard or per-module)
                            offer_deeplink = oid4vci_offers.get(
                                module_name
                            ) or oid4vci_offers.get("*", "")  # type: ignore[union-attr]
                        if offer_deeplink:
                            await self.trigger_oid4vci_offer(test_id, offer_deeplink)
                        else:
                            logger.warning(
                                f"  No offer for module '{module_name}' — skipping trigger"
                            )

                info = await self.wait_for_module(test_id, module_name)
                logs = await self.get_module_log(test_id)
            except Exception as exc:
                logger.error(
                    f"  Error running module '{module_name}': {exc}", exc_info=True
                )
                info = {"status": "INTERRUPTED", "result": "FAILED"}
                logs = []

            end_ts = time.monotonic()
            result = info.get("result", RESULT_FAILED)
            status = info.get("status", "INTERRUPTED")

            # Collect failure messages from log
            errors = [
                entry.get("msg", "")
                for entry in logs
                if entry.get("result") == "FAILURE"
            ]

            # Log details for failed modules to aid debugging
            if result not in (RESULT_PASSED, RESULT_WARNING):
                for entry in logs:
                    entry_result = entry.get("result", "INFO")
                    entry_msg = entry.get("msg", "")
                    entry_src = entry.get("src", "")
                    if entry_result in ("FAILURE", "WARNING"):
                        logger.error(f"  [{entry_result}] {entry_src}: {entry_msg}")

            results.append(
                TestResult(
                    plan_id=plan_id,
                    plan_name=plan_name,
                    module_name=module_name,
                    module_id=test_id if "test_id" in dir() else "",
                    status=status,
                    result=result,
                    duration_ms=int((end_ts - start_ts) * 1000),
                    logs=logs,
                    errors=errors,
                )
            )

        return results


# ── JUnit XML output ──────────────────────────────────────────────────────────


def write_junit_xml(summaries: list[PlanSummary], output_path: str) -> None:
    """Write a JUnit-compatible XML report."""
    root = ET.Element("testsuites")

    for summary in summaries:
        suite = ET.SubElement(
            root,
            "testsuite",
            name=summary.plan_name,
            tests=str(summary.modules_total),
            failures=str(summary.modules_failed),
            skipped=str(summary.modules_skipped),
            errors="0",
        )
        for tr in summary.results:
            case = ET.SubElement(
                suite,
                "testcase",
                classname=summary.plan_name,
                name=tr.module_name,
                time=str(tr.duration_ms / 1000),
            )
            if tr.result == RESULT_SKIPPED:
                ET.SubElement(case, "skipped")
            elif not tr.passed:
                failure = ET.SubElement(
                    case,
                    "failure",
                    message=f"Result: {tr.result}",
                    type=tr.result,
                )
                if tr.errors:
                    failure.text = "\n".join(tr.errors[:10])

    tree = ET.ElementTree(root)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    ET.indent(tree, space="  ")
    tree.write(output_path, encoding="unicode", xml_declaration=True)
    logger.info(f"JUnit XML written to {output_path}")


# ── Plan definitions ──────────────────────────────────────────────────────────


# ---------------------------------------------------------------------------
# Static test client JWKs (P-256 private key).
# Used by the conformance suite (acting as a wallet) for private_key_jwt
# authentication against the ACA-Py token endpoint.
# These are test-only keys — security is NOT a concern.
# ---------------------------------------------------------------------------
_CONFORMANCE_CLIENT_PRIVATE_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "OFLqKdPPhA2HwF7LI-VE7VHyhIAaUTMY1jBPSC8HEZc",
    "y": "CMWyVFy-1MiYMRiVD_ihOlDsB9TE32SQws0dYS4KTUg",
    "d": "M3mwiGtRJ519gSnDREpJiJNczdtMALlXTNxpN02-XBI",
    "kid": "conformance-test-key-1",
    "use": "sig",
    "alg": "ES256",
}
_CONFORMANCE_CLIENT_PRIVATE_JWK2 = {
    "kty": "EC",
    "crv": "P-256",
    "x": "HGV6TdbUSvMX4viM_fzCch53848NMH-cDRnRKU8jPRA",
    "y": "TAaNm7QiuVuJeFblIWU5PFBIeqcf1Fdpi9qwln8XU-A",
    "d": "B0SeBbWWcYTIroC_rD19SXUrZdi-QbkD2SrALSS3Ai8",
    "kid": "conformance-test-key-2",
    "use": "sig",
    "alg": "ES256",
}
_CONFORMANCE_CLIENT_JWKS = {"keys": [_CONFORMANCE_CLIENT_PRIVATE_JWK]}
_CONFORMANCE_CLIENT_JWKS2 = {"keys": [_CONFORMANCE_CLIENT_PRIVATE_JWK2]}


def build_oid4vci_issuer_config(setup: dict) -> tuple[str, dict, dict]:
    """Return (plan_name, variant, config) for the OID4VCI issuer test plan."""
    issuer = setup["issuer"]
    plan_name = "oid4vci-1_0-issuer-test-plan"
    variant = {
        "vci_grant_type": "pre_authorization_code",
        # ACA-Py's credential-offer deeplink uses ?credential_offer=<JSON> (by_value),
        # NOT ?credential_offer_uri=<URL> (by_reference).
        "vci_credential_offer_variant": "by_value",
        "vci_credential_issuance_mode": "immediate",
        "credential_format": "sd_jwt_vc",
        "vci_credential_encryption": "plain",
        # "none" was removed in a recent conformance suite update.
        # The conformance suite will authenticate to ACA-Py's token endpoint
        # using a JWT assertion signed with _CONFORMANCE_CLIENT_PRIVATE_JWK.
        # ACA-Py's pre-auth code token endpoint typically ignores client auth.
        "client_auth_type": "private_key_jwt",
        "vci_authorization_code_flow_variant": "issuer_initiated",
        # FAPI2 variant parameters required by AbstractVCIIssuerTestModule:
        # "unsigned" = plain PAR without a request JWT
        "fapi_request_method": "unsigned",
        # FAPI2SenderConstrainMethod: "dpop" or "mtls" (no "none")
        "sender_constrain": "dpop",
        # AuthorizationRequestType: "simple" or "rar"
        "authorization_request_type": "simple",
        # VCIProfile: only "haip" is currently valid (PLAIN_VCI is commented out)
        "vci_profile": "haip",
    }
    config = {
        # vci.* fields are used by VCIGetDynamicCredentialIssuerMetadata to
        # discover the token and credential endpoints from ACA-Py's metadata.
        "vci": {
            "credential_issuer_url": issuer["url"],
            "credential_configuration_id": issuer["sdjwt_identifier"],
            # static_tx_code: conformance suite uses this value directly instead
            # of exposing a /tx_code GET endpoint and waiting for our runner to
            # call it.  The value must match the pin stored in ACA-Py's exchange
            # record (set by setup_acapy.py).  The token endpoint receives
            # tx_code=<value> and ACA-Py validates it against record.pin.
            "static_tx_code": issuer["sdjwt_tx_code"],
        },
        # client.* is the wallet (conformance suite) client configuration.
        # The private key is used for private_key_jwt token endpoint auth.
        "client": {
            "client_id": "conformance-suite-wallet",
            "jwks": _CONFORMANCE_CLIENT_JWKS,
        },
        # client2 is required by some test modules that exercise two-client flows.
        "client2": {
            "client_id": "conformance-suite-wallet-2",
            "jwks": _CONFORMANCE_CLIENT_JWKS2,
        },
        # The credential offer to redeem (by_value variant).
        "credential_offer": {
            "credential_offer": issuer["sdjwt_offer"]["offer_uri"],
        },
    }
    return plan_name, variant, config


def _jwk_from_did_jwk(did_jwk_str: str) -> dict:
    """Decode the JWK embedded in a did:jwk DID string.

    The did:jwk DID method encodes a JWK document as base64url in the DID
    identifier (``did:jwk:{base64url_of_jwk}``).  This function decodes and
    returns the JWK dict (public key fields only).
    """
    b64 = did_jwk_str.split("did:jwk:", 1)[-1]
    b64 += "=" * (-len(b64) % 4)
    return json.loads(base64.urlsafe_b64decode(b64))


def _generate_ec_p256_jwk_pair() -> tuple[dict, dict]:
    """Generate a fresh P-256 EC JWK key pair.

    Returns ``(private_jwk, public_jwk)`` where ``private_jwk`` includes the
    ``d`` field and ``public_jwk`` contains only the public components.
    """
    key = ec_generate_private_key(SECP256R1())
    numbers = key.private_numbers()
    pub = numbers.public_numbers

    def _b64url(n: int, length: int = 32) -> str:
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    pub_jwk: dict = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(pub.x),
        "y": _b64url(pub.y),
    }
    priv_jwk = {**pub_jwk, "d": _b64url(numbers.private_value)}
    return priv_jwk, pub_jwk


def build_oid4vp_verifier_sdjwt_config(setup: dict) -> tuple[str, dict, dict]:
    """Return (plan_name, variant, config) for the OID4VP SD-JWT verifier test plan."""
    verifier = setup["verifier"]
    plan_name = "oid4vp-1final-verifier-test-plan"
    variant = {
        "credential_format": "sd_jwt_vc",
        # NOTE: The HAIP conformance suite only supports x509_san_dns / x509_hash for
        # client_id_prefix.  ACA-Py currently uses did:jwk — these tests will fail
        # with 'x5c is null' until X.509 support is added to the OID4VP verifier.
        "client_id_prefix": "x509_san_dns",
        "request_method": "request_uri_signed",
        # plain_vp is required when response_mode is direct_post; haip requires
        # direct_post.jwt.  Using plain_vp so the plan is created successfully.
        "vp_profile": "plain_vp",
        "response_mode": "direct_post",
    }
    # Extract the public HTTPS request_uri from the pre-created setup deeplink
    # so that authorization_endpoint and response_uri reflect the actual external
    # URL (e.g. https://acapy-tls-proxy.local:8444) rather than the internal
    # Docker endpoint (http://acapy-verifier:8033).  The conformance suite
    # validates that both URIs use https:// scheme.
    sdjwt_deeplink = verifier["sdjwt_vp_request"]["request_uri"]
    sdjwt_request_uri = parse_qs(urlparse(sdjwt_deeplink).query).get(
        "request_uri", [""]
    )[0]
    parsed_req_uri = urlparse(sdjwt_request_uri)
    public_base = f"{parsed_req_uri.scheme}://{parsed_req_uri.netloc}"  # e.g. https://acapy-tls-proxy.local:8444

    # Verifier signing JWK (leaf cert public key) — the suite uses this to
    # validate the JAR signature for x509_san_dns.
    verifier_pub_jwk = _jwk_from_did_jwk(verifier["p256_did"])

    # Credential signing JWK: a fresh key pair the conformance suite (wallet)
    # uses to sign the VP and/or key binding JWT it presents to the verifier.
    cred_signing_priv_jwk, _ = _generate_ec_p256_jwk_pair()

    # For x509_san_dns, EnsureMatchingClientId checks:
    #   expected = "x509_san_dns:" + client.client_id
    # and compares against the JAR's client_id field which our verifier sends as
    #   "x509_san_dns:{dns_name}"
    # So client.client_id must be the plain DNS name (without the scheme prefix).
    verifier_dns_name = verifier.get("x509_dns_name", "acapy-tls-proxy.local")

    config = {
        "server": {
            "verifier_url": verifier["url"],
            "client_id": verifier_dns_name,
            "authorization_endpoint": sdjwt_request_uri,
            "response_uri": (
                f"{public_base}/oid4vp/response/"
                f"{verifier['sdjwt_vp_request']['presentation_id']}"
            ),
            "jwks": {"keys": [verifier_pub_jwk]},
        },
        # client = the verifier acting as OAuth2 client / relying party.
        # client.client_id = the plain DNS name; the suite prepends
        # "x509_san_dns:" when checking matching against the JAR.
        "client": {
            "client_id": verifier_dns_name,
        },
        # AbstractCreateSdJwtCredential.createSdJwt() looks up:
        #   env.getElementFromObject("config", "credential.signing_jwk")
        # so the key must be nested as credential.signing_jwk.
        "credential": {
            "signing_jwk": cred_signing_priv_jwk,
        },
    }
    return plan_name, variant, config


def build_oid4vp_verifier_mdl_config(setup: dict) -> tuple[str, dict, dict]:
    """Return (plan_name, variant, config) for the OID4VP mDL verifier test plan."""
    verifier = setup["verifier"]
    plan_name = "oid4vp-1final-verifier-test-plan"
    variant = {
        "credential_format": "iso_mdl",
        # NOTE: Same x509 limitation as the sd_jwt_vc variant above.
        "client_id_prefix": "x509_san_dns",
        "request_method": "request_uri_signed",
        # plain_vp is required when response_mode is direct_post.
        "vp_profile": "plain_vp",
        "response_mode": "direct_post",
    }
    # Same HTTPS URL derivation as the sdjwt variant.
    mdoc_deeplink = verifier["mdoc_vp_request"]["request_uri"]
    mdoc_request_uri = parse_qs(urlparse(mdoc_deeplink).query).get("request_uri", [""])[
        0
    ]
    parsed_req_uri = urlparse(mdoc_request_uri)
    public_base = f"{parsed_req_uri.scheme}://{parsed_req_uri.netloc}"

    verifier_pub_jwk = _jwk_from_did_jwk(verifier["p256_did"])
    cred_signing_priv_jwk, _ = _generate_ec_p256_jwk_pair()

    verifier_dns_name = verifier.get("x509_dns_name", "acapy-tls-proxy.local")

    config = {
        "server": {
            "verifier_url": verifier["url"],
            "client_id": verifier_dns_name,
            "authorization_endpoint": mdoc_request_uri,
            "response_uri": (
                f"{public_base}/oid4vp/response/"
                f"{verifier['mdoc_vp_request']['presentation_id']}"
            ),
            "jwks": {"keys": [verifier_pub_jwk]},
        },
        "client": {
            "client_id": verifier_dns_name,
        },
        # MDL test doesn't use CreateSdJwtKbCredential, but keep the
        # credential block consistent for future-proofing.
        "credential": {
            "signing_jwk": cred_signing_priv_jwk,
        },
    }
    return plan_name, variant, config


# ── Main ──────────────────────────────────────────────────────────────────────


async def run_all(
    suite_url: str,
    scope: str,
    setup_file: str,
    output_xml: str,
) -> int:
    """Run the configured test plans and return exit code."""

    # Load setup output produced by setup_acapy.py
    try:
        with open(setup_file) as f:
            setup = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.error(f"Cannot load setup file {setup_file}: {exc}")
        return 2

    client = ConformanceSuiteClient(suite_url)
    try:
        await client.wait_until_ready()
    except RuntimeError as exc:
        logger.error(str(exc))
        return 2

    # Discover available test plans to verify connectivity
    available = await client.available_test_plans()
    logger.info(f"Available test plans: {available[:20]} ...")

    # Determine which plans to run.
    # Each entry: (plan_name, variant, config, alias, oid4vp_deeplinks, oid4vci_offers, offer_factory)
    # oid4vp_deeplinks: module_name → openid:// deeplink; None for non-OID4VP plans.
    # oid4vci_offers: module_name → openid-credential-offer:// deeplink; None for non-OID4VCI.
    # offer_factory: async () -> str that creates a fresh offer per module; takes priority.
    plans_to_run: list[
        tuple[
            str,
            dict,
            dict,
            str,
            dict[str, str] | None,
            dict[str, str] | None,
            Any | None,
        ]
    ] = []

    if scope in ("issuer", "all"):
        # OID4VCI issuer tests: the conformance suite acts as a mock wallet.
        # After the module enters WAITING state, we deliver a FRESH credential
        # offer (created by calling ACA-Py admin API) so each module receives
        # its own one-time-use pre-authorized code.
        issuer_info = setup.get("issuer", {})
        # sdjwt_credential_config_id is the ACA-Py internal UUID used by
        # SupportedCredential.retrieve_by_id; sdjwt_identifier is only the
        # human-readable config id used in issuer metadata / conformance config.
        sdjwt_supported_id = issuer_info.get("sdjwt_credential_config_id", "")
        # sdjwt_p256_did is the P-256 DID created for SD-JWT credential signing
        # (uses P-256 so that x5c cert binding works with ES256)
        issuer_did = issuer_info.get(
            "sdjwt_p256_did", issuer_info.get("ed25519_did", "")
        )
        sdjwt_tx_code = issuer_info.get("sdjwt_tx_code", None)
        _admin_url = ACAPY_ISSUER_ADMIN_URL

        async def make_sdjwt_offer(
            _sid=sdjwt_supported_id,
            _did=issuer_did,
            _pin=sdjwt_tx_code,
            _url=_admin_url,
        ) -> str:
            return await create_fresh_offer(
                admin_url=_url,
                supported_cred_id=_sid,
                issuer_did=_did,
                pin=_pin,
            )

        plans_to_run.append(
            (
                *build_oid4vci_issuer_config(setup),
                "acapy-issuer-sdjwt",
                None,  # No OID4VP deeplinks
                None,  # No static oid4vci_offers (using factory instead)
                make_sdjwt_offer,  # Fresh offer factory — called per-module
            )
        )

    if scope in ("verifier", "all"):
        # OID4VP verifier tests: the conformance suite acts as a mock wallet.
        # After each module enters WAITING state, we deliver the pre-created
        # OID4VP authorization request (openid:// deeplink) to the suite's
        # wallet endpoint so it can proceed with the test flow.
        oid4vp_module = "oid4vp-1final-verifier-happy-flow"
        sdjwt_deeplink = (
            setup.get("verifier", {}).get("sdjwt_vp_request", {}).get("request_uri", "")
        )
        mdoc_deeplink = (
            setup.get("verifier", {}).get("mdoc_vp_request", {}).get("request_uri", "")
        )
        plans_to_run.append(
            (
                *build_oid4vp_verifier_sdjwt_config(setup),
                "acapy-verifier-sdjwt",
                {oid4vp_module: sdjwt_deeplink} if sdjwt_deeplink else None,
                None,  # No OID4VCI offers
                None,  # No offer factory
            )
        )
        plans_to_run.append(
            (
                *build_oid4vp_verifier_mdl_config(setup),
                "acapy-verifier-mdl",
                {oid4vp_module: mdoc_deeplink} if mdoc_deeplink else None,
                None,  # No OID4VCI offers
                None,  # No offer factory
            )
        )

    summaries: list[PlanSummary] = []
    overall_passed = True

    for (
        plan_name,
        variant,
        config,
        alias,
        oid4vp_deeplinks,
        oid4vci_offers,
        oid4vci_offer_factory,
    ) in plans_to_run:
        logger.info(f"\n{'=' * 60}")
        logger.info(f"Running plan: {plan_name}  ({alias})")
        logger.info(f"Variant: {json.dumps(variant, indent=2)}")
        logger.info("=" * 60)

        try:
            plan_id = await client.create_plan(plan_name, variant, config, alias=alias)
        except Exception as exc:
            logger.error(f"Failed to create plan {plan_name}: {exc}")
            # Record as a failed plan-level error and continue
            summaries.append(
                PlanSummary(
                    plan_name=plan_name,
                    plan_id="",
                    modules_total=0,
                    modules_passed=0,
                    modules_failed=1,
                    modules_skipped=0,
                    results=[
                        TestResult(
                            plan_id="",
                            plan_name=plan_name,
                            module_name="plan_creation",
                            module_id="",
                            status="INTERRUPTED",
                            result=RESULT_FAILED,
                            duration_ms=0,
                            errors=[str(exc)],
                        )
                    ],
                )
            )
            overall_passed = False
            continue

        results = await client.run_plan(
            plan_id,
            plan_name,
            oid4vp_deeplinks=oid4vp_deeplinks,
            oid4vci_offers=oid4vci_offers,
            oid4vci_offer_factory=oid4vci_offer_factory,
        )

        modules_passed = sum(1 for r in results if r.passed)
        modules_failed = sum(
            1 for r in results if not r.passed and r.result != RESULT_SKIPPED
        )
        modules_skipped = sum(1 for r in results if r.result == RESULT_SKIPPED)

        summary = PlanSummary(
            plan_name=f"{plan_name} ({alias})",
            plan_id=plan_id,
            modules_total=len(results),
            modules_passed=modules_passed,
            modules_failed=modules_failed,
            modules_skipped=modules_skipped,
            results=results,
        )
        summaries.append(summary)

        if not summary.passed:
            overall_passed = False
            logger.error(
                f"FAILED: {modules_failed} module(s) failed in plan {plan_name}"
            )
        else:
            logger.info(
                f"PASSED: {modules_passed}/{len(results)} modules passed in plan {plan_name}"
            )

    await client.close()

    # Write JUnit XML
    write_junit_xml(summaries, output_xml)

    # Print summary table
    logger.info("\n" + "=" * 60)
    logger.info("CONFORMANCE TEST SUMMARY")
    logger.info("=" * 60)
    for s in summaries:
        status_icon = "✅" if s.passed else "❌"
        logger.info(
            f"{status_icon}  {s.plan_name}: "
            f"{s.modules_passed} passed, {s.modules_failed} failed, "
            f"{s.modules_skipped} skipped / {s.modules_total} total"
        )

    return 0 if overall_passed else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--suite-url",
        default=CONFORMANCE_SUITE_URL,
        help="Base URL of the OIDF conformance suite (default: %(default)s)",
    )
    parser.add_argument(
        "--setup-file",
        default=CONFORMANCE_SETUP_OUTPUT,
        help="Path to the ACA-Py setup output JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--output-xml",
        default=CONFORMANCE_OUTPUT_XML,
        help="Path to write JUnit XML results (default: %(default)s)",
    )
    parser.add_argument(
        "--scope",
        choices=["issuer", "verifier", "all"],
        default=CONFORMANCE_SCOPE,
        help="Which test plans to run (default: %(default)s)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    exit_code = asyncio.run(
        run_all(
            suite_url=args.suite_url,
            scope=args.scope,
            setup_file=args.setup_file,
            output_xml=args.output_xml,
        )
    )
    sys.exit(exit_code)
