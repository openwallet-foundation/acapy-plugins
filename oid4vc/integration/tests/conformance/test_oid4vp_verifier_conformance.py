"""
OID4VP Verifier Conformance Tests.

Drives the OIDF ``oid4vp-1final-verifier-test-plan`` against the ACA-Py
verifier service using:
  - SD-JWT VC credentials
  - ISO mDL (mDOC) credentials

Requires:
  - OIDF conformance suite running (``conformance`` Docker profile)
  - ACA-Py services set up via ``conformance/setup_acapy.py``
  - ``$CONFORMANCE_SETUP_OUTPUT`` written with verifier configuration

Run:
    pytest -m conformance tests/conformance/test_oid4vp_verifier_conformance.py -v
"""

import logging

import pytest
import pytest_asyncio

from .conftest import CONFORMANCE_SUITE_URL, run_plan

logger = logging.getLogger(__name__)

PLAN_NAME = "oid4vp-1final-verifier-test-plan"


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture(scope="class")
async def verifier_sdjwt_results(conformance_suite_client, conformance_setup):
    """Run the OID4VP final verifier plan (SD-JWT VC) and cache per-module results."""
    verifier = conformance_setup["verifier"]
    vp_req = verifier["sdjwt_vp_request"]

    variant = {
        "credential_format": "sd_jwt_vc",
        "client_id_prefix": "x509_san_dns",
        "request_method": "request_uri_signed",
        "response_mode": "direct_post",
    }
    config = {
        "server": {
            "verifier_url": verifier["url"],
            "authorization_endpoint": (
                f"{verifier['url']}/oid4vp/request/{vp_req['request_id']}"
            ),
            "response_uri": (
                f"{verifier['url']}/oid4vp/response/{vp_req['presentation_id']}"
            ),
        },
        "client": {
            "client_id": "conformance-suite",
        },
    }
    return await run_plan(
        conformance_suite_client,
        CONFORMANCE_SUITE_URL,
        PLAN_NAME,
        variant,
        config,
        alias="acapy-verifier-sdjwt",
    )


@pytest_asyncio.fixture(scope="class")
async def verifier_mdl_results(conformance_suite_client, conformance_setup):
    """Run the OID4VP final verifier plan (ISO mDL) and cache per-module results."""
    verifier = conformance_setup["verifier"]
    vp_req = verifier["mdoc_vp_request"]

    variant = {
        "credential_format": "iso_mdl",
        "client_id_prefix": "x509_san_dns",
        "request_method": "request_uri_signed",
        "response_mode": "direct_post",
    }
    config = {
        "server": {
            "verifier_url": verifier["url"],
            "authorization_endpoint": (
                f"{verifier['url']}/oid4vp/request/{vp_req['request_id']}"
            ),
            "response_uri": (
                f"{verifier['url']}/oid4vp/response/{vp_req['presentation_id']}"
            ),
        },
        "client": {
            "client_id": "conformance-suite",
            "mdoc_generated_auth_encryption_key": True,
        },
    }
    return await run_plan(
        conformance_suite_client,
        CONFORMANCE_SUITE_URL,
        PLAN_NAME,
        variant,
        config,
        alias="acapy-verifier-mdl",
    )


# ── Test classes ──────────────────────────────────────────────────────────────


@pytest.mark.conformance
class TestOID4VPVerifierSDJWT:
    """OID4VP 1.0 Final verifier conformance — SD-JWT VC credential format.

    The conformance suite acts as a *holder* (wallet) that presents credentials
    to the ACA-Py verifier.  Test modules exercise the full wallet-to-verifier
    flow including authorization request fetching, VP token construction,
    direct_post response, and result validation.
    """

    def _assert_all_pass(self, results: list[dict], label: str) -> None:
        failed = [
            f"{r['module']} → {r['result']}"
            + (f" : {'; '.join(r['errors'][:3])}" if r["errors"] else "")
            for r in results
            if not r["passed"] and r["result"] != "SKIPPED"
        ]
        assert not failed, (
            f"{label}: {len(failed)} module(s) did not pass:\n"
            + "\n".join(f"  - {f}" for f in failed)
        )

    async def test_all_modules_pass(self, verifier_sdjwt_results):
        """All OID4VP verifier test modules pass for SD-JWT VC format."""
        self._assert_all_pass(verifier_sdjwt_results, "verifier-sdjwt")

    async def test_at_least_one_module_ran(self, verifier_sdjwt_results):
        """The plan ran at least one test module (sanity check)."""
        assert len(verifier_sdjwt_results) > 0, (
            f"No test modules returned for plan '{PLAN_NAME}' (SD-JWT). "
            "Check that the conformance suite supports 'sd_jwt_vc' credential format."
        )

    async def test_authorization_request_module(self, verifier_sdjwt_results):
        """Authorization request / request_uri module passes."""
        auth_modules = [
            r
            for r in verifier_sdjwt_results
            if "authorization" in r["module"].lower()
            or "request" in r["module"].lower()
        ]
        failed = [
            r for r in auth_modules if not r["passed"] and r["result"] != "SKIPPED"
        ]
        assert not failed, (
            f"Authorization request module(s) failed: {[r['module'] for r in failed]}"
        )

    async def test_response_module(self, verifier_sdjwt_results):
        """Direct_post response module passes."""
        resp_modules = [
            r for r in verifier_sdjwt_results if "response" in r["module"].lower()
        ]
        failed = [
            r for r in resp_modules if not r["passed"] and r["result"] != "SKIPPED"
        ]
        assert not failed, f"Response module(s) failed: {[r['module'] for r in failed]}"


@pytest.mark.conformance
class TestOID4VPVerifierMdl:
    """OID4VP 1.0 Final verifier conformance — ISO 18013-5 mDL credential format.

    Tests ACA-Py's ability to request and verify ISO mDL presentations using the
    OID4VP direct_post response mode.
    """

    def _assert_all_pass(self, results: list[dict], label: str) -> None:
        failed = [
            f"{r['module']} → {r['result']}"
            for r in results
            if not r["passed"] and r["result"] != "SKIPPED"
        ]
        assert not failed, (
            f"{label}: {len(failed)} module(s) did not pass:\n"
            + "\n".join(f"  - {f}" for f in failed)
        )

    async def test_all_modules_pass(self, verifier_mdl_results):
        """All OID4VP verifier test modules pass for ISO mDL format."""
        self._assert_all_pass(verifier_mdl_results, "verifier-mdl")

    async def test_at_least_one_module_ran(self, verifier_mdl_results):
        """The plan ran at least one test module."""
        assert len(verifier_mdl_results) > 0, (
            f"No test modules returned for plan '{PLAN_NAME}' (mDL). "
            "Verify that mDL credential format is supported by the suite variant."
        )
