"""
OID4VCI Issuer Conformance Tests.

Drives the OIDF ``oid4vci-1_0-issuer-test-plan`` against the ACA-Py issuer
using the pre-authorization code grant with SD-JWT VC credentials.

Requires:
  - OIDF conformance suite running (``conformance`` Docker profile)
  - ACA-Py services set up via ``conformance/setup_acapy.py``
  - ``$CONFORMANCE_SETUP_OUTPUT`` written with issuer configuration

Run:
    pytest -m conformance tests/conformance/test_oid4vci_issuer_conformance.py -v
"""

import logging

import pytest
import pytest_asyncio

from .conftest import CONFORMANCE_SUITE_URL, run_plan

logger = logging.getLogger(__name__)

PLAN_NAME = "oid4vci-1_0-issuer-test-plan"


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture(scope="class")
async def issuer_sdjwt_results(conformance_suite_client, conformance_setup):
    """Run the OID4VCI 1.0 issuer plan (SD-JWT VC) and cache the per-module results."""
    issuer = conformance_setup["issuer"]
    variant = {
        "vci_grant_type": "pre_authorization_code",
        "vci_credential_offer_variant": "by_value",
        "vci_credential_issuance_mode": "immediate",
        "credential_format": "sd_jwt_vc",
        "vci_credential_encryption": "plain",
    }
    config = {
        "server": {
            "issuer": issuer["url"],
            "credential_endpoint": f"{issuer['url']}/credential",
            "token_endpoint": f"{issuer['url']}/token",
            "notification_endpoint": f"{issuer['url']}/notification",
            "openid_credential_issuer_discovery_url": (
                f"{issuer['url']}/.well-known/openid-credential-issuer"
            ),
        },
        "credential_offer": {
            "credential_offer": issuer["sdjwt_offer"]["offer_uri"],
        },
        "resource": {
            "resourceUrl": f"{issuer['url']}/credential",
            "credential_configuration_id": issuer["sdjwt_credential_config_id"],
        },
    }
    return await run_plan(
        conformance_suite_client,
        CONFORMANCE_SUITE_URL,
        PLAN_NAME,
        variant,
        config,
        alias="acapy-issuer-sdjwt",
    )


@pytest_asyncio.fixture(scope="class")
async def issuer_mdoc_results(conformance_suite_client, conformance_setup):
    """Run the OID4VCI 1.0 issuer plan (ISO mDL / mDOC) and cache the results."""
    issuer = conformance_setup["issuer"]
    variant = {
        "vci_grant_type": "pre_authorization_code",
        "vci_credential_offer_variant": "by_value",
        "vci_credential_issuance_mode": "immediate",
        "credential_format": "mso_mdoc",
        "vci_credential_encryption": "plain",
    }
    config = {
        "server": {
            "issuer": issuer["url"],
            "credential_endpoint": f"{issuer['url']}/credential",
            "token_endpoint": f"{issuer['url']}/token",
            "openid_credential_issuer_discovery_url": (
                f"{issuer['url']}/.well-known/openid-credential-issuer"
            ),
        },
        "credential_offer": {
            "credential_offer": issuer["mdoc_offer"]["offer_uri"],
        },
        "resource": {
            "resourceUrl": f"{issuer['url']}/credential",
            "credential_configuration_id": issuer["mdoc_credential_config_id"],
        },
    }
    return await run_plan(
        conformance_suite_client,
        CONFORMANCE_SUITE_URL,
        PLAN_NAME,
        variant,
        config,
        alias="acapy-issuer-mdoc",
    )


# ── Test classes ──────────────────────────────────────────────────────────────


@pytest.mark.conformance
class TestOID4VCIIssuerSDJWT:
    """OID4VCI 1.0 issuer conformance — SD-JWT VC credential format.

    Each test method below exercises a logical group of test modules returned
    by the conformance suite.  A single assertion failure reports the exact
    modules that did not pass so the developer can cross-reference the
    conformance suite UI at $CONFORMANCE_SUITE_URL.
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

    async def test_all_modules_pass(self, issuer_sdjwt_results):
        """All OID4VCI issuer test modules pass for SD-JWT VC format."""
        self._assert_all_pass(issuer_sdjwt_results, "issuer-sdjwt")

    async def test_at_least_one_module_ran(self, issuer_sdjwt_results):
        """The plan ran at least one test module (sanity check for suite connectivity)."""
        assert len(issuer_sdjwt_results) > 0, (
            f"No test modules were returned for plan '{PLAN_NAME}' (SD-JWT). "
            "Check that the OIDF conformance suite is running and that the plan "
            "name is correct."
        )

    async def test_discovery_metadata_module(self, issuer_sdjwt_results):
        """Discovery / metadata module passes."""
        discovery_modules = [
            r
            for r in issuer_sdjwt_results
            if "discovery" in r["module"].lower() or "metadata" in r["module"].lower()
        ]
        failed = [r for r in discovery_modules if not r["passed"]]
        assert not failed, (
            f"Discovery/metadata module(s) failed: {[r['module'] for r in failed]}"
        )

    async def test_token_endpoint_module(self, issuer_sdjwt_results):
        """Token endpoint module passes (pre-authorized code grant)."""
        token_modules = [
            r for r in issuer_sdjwt_results if "token" in r["module"].lower()
        ]
        failed = [r for r in token_modules if not r["passed"]]
        assert not failed, (
            f"Token endpoint module(s) failed: {[r['module'] for r in failed]}"
        )

    async def test_credential_endpoint_module(self, issuer_sdjwt_results):
        """Credential endpoint module passes."""
        cred_modules = [
            r
            for r in issuer_sdjwt_results
            if "credential" in r["module"].lower()
            and "offer" not in r["module"].lower()
        ]
        failed = [r for r in cred_modules if not r["passed"]]
        assert not failed, (
            f"Credential endpoint module(s) failed: {[r['module'] for r in failed]}"
        )


@pytest.mark.conformance
class TestOID4VCIIssuerMdoc:
    """OID4VCI 1.0 issuer conformance — ISO mDL / mDOC credential format."""

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

    async def test_all_modules_pass(self, issuer_mdoc_results):
        """All OID4VCI issuer test modules pass for mDOC format."""
        self._assert_all_pass(issuer_mdoc_results, "issuer-mdoc")

    async def test_at_least_one_module_ran(self, issuer_mdoc_results):
        """The plan ran at least one test module."""
        assert len(issuer_mdoc_results) > 0, (
            "No test modules returned for issuer-mdoc plan. "
            "Verify that the mDOC credential format is supported by the suite variant."
        )
