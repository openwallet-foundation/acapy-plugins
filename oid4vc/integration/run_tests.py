#!/usr/bin/env python3
"""OID4VC Integration Test Runner.

This script orchestrates the complete OID4VC v1 integration test suite:
- ACA-Py issuer (issues mso_mdoc and SD-JWT credentials)
- Credo holder/verifier (receives credentials, presents them)
- ACA-Py verifier (validates presentations via OID4VC plugin)

Usage:
    python run_tests.py [--docker] [--quick] [--type {mdoc,sdjwt,all}] [--help]

Options:
    --docker         Use docker-compose to run the full stack
    --quick          Run only core interop tests (skip extended scenarios)
    --type TYPE      Run tests for specific credential type (mdoc, sdjwt, or all)
    --help           Show help message

Test Flow:
1. ACA-Py issues credential to Credo
2. Credo presents credential to ACA-Py
3. ACA-Py validates presentation via OID4VC plugin

Both mso_mdoc (ISO 18013-5) and SD-JWT credential formats are tested.
"""

import argparse
import asyncio
import logging
import subprocess
import sys
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(Path(__file__).parent / "test-results" / "test_run.log"),
    ],
)
LOGGER = logging.getLogger(__name__)


class IntegrationTestRunner:
    """OID4VC Integration Test Suite Runner."""

    def __init__(
        self,
        use_docker: bool = False,
        quick_mode: bool = False,
        credential_type: str = "all",
    ):
        """Initialize test runner."""
        self.use_docker = use_docker
        self.quick_mode = quick_mode
        self.credential_type = credential_type
        self.test_results = {}

        # Ensure test results directory exists
        results_dir = Path(__file__).parent / "test-results"
        results_dir.mkdir(exist_ok=True)

    async def check_services_health(self) -> bool:
        """Check if all required services are healthy."""
        services = {
            "ACA-Py Issuer": "http://localhost:8021/status/live",
            "Credo Agent": "http://localhost:3020/health",
            "ACA-Py Verifier": "http://localhost:8031/status/live",
            "ACA-Py OID4VP": "http://localhost:8032/.well-known/openid_configuration",
        }

        import httpx

        for service_name, url in services.items():
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(url, timeout=5.0)
                    if response.status_code == 200:
                        LOGGER.info("✓ %s is healthy", service_name)
                    else:
                        LOGGER.error(
                            "✗ %s returned status %d",
                            service_name,
                            response.status_code,
                        )
                        return False
            except Exception as e:
                LOGGER.error("✗ %s is not accessible: %s", service_name, e)
                return False

        return True

    def run_docker_tests(self) -> bool:
        """Run tests using docker-compose."""
        LOGGER.info("Running integration tests with docker-compose...")

        try:
            # Build and start services
            LOGGER.info("Building and starting services...")
            subprocess.run(
                ["docker-compose", "up", "--build", "-d"],
                check=True,
                cwd=Path(__file__).parent,
            )

            # Docker Compose handles healthchecks via depends_on conditions
            # Services will wait for dependencies to be healthy before starting
            LOGGER.info("Services started, docker-compose managing healthchecks...")

            # Run tests
            test_cmd = ["docker-compose", "run", "--rm", "test-river"]

            if self.credential_type != "all":
                test_cmd.extend(["-m", self.credential_type])

            if self.quick_mode:
                test_cmd.extend(["-k", "not extended"])

            LOGGER.info("Running tests: %s", " ".join(test_cmd))
            result = subprocess.run(test_cmd, cwd=Path(__file__).parent)

            return result.returncode == 0

        except subprocess.CalledProcessError as e:
            LOGGER.error("Docker command failed: %s", e)
            return False
        finally:
            # Clean up
            LOGGER.info("Cleaning up services...")
            subprocess.run(
                ["docker-compose", "down", "-v"],
                cwd=Path(__file__).parent,
                capture_output=True,
            )

    async def run_local_tests(self) -> bool:
        """Run tests against locally running services."""
        LOGGER.info("Running integration tests against local services...")

        # Check services are running
        if not await self.check_services_health():
            LOGGER.error("Not all services are healthy. Please start services first.")
            LOGGER.info("To start services locally:")
            LOGGER.info("  cd credo && npm start &")
            LOGGER.info("  cd ../.. && make dev-watch &")
            return False

        # Run tests with uv
        test_cmd = ["uv", "run", "pytest", "tests/", "-v"]

        if self.credential_type != "all":
            test_cmd.extend(["-m", self.credential_type])

        if self.quick_mode:
            test_cmd.extend(["-k", "not extended"])

        # Add test reporting
        results_dir = Path(__file__).parent / "test-results"
        test_cmd.extend(
            [
                f"--junitxml={results_dir}/junit.xml",
                f"--html={results_dir}/report.html",
                "--self-contained-html",
            ]
        )

        LOGGER.info("Running tests: %s", " ".join(test_cmd))
        result = subprocess.run(test_cmd, cwd=Path(__file__).parent)

        return result.returncode == 0

    async def run_tests(self) -> bool:
        """Run the complete test suite."""
        LOGGER.info("Starting OID4VC Integration Test Suite")
        LOGGER.info("Configuration:")
        LOGGER.info("  Docker mode: %s", self.use_docker)
        LOGGER.info("  Quick mode: %s", self.quick_mode)
        LOGGER.info("  Credential type: %s", self.credential_type)

        if self.use_docker:
            success = self.run_docker_tests()
        else:
            success = await self.run_local_tests()

        if success:
            LOGGER.info("✓ All tests passed!")
        else:
            LOGGER.error("✗ Some tests failed!")

        return success


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="OID4VC Integration Test Runner")
    parser.add_argument(
        "--docker", action="store_true", help="Use docker-compose to run the full stack"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run only core interop tests (skip extended scenarios)",
    )
    parser.add_argument(
        "--type",
        choices=["mdoc", "sdjwt", "all"],
        default="all",
        help="Run tests for specific credential type",
    )

    args = parser.parse_args()

    runner = IntegrationTestRunner(
        use_docker=args.docker, quick_mode=args.quick, credential_type=args.type
    )

    success = asyncio.run(runner.run_tests())
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
