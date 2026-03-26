FROM python:3.12-slim-bookworm AS base
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y curl jq git && apt-get clean

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:$PATH"

# Setup project
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen

# Copy integration test components
COPY credo_wrapper/ credo_wrapper/
COPY tests/ tests/
COPY oid4vci_client/ oid4vci_client/
COPY acapy_controller.py ./

# Create test results directory
RUN mkdir -p test-results

# Default entrypoint for running tests
ENTRYPOINT ["uv", "run", "pytest"]
