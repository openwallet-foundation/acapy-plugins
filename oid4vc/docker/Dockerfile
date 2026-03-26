# =============================================================================
# Stage 0: Build isomdl-uniffi from source (Rust + maturin)
# =============================================================================
FROM python:3.13-slim-bookworm AS isomdl-builder

# Install Rust toolchain dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (stable)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# Accept branch, tag, or commit ref to build from
ARG ISOMDL_BRANCH=main

RUN git clone --depth 1 --branch "${ISOMDL_BRANCH}" \
    https://github.com/Indicio-tech/isomdl-uniffi.git /build/isomdl-uniffi

WORKDIR /build/isomdl-uniffi/python

RUN pip install --no-cache-dir "maturin>=1.0,<2.0"
RUN maturin build --release --out /build/dist

# =============================================================================
# Stage 1: Install ACA-Py and plugin dependencies
# =============================================================================
FROM python:3.13-slim-bookworm AS base

WORKDIR /usr/src/app

# Install only required build/runtime dependencies (no Rust needed here)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    git \
    && rm -rf /var/lib/apt/lists/*

# Accept build argument for ACA-Py version
ARG ACAPY_VERSION=1.5.1

# Clone ACA-Py source with shallow clone
RUN git clone --depth 1 --branch ${ACAPY_VERSION} \
    https://github.com/openwallet-foundation/acapy.git /usr/src/acapy

WORKDIR /usr/src/acapy

# Install ACA-Py
RUN pip install --no-cache-dir -e .
RUN pip install --no-cache-dir configargparse

# Setup plugin project structure
WORKDIR /usr/src/app

# Copy the entire plugin source tree
COPY oid4vc/pyproject.toml ./
COPY oid4vc/README.md ./
COPY oid4vc/oid4vc/ oid4vc/
COPY oid4vc/jwt_vc_json/ jwt_vc_json/
COPY oid4vc/mso_mdoc/ mso_mdoc/
COPY oid4vc/sd_jwt_vc/ sd_jwt_vc/
COPY status_list/ status_list/
RUN pip install -e ./status_list

# Install isomdl-uniffi from locally built wheel
COPY --from=isomdl-builder /build/dist/*.whl /tmp/isomdl/
RUN pip install --no-cache-dir /tmp/isomdl/*.whl && rm -rf /tmp/isomdl

# Install the plugin with extras for mso_mdoc and sd_jwt_vc
RUN pip install --no-cache-dir -e ".[mso_mdoc,sd_jwt_vc]"

# =============================================================================
# Stage 3: Final slim runtime image
# =============================================================================
FROM python:3.13-slim-bookworm

WORKDIR /usr/src/app

# Copy the complete environment from base stage
COPY --from=base /usr/src/acapy /usr/src/acapy
COPY --from=base /usr/src/app /usr/src/app

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy the entire Python environment from base stage, including site-packages
COPY --from=base /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=base /usr/local/bin /usr/local/bin

# Copy dev config
RUN mkdir -p /usr/src/app/docker
COPY oid4vc/docker/dev.yml /usr/src/app/docker/dev.yml
COPY oid4vc/docker/dev-verifier.yml /usr/src/app/docker/dev-verifier.yml
COPY oid4vc/docker/default.yml /usr/src/app/docker/default.yml

# Expose ports
EXPOSE 8030 8031 8032

# Add health check
HEALTHCHECK --interval=10s --timeout=5s --retries=12 --start-period=60s \
  CMD curl -f http://localhost:${ACAPY_ADMIN_PORT:-8021}/status/ready || exit 1

# Set working directory and run ACA-Py
WORKDIR /usr/src/acapy
CMD ["python", "-m", "acapy_agent", "start", "--arg-file", "/usr/src/app/docker/dev.yml"]
