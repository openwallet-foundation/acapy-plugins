# Dockerfile for ACA-Py with all plugins
FROM ghcr.io/openwallet-foundation/acapy-agent:py3.12-${ACA_PY_VERSION}

USER root

# Install uv for faster package management
RUN pip install uv

# Install plugins from root pyproject.toml using uv
RUN uv pip install --force-reinstall --no-deps .[plugins]

USER acapy

# Set entrypoint
ENTRYPOINT ["aca-py", "start"]
