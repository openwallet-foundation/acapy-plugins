# Dockerfile for ACA-Py with all plugins
ARG PYTHON_VERSION
FROM python:${PYTHON_VERSION}-slim-bookworm

# Redeclare build args for use in RUN commands
ARG REPO_OWNER
ARG ACA_PY_VERSION

USER root

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libsqlcipher-dev \
    && rm -rf /var/lib/apt/lists/*

# Install ACA-Py
RUN pip install acapy-agent==${ACA_PY_VERSION}

# Create acapy user
RUN useradd -m -s /bin/bash acapy

# Install plugins with --no-deps to avoid dependency conflicts
RUN pip install --no-deps \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=basicmessage_storage \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=cache_redis \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=cheqd \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=connection_update \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=connections \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=firebase_push_notifications \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=hedera \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=multitenant_provider \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=oid4vc \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=redis_events \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=rpc \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=status_list \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=webvh

USER acapy
WORKDIR /home/acapy

# Set entrypoint
ENTRYPOINT ["aca-py", "start"]
