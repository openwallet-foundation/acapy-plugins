# Dockerfile for ACA-Py with all plugins
ARG ACA_PY_VERSION
ARG REPO_OWNER
FROM ghcr.io/openwallet-foundation/acapy-agent:py3.12-${ACA_PY_VERSION}

# Redeclare build args for use in RUN commands
ARG ACA_PY_VERSION
ARG REPO_OWNER

USER root

# Install plugins with --no-deps to avoid dependency conflicts
RUN pip install --no-deps \
    git+https://github.com/${REPO_OWNER}/acapy-plugins@${ACA_PY_VERSION}#subdirectory=basicmessage_storage \
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

# Set entrypoint
ENTRYPOINT ["aca-py", "start"]
