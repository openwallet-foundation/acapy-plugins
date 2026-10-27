# isomdl-uniffi release used for mdoc support. Indicio publishes a Linux wheel
# for amd64 only; arm64 builds the same release from source.
ARG ISOMDL_VERSION=v0.1.0-indicio.1

FROM python:3.13-slim-bookworm AS base
WORKDIR /usr/src/app

# Install and configure poetry
USER root

# Install and configure poetry
WORKDIR /usr/src/app
ENV POETRY_VERSION=2.1.2
ENV POETRY_HOME=/opt/poetry
RUN apt-get update && apt-get install -y curl jq && apt-get clean
RUN curl -sSL https://install.python-poetry.org | python -

ENV PATH="/opt/poetry/bin:$PATH"
RUN poetry config virtualenvs.in-project true

# Setup project
RUN mkdir oid4vc && touch oid4vc/__init__.py
RUN mkdir jwt_vc_json && touch jwt_vc_json/__init__.py
RUN mkdir sd_jwt_vc && touch sd_jwt_vc/__init__.py
RUN mkdir mso_mdoc && touch mso_mdoc/__init__.py
RUN mkdir status_list && touch status_list/__init__.py
RUN mkdir mso_mdoc/isomdl
RUN mkdir -p keycloak/oid4vc_keycloak && touch keycloak/oid4vc_keycloak/__init__.py
COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --without dev --all-extras

ARG TARGETARCH
ARG ISOMDL_VERSION
RUN mkdir -p isomdl-uniffi/python/isomdl_uniffi && \
    if [ "$TARGETARCH" = "arm64" ]; then \
        apt-get update && apt-get install -y git build-essential && apt-get clean && \
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
        rm -rf isomdl-uniffi && \
        git clone --depth 1 --branch "$ISOMDL_VERSION" https://github.com/Indicio-tech/isomdl-uniffi.git && \
        cd isomdl-uniffi/python && PATH="/root/.cargo/bin:$PATH" python build.py; \
    fi

USER $user

FROM python:3.13-bookworm

ARG TARGETARCH
ARG ISOMDL_VERSION

WORKDIR /usr/src/app
COPY --from=base /usr/src/app/.venv /usr/src/app/.venv
ENV PATH="/usr/src/app/.venv/bin:$PATH"
RUN apt-get update && apt-get install -y curl jq && apt-get clean
COPY jwt_vc_json/ jwt_vc_json/
COPY mso_mdoc/ mso_mdoc/
COPY sd_jwt_vc/ sd_jwt_vc/
COPY oid4vc/ oid4vc/
COPY keycloak/oid4vc_keycloak/ keycloak/oid4vc_keycloak/
ADD https://github.com/openwallet-foundation/acapy-plugins.git#main:status_list/status_list/ status_list/
COPY docker/*.yml ./


# isomdl-uniffi: the release wheel on amd64, the bindings built in the base
# stage on arm64 (an empty directory on amd64).
COPY --from=base /usr/src/app/isomdl-uniffi/python/isomdl_uniffi /usr/src/app/mso_mdoc/isomdl
ENV PYTHONPATH="/usr/src/app/mso_mdoc/isomdl:$PYTHONPATH"
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        wheel_version="${ISOMDL_VERSION#v}"; wheel_version="${wheel_version%%-*}"; \
        pip install --no-cache-dir "https://github.com/Indicio-tech/isomdl-uniffi/releases/download/${ISOMDL_VERSION}/isomdl_uniffi-${wheel_version}-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"; \
    elif [ "$TARGETARCH" != "arm64" ]; then \
        echo "Unsupported architecture: $TARGETARCH"; \
        exit 1; \
    fi

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]
