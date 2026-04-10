FROM --platform=linux/amd64 python:3.13-slim-bookworm AS base
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
COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --without dev --all-extras
RUN .venv/bin/pip install --no-deps https://github.com/Indicio-tech/isomdl-uniffi/releases/download/v0.1.0-indicio.1/isomdl_uniffi-0.1.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
USER $user

FROM --platform=linux/amd64 python:3.13-bookworm

WORKDIR /usr/src/app
COPY --from=base /usr/src/app/.venv /usr/src/app/.venv
ENV PATH="/usr/src/app/.venv/bin:$PATH"
RUN apt-get update && apt-get install -y curl jq && apt-get clean
COPY jwt_vc_json/ jwt_vc_json/
COPY mso_mdoc/ mso_mdoc/
COPY sd_jwt_vc/ sd_jwt_vc/
COPY oid4vc/ oid4vc/
ADD https://github.com/openwallet-foundation/acapy-plugins.git#main:status_list/status_list/ status_list/
COPY docker/*.yml ./

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]
