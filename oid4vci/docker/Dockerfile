FROM python:3.9-slim-bullseye AS base
USER root

# Install jwt_vc_json plugin
WORKDIR /usr/src
RUN mkdir jwt_vc_json
COPY jwt_vc_json jwt_vc_json

# Install and configure poetry
WORKDIR /usr/src/app
ENV POETRY_VERSION=1.7.1
ENV POETRY_HOME=/opt/poetry
RUN apt-get update && apt-get install -y curl jq && apt-get clean
RUN curl -sSL https://install.python-poetry.org | python -

ENV PATH="/opt/poetry/bin:$PATH"
RUN poetry config virtualenvs.in-project true

# Setup project
RUN mkdir oid4vci && touch oid4vci/__init__.py
COPY oid4vci/pyproject.toml oid4vci/poetry.lock oid4vci/README.md ./
RUN poetry install --without dev --all-extras
USER $user

FROM python:3.9-bullseye

WORKDIR /usr/src/app
COPY --from=base /usr/src/app/.venv /usr/src/app/.venv
ENV PATH="/usr/src/app/.venv/bin:$PATH"
RUN apt-get update && apt-get install -y curl jq && apt-get clean
COPY oid4vci/oid4vci/ oid4vci/
COPY oid4vci/docker/*.yml ./

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]
