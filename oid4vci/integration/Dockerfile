FROM python:3.9-slim-bookworm AS base
WORKDIR /usr/src/app

ENV POETRY_VERSION=1.5.0
ENV POETRY_HOME=/opt/poetry
RUN apt-get update && apt-get install -y curl jq && apt-get clean
RUN curl -sSL https://install.python-poetry.org | python -

ENV PATH="/opt/poetry/bin:$PATH"
RUN poetry config virtualenvs.in-project true

# Setup project
RUN mkdir oid4vci_client && touch oid4vci_client/__init__.py
COPY pyproject.toml poetry.lock README.md ./
RUN poetry install

COPY oid4vci_client/ oid4vci_client/
COPY tests/ tests/

ENTRYPOINT ["poetry", "run", "pytest"]
