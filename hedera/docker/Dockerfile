FROM python:3.12-slim-bookworm AS base

ARG GITHUB_TOKEN

WORKDIR /usr/src/app

# Install and configure poetry
USER root

WORKDIR /usr/src/app
ENV POETRY_VERSION=2.1.2
ENV POETRY_HOME=/opt/poetry
RUN apt-get update && apt-get install -y curl wget git && apt-get clean 
RUN curl -sSL https://install.python-poetry.org | python -

ENV PATH="/opt/poetry/bin:$PATH"
ENV PDM_BUILD_SCM_VERSION="0.1.0"

RUN poetry config virtualenvs.in-project true

# Setup project
RUN mkdir hedera && touch hedera/__init__.py
COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --without dev --with integration --all-extras \
    && rm -rf /root/.cache/pypoetry

USER $user

FROM python:3.12-bookworm

WORKDIR /usr/src/app
COPY --from=base /usr/src/app/.venv /usr/src/app/.venv
ENV PATH="/usr/src/app/.venv/bin:$PATH"

COPY hedera/ hedera/
COPY docker/*.yml ./

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]
