FROM python:3.12-slim-bookworm AS base
WORKDIR /usr/src/app

ENV POETRY_VERSION=1.5.0
ENV POETRY_HOME=/opt/poetry
RUN apt-get update && apt-get install -y curl jq && apt-get clean
RUN curl -sSL https://install.python-poetry.org | python -

ENV PATH="/opt/poetry/bin:$PATH"
RUN poetry config virtualenvs.in-project true

# Setup project
COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --only main

# add tests to image
COPY tests/* tests/

ENTRYPOINT ["poetry", "run", "pytest"]