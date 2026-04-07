FROM python:3.13-slim-bookworm AS base

WORKDIR /usr/src/app

# Install system dependencies
RUN apt-get update && apt-get install -y curl jq postgresql-client && apt-get clean

# Install Poetry
ENV POETRY_VERSION=2.1.2
RUN curl -sSL https://install.python-poetry.org | python3 -
ENV PATH="/root/.local/bin:$PATH"

# Copy project files
COPY pyproject.toml poetry.lock ./
COPY admin/ admin/
COPY tenant/ tenant/
COPY core/ core/
COPY resources/ resources/
COPY alembic/ alembic/
COPY README.md ./

# Install Python dependencies
RUN poetry install --no-interaction --no-ansi --without dev

# Set environment variable for Alembic DB URL (can be overridden at runtime)
ENV ALEMBIC_DB_URL=""
ENV ALEMBIC_DB_SCHEMA="admin"

# Entrypoint script to initialize DB and run servers
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
