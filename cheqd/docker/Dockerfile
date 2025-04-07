FROM python:3.12-slim-bookworm AS base
WORKDIR /usr/src/app

# Install and configure poetry
USER root

ENV POETRY_VERSION=2.1.2
ENV POETRY_HOME=/opt/poetry
RUN apt-get update && apt-get install -y curl && apt-get clean
RUN curl -sSL https://install.python-poetry.org | python -

ENV PATH="/opt/poetry/bin:$PATH"
RUN poetry config virtualenvs.in-project true

# Setup project
RUN mkdir cheqd && touch cheqd/__init__.py
COPY pyproject.toml poetry.lock README.md ./
ARG install_flags='--with integration --extras aca-py'
RUN poetry install ${install_flags}
USER $user

FROM python:3.12-bookworm
WORKDIR /usr/src/app
COPY --from=base /usr/src/app/.venv /usr/src/app/.venv
ENV PATH="/usr/src/app/.venv/bin:$PATH"

COPY cheqd/ cheqd/
COPY docker/*.yml ./

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
# CMD ["start", "--arg-file", "integration.yml"]
