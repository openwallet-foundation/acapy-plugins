FROM python:3.9-slim AS base
USER root

# Install oid4vci plugin
WORKDIR /usr/src
RUN mkdir oid4vci
COPY oid4vci oid4vci

# Install and configure poetry
WORKDIR /usr/src/app
ENV POETRY_VERSION=1.7.1
ENV POETRY_HOME=/opt/poetry
RUN apt-get update && apt-get install -y curl && apt-get clean
RUN curl -sSL https://install.python-poetry.org | python -

ENV PATH="/opt/poetry/bin:$PATH"
RUN poetry config virtualenvs.in-project true

# Setup project
RUN mkdir jwt_vc_json && touch jwt_vc_json/__init__.py
COPY jwt_vc_json/pyproject.toml jwt_vc_json/poetry.lock jwt_vc_json/README.md ./
ARG install_flags='--with integration --all-extras'
RUN poetry install ${install_flags}
USER $user

FROM python:3.9-bullseye
WORKDIR /usr/src/app
COPY --from=base /usr/src/app/.venv /usr/src/app/.venv
ENV PATH="/usr/src/app/.venv/bin:$PATH"

COPY jwt_vc_json/jwt_vc_json/ jwt_vc_json/
COPY jwt_vc_json/docker/*.yml ./

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]