FROM python:3.12-slim-bullseye AS base

ARG GITHUB_TOKEN

WORKDIR /usr/src/app

# Install and configure poetry
USER root

WORKDIR /usr/src/app
ENV POETRY_VERSION=1.7.1
ENV POETRY_HOME=/opt/poetry
RUN apt-get update && apt-get install -y curl wget git && apt-get clean 
RUN curl -sSL https://install.python-poetry.org | python -

ENV PATH="/opt/poetry/bin:$PATH"

RUN poetry config virtualenvs.in-project true \
    && poetry config repositories.did-sdk-py https://github.com/hashgraph/did-sdk-py \
    && poetry config http-basic.did-sdk-py x-token-auth $GITHUB_TOKEN

# Setup project
RUN mkdir hedera_did && touch hedera_did/__init__.py
COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --without dev --with integration --all-extras \
    && rm -rf /root/.cache/pypoetry

USER $user

FROM python:3.12-bullseye

RUN apt-get update && apt-get install -y zip && apt-get clean 

# Install sdkman: https://sdkman.io/install
ENV SDKMAN_DIR="/usr/local/sdkman"
RUN curl -s "https://get.sdkman.io" | bash

# Update shell in order to properly execute "source"
SHELL ["/bin/bash", "-c"]

# Install Temurin JDK 21
RUN source "/usr/local/sdkman/bin/sdkman-init.sh" && sdk install java 21.0.5-tem

ENV JAVA_HOME=/usr/local/sdkman/candidates/java/current
ENV PATH=$JAVA_HOME/bin:$PATH

WORKDIR /usr/src/app
COPY --from=base /usr/src/app/.venv /usr/src/app/.venv
ENV PATH="/usr/src/app/.venv/bin:$PATH"

COPY hedera_did/ hedera_did/
COPY docker/*.yml ./

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]
