# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.134.0/containers/python-3/.devcontainer/base.Dockerfile
ARG VARIANT="3.12"
FROM mcr.microsoft.com/devcontainers/python:${VARIANT}

ARG GITHUB_TOKEN

ARG POETRY_VERSION="1.8.3"
ENV POETRY_HOME="/opt/poetry" \
    POETRY_VERSION=${POETRY_VERSION}

RUN curl -sSL https://install.python-poetry.org | python3 - \
    && update-alternatives --install /usr/local/bin/poetry poetry /opt/poetry/bin/poetry 900 \
    # Enable tab completion for bash
    && poetry completions bash >> /home/vscode/.bash_completion \
    # Enable tab completion for Zsh
    && mkdir -p /home/vscode/.zfunc/ \
    && poetry completions zsh > /home/vscode/.zfunc/_poetry \
    && echo "fpath+=~/.zfunc\nautoload -Uz compinit && compinit" >> /home/vscode/.zshrc

# Install sdkman: https://sdkman.io/install
ENV SDKMAN_DIR="/usr/local/sdkman"
RUN curl -s "https://get.sdkman.io" | bash

# Update shell in order to properly execute "source"
SHELL ["/bin/bash", "-c"]

# Install Temurin JDK 21
RUN source "/usr/local/sdkman/bin/sdkman-init.sh" && sdk install java 21.0.2-tem

ENV JAVA_HOME=/usr/local/sdkman/candidates/java/current
ENV PATH=$JAVA_HOME/bin:$PATH

COPY pyproject.toml ./

RUN poetry config virtualenvs.create false \
    && poetry config repositories.did-sdk-py https://github.com/hashgraph/did-sdk-py \
    && poetry config http-basic.did-sdk-py x-token-auth $GITHUB_TOKEN

RUN poetry install --no-root --no-interaction --with integration --extras "aca-py" \
    && rm -rf /root/.cache/pypoetry
