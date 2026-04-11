FROM python:3.13-slim-bookworm AS base
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
RUN mkdir mso_mdoc/isomdl
COPY pyproject.toml poetry.lock README.md ./
RUN poetry install --without dev --all-extras

#build the isomdl library from indicio. Tempory solution until we have a wheel on pypi with linux arm support
RUN apt-get update && apt-get install -y git build-essential && apt-get clean
RUN git clone https://github.com/Indicio-tech/isomdl-uniffi.git
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /usr/src/app/isomdl-uniffi/python
RUN python build.py

USER $user

FROM python:3.13-bookworm

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

#Install the isomdl library built in the base stage. 
COPY --from=base /usr/src/app/isomdl-uniffi/python/isomdl_uniffi /usr/src/app/mso_mdoc/isomdl
ENV PYTHONPATH="/usr/src/app/mso_mdoc/isomdl:$PYTHONPATH"

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]
