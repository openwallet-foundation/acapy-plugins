# syntax=docker/dockerfile:1

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

# isomdl-uniffi isn't on PyPI and can't be a poetry dependency (it requires
# a Rust toolchain to build). Build from source against the
# feat/mso-status-claim branch (adds MSO-level status-claim support for
# revocable mdoc issuance, not yet in a released wheel).
#
# NOTE: upstream main normally installs a prebuilt isomdl-uniffi wheel here
# (see git history) — faster and truly multi-arch. This intentionally
# diverges from that because the wheel doesn't yet have status-claim
# support, which mDL revocation depends on. Once isomdl-uniffi cuts a
# release wheel with that support, revert this stage to the wheel install.
#
# Fetched via ADD (not RUN git clone) so BuildKit checks the remote ref on
# every build and only invalidates this layer when the branch's commit
# actually changes — a plain `RUN git clone <fixed args>` caches on the
# command text and would keep reusing a stale checkout after new commits
# land on the branch, requiring a full --no-cache rebuild every time.
RUN apt-get update && apt-get install -y git build-essential && apt-get clean
ADD https://github.com/Indicio-tech/isomdl-uniffi.git#feat/mso-status-claim /usr/src/app/isomdl-uniffi
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# isomdl-uniffi's .cargo/config.toml routes both x86_64 and aarch64 Linux
# targets through `zig cc` (see its mise.toml, which pins zig) even for
# native builds; without `zig` on PATH the Rust link step fails with
# "zig: not found".
RUN pip install --no-cache-dir ziglang \
    && printf '#!/bin/sh\nexec python3 -m ziglang "$@"\n' > /usr/local/bin/zig \
    && chmod +x /usr/local/bin/zig

WORKDIR /usr/src/app/isomdl-uniffi/python
# Cache cargo's downloaded crate registry and this crate's compiled build
# artifacts across builds, so an isomdl-uniffi source change (a new commit
# on the branch above) only recompiles the crates that actually changed
# instead of all ~250 dependencies from scratch every time.
RUN --mount=type=cache,target=/root/.cargo/registry,id=cargo-registry \
    --mount=type=cache,target=/usr/src/app/isomdl-uniffi/rust/target,id=isomdl-uniffi-target \
    python build.py

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

# Install the isomdl library built in the base stage.
COPY --from=base /usr/src/app/isomdl-uniffi/python/isomdl_uniffi /usr/src/app/mso_mdoc/isomdl
ENV PYTHONPATH="/usr/src/app/mso_mdoc/isomdl:$PYTHONPATH"

ENTRYPOINT ["/bin/bash", "-c", "aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]
