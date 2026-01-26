FROM python:3.12-slim-bookworm AS base
WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y curl && apt-get clean
ENV PDM_VERSION=2.15.4
ENV PDM_HOME=/opt/pdm
RUN curl -sSL https://pdm-project.org/install-pdm.py | python3 -


FROM python:3.12-slim-bookworm
WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y curl git && apt-get clean

COPY --from=base /opt/pdm /opt/pdm

ENV PATH="/opt/pdm/bin:$PATH"

# Setup project
COPY pyproject.toml pdm.lock README.md ./
RUN pdm install

# add tests to image
COPY credo_wrapper/ credo_wrapper/
COPY tests/ tests/

ENTRYPOINT ["pdm", "run", "pytest"]
