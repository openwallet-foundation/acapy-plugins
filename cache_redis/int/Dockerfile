FROM python:3.12-slim-bullseye
WORKDIR /usr/src/app/

ENV POETRY_HOME=/opt/poetry \
    VENV=/usr/src/app/.venv
ENV PATH="$POETRY_HOME/bin:$VENV/bin:$PATH"

RUN apt-get update && apt-get install -y curl && apt-get clean
RUN curl -sSL https://install.python-poetry.org | python -
RUN poetry config virtualenvs.create true; poetry config virtualenvs.in-project true

COPY pyproject.toml poetry.lock ./
RUN poetry install --only main

COPY tests/ tests/

ENTRYPOINT ["poetry", "run", "pytest"]
