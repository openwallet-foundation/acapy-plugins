FROM python:3.12-slim-bullseye
WORKDIR /usr/src/app/

ENV POETRY_HOME=/opt/poetry \
    VENV=/usr/src/app/.venv
ENV PATH="$POETRY_HOME/bin:$VENV/bin:$PATH"

RUN apt-get update && apt-get install -y curl && apt-get clean
RUN curl -sSL https://install.python-poetry.org | python -
RUN poetry config virtualenvs.create true; poetry config virtualenvs.in-project true

RUN mkdir acapy_cache_redis && touch acapy_cache_redis/__init__.py
COPY README.md pyproject.toml poetry.lock ./

RUN poetry install --no-dev

COPY docker/default.yml .
COPY acapy_cache_redis/ acapy_cache_redis/

ENTRYPOINT ["poetry", "run", "aca-py"]
CMD ["start", "--arg-file", "default.yml"]
