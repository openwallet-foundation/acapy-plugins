FROM python:3.9-alpine AS base
WORKDIR /usr/src/app
RUN apk update && \
  apk add \
  build-base \
  curl \
  git \
  libffi-dev \
  openssh-client \
  postgresql-dev

RUN pip3 install --no-cache-dir poetry==1.8.3
ENV POETRY_HOME=/opt/poetry \
  VENV=/usr/src/app/.venv
ENV PATH="$POETRY_HOME/bin:$VENV/bin:$PATH"
RUN poetry config virtualenvs.create true; poetry config virtualenvs.in-project true

COPY ./pyproject.toml ./poetry.lock ./
RUN mkdir ./relay && touch ./relay/__init__.py
RUN poetry install

# Copy virtual environment into clean base
FROM python:3.9-alpine AS main
WORKDIR /usr/src/app
COPY --from=base /usr/src/app /usr/src/app
ENV PATH="/usr/src/app/.venv/bin:$PATH"

# Add docker-compose-wait tool
ENV WAIT_VERSION 2.7.2
ADD https://github.com/ufoscout/docker-compose-wait/releases/download/$WAIT_VERSION/wait /wait
RUN chmod +x /wait

COPY ./relay/ ./relay/
ENTRYPOINT ["/bin/sh", "-c", "/wait && \"$@\"", "--"]
CMD ["uvicorn", "relay:app", "--host", "0.0.0.0", "--port", "80"]
