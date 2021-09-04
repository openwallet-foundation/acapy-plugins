FROM python:3.7
WORKDIR /app

# Add docker-compose-wait tool
ENV WAIT_VERSION 2.7.2
ADD https://github.com/ufoscout/docker-compose-wait/releases/download/$WAIT_VERSION/wait /wait
RUN chmod +x /wait

RUN curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/install-poetry.py | POETRY_HOME=/opt/poetry python - && \
    cd /usr/local/bin && \
    ln -s /opt/poetry/bin/poetry && \
    poetry config virtualenvs.create false

COPY ./pyproject.toml ./poetry.lock /app/

RUN poetry install --no-root

COPY ./relay/ /app/relay/
ENTRYPOINT ["/bin/sh", "-c", "/wait && poetry run \"$@\"", "--"]
CMD ["uvicorn", "relay:app", "--host", "0.0.0.0", "--port", "80"]
