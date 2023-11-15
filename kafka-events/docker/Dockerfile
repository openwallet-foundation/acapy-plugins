FROM ghcr.io/hyperledger/aries-cloudagent-python:py3.9-indy-1.16.0-0.8.0-rc0

RUN pip3 install --no-cache-dir poetry

USER root

# Add docker-compose-wait tool
ENV WAIT_VERSION 2.7.2
ADD https://github.com/ufoscout/docker-compose-wait/releases/download/$WAIT_VERSION/wait /wait
RUN chmod +x /wait

RUN mkdir kafka_queue && touch kafka_queue/__init__.py

COPY ./README.md ./setup.py ./pyproject.toml ./poetry.lock ./
USER root
RUN chown indy:indy -R .
USER indy

RUN poetry install --no-dev

# Make site packages location more accessible (for use with volumes)
RUN ln -s $(poetry env info -p)/lib/python3.6/site-packages site-packages

COPY kafka_queue kafka_queue
COPY ./docker/default.yml .
COPY ./docker/plugins-config.yaml .

ENTRYPOINT ["/bin/sh", "-c", "/wait && poetry run aca-py \"$@\"", "--"]
CMD ["start",  "--plugin", "kafka_queue", "--arg-file", "default.yml"]
