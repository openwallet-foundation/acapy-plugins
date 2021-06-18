FROM python:3.7

RUN pip3 install --no-cache-dir poetry

USER root

COPY kafka-events kafka-events

COPY ./README.md .
COPY ./setup.py .
COPY ./pyproject.toml .
COPY ./poetry.lock .
COPY ./docker/default.yml .
COPY ./docker/plugins-config.yaml .
USER $user

RUN poetry install --no-dev

# Make site packages location more accessible (for use with volumes)
RUN ln -s $(poetry env info -p)/lib/python3.6/site-packages site-packages

ENTRYPOINT ["/bin/bash", "-c", "poetry run aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]
