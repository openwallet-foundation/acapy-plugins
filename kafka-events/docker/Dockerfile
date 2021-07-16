FROM bcgovimages/von-image:py36-1.15-1

RUN pip3 install --no-cache-dir poetry

USER root

COPY kafka_queue kafka_queue

COPY ./README.md .
COPY ./setup.py .
COPY ./pyproject.toml .
COPY ./poetry.lock .
COPY ./docker/default.yml .
COPY ./docker/plugins-config.yaml .
RUN chown -R indy:indy .
USER $user

RUN poetry install --no-dev

# Make site packages location more accessible (for use with volumes)
RUN ln -s $(poetry env info -p)/lib/python3.6/site-packages site-packages

ENTRYPOINT ["/bin/bash", "-c", "poetry run aca-py \"$@\"", "--"]
CMD ["start", "--arg-file", "default.yml"]
