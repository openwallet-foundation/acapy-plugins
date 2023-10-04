FROM ghcr.io/hyperledger/aries-cloudagent-python:py3.9-0.10.3

USER root

# install plugins as binaries
RUN pip install git+https://github.com/usingtechnology/aries-cloudagent-python-plugins@main#subdirectory=basicmessage_storage

USER $user
# copy configurations, choose at deploy time...
COPY ./configs configs

CMD ["aca-py"]