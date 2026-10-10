# FROM ghcr.io/openwallet-foundation/acapy-agent:py3.12-1.2.2
FROM ghcr.io/openwallet-foundation/acapy-agent:py3.12-1.4.0
#FROM acapy-vcdm
# FROM acapy:dev

RUN mkdir -p src/acapy_plugin_did_indy && touch src/acapy_plugin_did_indy/__init__.py

ADD pyproject.toml README.md uv.lock ./
RUN pip install -e .

ADD src/acapy_plugin_did_indy/ src/acapy_plugin_did_indy/
