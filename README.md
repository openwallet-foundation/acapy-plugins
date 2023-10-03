# aries-acapy-plugins

This repository contains approved and tested plugins for Aries Cloudagent Python.

For production use, plugins should be installed as libraries to an ACA-Py image. See [Dockerfile](./Dockerfile)

## Plugins 
TODO: developers should provide a blurb about their plugin and use, we can link to the folder/README for more information

### build and run
Not sure how far we want to take adding configurations? Could get unmanageable and redundant as developers will be adding into their plugin directories.

Should we have a docker compose environment with postgres?
Do we need integration tests across ALL plugins on the same image? What if some only work in certain configuration (ie multitenant)

```
docker build -f ./Dockerfile --tag acapy_plugins .
docker run -it -p 9060:9060 -p 9061:9061 --rm acapy_plugins start --arg-file=./configs/multitenant-plugins.yml
```