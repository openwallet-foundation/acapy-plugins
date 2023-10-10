wish list
[ ] support multi-tenant 

cd oid4vci
poetry lock
poetry install
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker build -f ./docker/Dockerfile --tag acapy_plugins .
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker build -f ./Dockerfile --tag acapy_plugins .
docker run -it -p 3000:3000 -p 3001:3001 -p 8081:8081 --rm acapy_plugins start --arg-file=integration.yml