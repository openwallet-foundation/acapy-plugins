#!/bin/bash

TUNNEL_HOST=${TUNNEL_HOST:-tunnel}
TUNNEL_PORT=${TUNNEL_PORT:-4040}

echo "tunnel end point [$TUNNEL_HOST:$TUNNEL_PORT]"

while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' "${TUNNEL_HOST}:${TUNNEL_PORT}/status")" != "200" ]]; do
    echo "Waiting for tunnel..."
    sleep 1
done
ACAPY_ENDPOINT=$(curl --silent "${TUNNEL_HOST}:${TUNNEL_PORT}/start" | python -c "import sys, json; print(json.load(sys.stdin)['url'])")
echo "fetched end point [$ACAPY_ENDPOINT]"

export ACAPY_ENDPOINT="[$ACAPY_ENDPOINT, ${ACAPY_ENDPOINT/http/ws}]"
#export ACAPY_ENDPOINT="$ACAPY_ENDPOINT"
exec "$@"
