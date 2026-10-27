#!/bin/bash
set -e

TUNNEL_ENDPOINT=${TUNNEL_ENDPOINT:-http://ngrok:4040}

tunnel_url () {
  curl --silent "${TUNNEL_ENDPOINT}/api/tunnels" | jq -r --arg name "$1" '.tunnels[] | select(.name == $name) | .public_url'
}

# Get the authserver tunnel public URL using jq
AUTHSERVER_NGROK_URL=${AUTHSERVER_NGROK_URL:-$(tunnel_url authserver)}
export AUTHSERVER_NGROK_URL
echo "AUTHSERVER_NGROK_URL: $AUTHSERVER_NGROK_URL"

# Issuer and Keycloak tunnels (Keycloak only in ../demo-keycloak)
ISSUER_NGROK_URL=${ISSUER_NGROK_URL:-$(tunnel_url issuer)}
export ISSUER_NGROK_URL
echo "ISSUER_NGROK_URL: $ISSUER_NGROK_URL"
KEYCLOAK_NGROK_URL=${KEYCLOAK_NGROK_URL:-$(tunnel_url keycloak)}
export KEYCLOAK_NGROK_URL
echo "KEYCLOAK_NGROK_URL: $KEYCLOAK_NGROK_URL"

exec "$@"
