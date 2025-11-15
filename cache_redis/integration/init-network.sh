#!/usr/bin/env sh
set -eu

# Name of the docker network (must match the one used in docker-compose.yml)
NETWORK_NAME="acapy_default"

# Generate a random octet between 20–220 using /dev/urandom
OCTET=$(od -An -N1 -i /dev/urandom | awk '{print ($1 % 201) + 20}')
SUBNET="172.${OCTET}.0.0/16"
SUBNET_PREFIX="172.${OCTET}"

# Export variables (note: exporting only works if you source this script)
echo "🧭 Using subnet: $SUBNET"
echo "🔢 Prefix: $SUBNET_PREFIX"

# Remove existing network if it exists
if docker network ls --format '{{.Name}}' | grep -q "^${NETWORK_NAME}$"; then
    docker network rm "${NETWORK_NAME}" || true
fi

# Create the new network
docker network create --driver=bridge --subnet="${SUBNET}" "${NETWORK_NAME}"

# Print export commands for manual sourcing
echo "export SUBNET=${SUBNET}"
echo "export SUBNET_PREFIX=${SUBNET_PREFIX}"
