#!/bin/bash
set -e

# Check required env vars
if [ -z "$ADMIN_DB_HOST" ] || [ -z "$ADMIN_DB_USER" ] || [ -z "$ADMIN_DB_PASSWORD" ] || [ -z "$ADMIN_DB_NAME" ]; then
  echo "ADMIN_DB_HOST, ADMIN_DB_USER, ADMIN_DB_PASSWORD, and ADMIN_DB_NAME must be set as environment variables."
  exit 1
fi

# Wait for PostgreSQL to be available
until pg_isready -h "$ADMIN_DB_HOST" -U "postgres"; do
  echo "Waiting for PostgreSQL at $ADMIN_DB_HOST..."
  sleep 2
done

# Only run DB init script if the admin database does not exist.
# TODO parmaterize the DB admin user and password. Not the same as ADMIN_DB_USER/PASSWORD which are specific to the auth server admin.
if ! PGPASSWORD="postgres" psql -h "$ADMIN_DB_HOST" -U "postgres" -lqt | cut -d \| -f 1 | grep -qw "$ADMIN_DB_NAME"; then
  echo "Database $ADMIN_DB_NAME does not exist. Running init.sql..."
  PGPASSWORD="postgres" psql -h "$ADMIN_DB_HOST" -U "postgres" \
    -v ADMIN_DB_NAME="$ADMIN_DB_NAME" \
    -v ADMIN_DB_USER="$ADMIN_DB_USER" \
    -v ADMIN_DB_PASSWORD="${ADMIN_DB_PASSWORD}" \
    -f alembic/sql/init.sql
else
  echo "Database $POSTGRES_DB already exists. Skipping init.sql."
fi

# Set Alembic DB URL (use sync driver for migrations)
export ALEMBIC_DB_URL="postgresql+psycopg://$ADMIN_DB_USER:$ADMIN_DB_PASSWORD@$ADMIN_DB_HOST:5432/$POSTGRES_DB"
export ALEMBIC_DB_SCHEMA="admin"

# If these are not unset, they will interfere with the tenant provisioning in the auth server, which also uses Alembic but needs to connect to the tenant DBs with different credentials. 
unset ALEMBIC_DB_URL
unset ALEMBIC_DB_SCHEMA

# Need the authserver endpoint
TUNNEL_ENDPOINT=${TUNNEL_ENDPOINT:-http://ngrok:4040}

WAIT_INTERVAL=${WAIT_INTERVAL:-3}
WAIT_ATTEMPTS=${WAIT_ATTEMPTS:-10}

liveliness_check () {
        set -o pipefail
        for CURRENT_ATTEMPT in $(seq 1 "$WAIT_ATTEMPTS"); do
                # Use jq to check if the 'issuer' tunnel is available
                if curl -sf "${1}/api/tunnels" | jq -e 'any(.tunnels[]; .name == "authserver" and .public_url != null)' > /dev/null; then
                        break
                else
                        if [[ $CURRENT_ATTEMPT -ge $WAIT_ATTEMPTS ]]; then
                                echo "Failed while waiting for 'issuer' tunnel in ${1}/api/tunnels"
                                exit 1
                        fi
                        echo "Waiting for 'issuer' tunnel..." 1>&2
                        sleep "$WAIT_INTERVAL" &
                        wait $!
                fi
        done
}

liveliness_check "${TUNNEL_ENDPOINT}"

# Get the authserver tunnel public URL using jq
export TENANT_ISSUER_BASE_URL=$(curl --silent "${TUNNEL_ENDPOINT}/api/tunnels" | jq -r '.tunnels[] | select(.name == "authserver") | .public_url')
echo "TENANT_ISSUER_BASE_URL: $TENANT_ISSUER_BASE_URL"

# Run Alembic migrations
echo $PWD
poetry run python alembic/admin/migrate.py

# Start Admin API
poetry run uvicorn admin.main:app --host 0.0.0.0 --port 9000 &
# Start Tenant API
poetry run uvicorn tenant.main:app --host 0.0.0.0 --port 9001 &
wait
