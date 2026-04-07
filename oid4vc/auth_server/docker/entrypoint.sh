#!/bin/bash
set -e

# Check required env vars
if [ -z "$ADMIN_DB_HOST" ] || [ -z "$ADMIN_DB_USER" ] || [ -z "$ADMIN_DB_PASSWORD" ] || [ -z "$ADMIN_DB_NAME" ]; then
  echo "ADMIN_DB_HOST, ADMIN_DB_USER, ADMIN_DB_PASSWORD, and ADMIN_DB_NAME must be set as environment variables."
  exit 1
fi

# Wait for PostgreSQL to be available
until pg_isready -h "$ADMIN_DB_HOST" -p "${ADMIN_DB_PORT:-5432}" -U "postgres"; do
  echo "Waiting for PostgreSQL at $ADMIN_DB_HOST..."
  sleep 2
done

# Only run DB init script if the admin database does not exist.
# TODO parameterize the DB superuser and password. Not the same as ADMIN_DB_USER/PASSWORD which are specific to the auth server admin.
# Note: psql -lqt is avoided here because its internal query references daticulocale (PG15 name)
# which was renamed to datlocale in PostgreSQL 16+, causing a column-not-found error.
if ! PGPASSWORD="postgres" psql -h "$ADMIN_DB_HOST" -U "postgres" -tc "SELECT 1 FROM pg_database WHERE datname = '$ADMIN_DB_NAME'" | grep -q 1; then
  echo "Database $ADMIN_DB_NAME does not exist. Running init.sql..."
  PGPASSWORD="postgres" psql -h "$ADMIN_DB_HOST" -U "postgres" \
    -v ADMIN_DB_NAME="$ADMIN_DB_NAME" \
    -v ADMIN_DB_USER="$ADMIN_DB_USER" \
    -v ADMIN_DB_PASSWORD="'${ADMIN_DB_PASSWORD}'" \
    -f alembic/sql/init.sql
else
  echo "Database $ADMIN_DB_NAME already exists. Skipping init.sql."
fi

# Need the authserver endpoint
TUNNEL_ENDPOINT=${TUNNEL_ENDPOINT:-http://ngrok:4040}

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
