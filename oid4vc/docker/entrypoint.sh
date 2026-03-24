#!/bin/bash

TUNNEL_ENDPOINT=${TUNNEL_ENDPOINT:-http://localhost:4040}

WAIT_INTERVAL=${WAIT_INTERVAL:-3}
WAIT_ATTEMPTS=${WAIT_ATTEMPTS:-10}

liveliness_check () {
        for CURRENT_ATTEMPT in $(seq 1 "$WAIT_ATTEMPTS"); do
                # Use jq to check if the 'issuer' tunnel is available
                if curl -s "${1}/api/tunnels" | jq -e '.tunnels[] | select(.name == "issuer" and .public_url != null)' > /dev/null; then
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

# Capture the JSON response from the endpoint using jq
export OID4VCI_ENDPOINT=$(curl --silent "${TUNNEL_ENDPOINT}/api/tunnels" | jq -r '.tunnels[] | select(.name == "issuer") | .public_url')
export OID4VCI_AUTH_SERVER_URL=$(curl --silent "${TUNNEL_ENDPOINT}/api/tunnels" | jq -r '.tunnels[] | select(.name == "authserver") | .public_url')

#Temp fix until the issuer API is working properly to set issuer metadata.
export OID4VCI_AUTH_SERVER_CLIENT="{\"auth_type\": \"client_secret_basic\", \"client_id\": \"client1\", \"client_secret\": \"clientsecret\", \"public_url\": \"${AUTH_ENDPOINT}/tenants/3bc7d189-b612-475d-a2b7-32a501cc1e46\", \"private_url\": \"http://auth-server:9000/tenants/3bc7d189-b612-475d-a2b7-32a501cc1e46\" }"
#export OID4VCI_AUTH_SERVER_URL="${AUTH_ENDPOINT}/tenants/8242a581-499d-4000-b0b4-1023390e8cb2"

export STATUS_LIST_PUBLIC_URI=${OID4VCI_ENDPOINT}/tenant/{tenant_id}/status/{list_number}

echo "OID4VCI_AUTH_SERVER_CLIENT: $OID4VCI_AUTH_SERVER_CLIENT"
echo "OID4VCI_AUTH_SERVER_URL: $OID4VCI_AUTH_SERVER_URL"
echo "STATUS_LIST_PUBLIC_URI: $STATUS_LIST_PUBLIC_URI"

exec "$@"
