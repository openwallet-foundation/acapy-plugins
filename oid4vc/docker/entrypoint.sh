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

export OID4VCI_ENDPOINT=$(curl --silent "${TUNNEL_ENDPOINT}/api/tunnels" | jq -r '.tunnels[] | select(.name == "issuer") | .public_url')

export STATUS_LIST_PUBLIC_URI=${OID4VCI_ENDPOINT}/tenant/{tenant_id}/status/{list_number}

echo "STATUS_LIST_PUBLIC_URI: $STATUS_LIST_PUBLIC_URI"

exec "$@"
