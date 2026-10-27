#!/bin/bash

TUNNEL_ENDPOINT=${TUNNEL_ENDPOINT:-http://ngrok:4040}

WAIT_INTERVAL=${WAIT_INTERVAL:-3}
WAIT_ATTEMPTS=${WAIT_ATTEMPTS:-10}

# Public URL of the 'issuer' tunnel, or nothing while ngrok is not ready.
issuer_tunnel_url () {
        curl --silent "${1}/api/tunnels" \
                | jq -r '.tunnels[]? | select(.name == "issuer") | .public_url // empty' 2>/dev/null
}

# Wait until the tunnel has a public URL. (Checking the URL itself: jq 1.6's
# -e exits 0 on empty input, so a check on curl's output passes while ngrok's
# API is still refusing connections.)
wait_for_issuer_tunnel () {
        for CURRENT_ATTEMPT in $(seq 1 "$WAIT_ATTEMPTS"); do
                OID4VCI_ENDPOINT=$(issuer_tunnel_url "$1")
                if [[ -n "$OID4VCI_ENDPOINT" ]]; then
                        return
                fi
                if [[ $CURRENT_ATTEMPT -ge $WAIT_ATTEMPTS ]]; then
                        echo "Failed while waiting for 'issuer' tunnel in ${1}/api/tunnels"
                        exit 1
                fi
                echo "Waiting for 'issuer' tunnel..." 1>&2
                sleep "$WAIT_INTERVAL" &
                wait $!
        done
}

wait_for_issuer_tunnel "${TUNNEL_ENDPOINT}"

export OID4VCI_ENDPOINT
echo "OID4VCI_ENDPOINT: $OID4VCI_ENDPOINT"

export STATUS_LIST_PUBLIC_URI=${OID4VCI_ENDPOINT}/tenant/{tenant_id}/status/{list_number}

echo "STATUS_LIST_PUBLIC_URI: $STATUS_LIST_PUBLIC_URI"

exec "$@"
