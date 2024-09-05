#!/bin/bash

TUNNEL_ENDPOINT=${TUNNEL_ENDPOINT:-http://localhost:4040}

WAIT_INTERVAL=${WAIT_INTERVAL:-3}
WAIT_ATTEMPTS=${WAIT_ATTEMPTS:-10}

liveliness_check () {
        for CURRENT_ATTEMPT in $(seq 1 "$WAIT_ATTEMPTS"); do
                if ! curl -s -o /dev/null -w '%{http_code}' "${1}/api/tunnels/command_line" | grep "200" > /dev/null; then
			if [[ $CURRENT_ATTEMPT -gt $WAIT_ATTEMPTS ]]
			then
				echo "Failed while waiting for 200 status from ${1}"
				exit 1
			fi
			
			echo "Waiting for tunnel..." 1>&2
                        sleep "$WAIT_INTERVAL" &
                        wait $!
                else
                        break
                fi
        done
}

liveliness_check "${TUNNEL_ENDPOINT}"

# Capture the JSON response from the endpoint
OID4VCI_ENDPOINT=$(curl --silent "${TUNNEL_ENDPOINT}/api/tunnels/command_line" | python -c "import sys, json; print(json.load(sys.stdin)['public_url'])")
# Print the response for debugging purposes
# echo "JSON Response: $RESPONSE"
export OID4VCI_ENDPOINT=${OID4VCI_ENDPOINT}
exec "$@"
