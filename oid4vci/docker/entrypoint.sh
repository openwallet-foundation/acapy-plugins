#!/bin/bash

TUNNEL_ENDPOINT=${TUNNEL_ENDPOINT:-http://localhost:4040}

WAIT_INTERVAL=${WAIT_INTERVAL:-3}
WAIT_ATTEMPTS=${WAIT_ATTEMPTS:-10}

liveliness_check () {
        for CURRENT_ATTEMPT in $(seq 1 "$WAIT_ATTEMPTS"); do
                if ! curl -s -o /dev/null -w '%{http_code}' "${1}/status" | grep "200" > /dev/null; then
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
RESPONSE=$(curl --silent "${TUNNEL_ENDPOINT}/api/tunnels/command_line")
# Print the response for debugging purposes
# echo "JSON Response: $RESPONSE"

if [[ $RESPONSE == *"\"public_url\""* ]]; then

  # Extract the public URL
  public_url=$(echo "$RESPONSE" | jq -r '.public_url')
  echo "public_url: $public_url"

  # Set it as an environment variable
  export OID4VCI_ENDPOINT="$public_url"

  # Execute the provided command (arguments)
  exec "$@"
else
  echo "Failed to retrieve public URL from ngrok"
  exit 1
fi
