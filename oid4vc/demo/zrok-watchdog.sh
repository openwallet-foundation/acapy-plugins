#!/bin/sh
# Watchdog for zrok reserved shares.
#
# zrok's agent can silently lose its underlying OpenZiti circuit while still
# reporting the share as "active" (openziti/zrok#1259) — the container never
# crashes, so Docker's own restart policy never kicks in, and requests start
# failing with a 502 from the zrok edge with no local symptom to detect it.
# This polls each share's PUBLIC url from outside the tunnel and restarts the
# container the moment it stops answering, which forces the agent to
# re-establish a fresh circuit.

set -eu

CHECK_INTERVAL="${CHECK_INTERVAL:-30}"
TIMEOUT="${CHECK_TIMEOUT:-10}"

check_and_restart() {
  service="$1"
  url="$2"
  [ -z "$url" ] && return 0

  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time "$TIMEOUT" "$url" || echo 000)
  if [ "$code" = "502" ] || [ "$code" = "000" ]; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $service unreachable via $url (HTTP $code) - restarting"
    # Compose prefixes actual container names with the project name
    # (e.g. "demo-issuer-zrok-1"), so look the container up by its
    # compose service label rather than assuming the bare service name.
    container=$(docker ps -q --filter "label=com.docker.compose.service=$service")
    if [ -z "$container" ]; then
      echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $service: no running container found for restart"
      return 0
    fi
    docker restart "$container" || echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $service restart failed"
    # give the agent a moment to re-establish before the next check
    sleep 20
  fi
}

echo "zrok-watchdog: polling every ${CHECK_INTERVAL}s (timeout ${TIMEOUT}s)"

while true; do
  check_and_restart issuer-zrok "${ISSUER_PUBLIC_URL:-}"
  check_and_restart authserver-zrok "${AUTHSERVER_PUBLIC_URL:-}"
  check_and_restart demo-zrok "${DEMO_PUBLIC_URL:-}"
  sleep "$CHECK_INTERVAL"
done
