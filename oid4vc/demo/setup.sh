#!/usr/bin/env bash
# demo/setup.sh — Configure ACA-Py issuer and verifier for the mDOC demo.
#
# Run ONCE after "docker compose up -d":
#   ./setup.sh
#
# The script:
#   1. Waits for ACA-Py issuer and verifier to be healthy.
#   2. Creates a P-256 DID used to sign mDOC credentials.
#   3. Generates mDOC signing keys / self-signed issuer certificate.
#   4. Creates an mDL (org.iso.18013.5.1.mDL) credential configuration.
#   5. Creates an SD-JWT credential configuration (backup / comparison).
#   6. Prints out wallet URL and Playwright instructions.
#
# Environment variables (from .env or shell):
#   ACAPY_ISSUER_ADMIN_URL   default http://localhost:8021
#   ACAPY_VERIFIER_ADMIN_URL default http://localhost:8031
#   WALLET_URL               default http://localhost:7101
set -euo pipefail

# Load .env from the same directory as this script so port overrides are honoured.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$SCRIPT_DIR/.env"
  set +a
fi

ISSUER_ADMIN="${ACAPY_ISSUER_ADMIN_URL:-http://localhost:8021}"
VERIFIER_ADMIN="${ACAPY_VERIFIER_ADMIN_URL:-http://localhost:8031}"
WALLET_URL="${WALTID_WALLET_URL:-${WALLET_URL:-http://localhost:7101}}"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[demo]${RESET} $*"; }
success() { echo -e "${GREEN}[demo] ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}[demo] !${RESET} $*"; }
error()   { echo -e "${RED}[demo] ✗${RESET} $*"; }

# ── Helpers ───────────────────────────────────────────────────────────────────

wait_for_ready() {
  local url="$1/status/ready"
  local label="$2"
  info "Waiting for $label to be ready…"
  for i in $(seq 1 60); do
    if curl -sf "$url" | grep -qE '"ready":\s*true'; then
      success "$label is ready"
      return 0
    fi
    sleep 2
  done
  echo "ERROR: $label did not become ready at $url" >&2
  exit 1
}

post_json() {
  # post_json URL BODY  →  stdout full response
  curl -sf -X POST "$1" \
    -H "Content-Type: application/json" \
    -d "$2"
}

get_json() {
  curl -sf "$1"
}

# ── Check external endpoint reachability ─────────────────────────────────────
#
# If ISSUER_OID4VCI_ENDPOINT or VERIFIER_OID4VP_ENDPOINT is set to an
# external tunnel (zrok, ngrok, …), verify each is actually live.  A dead
# tunnel proxy typically returns an HTML error page instead of JSON.
#
# When a tunnel is stale the variable is automatically commented out in .env
# and the affected container is restarted so all credential-offer and
# presentation-request URLs embed the docker-internal hostname instead.  A
# one-time .env.bak backup is created before editing.

_check_and_restart_if_stale() {
  # Usage: _check_and_restart_if_stale ENV_VAR SERVICE_NAME
  local env_var="$1"
  local service="$2"
  local value="${!env_var:-}"

  # Nothing to do when the variable is unset or already points to a local URL.
  if [[ -z "$value" ]] || [[ "$value" == http://acapy-* ]] || [[ "$value" == http://localhost* ]]; then
    return 0
  fi

  info "Checking external endpoint ${env_var}=${value}"

  # Probe the root.  A live ACA-Py server returns JSON; a dead tunnel proxy
  # (e.g. the zrok "tunnel not found" page) returns HTML.
  local body
  body=$(curl -s --max-time 5 "${value}/" 2>/dev/null) || body=""
  local first_char
  first_char=$(python3 -c "import sys; s=sys.stdin.read().strip(); print(s[:1] if s else '')" <<< "$body" 2>/dev/null) || first_char=""

  if [[ -n "$first_char" && "$first_char" != "<" ]]; then
    success "External endpoint is live: ${value}"
    return 0
  fi

  warn "Tunnel ${value} is down (no response or HTML error page)."
  warn "Commenting out ${env_var} in .env and restarting ${service} to use"
  warn "the docker-internal hostname.  Backup saved as .env.bak (first time only)."

  # Comment out the variable in .env using Python for cross-platform compat.
  python3 - <<PYEOF
import re, shutil, pathlib
p = pathlib.Path("${SCRIPT_DIR}/.env")
bak = p.parent / ".env.bak"
if not bak.exists():
    shutil.copy(p, bak)
content = p.read_text()
content = re.sub(
    r'^(${env_var}=)',
    r'# [auto-disabled: tunnel unreachable — re-enable when active] \1',
    content,
    flags=re.MULTILINE,
)
p.write_text(content)
PYEOF

  # Remove from the current shell so docker compose reads the updated .env.
  unset "${env_var}"

  # Recreate the container with the corrected environment.
  info "Restarting ${service}…"
  (cd "${SCRIPT_DIR}" && docker compose up -d --force-recreate "${service}")
  success "${service} restarted — URLs will now use the docker-internal hostname."
}

_check_and_restart_if_stale ISSUER_OID4VCI_ENDPOINT  acapy-issuer
_check_and_restart_if_stale VERIFIER_OID4VP_ENDPOINT acapy-verifier

# ── Wait for services ─────────────────────────────────────────────────────────

wait_for_ready "$ISSUER_ADMIN"  "ACA-Py issuer"
wait_for_ready "$VERIFIER_ADMIN" "ACA-Py verifier"

# ── Step 1: Create issuer DID (P-256, required for mDOC ECDSA signing) ───────

info "Creating P-256 issuer DID…"
DID_RESP=$(post_json "$ISSUER_ADMIN/wallet/did/create" \
  '{"method":"key","options":{"key_type":"p256"}}')
ISSUER_DID=$(echo "$DID_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['result']['did'])")
success "Issuer DID: $ISSUER_DID"

# ── Step 2: Generate mDOC signing keys ───────────────────────────────────────

info "Generating mDOC signing keys…"
KEY_RESP=$(post_json "$ISSUER_ADMIN/mso_mdoc/generate-keys" '{}' 2>/dev/null || echo '{"key_id":"auto"}')
KEY_ID=$(echo "$KEY_RESP" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('key_id','auto'))" 2>/dev/null || echo "auto")
success "mDOC signing key: $KEY_ID"

# ── Step 3: Create mDL credential configuration ──────────────────────────────

MDL_CONFIG_ID="org.iso.18013.5.1.mDL_demo"
info "Creating mDL credential configuration (id=$MDL_CONFIG_ID)…"

MDL_CONFIG=$(python3 - <<PYEOF
import json
config = {
    "id": "$MDL_CONFIG_ID",
    "format": "mso_mdoc",
    "scope": "mDL",
    "doctype": "org.iso.18013.5.1.mDL",
    "cryptographic_binding_methods_supported": ["cose_key", "did:key", "did"],
    "cryptographic_suites_supported": ["ES256"],
    "proof_types_supported": {
        "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
    },
    "format_data": {
        "doctype": "org.iso.18013.5.1.mDL",
        "claims": {
            "org.iso.18013.5.1": {
                "family_name":       {"mandatory": True},
                "given_name":        {"mandatory": True},
                "birth_date":        {"mandatory": True},
                "issuing_country":   {"mandatory": True},
                "issuing_authority": {"mandatory": True},
                "document_number":   {"mandatory": True},
                "un_distinguishing_sign": {"mandatory": True},
                "portrait":          {"mandatory": True},
                "issue_date":        {"mandatory": False},
                "expiry_date":       {"mandatory": False},
                "driving_privileges":{"mandatory": False}
            }
        }
    },
    "display": [
        {
            "name": "Mobile Driving License",
            "locale": "en-US",
            "description": "ISO 18013-5 compliant mobile driving license"
        }
    ]
}
print(json.dumps(config))
PYEOF
)

MDL_CRED_ID=$(get_json "$ISSUER_ADMIN/oid4vci/credential-supported/records" | \
  python3 -c "
import json, sys
records = json.load(sys.stdin).get('results', [])
match = next((r['supported_cred_id'] for r in records if r.get('identifier') == '$MDL_CONFIG_ID'), '')
print(match)
" 2>/dev/null)

if [[ -n "$MDL_CRED_ID" ]]; then
  info "mDL credential config already exists, reusing it…"
else
  MDL_RESP=$(post_json "$ISSUER_ADMIN/oid4vci/credential-supported/create" "$MDL_CONFIG")
  MDL_CRED_ID=$(echo "$MDL_RESP" | python3 -c "import json,sys; print(json.load(sys.stdin)['supported_cred_id'])")
fi
success "mDL credential config: $MDL_CRED_ID"

# ── Step 4: Register issuer certificate as trust anchor on verifier ──────────

info "Fetching issuer mDOC certificate for trust anchor registration…"
ISSUER_CERT_PEM=$(get_json "$ISSUER_ADMIN/mso_mdoc/certificates/default" | \
  python3 -c "import json,sys; print(json.load(sys.stdin)['certificate_pem'])")

if [[ -z "$ISSUER_CERT_PEM" ]]; then
  warn "Could not retrieve issuer certificate — skipping trust anchor registration."
  warn "Run 'POST $VERIFIER_ADMIN/mso_mdoc/trust-anchors' manually after setup."
else
  TRUST_ANCHOR_BODY=$(python3 -c "
import json, sys
print(json.dumps({
    'certificate_pem': sys.stdin.read(),
    'anchor_id': 'demo-issuer',
    'metadata': {'source': 'demo-issuer'},
}))
" <<< "$ISSUER_CERT_PEM")

  post_json "$VERIFIER_ADMIN/mso_mdoc/trust-anchors" "$TRUST_ANCHOR_BODY" > /dev/null
  success "Issuer certificate registered as trust anchor on verifier"
fi

# ── Step 5: Store config for Playwright ──────────────────────────────────────
#
# NOTE: The SD-JWT credential configuration is intentionally skipped here.
# ACA-Py serialises vc+sd-jwt claims in path-based array format in the
# /.well-known/openid-credential-issuer metadata, which the waltid wallet
# cannot parse (it expects a JSON object at $.claims).  The mDL demo only
# needs the mso_mdoc credential, so the SD-JWT config is omitted to keep the
# metadata compatible with the waltid wallet.
SDJWT_CRED_ID=""

cat > /tmp/demo-config.env <<EOF
ISSUER_DID=$ISSUER_DID
MDL_CRED_CONFIG_ID=$MDL_CRED_ID
SDJWT_CRED_CONFIG_ID=$SDJWT_CRED_ID
EOF

success "Config written to /tmp/demo-config.env"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}  OID4VC Demo is ready!${RESET}"
echo -e "${GREEN}═══════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  Walt.id Web Wallet:   ${CYAN}${WALLET_URL}${RESET}"
echo -e "  Issuer admin API:     ${CYAN}${ISSUER_ADMIN}${RESET}"
echo -e "  Verifier admin API:   ${CYAN}${VERIFIER_ADMIN}${RESET}"
echo ""
echo -e "  Issuer DID:           ${YELLOW}${ISSUER_DID}${RESET}"
echo -e "  mDL config ID:        ${YELLOW}${MDL_CRED_ID}${RESET}"
echo ""
echo -e "  Run the Playwright demo:"
echo -e "    ${CYAN}cd playwright && npm install && npx playwright test --headed${RESET}"
echo ""
echo -e "  Or run headless (for CI/scripted demo):"
echo -e "    ${CYAN}cd playwright && npx playwright test${RESET}"
echo ""
