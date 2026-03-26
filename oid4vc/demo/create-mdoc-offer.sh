#!/usr/bin/env bash
# Create an mDoc OID4VCI credential offer URL
#
# This is a wrapper around create-mdoc-offer.ts for convenience.
#
# Usage:
#   ./create-mdoc-offer.sh [OPTIONS]
#
# Options (all optional):
#   --issuer-url URL        Credential issuer public URL
#   --issuer-did DID        Issuer DID
#   --config-id ID          Credential config ID (default: org.iso.18013.5.1.mDL_demo)
#   --subject JSON          Credential subject as JSON
#   --given-name NAME       Holder first name
#   --family-name NAME      Holder last name
#   --birth-date DATE       Birth date (YYYY-MM-DD)
#   --doc-number NUM        Document number
#   --help                  Show this help
#
# Examples:
#   # Use all defaults (Alice Holder)
#   ./create-mdoc-offer.sh
#
#   # Custom holder with short options
#   ./create-mdoc-offer.sh --given-name Bob --family-name Builder --birth-date 1985-03-20
#
#   # Full custom subject
#   ./create-mdoc-offer.sh \\
#     --subject '{"org.iso.18013.5.1":{"given_name":"Carol","family_name":"Smith",...}}'
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default values
GIVEN_NAME="Alice"
FAMILY_NAME="Holder"
BIRTH_DATE="1990-06-15"
DOC_NUMBER="DL-DEMO-001"
ISSUING_COUNTRY="US"
ISSUING_AUTHORITY="Demo DMV"
SUBJECT=""
EXTRA_ARGS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --given-name)
      GIVEN_NAME="$2"
      shift 2
      ;;
    --family-name)
      FAMILY_NAME="$2"
      shift 2
      ;;
    --birth-date)
      BIRTH_DATE="$2"
      shift 2
      ;;
    --doc-number)
      DOC_NUMBER="$2"
      shift 2
      ;;
    --subject)
      SUBJECT="$2"
      shift 2
      ;;
    --help|-h)
      head -n 50 "$0" | tail -n +3
      exit 0
      ;;
    *)
      # Pass through to create-mdoc-offer.ts
      EXTRA_ARGS+=("$1")
      if [[ $# -gt 1 && ! "$2" =~ ^-- ]]; then
        EXTRA_ARGS+=("$2")
        shift 2
      else
        shift 1
      fi
      ;;
  esac
done

# Build subject JSON if not provided
if [[ -z "$SUBJECT" ]]; then
  ISSUE_DATE=$(date +%Y-%m-%d)
  EXPIRY_DATE=$(date -d "+10 years" +%Y-%m-%d 2>/dev/null || date -v+10y +%Y-%m-%d)
  
  SUBJECT=$(python3 - <<PYEOF
import json
subject = {
  "org.iso.18013.5.1": {
    "given_name": "$GIVEN_NAME",
    "family_name": "$FAMILY_NAME",
    "birth_date": "$BIRTH_DATE",
    "issuing_country": "$ISSUING_COUNTRY",
    "issuing_authority": "$ISSUING_AUTHORITY",
    "document_number": "$DOC_NUMBER",
    "issue_date": "$ISSUE_DATE",
    "expiry_date": "$EXPIRY_DATE",
    "portrait": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
    "un_distinguishing_sign": "USA",
    "driving_privileges": [
      {"vehicle_category_code": "C", "issue_date": "2020-01-01", "expiry_date": "2030-01-01"}
    ]
  }
}
print(json.dumps(subject))
PYEOF
)
fi

# Run the TypeScript script
cd "$SCRIPT_DIR"
npx ts-node create-mdoc-offer.ts \
  --subject "$SUBJECT" \
  ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
