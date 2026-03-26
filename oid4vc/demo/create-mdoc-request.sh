#!/usr/bin/env bash
# Create an mDoc OID4VP verification request URL
#
# This is a wrapper around create-mdoc-request.ts for convenience.
#
# Usage:
#   ./create-mdoc-request.sh [OPTIONS]
#
# Options (all optional):
#   --verifier-url URL      Verifier public URL
#   --fields FIELDS         Comma-separated fields to request (default: given_name,family_name)
#   --help                  Show this help
#
# Examples:
#   # Use all defaults (given_name, family_name)
#   ./create-mdoc-request.sh
#
#   # Custom fields
#   ./create-mdoc-request.sh --fields given_name,family_name,birth_date,document_number
#
#   # Specific verifier
#   ./create-mdoc-request.sh --verifier-url https://verifier.example.com
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Default values
FIELDS="given_name,family_name"
EXTRA_ARGS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fields)
      FIELDS="$2"
      shift 2
      ;;
    --help|-h)
      head -n 25 "$0" | tail -n +3
      exit 0
      ;;
    *)
      # Pass through to create-mdoc-request.ts
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

# Run the TypeScript script
cd "$SCRIPT_DIR"
npx ts-node create-mdoc-request.ts \
  --fields "$FIELDS" \
  ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}
