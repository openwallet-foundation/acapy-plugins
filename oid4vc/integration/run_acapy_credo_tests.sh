#!/usr/bin/env bash

# New test runner for our current ACA-Py + Credo integration testing setup
# This replaces the legacy interop testing approach

F=docker-compose.yml

ARG=$1
shift

case $ARG in
  help)
    echo "USAGE: ./run_acapy_credo_tests.sh [command] [args...]"
    echo "  Passing no args will down, build, and run all tests"
    echo "  down      - Stop and remove all containers"
    echo "  build     - Build all containers"
    echo "  logs      - Show logs from all services"  
    echo "  test      - Run specific test (e.g., test endpoint_test)"
    echo "  endpoint  - Test dual OID4VCI endpoints"
    echo "  credo     - Test Credo agent health"
    echo "  issuance  - Test OID4VCI credential issuance (ACA-Py → Credo analysis)"
    echo "  flow      - Test complete OID4VC flow (issue → receive → present → verify)"
    echo "  Any other args will be passed to pytest inside the container"
    ;;
  down)
    docker compose -f $F down -v
    ;;

  build)
    docker compose -f $F build
    ;;

  logs)
    docker compose -f $F logs "$@" | less -R
    ;;

  test)
    # Run our current integration tests
    if [ -z "$1" ]; then
      echo "Running all ACA-Py + Credo integration tests..."
      docker compose -f $F run --rm test-river uv run pytest tests/ -v
    else
      echo "Running specific test: $1"
      docker compose -f $F run --rm test-river uv run pytest tests/$1 -v
    fi
    ;;

  endpoint)
    # Test our new dual endpoint functionality
    echo "🔗 Testing dual OID4VCI well-known endpoints..."
    docker compose -f $F run --rm test-river uv run python tests/test_dual_endpoints.py run
    ;;

  credo)
    # Test Credo agent functionality
    echo "Testing Credo agent..."
    docker compose -f $F run --rm test-river curl -s http://credo-agent:3020/health | jq .
    ;;

  issuance)
    # Test credential issuance from ACA-Py to Credo
        echo "Running OID4VCI credential issuance test (ACA-Py issuer + Credo integration analysis)..."
        uv run python3 tests/test_acapy_to_credo_issuance.py run
    ;;

  flow)
    # Test complete credential flow: ACA-Py issues → Credo receives → Credo presents → ACA-Py verifies
    echo "🔄 Testing complete OID4VC flow: ACA-Py → Credo → ACA-Py..."
    docker compose -f $F run --rm test-river uv run python tests/test_complete_oid4vc_flow.py run
    ;;

  *)
    # Default: rebuild and run all tests
    echo "Running full ACA-Py + Credo integration test suite..."
    docker compose -f $F down -v
    docker compose -f $F build
    docker compose -f $F up -d
    
    # Wait for services to be ready
    echo "Waiting for services to be ready..."
    sleep 30
    
    # Run our endpoint test first
    echo "🔗 Testing OID4VCI endpoints..."
    docker compose -f $F run --rm test-river bash -c '
      echo "Standard endpoint:" && curl -s http://acapy-issuer:8022/.well-known/openid-credential-issuer | jq .
      echo "Deprecated endpoint:" && curl -s http://acapy-issuer:8022/.well-known/openid_credential_issuer | jq .
    '
    
    # Run any additional tests passed as arguments
    if [ $# -gt 0 ]; then
      echo "🧪 Running specified tests: $*"
      docker compose -f $F run --rm test-river python -m pytest tests/ -v -k "$*"
    else
      echo "🧪 Running basic connectivity tests..."
      docker compose -f $F run --rm test-river bash -c '
        echo "Checking ACA-Py issuer..." && curl -s http://acapy-issuer:8021/status/ready | jq .
        echo "Checking ACA-Py verifier..." && curl -s http://acapy-verifier:8031/status/ready | jq .  
        echo "Checking Credo agent..." && curl -s http://credo-agent:3020/health | jq .
      '
    fi
    ;;
esac