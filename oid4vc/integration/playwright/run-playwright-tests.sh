#!/bin/bash
# run-playwright-tests.sh - Run Playwright E2E tests with walt.id wallet
#
# This script starts all required services, waits for health checks,
# runs the Playwright tests, and copies artifacts.
#
# Usage:
#   ./run-playwright-tests.sh [options] [test-pattern]
#
# Options:
#   --headed        Run tests in headed mode (visible browser)
#   --debug         Enable Playwright debug mode
#   --ui            Open Playwright UI mode
#   --no-teardown   Don't stop services after tests
#   --build         Rebuild docker images before running
#   --mdoc-only     Run only mDOC tests
#   --sdjwt-only    Run only SD-JWT tests
#   --jwtvc-only    Run only JWT-VC tests
#
# Examples:
#   ./run-playwright-tests.sh                    # Run all tests
#   ./run-playwright-tests.sh --mdoc-only        # Run only mDOC tests
#   ./run-playwright-tests.sh --headed --debug   # Debug with visible browser

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
HEADED=""
DEBUG=""
UI_MODE=""
TEARDOWN=true
BUILD=""
TEST_PATTERN=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --headed)
      HEADED="--headed"
      shift
      ;;
    --debug)
      DEBUG="--debug"
      shift
      ;;
    --ui)
      UI_MODE="--ui"
      shift
      ;;
    --no-teardown)
      TEARDOWN=false
      shift
      ;;
    --build)
      BUILD="--build"
      shift
      ;;
    --mdoc-only)
      TEST_PATTERN="mdoc"
      shift
      ;;
    --sdjwt-only)
      TEST_PATTERN="sdjwt"
      shift
      ;;
    --jwtvc-only)
      TEST_PATTERN="jwtvc"
      shift
      ;;
    *)
      TEST_PATTERN="$1"
      shift
      ;;
  esac
done

log_info() {
  echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
  if [ "$TEARDOWN" = true ]; then
    log_info "Stopping services..."
    cd "$PROJECT_ROOT"
    docker compose --profile waltid down -v 2>/dev/null || true
  else
    log_warn "Services left running (--no-teardown specified)"
    log_info "To stop: docker compose --profile waltid down -v"
  fi
}

# Set trap for cleanup
trap cleanup EXIT

# Check dependencies
check_dependencies() {
  log_info "Checking dependencies..."
  
  if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed"
    exit 1
  fi
  
  if ! command -v docker compose &> /dev/null; then
    log_error "Docker Compose is not installed"
    exit 1
  fi
  
  if ! command -v node &> /dev/null; then
    log_error "Node.js is not installed"
    exit 1
  fi
  
  # Check for ARM64 architecture and warn about walt.id compatibility
  ARCH=$(uname -m)
  if [[ "$ARCH" == "arm64" || "$ARCH" == "aarch64" ]]; then
    log_warn "Running on ARM64 architecture detected"
    log_warn "walt.id services are amd64-only and may require Rosetta 2 (macOS) or QEMU emulation (Linux)"
    log_warn "Performance may be degraded. Consider using --mdoc-only or --sdjwt-only to skip walt.id tests"
  fi
  
  log_success "All dependencies found"
}

# Generate certificates if needed
generate_certs() {
  local certs_dir="$SCRIPT_DIR/certs"
  
  if [ ! -f "$certs_dir/issuer.pem" ]; then
    log_info "Generating test certificates..."
    cd "$certs_dir"
    ./generate-certs.sh
    log_success "Certificates generated"
  else
    log_info "Certificates already exist"
  fi
}

# Start services
start_services() {
  log_info "Starting services with waltid profile..."
  cd "$PROJECT_ROOT"
  
  if [ -n "$BUILD" ]; then
    log_info "Building images..."
    docker compose --profile waltid build
  fi
  
  docker compose --profile waltid up -d
  
  log_success "Services started"
}

# Wait for service health
wait_for_service() {
  local name=$1
  local url=$2
  local max_retries=${3:-60}
  local retry_count=0
  
  log_info "Waiting for $name at $url..."
  
  while [ $retry_count -lt $max_retries ]; do
    if curl -sf "$url" > /dev/null 2>&1; then
      log_success "$name is ready"
      return 0
    fi
    
    retry_count=$((retry_count + 1))
    sleep 2
  done
  
  log_error "$name failed to become ready after $max_retries attempts"
  return 1
}

# Wait for all services
wait_for_services() {
  log_info "Waiting for all services to be healthy..."
  
  # Wait for ACA-Py Issuer
  wait_for_service "ACA-Py Issuer" "http://localhost:8021/status/ready"
  
  # Wait for ACA-Py Verifier
  wait_for_service "ACA-Py Verifier" "http://localhost:8031/status/ready"
  
  # Wait for walt.id wallet API
  wait_for_service "walt.id Wallet API" "http://localhost:7001/health"
  
  # Wait for walt.id web wallet
  wait_for_service "walt.id Web Wallet" "http://localhost:7101"
  
  log_success "All services are healthy"
}

# Install Playwright dependencies
install_playwright() {
  log_info "Installing Playwright dependencies..."
  cd "$SCRIPT_DIR"
  
  if [ ! -d "node_modules" ]; then
    npm install
  fi
  
  # Install browsers if needed
  npx playwright install chromium
  
  log_success "Playwright ready"
}

# Run tests
run_tests() {
  log_info "Running Playwright tests..."
  cd "$SCRIPT_DIR"
  
  local test_args=""
  
  if [ -n "$HEADED" ]; then
    test_args="$test_args $HEADED"
  fi
  
  if [ -n "$DEBUG" ]; then
    test_args="$test_args $DEBUG"
  fi
  
  if [ -n "$UI_MODE" ]; then
    test_args="$test_args $UI_MODE"
  fi
  
  if [ -n "$TEST_PATTERN" ]; then
    test_args="$test_args --grep $TEST_PATTERN"
  fi
  
  # Create test-results directory
  mkdir -p test-results
  
  # Run tests
  if npx playwright test $test_args; then
    log_success "All tests passed!"
    return 0
  else
    log_error "Some tests failed"
    return 1
  fi
}

# Show test results
show_results() {
  log_info "Test artifacts saved to:"
  echo "  - playwright/test-results/     (screenshots, videos, traces)"
  echo "  - playwright/playwright-report/ (HTML report)"
  
  if [ -f "$SCRIPT_DIR/playwright-report/index.html" ]; then
    log_info "To view report: npx playwright show-report"
  fi
}

# Main execution
main() {
  echo ""
  echo "=========================================="
  echo "  Playwright E2E Tests for OID4VC"
  echo "  walt.id Web Wallet Integration"
  echo "=========================================="
  echo ""
  
  check_dependencies
  generate_certs
  install_playwright
  start_services
  wait_for_services
  
  local test_result=0
  run_tests || test_result=$?
  
  show_results
  
  exit $test_result
}

main
