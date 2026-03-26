#!/bin/bash
# run-conformance-tests.sh
#
# Manages the OIDF Conformance Suite integration test environment.
# Activates the `conformance` Docker Compose profile which starts:
#   - MongoDB (for the conformance suite)
#   - OIDF Conformance Server (built from source with Maven)
#   - ACA-Py Issuer & Verifier (shared with base profile)
#   - Conformance Runner (setup_acapy.py + run_conformance.py)
#
# Usage:
#   ./run-conformance-tests.sh [command] [options]
#
# Commands:
#   run [scope]     Build and run conformance tests (default: all)
#   build           Build all conformance images without running
#   setup           Run setup_acapy.py only (start services, configure ACA-Py)
#   issuer          Run OID4VCI issuer tests only
#   verifier        Run OID4VP verifier tests only
#   pytest          Run pytest conformance wrapper tests against running services
#   logs [service]  Tail logs for a service (default: conformance-runner)
#   results         Print the JUnit XML result summary
#   status          Show status of conformance services
#   clean           Stop and remove conformance containers and volumes
#   help            Show this message

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
RESULTS_DIR="$SCRIPT_DIR/test-results"
# Use an array so paths with spaces are handled correctly (macOS paths often contain spaces)
COMPOSE_OPTS=(-f "$COMPOSE_FILE" --profile conformance)

# Allow overriding the conformance suite branch (e.g. a specific release tag)
export CONFORMANCE_SUITE_BRANCH="${CONFORMANCE_SUITE_BRANCH:-master}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-oid4vc-integration}"

# ── Colour helpers ─────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${BLUE}ℹ  $*${NC}"; }
success() { echo -e "${GREEN}✅ $*${NC}"; }
warn()    { echo -e "${YELLOW}⚠  $*${NC}"; }
error()   { echo -e "${RED}❌ $*${NC}" >&2; }
section() { echo -e "\n${CYAN}── $* ────────────────────────────────────────────${NC}"; }

# ── Docker helpers ─────────────────────────────────────────────────────────────

check_docker() {
    if ! docker info >/dev/null 2>&1; then
        error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

dc() {
    docker compose "${COMPOSE_OPTS[@]}" "$@"
}

# Build ACA-Py images for the native platform.
# On Apple Silicon (arm64) Rust is compiled natively to avoid Docker VM OOM
# from QEMU x86_64 emulation.  On x86_64 CI runners the detected platform is
# linux/amd64.  Override by setting DOCKER_PLATFORM in the environment.
_build_acapy_images() {
    local project="${COMPOSE_PROJECT_NAME:-oid4vc-integration}"
    local project_root
    project_root="$(cd "$SCRIPT_DIR/../.." && pwd)"

    # Auto-detect native platform unless the caller already exported DOCKER_PLATFORM
    if [[ -z "${DOCKER_PLATFORM:-}" ]]; then
        local arch
        arch="$(uname -m)"
        case "$arch" in
            arm64|aarch64) export DOCKER_PLATFORM="linux/arm64" ;;
            *)             export DOCKER_PLATFORM="linux/amd64" ;;
        esac
    fi
    info "  Using platform: $DOCKER_PLATFORM"

    for svc in acapy-issuer acapy-verifier; do
        local img="${project}-${svc}:latest"
        if docker image inspect "$img" &>/dev/null; then
            info "  $svc image already present ($img) — skipping rebuild"
        else
            info "  Building $svc → $img  ($DOCKER_PLATFORM, Rust ~10 min first time)…"
            docker buildx build \
                --platform "$DOCKER_PLATFORM" \
                --progress=plain \
                --load \
                --build-arg ACAPY_VERSION=1.4.0 \
                --build-arg ISOMDL_BRANCH=fix/python-build-system \
                -f oid4vc/docker/Dockerfile \
                -t "$img" \
                "$project_root"
        fi
    done
}

# ── Commands ──────────────────────────────────────────────────────────────────

cmd_build() {
    section "Building conformance images"
    info "Building OIDF conformance server from source (branch: $CONFORMANCE_SUITE_BRANCH)"
    info "Note: Maven build may take 10-20 minutes on first run. Subsequent builds are cached."
    dc build --pull conformance-server conformance-runner
    info "Building ACA-Py images (native arm64)…"
    _build_acapy_images
    success "Conformance images built"
}

cmd_run() {
    local scope="${1:-all}"
    section "Running conformance tests (scope=$scope)"

    check_docker
    mkdir -p "$RESULTS_DIR"

    # Stop any leftover conformance containers
    dc down --remove-orphans 2>/dev/null || true

    # Configure HTTPS endpoints for the OIDF conformance suite.
    # The HAIP profile requires https:// on all credential-issuer and verifier URLs.
    # acapy-tls-proxy (nginx) terminates TLS on 8443/8444 and proxies to the HTTP
    # ACA-Py containers.  These env vars are interpolated by docker-compose into
    # the ACA-Py OID4VC endpoint config so all metadata and offers advertise HTTPS.
    export ISSUER_OID4VCI_ENDPOINT="https://acapy-tls-proxy.local:8443"
    export VERIFIER_OID4VP_ENDPOINT="https://acapy-tls-proxy.local:8444"

    info "Starting infrastructure services (MongoDB, ACA-Py, conformance server)…"
    info "  Conformance suite branch: $CONFORMANCE_SUITE_BRANCH"
    info "  Note: First run builds the conformance suite from source (~15 min)"

    # Build ACA-Py images using native linux/arm64 to avoid Docker VM OOM during
    # Rust compilation under x86_64 QEMU emulation on Apple Silicon hosts.
    # Both images share the same Dockerfile+args, so the second build hits cache instantly.
    _build_acapy_images

    # Start infrastructure services (images already built above, --build is a no-op)
    # Use || true because acapy-tls-proxy has depends_on: condition: service_healthy
    # for acapy-issuer and acapy-verifier, and dc up -d may timeout waiting for the
    # healthcheck grace period before starting acapy-tls-proxy.  The polling loop
    # below (deadline=600s) waits for all services to actually become healthy.
    dc up -d \
        conformance-mongodb \
        conformance-server \
        acapy-issuer \
        acapy-verifier \
        acapy-tls-proxy || true

    info "Waiting for all services to become healthy…"
    # poll until conformance-server + both acapy services + tls proxy are healthy
    local wait_services=(conformance-server acapy-issuer acapy-verifier acapy-tls-proxy)
    local deadline=$((SECONDS + 600))
    for svc in "${wait_services[@]}"; do
        while true; do
            local state
            state=$(docker inspect \
                --format='{{.State.Health.Status}}' \
                "oid4vc-integration-${svc}-1" 2>/dev/null || echo "not-found")
            if [[ "$state" == "healthy" ]]; then
                success "  $svc is healthy"
                break
            fi
            if (( SECONDS > deadline )); then
                error "Timed out waiting for $svc to become healthy"
                dc logs "$svc" | tail -30
                dc down
                exit 2
            fi
            sleep 5
        done
    done

    info "Running setup_acapy.py + run_conformance.py (scope=$scope)…"
    info "Results will be written to: $RESULTS_DIR/conformance-junit.xml"

    CONFORMANCE_SCOPE="$scope" \
        dc run \
            --rm \
            --no-deps \
            -e CONFORMANCE_SCOPE="$scope" \
            conformance-runner

    local rc=$?

    # Stop infrastructure
    dc down 2>/dev/null || true

    if [ $rc -eq 0 ]; then
        success "Conformance tests PASSED"
    else
        error "Conformance tests FAILED (exit code $rc)"
        cmd_results || true
        exit $rc
    fi
}

cmd_setup_only() {
    section "ACA-Py conformance setup only"
    check_docker

    # Start infrastructure services in the background
    info "Starting ACA-Py services and conformance suite…"
    dc up -d --build conformance-mongodb conformance-server acapy-issuer acapy-verifier

    info "Waiting for conformance suite to become healthy (this may take a few minutes)…"
    dc wait conformance-server 2>/dev/null || \
        docker compose "${COMPOSE_OPTS[@]}" exec conformance-server true 2>/dev/null || true

    info "Running setup_acapy.py…"
    dc run --rm conformance-runner \
        python conformance/setup_acapy.py
    success "ACA-Py conformance setup complete — output at /tmp/conformance-setup.json"
}

cmd_issuer() {
    section "OID4VCI Issuer conformance tests"
    cmd_run "issuer"
}

cmd_verifier() {
    section "OID4VP Verifier conformance tests"
    cmd_run "verifier"
}

cmd_pytest() {
    section "Running pytest conformance wrappers"
    check_docker

    # Assume services are already up; just run pytest inside a new runner container
    # (mounts test-results from host)
    dc run --rm \
        -e CONFORMANCE_SETUP_OUTPUT=/tmp/conformance-setup.json \
        conformance-runner \
        python -m pytest tests/conformance/ \
            -m conformance \
            -v \
            --tb=short \
            --junit-xml=/usr/src/app/test-results/conformance-pytest.xml

    success "pytest conformance wrapper tests complete"
}

cmd_logs() {
    local service="${1:-conformance-runner}"
    check_docker
    info "Tailing logs for service: $service"
    dc logs -f "$service"
}

cmd_results() {
    local xml_file="$RESULTS_DIR/conformance-junit.xml"
    section "Conformance Test Results"

    if [ ! -f "$xml_file" ]; then
        warn "No results file found at $xml_file"
        info "Run './run-conformance-tests.sh run' first to generate results"
        return 1
    fi

    info "Results file: $xml_file"
    echo ""

    # Pretty-print totals using grep/awk
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$xml_file" <<'PYEOF'
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1])
root = tree.getroot()
total = passed = failed = skipped = 0
for suite in root.findall('testsuite'):
    t = int(suite.get('tests', 0))
    f = int(suite.get('failures', 0))
    s = int(suite.get('skipped', 0))
    p = t - f - s
    total += t; passed += p; failed += f; skipped += s
    icon = "✅" if f == 0 else "❌"
    print(f"  {icon}  {suite.get('name', 'unknown')}: {p} passed / {f} failed / {s} skipped (total {t})")

print()
overall_icon = "✅" if failed == 0 else "❌"
print(f"  {overall_icon}  TOTAL: {passed}/{total} passed ({skipped} skipped, {failed} failed)")
PYEOF
    else
        cat "$xml_file"
    fi
}

cmd_status() {
    section "Conformance Service Status"
    check_docker
    dc ps 2>/dev/null || info "No conformance services running"
}

cmd_clean() {
    section "Cleaning conformance environment"
    check_docker
    dc down -v --remove-orphans 2>/dev/null || true
    success "Conformance services stopped and volumes removed"
    info "Note: Test results in $RESULTS_DIR/ are preserved"
}

show_usage() {
    cat <<EOF

OIDF Conformance Test Runner for ACA-Py OID4VC
===============================================

Usage: $(basename "$0") [command] [options]

Commands:
  run [scope]    Build & run conformance tests
                   scope: all | issuer | verifier  (default: all)
  build          Build conformance images without running
  setup          Start services and configure ACA-Py (no tests)
  issuer         Run OID4VCI issuer tests only
  verifier       Run OID4VP verifier tests only
  pytest         Run pytest wrapper tests (requires services running)
  logs [svc]     Tail logs for a service  (default: conformance-runner)
  results        Print summary of latest test results
  status         Show status of conformance services
  clean          Stop and remove conformance containers/volumes
  help           Show this help message

Environment variables:
  CONFORMANCE_SUITE_BRANCH   Git branch/tag to build (default: main)
  CONFORMANCE_SCOPE          Test scope: all|issuer|verifier (default: all)
  COMPOSE_PROJECT_NAME       Docker Compose project name (default: oid4vc-integration)

Examples:
  # First run (builds Maven + Java; takes ~15-20 min):
  $(basename "$0") run

  # Re-run only issuer tests (images cached):
  $(basename "$0") issuer

  # Use a specific conformance suite release:
  CONFORMANCE_SUITE_BRANCH=release-v6.0 $(basename "$0") run

  # View failure details after a run:
  $(basename "$0") results

  # Clean up everything:
  $(basename "$0") clean

EOF
}

# ── Entry point ───────────────────────────────────────────────────────────────

main() {
    check_docker

    case "${1:-run}" in
        run)      cmd_run      "${2:-all}" ;;
        build)    cmd_build ;;
        setup)    cmd_setup_only ;;
        issuer)   cmd_issuer ;;
        verifier) cmd_verifier ;;
        pytest)   cmd_pytest ;;
        logs)     cmd_logs    "${2:-conformance-runner}" ;;
        results)  cmd_results ;;
        status)   cmd_status ;;
        clean)    cmd_clean ;;
        help|-h|--help) show_usage ;;
        *)
            error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

main "$@"
