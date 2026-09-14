#!/usr/bin/env python3
"""A script to run a local test of a specific version of acapy-agent against all
(or selected) plugins' integration tests. The script is designed for testing
ACA-Py release candidates to verify them before a new release.

The script pins each plugin's acapy-agent dependency to the specified version,
runs the integration tests, and then reverts any changes made to
pyproject.toml and poetry.lock files.

Usage: ./test_acapy_version.py <acapy-agent-version> [plugin ...] [--tag REF]

Examples: ./test_acapy_version.py 1.7.0rc0
          ./test_acapy_version.py 1.7.0rc0 basicmessage_storage webvh
          ./test_acapy_version.py 1.3.6rc0 --tag 1.3.2.1

--tag checks out the given git tag/ref (e.g. the most recent tag for an
ACA-Py LTS line) into a temporary worktree and runs the test there instead
of against the current checkout, so the plugin set and code match what
actually shipped on that line. The current working tree is left untouched.

Requires: poetry, docker (with compose plugin). Run from the repo root.
"""

import argparse
import datetime
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent

# Full output for anything that fails is appended here instead of printed, so
# stdout stays limited to progress/status lines. Gitignored via the repo's
# blanket `*.log` rule. Lives in REPO_ROOT (not a --tag worktree) so it
# survives after the temporary worktree is removed.
RUN_LOG_PATH = REPO_ROOT / ".test-acapy-version.log"

# Matches pr-integration-tests.yaml, which skips cheqd's integration tests.
SKIP_TESTS = {"cheqd"}

# plugin_globals holds shared pyproject.toml sections for repo_manager.py; it
# isn't an actual plugin (matches pr-integration-tests.yaml, which excludes it
# the same way).
EXCLUDED_PLUGINS = {"plugin_globals"}

ACAPY_DEP_RE = re.compile(r'(acapy-agent\s*=\s*\{\s*version\s*=\s*")[^"]+(")')

# Native bindings that acapy-agent owns transitively (crypto/wallet/indy
# libraries). Plugins pin these tightly in their integration dev-dependency
# group to match whatever acapy-agent needed when the pin was last touched;
# an older tag's pins can be stale for a newer acapy-agent version within the
# same line, causing spurious `poetry lock` conflicts unrelated to the plugin
# itself.
NATIVE_BINDING_DEPS = ("anoncreds", "aries-askar", "indy-credx", "indy-vdr", "python3-indy")

NATIVE_BINDING_DEP_RE = re.compile(
    r'(' + "|".join(re.escape(dep) for dep in NATIVE_BINDING_DEPS) + r')'
    r'(\s*=\s*\{\s*version\s*=\s*")[~^]?([^"]+)(")'
)


def discover_plugins(root: Path) -> list[str]:
    """A plugin is any top-level directory whose pyproject.toml declares an
    acapy-agent dependency. Derived instead of hardcoded so new plugins are
    picked up automatically.
    """
    plugins = []
    for pyproject in sorted(root.glob("*/pyproject.toml")):
        plugin = pyproject.parent.name
        if plugin in EXCLUDED_PLUGINS:
            continue
        if "acapy-agent" in pyproject.read_text():
            plugins.append(plugin)
    return plugins


def check_clean(root: Path) -> None:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--", "*/pyproject.toml", "*/poetry.lock"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        print(
            "error: uncommitted changes already present in pyproject.toml/poetry.lock "
            "files. Commit or stash first.",
            file=sys.stderr,
        )
        print(result.stdout, file=sys.stderr)
        sys.exit(1)


def revert(touched_files: list[str], root: Path) -> None:
    print()
    print("== Reverting version bump changes ==")
    if touched_files:
        subprocess.run(["git", "checkout", "--", *touched_files], cwd=root)
        print("Reverted:", " ".join(touched_files))
    else:
        print("(nothing to revert)")


def create_worktree(tag: str) -> Path:
    """Check out `tag` into a temporary git worktree and return its path, so
    the test can run against that tag's actual plugin set and source instead
    of the current checkout (old tags predate this script and don't have a
    fixed plugin list, so its own tree can't just be checked out in place).
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="test-acapy-version-"))
    worktree_path = tmp_dir / "worktree"
    print(f"== Checking out '{tag}' into temporary worktree {worktree_path} ==")
    result = subprocess.run(
        ["git", "worktree", "add", "--detach", str(worktree_path), tag],
        cwd=REPO_ROOT,
    )
    if result.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        print(f"error: failed to check out '{tag}'", file=sys.stderr)
        sys.exit(1)
    return worktree_path


def reclaim_ownership(path: Path) -> None:
    """Integration test containers run as root and can leave files in the
    worktree (e.g. poetry/build artifacts) owned by root, which then blocks
    cleanup as the invoking user. Use a throwaway container to chown
    everything back before removing it.
    """
    subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{path}:/wt",
            "alpine",
            "chown", "-R", f"{os.getuid()}:{os.getgid()}", "/wt",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def remove_worktree(worktree_path: Path) -> None:
    print()
    print(f"== Removing temporary worktree {worktree_path} ==")
    reclaim_ownership(worktree_path)
    subprocess.run(
        ["git", "worktree", "remove", "--force", str(worktree_path)],
        cwd=REPO_ROOT,
    )
    subprocess.run(["git", "worktree", "prune"], cwd=REPO_ROOT)
    shutil.rmtree(worktree_path.parent, ignore_errors=True)


def set_version(pyproject_path: Path, version: str) -> bool:
    text = pyproject_path.read_text()
    new_text, n = ACAPY_DEP_RE.subn(rf"\g<1>{version}\g<2>", text)
    if n == 0:
        print(
            f"warning: no acapy-agent dependency line found in {pyproject_path}",
            file=sys.stderr,
        )
        return False
    pyproject_path.write_text(new_text)
    return True


def relax_native_binding_pins(pyproject_path: Path) -> None:
    """Loosen exact/tilde/caret pins on acapy-agent's own native-binding
    deps (see NATIVE_BINDING_DEPS) to a lower-bound-only constraint, so
    `poetry lock` can pick whatever version the target acapy-agent release
    actually needs instead of being stuck on whatever was pinned when this
    pyproject.toml was last touched. Only called for --tag runs: on the
    current checkout these pins are already kept current, so relaxing them
    there would just let poetry drift to untested binding versions.
    """
    text = pyproject_path.read_text()
    new_text = NATIVE_BINDING_DEP_RE.sub(r"\1\2>=\3\4", text)
    if new_text != text:
        pyproject_path.write_text(new_text)


_ENV_SNAPSHOT_SENTINEL = "___TEST_ACAPY_VERSION_ENV_SNAPSHOT___"


def env_from_sourced_script(script: Path) -> dict[str, str]:
    """Run a shell script with `.` (source) and return the environment it leaves
    behind, so variables it exports (e.g. init-network.sh's SUBNET/SUBNET_PREFIX)
    are visible to the docker compose calls that follow it.
    """
    result = subprocess.run(
        ["sh", "-c", f"set -a; . ./{script.name}; echo {_ENV_SNAPSHOT_SENTINEL}; env"],
        cwd=script.parent,
        capture_output=True,
        text=True,
    )
    script_output, _, env_dump = result.stdout.partition(_ENV_SNAPSHOT_SENTINEL + "\n")
    if result.returncode != 0:
        log_failure(f"{script.name} output", text=script_output + result.stderr)
        print(
            f"[{now()}] warning: {script.name} failed, continuing with unmodified "
            f"environment -- details in {RUN_LOG_PATH.name}"
        )
        return dict(os.environ)

    env = dict(os.environ)
    for line in env_dump.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            env[key] = value
    return env


def now() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S")


def run_logged(
    cmd: list[str],
    cwd: Path,
    log_path: Path,
    env: dict[str, str] | None = None,
    mode: str = "w",
) -> int:
    """Run cmd with stdout/stderr redirected to log_path instead of the
    console, so a passing run (the common case) doesn't flood the terminal.
    """
    with open(log_path, mode) as log_file:
        result = subprocess.run(cmd, cwd=cwd, env=env, stdout=log_file, stderr=subprocess.STDOUT)
    return result.returncode


def log_failure(label: str, log_path: Path | None = None, text: str | None = None) -> None:
    """Append full output to RUN_LOG_PATH instead of printing it, so stdout
    stays limited to progress/status lines.
    """
    content = text if text is not None else (log_path.read_text() if log_path and log_path.exists() else "")
    with open(RUN_LOG_PATH, "a") as f:
        f.write(f"---- {label} ----\n")
        f.write(content)
        if content and not content.endswith("\n"):
            f.write("\n")
        f.write(f"---- end {label} ----\n\n")


def compose_down(integration_dir: Path) -> None:
    subprocess.run(
        ["docker", "compose", "down", "--remove-orphans", "--rmi", "local"],
        cwd=integration_dir,
        stderr=subprocess.DEVNULL,
    )


def remove_standalone_network(name: str) -> None:
    """Remove a docker network created outside of any compose project (e.g. by
    init-network.sh), which `compose_down` won't touch. Best-effort: a later
    plugin's leftover network shouldn't fail the whole run.
    """
    subprocess.run(
        ["docker", "network", "rm", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def test_plugin(
    plugin: str,
    version: str,
    touched_files: list[str],
    root: Path,
    log_dir: Path,
    relax_bindings: bool,
) -> str:
    print(f"[{now()}] [{plugin}] starting (acapy-agent {version})")
    plugin_dir = root / plugin
    pyproject = plugin_dir / "pyproject.toml"
    lock = plugin_dir / "poetry.lock"

    if not pyproject.exists():
        print(f"[{now()}] [{plugin}] skip: no pyproject.toml")
        return "no-pyproject"

    if not set_version(pyproject, version):
        print(f"[{now()}] [{plugin}] skip: no acapy-agent dependency")
        return "no-acapy-dep"
    if relax_bindings:
        relax_native_binding_pins(pyproject)
    touched_files.append(str(pyproject.relative_to(root)))

    lock_log = log_dir / f"{plugin}-lock.log"
    if run_logged(["poetry", "lock"], cwd=plugin_dir, log_path=lock_log) != 0:
        log_failure(f"{plugin} poetry lock output", log_path=lock_log)
        print(
            f"[{now()}] [{plugin}] FAILED: poetry lock (version {version} likely "
            f"unresolvable) -- details in {RUN_LOG_PATH.name}"
        )
        lock_log.unlink(missing_ok=True)
        if lock.exists():
            touched_files.append(str(lock.relative_to(root)))
        return "lock-failed"
    lock_log.unlink(missing_ok=True)
    touched_files.append(str(lock.relative_to(root)))

    if plugin in SKIP_TESTS:
        print(f"[{now()}] [{plugin}] skipped (matches CI)")
        return "skipped"

    integration_dir = plugin_dir / "integration"
    if not (integration_dir / "docker-compose.yml").exists():
        print(f"[{now()}] [{plugin}] skip: no integration/docker-compose.yml")
        return "no-integration-tests"

    # init-network.sh (only used by cache_redis) exports a randomized SUBNET/
    # SUBNET_PREFIX and creates a standalone "acapy_default" docker network
    # with that subnet. That's separate from the "integration_acapy_default"
    # network docker compose creates for the stack itself. Passing the same
    # SUBNET into `compose up` would make the two collide ("pool overlaps"),
    # so its env is scoped to the build step only and `up`/`run` fall back to
    # docker-compose.yml's own default subnet, matching the working behavior
    # this replaces.
    init_network = integration_dir / "init-network.sh"
    build_env = env_from_sourced_script(init_network) if init_network.exists() else dict(os.environ)

    build_log = log_dir / f"{plugin}-build.log"
    if run_logged(["docker", "compose", "build"], cwd=integration_dir, log_path=build_log, env=build_env) != 0:
        log_failure(f"{plugin} docker compose build output", log_path=build_log)
        print(f"[{now()}] [{plugin}] FAILED: docker compose build -- details in {RUN_LOG_PATH.name}")
        build_log.unlink(missing_ok=True)
        compose_down(integration_dir)
        if init_network.exists():
            remove_standalone_network("acapy_default")
        return "build-failed"
    # Build succeeded -- from here only the test run itself matters.
    build_log.unlink(missing_ok=True)

    test_log = log_dir / f"{plugin}-test.log"
    if plugin == "cache_redis":
        test_exit = run_logged(["docker", "compose", "up", "-d"], cwd=integration_dir, log_path=test_log)
        if test_exit == 0:
            test_exit = run_logged(
                ["docker", "compose", "run", "--rm", "tests"],
                cwd=integration_dir,
                log_path=test_log,
                mode="a",
            )
    else:
        test_exit = run_logged(
            ["docker", "compose", "up", "--exit-code-from", "tests"],
            cwd=integration_dir,
            log_path=test_log,
        )

    compose_down(integration_dir)
    if init_network.exists():
        remove_standalone_network("acapy_default")

    if test_exit != 0:
        log_failure(f"{plugin} integration test output", log_path=test_log)
        print(f"[{now()}] [{plugin}] FAILED: integration tests -- details in {RUN_LOG_PATH.name}")
        test_log.unlink(missing_ok=True)
        return "fail"

    test_log.unlink(missing_ok=True)
    print(f"[{now()}] [{plugin}] PASSED")
    return "pass"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test plugins' integration suites against a specific acapy-agent version.",
    )
    parser.add_argument("version", help="acapy-agent version to test, e.g. 1.7.0rc0")
    parser.add_argument(
        "plugins", nargs="*", help="Plugins to test (default: all discovered plugins)"
    )
    parser.add_argument(
        "--tag",
        metavar="REF",
        help=(
            "Test against this git tag/ref instead of the current checkout "
            "(e.g. the most recent tag for an ACA-Py LTS line), checked out "
            "into a temporary worktree. Leaves the current working tree untouched."
        ),
    )
    args = parser.parse_args()

    RUN_LOG_PATH.write_text(
        f"test_acapy_version.py run -- {datetime.datetime.now().isoformat(timespec='seconds')}\n"
        f"acapy-agent version: {args.version}\n"
        + (f"tag: {args.tag}\n" if args.tag else "")
    )
    print(f"Full output on failure will be written to {RUN_LOG_PATH.name}")

    root = REPO_ROOT
    worktree_path: Path | None = None
    if args.tag:
        worktree_path = create_worktree(args.tag)
        root = worktree_path

    log_dir = Path(tempfile.mkdtemp(prefix="test-acapy-version-logs-"))
    try:
        os.chdir(root)
        check_clean(root)

        all_plugins = discover_plugins(root)
        plugins = args.plugins or all_plugins

        touched_files: list[str] = []
        results: dict[str, str] = {}
        try:
            for plugin in plugins:
                results[plugin] = test_plugin(
                    plugin, args.version, touched_files, root, log_dir, bool(args.tag)
                )
        finally:
            revert(touched_files, root)
    finally:
        shutil.rmtree(log_dir, ignore_errors=True)
        os.chdir(REPO_ROOT)
        if worktree_path:
            remove_worktree(worktree_path)

    print()
    tag_suffix = f", tag {args.tag}" if args.tag else ""
    print(f"================ Summary (acapy-agent {args.version}{tag_suffix}) ================")
    for plugin in plugins:
        print(f"{plugin:<30} {results.get(plugin, 'not-run')}")


if __name__ == "__main__":
    main()
