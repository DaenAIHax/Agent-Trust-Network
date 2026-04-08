"""
Pytest fixtures for the Cullis full-stack E2E test (Item 12 in plan.md).

The `e2e_stack` fixture is session-scoped: it boots the entire docker
compose stack ONCE for all e2e tests in the session, then tears it down
in a try/finally so a failed test never leaks containers.

By design these fixtures only run when pytest is invoked with `-m e2e`.
The `not e2e` marker filter in pytest.ini skips them otherwise.
"""
import os
import pathlib
import shutil
import subprocess
import time
from typing import Iterator

import httpx
import pytest

# Resolve paths relative to this file so the test can be invoked from any cwd.
_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
_COMPOSE_FILE = _HERE / "docker-compose.e2e.yml"
_PROJECT_NAME = "cullis-e2e"

# Endpoints exposed on the host (matching the port mapping in the compose file)
BROKER_URL = "http://localhost:18000"
PROXY_ALPHA_URL = "http://localhost:19100"
PROXY_BETA_URL = "http://localhost:19101"

# Credentials baked into docker-compose.e2e.yml
ADMIN_SECRET = "cullis-e2e-admin-secret-do-not-reuse"
PROXY_ALPHA_ADMIN_SECRET = "cullis-e2e-proxy-alpha-secret"
PROXY_BETA_ADMIN_SECRET = "cullis-e2e-proxy-beta-secret"

# Bounds for boot wait
_HEALTH_TIMEOUT_SECONDS = 180
_HEALTH_POLL_INTERVAL = 2.0


def _docker_compose_cmd() -> list[str]:
    """
    Detect whether to use `docker compose` (plugin) or `docker-compose`
    (standalone). Raises SkipTest if neither is available.
    """
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed — skipping e2e tests")
    # Try plugin first
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            check=True, capture_output=True, timeout=10,
        )
        return ["docker", "compose"]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        pass
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    pytest.skip("docker compose plugin not found — skipping e2e tests")


def _compose(args: list[str], *, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run a docker compose subcommand against the e2e project."""
    cmd = _docker_compose_cmd() + [
        "--project-name", _PROJECT_NAME,
        "-f", str(_COMPOSE_FILE),
    ] + args
    return subprocess.run(
        cmd,
        cwd=str(_REPO_ROOT),
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _wait_for_url(url: str, label: str, timeout: int = _HEALTH_TIMEOUT_SECONDS) -> None:
    """Poll a URL until it returns 200, or fail the test after `timeout` seconds."""
    deadline = time.monotonic() + timeout
    last_err: str = ""
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=3.0)
            if r.status_code == 200:
                return
            last_err = f"HTTP {r.status_code}"
        except Exception as exc:
            last_err = str(exc)
        time.sleep(_HEALTH_POLL_INTERVAL)
    raise TimeoutError(
        f"{label} did not become healthy within {timeout}s "
        f"(last error: {last_err}, url: {url})"
    )


@pytest.fixture(scope="session")
def e2e_stack() -> Iterator[dict]:
    """
    Boot the full Cullis stack via docker compose, wait for /healthz on
    every service, yield the relevant URLs, then tear everything down.

    Yields a dict:
        {
          "broker_url":      "http://localhost:18000",
          "proxy_alpha_url": "http://localhost:19100",
          "proxy_beta_url":  "http://localhost:19101",
          "admin_secret":    "cullis-e2e-admin-secret-do-not-reuse",
        }

    The teardown runs even if a test fails. If KEEP_E2E_STACK=1 is set
    in the environment, the stack is left running for manual inspection.
    """
    if not _COMPOSE_FILE.exists():
        pytest.fail(f"Compose file missing: {_COMPOSE_FILE}")

    # Pre-flight: make sure docker is reachable. Some CI sandboxes have
    # docker installed but cannot actually start containers.
    try:
        subprocess.run(
            ["docker", "info"], check=True, capture_output=True, timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker daemon is not reachable: {exc}")

    # Clean up any leftover stack from a previous interrupted run
    _compose(["down", "-v", "--remove-orphans"], check=False, timeout=120)

    print(f"\n[e2e] Booting stack via {_COMPOSE_FILE.name}...")
    try:
        _compose(["up", "-d", "--build"], timeout=600)
    except subprocess.CalledProcessError as exc:
        print(f"[e2e] docker compose up failed:\n{exc.stderr}")
        raise

    try:
        # Health checks against the host-exposed endpoints
        _wait_for_url(f"{BROKER_URL}/healthz",       "broker")
        _wait_for_url(f"{BROKER_URL}/readyz",        "broker readyz")
        _wait_for_url(f"{PROXY_ALPHA_URL}/health",   "proxy-alpha")
        _wait_for_url(f"{PROXY_BETA_URL}/health",    "proxy-beta")
        print("[e2e] Stack is healthy. Yielding to tests.")

        yield {
            "broker_url":      BROKER_URL,
            "proxy_alpha_url": PROXY_ALPHA_URL,
            "proxy_beta_url":  PROXY_BETA_URL,
            "admin_secret":    ADMIN_SECRET,
            "proxy_alpha_admin_secret": PROXY_ALPHA_ADMIN_SECRET,
            "proxy_beta_admin_secret":  PROXY_BETA_ADMIN_SECRET,
        }
    finally:
        if os.environ.get("KEEP_E2E_STACK") == "1":
            print(
                f"\n[e2e] KEEP_E2E_STACK=1 set — leaving the stack running.\n"
                f"      Inspect:  docker compose --project-name {_PROJECT_NAME} "
                f"-f {_COMPOSE_FILE} ps\n"
                f"      Tear down: docker compose --project-name {_PROJECT_NAME} "
                f"-f {_COMPOSE_FILE} down -v"
            )
        else:
            print("\n[e2e] Tearing down stack...")
            _compose(["down", "-v", "--remove-orphans"], check=False, timeout=120)
            print("[e2e] Teardown complete.")
