"""
Proxy provisioning helper — runs the in-container setup_proxy_org.py
helper via `docker compose exec` and parses its JSON stdout.

This avoids HTML scraping of the proxy dashboard (CSRF tokens, form
submission) by directly invoking the proxy's own Python modules inside
the container. The reused functions (`set_config`, `generate_org_ca`,
`AgentManager.create_agent`) are exactly the ones the dashboard uses,
so the test exercises the real production paths.
"""
import json
import pathlib
import subprocess
import time
from dataclasses import dataclass

import httpx


_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent.parent
_COMPOSE_FILE = _REPO_ROOT / "tests" / "e2e" / "docker-compose.e2e.yml"
_PROJECT_NAME = "cullis-e2e"


@dataclass
class ProvisionedAgent:
    org_id: str
    agent_id: str
    api_key: str


@dataclass
class RegisteredOrg:
    org_id: str


def _docker_compose_cmd() -> list[str]:
    """Return the working `docker compose` invocation prefix."""
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            check=True, capture_output=True, timeout=10,
        )
        return ["docker", "compose"]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return ["docker-compose"]


def _run_setup(proxy_service_name: str, extra_args: list[str]) -> dict:
    """Run setup_proxy_org.py inside `proxy_service_name` and parse JSON stdout."""
    cmd = _docker_compose_cmd() + [
        "--project-name", _PROJECT_NAME,
        "-f", str(_COMPOSE_FILE),
        "exec", "-T", proxy_service_name,
        "python", "/e2e_scripts/setup_proxy_org.py",
    ] + extra_args
    result = subprocess.run(
        cmd,
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"setup_proxy_org.py failed in {proxy_service_name}:\n"
            f"args:   {extra_args}\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )

    # The script may print log noise on stderr; the JSON is on stdout.
    # Take the LAST line of stdout that parses as JSON, in case earlier
    # lines contain DB init logs.
    last_json: dict | None = None
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            last_json = json.loads(line)
        except json.JSONDecodeError:
            continue
    if last_json is None:
        raise RuntimeError(
            f"setup_proxy_org.py produced no JSON on stdout:\n{result.stdout}"
        )
    return last_json


def register_org(
    proxy_service_name: str,
    broker_url: str,
    invite_token: str,
    org_id: str,
    display_name: str,
) -> RegisteredOrg:
    """
    Phase 1: register the org with the broker via setup_proxy_org.py
    --phase=org. The org ends up in `pending` state on the broker side.

    `broker_url` is the URL the proxy container uses INSIDE the docker
    network — for the e2e stack that is `http://broker:8000`, NOT the
    host-exposed `http://localhost:18000` URL the test runner uses.

    Restarts the proxy container afterwards so the lifespan re-runs and
    initializes the BrokerBridge with the freshly persisted broker_url.
    Without this restart the egress endpoints stay at
    503 "Egress bridge not initialized".
    """
    _run_setup(proxy_service_name, [
        "--phase",        "org",
        "--broker-url",   broker_url,
        "--invite-token", invite_token,
        "--org-id",       org_id,
        "--display-name", display_name,
    ])
    _restart_proxy_and_wait(proxy_service_name)
    return RegisteredOrg(org_id=org_id)


def create_agent(
    proxy_service_name: str,
    org_id: str,
    agent_name: str,
    capabilities: list[str],
) -> ProvisionedAgent:
    """
    Phase 2: create the local internal agent (x509 + API key) and register
    it with the broker registry. Requires the org to already be `active`
    on the broker side, i.e. approve_org() has been called between
    register_org() and create_agent().
    """
    payload = _run_setup(proxy_service_name, [
        "--phase",        "agent",
        "--org-id",       org_id,
        "--agent-name",   agent_name,
        "--capabilities", ",".join(capabilities),
    ])
    return ProvisionedAgent(
        org_id=payload["org_id"],
        agent_id=payload["agent_id"],
        api_key=payload["api_key"],
    )


# Map service name → host-exposed health URL.  Kept here so the helper
# does not need to import the conftest module (would create a cycle).
_HEALTH_URLS = {
    "proxy-alpha": "http://localhost:19100/health",
    "proxy-beta":  "http://localhost:19101/health",
}


def _restart_proxy_and_wait(proxy_service_name: str, timeout: int = 60) -> None:
    """`docker compose restart` the proxy and poll /health until 200."""
    cmd = _docker_compose_cmd() + [
        "--project-name", _PROJECT_NAME,
        "-f", str(_COMPOSE_FILE),
        "restart", proxy_service_name,
    ]
    subprocess.run(
        cmd,
        cwd=str(_REPO_ROOT),
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )

    health_url = _HEALTH_URLS.get(proxy_service_name)
    if not health_url:
        # Unknown service — skip health wait, caller will see the failure
        # on the next API call if the restart did not complete in time.
        return

    deadline = time.monotonic() + timeout
    last_err = ""
    while time.monotonic() < deadline:
        try:
            r = httpx.get(health_url, timeout=2.0)
            if r.status_code == 200:
                return
            last_err = f"HTTP {r.status_code}"
        except Exception as exc:
            last_err = str(exc)
        time.sleep(1.0)
    raise RuntimeError(
        f"{proxy_service_name} did not become healthy after restart "
        f"within {timeout}s (last error: {last_err})"
    )
