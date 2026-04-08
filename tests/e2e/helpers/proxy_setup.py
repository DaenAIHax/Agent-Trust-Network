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
from dataclasses import dataclass


_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent.parent
_COMPOSE_FILE = _REPO_ROOT / "tests" / "e2e" / "docker-compose.e2e.yml"
_PROJECT_NAME = "cullis-e2e"


@dataclass
class ProvisionedAgent:
    org_id: str
    agent_id: str
    api_key: str


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


def provision_org_and_agent(
    proxy_service_name: str,
    broker_url: str,
    invite_token: str,
    org_id: str,
    display_name: str,
    agent_name: str,
    capabilities: list[str],
) -> ProvisionedAgent:
    """
    Run setup_proxy_org.py inside the named proxy container.

    `broker_url` is the URL the proxy container uses INSIDE the docker
    network — for the e2e stack that is `http://broker:8000`, NOT the
    host-exposed `http://localhost:18000` URL the test runner uses.

    Returns the provisioned credentials needed to drive the egress API
    from the host (ProvisionedAgent.api_key is sent as `X-API-Key`).
    """
    cmd = _docker_compose_cmd() + [
        "--project-name", _PROJECT_NAME,
        "-f", str(_COMPOSE_FILE),
        "exec", "-T", proxy_service_name,
        "python", "/e2e_scripts/setup_proxy_org.py",
        "--broker-url",   broker_url,
        "--invite-token", invite_token,
        "--org-id",       org_id,
        "--display-name", display_name,
        "--agent-name",   agent_name,
        "--capabilities", ",".join(capabilities),
    ]
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

    return ProvisionedAgent(
        org_id=last_json["org_id"],
        agent_id=last_json["agent_id"],
        api_key=last_json["api_key"],
    )
