"""
Cullis demo orchestrator — drives the demo stack defined in
scripts/demo/docker-compose.demo.yml.

Sub-commands (invoked from deploy_demo.sh):

  init   one-shot bootstrap after `docker compose up`:
           1. wait for broker /readyz
           2. generate two invite tokens (admin secret)
           3. register both orgs with the broker (status=pending)
           4. approve both orgs
           5. create one agent per org with capability "order.check"
              (alpha::sender + beta::checker)
           6. persist the issued API keys to scripts/demo/.state.json
              so the standalone sender.py / checker.py scripts can read them

  info   print dashboard URLs + bootstrap credentials so a live audience
         can log into the broker and proxy dashboards from a browser

  reset  delete .state.json so the next `init` starts fresh

The actual conversation between agents lives in scripts/demo/sender.py
and scripts/demo/checker.py — two ~50-line standalone Python scripts
that talk to their proxy via X-API-Key, no LLM, no Anthropic API.

This orchestrator deliberately does NOT depend on tests/e2e/helpers — it
re-implements the few HTTP calls it needs (under 100 lines total) so
the demo and the test suite stay decoupled and can evolve separately.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
from dataclasses import dataclass

import httpx


# ─────────────────────────────────────────────────────────────────────────────
# Constants — must stay in sync with scripts/demo/docker-compose.demo.yml
# ─────────────────────────────────────────────────────────────────────────────

_HERE = pathlib.Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
_COMPOSE_FILE = _HERE / "docker-compose.demo.yml"
_PROJECT_NAME = "cullis-demo"
_STATE_FILE = _HERE / ".state.json"

BROKER_URL_HOST = "http://localhost:8800"
PROXY_ALPHA_URL_HOST = "http://localhost:9800"
PROXY_BETA_URL_HOST = "http://localhost:9801"

# Same URL but as the proxy containers see the broker on the docker network
BROKER_URL_INTERNAL = "http://broker:8000"

ADMIN_SECRET = "cullis-demo-admin-secret"

ORG_ALPHA = ("alpha", "Alpha Org",  "proxy-alpha", PROXY_ALPHA_URL_HOST)
ORG_BETA  = ("beta",  "Beta Org",   "proxy-beta",  PROXY_BETA_URL_HOST)

DEMO_CAPABILITY = "order.check"
# Agent role names. Kept generic on purpose: these agents are dumb HTTP
# scripts (no LLM, no Anthropic API) — they exist to prove the broker
# routes messages between two orgs end-to-end.
SENDER_NAME  = "sender"
CHECKER_NAME = "checker"

_HEALTH_TIMEOUT_SECONDS = 180


# ─────────────────────────────────────────────────────────────────────────────
# Pretty printing — meant for a live audience, not for parsing
# ─────────────────────────────────────────────────────────────────────────────

_BOLD  = "\033[1m"
_DIM   = "\033[2m"
_GREEN = "\033[32m"
_CYAN  = "\033[36m"
_RED   = "\033[31m"
_RESET = "\033[0m"


def _step(idx: int, total: int, msg: str) -> None:
    print(f"  {_CYAN}[{idx}/{total}]{_RESET} {msg}", flush=True)


def _ok(msg: str) -> None:
    print(f"  {_GREEN}\u2713{_RESET}  {msg}", flush=True)


def _info(msg: str) -> None:
    print(f"  {_DIM}{msg}{_RESET}", flush=True)


def _err(msg: str) -> None:
    print(f"  {_RED}\u2717{_RESET}  {msg}", file=sys.stderr, flush=True)


def _section(title: str) -> None:
    print(f"\n{_BOLD}\u2500\u2500 {title} \u2500\u2500{_RESET}", flush=True)


# ─────────────────────────────────────────────────────────────────────────────
# Docker compose helpers
# ─────────────────────────────────────────────────────────────────────────────

def _compose_cmd() -> list[str]:
    """Return the working `docker compose` invocation prefix for this stack."""
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            check=True, capture_output=True, timeout=10,
        )
        return ["docker", "compose"]
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return ["docker-compose"]


def _compose(args: list[str], *, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
    cmd = _compose_cmd() + [
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


def _exec_in_proxy(service: str, script_args: list[str]) -> dict:
    """Run setup_proxy_org.py inside the named proxy container, parse JSON."""
    cmd = _compose_cmd() + [
        "--project-name", _PROJECT_NAME,
        "-f", str(_COMPOSE_FILE),
        "exec", "-T", service,
        "python", "/demo_scripts/setup_proxy_org.py",
    ] + script_args
    result = subprocess.run(
        cmd,
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"setup_proxy_org.py failed in {service}:\n"
            f"  args:   {script_args}\n"
            f"  stdout: {result.stdout}\n"
            f"  stderr: {result.stderr}"
        )
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


def _restart_proxy_and_wait(service: str, host_health_url: str, timeout: int = 60) -> None:
    _compose(["restart", service], timeout=60)
    deadline = time.monotonic() + timeout
    last_err = ""
    while time.monotonic() < deadline:
        try:
            r = httpx.get(host_health_url, timeout=2.0)
            if r.status_code == 200:
                return
            last_err = f"HTTP {r.status_code}"
        except Exception as exc:
            last_err = str(exc)
        time.sleep(1.0)
    raise RuntimeError(
        f"{service} did not become healthy after restart in {timeout}s "
        f"(last error: {last_err})"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Broker fixture — local KMS needs the broker CA on disk
# ─────────────────────────────────────────────────────────────────────────────

def ensure_broker_certs_fixture() -> None:
    """
    Mirror of the e2e conftest fixture: copy the dev broker CA into
    scripts/demo/.fixtures/broker_certs with permissions the container
    user can read AND write (the lifespan persists .admin_secret_hash
    inside this dir on first boot).
    """
    import shutil

    fixture_dir = _HERE / ".fixtures" / "broker_certs"
    src_key  = _REPO_ROOT / "certs" / "broker-ca-key.pem"
    src_cert = _REPO_ROOT / "certs" / "broker-ca.pem"

    if not src_key.exists() or not src_cert.exists():
        gen_script = _REPO_ROOT / "generate_certs.py"
        if not gen_script.exists():
            raise RuntimeError(
                "scripts/demo: certs/broker-ca.pem missing and generate_certs.py "
                "is not in the repo. Run `python generate_certs.py` first."
            )
        _info("generating broker CA via generate_certs.py...")
        subprocess.run(
            [sys.executable, str(gen_script)],
            cwd=str(_REPO_ROOT),
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )

    fixture_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(fixture_dir, 0o777)
    for src in (src_key, src_cert):
        dst = fixture_dir / src.name
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o644)
    # Drop any stale admin secret hash so the lifespan re-bootstraps it
    # against the demo ADMIN_SECRET on the next boot.
    stale = fixture_dir / ".admin_secret_hash"
    if stale.exists():
        stale.unlink()


# ─────────────────────────────────────────────────────────────────────────────
# Broker HTTP — admin invites + org approval
# ─────────────────────────────────────────────────────────────────────────────

def _wait_for_url(url: str, label: str, timeout: int = _HEALTH_TIMEOUT_SECONDS) -> None:
    deadline = time.monotonic() + timeout
    last_err = ""
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=3.0)
            if r.status_code == 200:
                return
            last_err = f"HTTP {r.status_code}"
        except Exception as exc:
            last_err = str(exc)
        time.sleep(2.0)
    raise RuntimeError(
        f"{label} did not become healthy within {timeout}s "
        f"(last error: {last_err}, url: {url})"
    )


def generate_invite(label: str, ttl_hours: int = 1) -> str:
    r = httpx.post(
        f"{BROKER_URL_HOST}/v1/admin/invites",
        json={"label": label, "ttl_hours": ttl_hours},
        headers={"X-Admin-Secret": ADMIN_SECRET},
        timeout=10.0,
    )
    if r.status_code not in (200, 201):
        raise RuntimeError(f"generate_invite({label}): HTTP {r.status_code} {r.text[:200]}")
    return r.json()["token"]


def approve_org(org_id: str) -> None:
    r = httpx.post(
        f"{BROKER_URL_HOST}/v1/admin/orgs/{org_id}/approve",
        headers={"X-Admin-Secret": ADMIN_SECRET},
        timeout=10.0,
    )
    # 409 = already active — treat as success so `init` can be re-run
    if r.status_code not in (200, 201, 204, 409):
        raise RuntimeError(f"approve_org({org_id}): HTTP {r.status_code} {r.text[:200]}")


# ─────────────────────────────────────────────────────────────────────────────
# Egress conversation — same calls a real customer SDK would make
# ─────────────────────────────────────────────────────────────────────────────

def _egress_headers(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key, "Content-Type": "application/json"}


def open_session(proxy_url: str, api_key: str, target_agent_id: str, target_org_id: str) -> str:
    r = httpx.post(
        f"{proxy_url}/v1/egress/sessions",
        json={
            "target_agent_id": target_agent_id,
            "target_org_id":   target_org_id,
            "capabilities":    [DEMO_CAPABILITY],
        },
        headers=_egress_headers(api_key),
        timeout=15.0,
    )
    if r.status_code != 200:
        raise RuntimeError(f"open_session: HTTP {r.status_code} {r.text[:200]}")
    return r.json()["session_id"]


def accept_session(proxy_url: str, api_key: str, session_id: str) -> None:
    r = httpx.post(
        f"{proxy_url}/v1/egress/sessions/{session_id}/accept",
        headers=_egress_headers(api_key),
        timeout=15.0,
    )
    if r.status_code not in (200, 204):
        raise RuntimeError(f"accept_session: HTTP {r.status_code} {r.text[:200]}")


def send_message(proxy_url: str, api_key: str, session_id: str, payload: dict, recipient_agent_id: str) -> None:
    r = httpx.post(
        f"{proxy_url}/v1/egress/send",
        json={
            "session_id":         session_id,
            "payload":            payload,
            "recipient_agent_id": recipient_agent_id,
        },
        headers=_egress_headers(api_key),
        timeout=15.0,
    )
    if r.status_code not in (200, 201, 202):
        raise RuntimeError(f"send_message: HTTP {r.status_code} {r.text[:200]}")


def poll_for_message(
    proxy_url: str, api_key: str, session_id: str, marker_value: str, timeout_seconds: float = 20.0,
) -> dict:
    deadline = time.monotonic() + timeout_seconds
    last_err = ""
    while time.monotonic() < deadline:
        try:
            r = httpx.get(
                f"{proxy_url}/v1/egress/messages/{session_id}",
                headers=_egress_headers(api_key),
                timeout=5.0,
            )
            if r.status_code == 200:
                for msg in r.json().get("messages", []):
                    payload = msg.get("payload") or {}
                    if payload.get("marker") == marker_value:
                        return msg
            else:
                last_err = f"HTTP {r.status_code}"
        except Exception as exc:
            last_err = str(exc)
        time.sleep(0.5)
    raise RuntimeError(
        f"poll_for_message: did not receive marker={marker_value} within "
        f"{timeout_seconds}s (last error: {last_err})"
    )


# ─────────────────────────────────────────────────────────────────────────────
# State persistence — share API keys between `init` and `send`
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DemoState:
    alpha_agent_id: str
    alpha_api_key: str
    alpha_org_secret: str
    beta_agent_id: str
    beta_api_key: str
    beta_org_secret: str

    def to_dict(self) -> dict:
        return {
            "alpha_agent_id":   self.alpha_agent_id,
            "alpha_api_key":    self.alpha_api_key,
            "alpha_org_secret": self.alpha_org_secret,
            "beta_agent_id":    self.beta_agent_id,
            "beta_api_key":     self.beta_api_key,
            "beta_org_secret":  self.beta_org_secret,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DemoState":
        return cls(
            alpha_agent_id=d["alpha_agent_id"],
            alpha_api_key=d["alpha_api_key"],
            alpha_org_secret=d.get("alpha_org_secret", ""),
            beta_agent_id=d["beta_agent_id"],
            beta_api_key=d["beta_api_key"],
            beta_org_secret=d.get("beta_org_secret", ""),
        )


def save_state(state: DemoState) -> None:
    _STATE_FILE.write_text(json.dumps(state.to_dict(), indent=2) + "\n")
    os.chmod(_STATE_FILE, 0o600)


def load_state() -> DemoState:
    if not _STATE_FILE.exists():
        raise SystemExit(
            f"{_RED}\u2717{_RESET} No demo state at {_STATE_FILE}\n"
            "  Run  ./deploy_demo.sh up  first."
        )
    return DemoState.from_dict(json.loads(_STATE_FILE.read_text()))


# ─────────────────────────────────────────────────────────────────────────────
# Sub-commands
# ─────────────────────────────────────────────────────────────────────────────

def cmd_init(_args: argparse.Namespace) -> int:
    """Bootstrap the demo: invites → orgs → approval → agents → save state."""
    _section("Bootstrap")

    _step(1, 6, "Waiting for broker /readyz...")
    _wait_for_url(f"{BROKER_URL_HOST}/readyz", "broker")
    _wait_for_url(f"{PROXY_ALPHA_URL_HOST}/health", "proxy-alpha")
    _wait_for_url(f"{PROXY_BETA_URL_HOST}/health",  "proxy-beta")
    _ok("broker + 2 proxies are healthy")

    _step(2, 6, "Generating invite tokens (admin)")
    invite_alpha = generate_invite("demo-alpha")
    invite_beta  = generate_invite("demo-beta")
    _ok("invite tokens issued")

    _step(3, 6, "Registering both orgs (broker status=pending)")
    org_secrets: dict[str, str] = {}
    for org_id, display, service, _ in (ORG_ALPHA, ORG_BETA):
        invite = invite_alpha if org_id == "alpha" else invite_beta
        org_payload = _exec_in_proxy(service, [
            "--phase",        "org",
            "--broker-url",   BROKER_URL_INTERNAL,
            "--invite-token", invite,
            "--org-id",       org_id,
            "--display-name", display,
        ])
        org_secrets[org_id] = org_payload.get("org_secret", "")
        # Restart proxy so its lifespan picks up the freshly persisted
        # broker_url and initializes the BrokerBridge — without this the
        # egress endpoints stay at 503 "bridge not initialized".
        host_health = PROXY_ALPHA_URL_HOST if service == "proxy-alpha" else PROXY_BETA_URL_HOST
        _restart_proxy_and_wait(service, f"{host_health}/health")
        _ok(f"org '{org_id}' registered + proxy restarted")

    _step(4, 6, "Network admin approves both orgs")
    approve_org("alpha")
    approve_org("beta")
    _ok("orgs approved (status=active)")

    _step(5, 6, f"Creating one agent per org with capability '{DEMO_CAPABILITY}'")
    alpha_payload = _exec_in_proxy("proxy-alpha", [
        "--phase",        "agent",
        "--org-id",       "alpha",
        "--agent-name",   SENDER_NAME,
        "--capabilities", DEMO_CAPABILITY,
    ])
    beta_payload = _exec_in_proxy("proxy-beta", [
        "--phase",        "agent",
        "--org-id",       "beta",
        "--agent-name",   CHECKER_NAME,
        "--capabilities", DEMO_CAPABILITY,
    ])
    _ok(f"alpha::{SENDER_NAME}   api_key={alpha_payload['api_key'][:24]}...")
    _ok(f"beta::{CHECKER_NAME}   api_key={beta_payload['api_key'][:24]}...")

    _step(6, 6, "Persisting demo state")
    state = DemoState(
        alpha_agent_id=alpha_payload["agent_id"],
        alpha_api_key=alpha_payload["api_key"],
        alpha_org_secret=org_secrets.get("alpha", ""),
        beta_agent_id=beta_payload["agent_id"],
        beta_api_key=beta_payload["api_key"],
        beta_org_secret=org_secrets.get("beta", ""),
    )
    save_state(state)
    _ok(f"state saved to {_STATE_FILE.relative_to(_REPO_ROOT)}")

    print()
    print(f"  {_BOLD}{_GREEN}Demo ready.{_RESET}  Run the conversation with:")
    print(f"    {_CYAN}./deploy_demo.sh send{_RESET}")
    print()
    return 0


def cmd_info(_args: argparse.Namespace) -> int:
    """
    Print every URL + credential a curious audience needs to explore the
    demo architecture in a browser:
      - the broker dashboard (network admin view + per-org views)
      - the two MCP proxy dashboards
      - the in-process agent IDs and API keys created by `init`
    """
    state = load_state()

    _section("Architecture tour")

    print(f"  {_BOLD}Broker dashboard{_RESET}    {_CYAN}{BROKER_URL_HOST}/dashboard/login{_RESET}")
    print(f"    {_DIM}Network admin view: see invites, orgs, agents, sessions, audit log{_RESET}")
    print(f"      user      {_BOLD}admin{_RESET}")
    print(f"      password  {_BOLD}{ADMIN_SECRET}{_RESET}")
    print()
    print(f"    {_DIM}Org alpha view (its agents, bindings, policies):{_RESET}")
    print(f"      user      {_BOLD}alpha{_RESET}")
    print(f"      password  {_BOLD}{state.alpha_org_secret or '<unknown — re-run up>'}{_RESET}")
    print()
    print(f"    {_DIM}Org beta view:{_RESET}")
    print(f"      user      {_BOLD}beta{_RESET}")
    print(f"      password  {_BOLD}{state.beta_org_secret or '<unknown — re-run up>'}{_RESET}")
    print()

    print(f"  {_BOLD}Proxy alpha dashboard{_RESET}    {_CYAN}{PROXY_ALPHA_URL_HOST}/proxy/login{_RESET}")
    print(f"    {_DIM}Org alpha's MCP gateway: agents, sessions, policies, audit{_RESET}")
    print(f"      broker URL    {_BOLD}{BROKER_URL_HOST}{_RESET}")
    print(f"      invite token  {_BOLD}any-string{_RESET}  {_DIM}(form value not validated){_RESET}")
    print()

    print(f"  {_BOLD}Proxy beta dashboard{_RESET}     {_CYAN}{PROXY_BETA_URL_HOST}/proxy/login{_RESET}")
    print(f"    {_DIM}Org beta's MCP gateway, same UI{_RESET}")
    print(f"      broker URL    {_BOLD}{BROKER_URL_HOST}{_RESET}")
    print(f"      invite token  {_BOLD}any-string{_RESET}  {_DIM}(form value not validated){_RESET}")
    print()

    print(f"  {_BOLD}Agents created by bootstrap{_RESET}")
    print(f"    {state.alpha_agent_id:14}  api_key={state.alpha_api_key}")
    print(f"    {state.beta_agent_id:14}  api_key={state.beta_api_key}")
    print()
    print(f"  {_DIM}State file: {_STATE_FILE.relative_to(_REPO_ROOT)}{_RESET}")
    print()
    return 0


def cmd_reset(_args: argparse.Namespace) -> int:
    if _STATE_FILE.exists():
        _STATE_FILE.unlink()
        _ok(f"removed {_STATE_FILE.relative_to(_REPO_ROOT)}")
    else:
        _info("no demo state to remove")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Cullis demo orchestrator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init",  help="bootstrap orgs + agents (run once after `up`)")
    p_init.set_defaults(func=cmd_init)

    p_info = sub.add_parser("info",  help="print dashboard URLs + bootstrap credentials")
    p_info.set_defaults(func=cmd_info)

    p_reset = sub.add_parser("reset", help="delete .state.json")
    p_reset.set_defaults(func=cmd_reset)

    p_fixt = sub.add_parser("fixture", help="ensure broker cert fixture exists (called by deploy_demo.sh)")
    p_fixt.set_defaults(func=lambda _a: (ensure_broker_certs_fixture(), 0)[1])

    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        _err(str(exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
