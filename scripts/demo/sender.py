"""
sender.py — Cullis demo agent (alpha::sender).

One-shot script: opens a session to beta::checker, waits for it to
become active (the checker daemon auto-accepts pending sessions), sends
a single {"check": "ok"} payload, and exits.

NO LLM, NO Anthropic API key. The only credential this script uses is
the X-API-Key issued to alpha::sender by its own MCP proxy during
deploy_demo.sh up — that key is read from scripts/demo/.state.json.

Run it after deploy_demo.sh up has finished:

    python scripts/demo/sender.py

Then watch the checker daemon log to see the message arrive:

    tail -f scripts/demo/.checker.log
"""
from __future__ import annotations

import json
import pathlib
import sys
import time

import httpx

_HERE = pathlib.Path(__file__).resolve().parent
_STATE_FILE = _HERE / ".state.json"
_PROXY_ALPHA_URL = "http://localhost:9800"

_HTTP_TIMEOUT_SECONDS = 15.0
_ACCEPT_WAIT_SECONDS = 5.0


def _load_state() -> dict:
    if not _STATE_FILE.exists():
        sys.exit(
            f"sender: {_STATE_FILE} not found — run ./deploy_demo.sh up first"
        )
    return json.loads(_STATE_FILE.read_text())


def _log(agent_id: str, msg: str) -> None:
    print(f"[{agent_id}] {msg}", flush=True)


def main() -> int:
    state = _load_state()
    sender_id  = state["alpha_agent_id"]
    sender_key = state["alpha_api_key"]
    target_id  = state["beta_agent_id"]

    headers = {"X-API-Key": sender_key}
    client = httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS, headers=headers)
    session_id: str | None = None

    try:
        # 1) open the cross-org session
        _log(sender_id, f"opening session to {target_id} (capability 'order.check')")
        resp = client.post(
            f"{_PROXY_ALPHA_URL}/v1/egress/sessions",
            json={
                "target_agent_id": target_id,
                "target_org_id":   "beta",
                "capabilities":    ["order.check"],
            },
        )
        if resp.status_code != 200:
            _log(sender_id, f"open_session failed: HTTP {resp.status_code} {resp.text[:300]}")
            return 1
        session_id = resp.json()["session_id"]
        _log(sender_id, f"session_id = {session_id}")

        # 2) wait until the checker daemon flips the session to "active"
        _log(sender_id, "waiting for checker to accept...")
        deadline = time.monotonic() + _ACCEPT_WAIT_SECONDS
        active = False
        while time.monotonic() < deadline:
            sresp = client.get(f"{_PROXY_ALPHA_URL}/v1/egress/sessions")
            if sresp.status_code == 200:
                for s in sresp.json().get("sessions", []):
                    if s.get("session_id") == session_id and s.get("status") == "active":
                        active = True
                        break
            if active:
                break
            time.sleep(0.3)
        if not active:
            _log(sender_id, "checker did not accept within 5s — is checker.py running?")
            _log(sender_id, "  hint: ./deploy_demo.sh checker-log")
            return 2
        _log(sender_id, "session is active")

        # 3) send the check
        payload = {"check": "ok"}
        _log(sender_id, f"sending {json.dumps(payload)}")
        send_resp = client.post(
            f"{_PROXY_ALPHA_URL}/v1/egress/send",
            json={
                "session_id":         session_id,
                "recipient_agent_id": target_id,
                "payload":            payload,
            },
        )
        if send_resp.status_code != 200:
            _log(sender_id, f"send failed: HTTP {send_resp.status_code} {send_resp.text[:300]}")
            return 3

        _log(sender_id, "message routed through the broker — done")
        _log(sender_id, "tail scripts/demo/.checker.log to see it arrive on the other side")
        return 0
    finally:
        # Always close the session if we managed to open one, otherwise it
        # lingers in 'active' state forever and clutters the dashboards.
        if session_id is not None:
            try:
                close_resp = client.post(
                    f"{_PROXY_ALPHA_URL}/v1/egress/sessions/{session_id}/close",
                )
                if close_resp.is_success:
                    _log(sender_id, f"closed session {session_id}")
                else:
                    _log(
                        sender_id,
                        f"close session {session_id} failed: HTTP {close_resp.status_code} {close_resp.text[:200]}",
                    )
            except httpx.RequestError as exc:
                _log(sender_id, f"close session {session_id} error: {exc}")
        client.close()


if __name__ == "__main__":
    sys.exit(main())
