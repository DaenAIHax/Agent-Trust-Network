"""Local onboarding dashboard for cullis-connector.

Runs as a standalone FastAPI app on ``http://127.0.0.1:7777`` (configurable)
and wraps the device-code enrollment flow with three screens:

    /setup      — proxy URL + requester form
    /waiting    — admin-approval spinner (HTMX-polled)
    /connected  — identity summary + IDE auto-configure

The MCP stdio server (see ``server.py``) is a separate process: both read
and write ``~/.cullis/identity/``, so once the dashboard finishes
enrollment the MCP side can ``load_identity`` without any IPC.

Pending-enrollment state (in-flight keypair + session_id) is held in
process memory only — if the user closes the dashboard before admin
approves, they start fresh next time. The private key never touches disk
until the server has approved.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from cullis_connector.config import ConnectorConfig
from cullis_connector.enrollment import (
    EnrollmentFailed,
    RequesterInfo,
    _bcrypt_hash,
    _generate_api_key,
    _start,
)
from cullis_connector.identity import (
    IdentityBundle,
    generate_keypair,
    has_identity,
    load_identity,
    public_key_to_pem,
    save_identity,
)
from cullis_connector.identity.store import IdentityMetadata

_log = logging.getLogger("cullis_connector.web")

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_STATIC_DIR = Path(__file__).parent / "static"


# ── Pending-enrollment in-memory state ───────────────────────────────────
#
# Single-user, single-process. A second tab on the same dashboard shares
# the same state — intentional, so the user can't accidentally start two
# enrollments in parallel.


@dataclass
class _Pending:
    session_id: str
    enroll_url: str
    site_url: str
    verify_tls: bool
    private_key: EllipticCurvePrivateKey
    api_key_raw: str
    requester: RequesterInfo
    started_at: float = field(default_factory=time.time)
    poll_interval_s: int = 5


_pending: _Pending | None = None


def _clear_pending() -> None:
    global _pending
    _pending = None


# ── App factory ──────────────────────────────────────────────────────────


def build_app(config: ConnectorConfig) -> FastAPI:
    """Return a FastAPI app bound to the given connector config.

    The config's ``config_dir`` is where the identity will be persisted on
    admin approval. ``site_url`` / ``verify_tls`` act as defaults for the
    setup form so a preconfigured deploy can skip the URL step.
    """
    app = FastAPI(title="Cullis Connector", docs_url=None, redoc_url=None)

    templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # ── Routes ────────────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    def root() -> Response:
        """Dispatch to the correct screen based on current state."""
        if has_identity(config.config_dir):
            return RedirectResponse("/connected", status_code=303)
        if _pending is not None:
            return RedirectResponse("/waiting", status_code=303)
        return RedirectResponse("/setup", status_code=303)

    @app.get("/setup", response_class=HTMLResponse)
    def setup_get(request: Request, error: str | None = None) -> Response:
        # If identity already exists, don't show the form — nothing to do.
        if has_identity(config.config_dir):
            return RedirectResponse("/connected", status_code=303)

        return templates.TemplateResponse(
            request,
            "setup.html",
            {
                "connector_status": "offline",
                "connector_status_label": "Offline",
                "site_url": config.site_url or "",
                "requester_name": "",
                "requester_email": "",
                "reason": "",
                "verify_tls_off": not config.verify_tls,
                "error": error,
            },
        )

    @app.post("/setup")
    def setup_post(
        request: Request,
        site_url: str = Form(...),
        requester_name: str = Form(...),
        requester_email: str = Form(...),
        reason: str = Form(""),
        verify_tls_off: str | None = Form(None),
    ) -> Response:
        global _pending

        if has_identity(config.config_dir):
            return RedirectResponse("/connected", status_code=303)

        verify_tls = verify_tls_off is None
        site_url = site_url.strip().rstrip("/")
        requester = RequesterInfo(
            name=requester_name.strip(),
            email=requester_email.strip(),
            reason=(reason or "").strip() or None,
        )

        private_key = generate_keypair()
        pubkey_pem = public_key_to_pem(private_key.public_key()).decode()
        api_key_raw = _generate_api_key()
        api_key_hash = _bcrypt_hash(api_key_raw)

        try:
            start_resp = _start(
                site_url=site_url,
                pubkey_pem=pubkey_pem,
                requester=requester,
                api_key_hash=api_key_hash,
                verify_tls=verify_tls,
                timeout_s=config.request_timeout_s,
            )
        except EnrollmentFailed as exc:
            return templates.TemplateResponse(
                request,
                "setup.html",
                {
                    "connector_status": "offline",
                    "connector_status_label": "Offline",
                    "site_url": site_url,
                    "requester_name": requester.name,
                    "requester_email": requester.email,
                    "reason": requester.reason or "",
                    "verify_tls_off": not verify_tls,
                    "error": str(exc),
                },
                status_code=400,
            )

        _pending = _Pending(
            session_id=str(start_resp["session_id"]),
            enroll_url=str(start_resp.get("enroll_url") or ""),
            site_url=site_url,
            verify_tls=verify_tls,
            private_key=private_key,
            api_key_raw=api_key_raw,
            requester=requester,
            poll_interval_s=int(start_resp.get("poll_interval_s", 5)),
        )
        return RedirectResponse("/waiting", status_code=303)

    @app.get("/waiting", response_class=HTMLResponse)
    def waiting_get(request: Request) -> Response:
        if has_identity(config.config_dir):
            return RedirectResponse("/connected", status_code=303)
        if _pending is None:
            return RedirectResponse("/setup", status_code=303)

        return templates.TemplateResponse(
            request,
            "waiting.html",
            {
                "connector_status": "waiting",
                "connector_status_label": "Pending approval",
                "session_id": _pending.session_id,
                "enroll_url": _pending.enroll_url,
                "started_at_ms": int(_pending.started_at * 1000),
            },
        )

    @app.get("/api/status")
    def api_status() -> JSONResponse:
        """Single-shot poll of the remote enrollment status.

        Returns JSON so the waiting page's HTMX can route to the next
        screen on its own.
        """
        if has_identity(config.config_dir):
            return JSONResponse({"status": "approved"})
        if _pending is None:
            return JSONResponse({"status": "idle"})

        poll_url = (
            f"{_pending.site_url}/v1/enrollment/{_pending.session_id}/status"
        )
        try:
            resp = httpx.get(
                poll_url,
                verify=_pending.verify_tls,
                timeout=config.request_timeout_s,
            )
        except httpx.HTTPError as exc:
            _log.warning("poll transient error: %s", exc)
            return JSONResponse({"status": "pending", "transient": True})

        if resp.status_code == 404:
            _clear_pending()
            return JSONResponse(
                {"status": "error", "error": "Session no longer exists on the proxy."},
                status_code=200,
            )
        if resp.status_code != 200:
            return JSONResponse(
                {
                    "status": "error",
                    "error": f"Proxy returned HTTP {resp.status_code}",
                },
                status_code=200,
            )

        record = resp.json()
        remote_status = record.get("status", "pending")

        if remote_status == "pending":
            return JSONResponse({"status": "pending"})

        if remote_status == "approved":
            cert_pem = record.get("cert_pem")
            if not cert_pem:
                return JSONResponse(
                    {
                        "status": "error",
                        "error": "Approved enrollment is missing cert_pem.",
                    }
                )
            agent_id = str(record.get("agent_id") or "")
            capabilities = list(record.get("capabilities") or [])
            metadata = IdentityMetadata(
                agent_id=agent_id,
                capabilities=capabilities,
                site_url=_pending.site_url,
                issued_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )
            save_identity(
                config_dir=config.config_dir,
                cert_pem=cert_pem,
                private_key=_pending.private_key,
                ca_chain_pem=None,  # Phase 2c will fetch the CA chain.
                metadata=metadata,
                api_key=_pending.api_key_raw,
            )
            _clear_pending()
            return JSONResponse({"status": "approved", "agent_id": agent_id})

        if remote_status == "rejected":
            reason = record.get("rejection_reason") or "Admin rejected the request."
            _clear_pending()
            return JSONResponse({"status": "rejected", "error": reason})

        if remote_status == "expired":
            _clear_pending()
            return JSONResponse(
                {"status": "expired", "error": "Enrollment session expired."}
            )

        return JSONResponse(
            {"status": "error", "error": f"Unexpected status '{remote_status}'"}
        )

    @app.post("/cancel")
    def cancel() -> Response:
        _clear_pending()
        return RedirectResponse("/setup", status_code=303)

    @app.get("/connected", response_class=HTMLResponse)
    def connected_get(request: Request) -> Response:
        if not has_identity(config.config_dir):
            return RedirectResponse("/setup", status_code=303)

        identity = load_identity(config.config_dir)
        meta = identity.metadata
        site_host = _host_of(meta.site_url)

        return templates.TemplateResponse(
            request,
            "connected.html",
            {
                "connector_status": "online",
                "connector_status_label": "Online",
                "agent_id": meta.agent_id or "(unassigned)",
                "site_host": site_host,
                "capabilities": list(meta.capabilities or []),
                "issued_at": meta.issued_at or "—",
                "ides": _detect_ides(),
            },
        )

    @app.post("/configure/{ide_id}")
    def configure_ide(ide_id: str) -> JSONResponse:
        """Stub for Day 2 — the real IDE JSON-merge logic lands next.

        Returning 202 so the waiting button shows a neutral feedback
        rather than a green check.
        """
        _log.info("configure/%s requested — Day 2 scaffolding", ide_id)
        return JSONResponse(
            {
                "status": "pending",
                "message": (
                    "IDE auto-config ships in Day 2. For now, copy the MCP "
                    "config manually using the button below."
                ),
            },
            status_code=202,
        )

    return app


# ── Helpers ──────────────────────────────────────────────────────────────


def _host_of(url: str) -> str:
    if not url:
        return "—"
    try:
        parsed = urlparse(url)
        return parsed.netloc or url
    except ValueError:
        return url


def _detect_ides() -> list[dict[str, Any]]:
    """Day-1 placeholder: report all three IDEs as 'detected'.

    Day 2 will look at concrete paths (``~/Library/Application Support/
    Claude/claude_desktop_config.json`` etc.) to decide detected vs
    missing. For now the cards are actionable but the POST is a no-op
    stub.
    """
    return [
        {"id": "claude-desktop", "name": "Claude Desktop", "status": "detected"},
        {"id": "cursor", "name": "Cursor", "status": "detected"},
        {"id": "cline", "name": "Cline (VS Code)", "status": "detected"},
        {"id": "manual", "name": "Other MCP client", "status": "detected"},
    ]
