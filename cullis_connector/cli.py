"""Command-line entry point for cullis-connector.

Three top-level modes:

* ``cullis-connector serve`` (default when no subcommand is given) — run
  the MCP stdio server. Requires a valid identity on disk; fails with a
  clear hint if none is present yet.

* ``cullis-connector enroll`` — one-shot device-code enrollment: generate
  keypair, submit to the Site, print the admin URL, poll until approved,
  persist cert + metadata under ``~/.cullis/identity/``.

* ``cullis-connector dashboard`` — local web UI on http://127.0.0.1:7777
  that wraps enrollment in a three-screen wizard and (from Day 2) can
  auto-configure Claude Desktop / Cursor / Cline. Intended as the
  default onboarding path for end users who shouldn't need the CLI.
"""
from __future__ import annotations

import argparse
import sys
from typing import Sequence

from cullis_connector import __version__
from cullis_connector._logging import get_logger, setup_logging
from cullis_connector.config import ConnectorConfig, load_config
from cullis_connector.identity import IdentityNotFound, has_identity, load_identity

_log = get_logger("cli")


# ── Argument parser ──────────────────────────────────────────────────────


def _add_shared_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--site-url",
        dest="site_url",
        help="Base URL of the Cullis Site (e.g. https://cullis.acme.local:9443). "
             "Overrides CULLIS_SITE_URL env var and config.yaml.",
    )
    parser.add_argument(
        "--config-dir",
        dest="config_dir",
        help="Directory holding config.yaml and identity/. Defaults to ~/.cullis/. "
             "Use distinct dirs for multi-org setups.",
    )
    parser.add_argument(
        "--no-verify-tls",
        dest="verify_tls",
        action="store_false",
        default=None,
        help="Disable TLS verification (development only — never use in production).",
    )
    parser.add_argument(
        "--log-level",
        dest="log_level",
        choices=["debug", "info", "warning", "error"],
        help="Set log verbosity. Logs always go to stderr.",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cullis-connector",
        description=(
            "Cullis Connector — MCP server bridging local MCP clients to "
            "the Cullis federated agent trust network."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"cullis-connector {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser(
        "serve",
        help="Run the MCP stdio server (default when no subcommand given).",
    )
    _add_shared_args(serve)

    enroll = subparsers.add_parser(
        "enroll",
        help="Run the device-code enrollment flow once and exit.",
    )
    _add_shared_args(enroll)
    enroll.add_argument(
        "--requester-name",
        required=True,
        help="Your full name as the admin will see it in the pending list.",
    )
    enroll.add_argument(
        "--requester-email",
        required=True,
        help="Your email — admin uses it to verify you are who you claim.",
    )
    enroll.add_argument(
        "--reason",
        default=None,
        help="Short note for the admin explaining why you need access.",
    )
    enroll.add_argument(
        "--device-info",
        default=None,
        help="Free-form host/OS string recorded in the enrollment audit.",
    )

    dashboard = subparsers.add_parser(
        "dashboard",
        help="Run the local onboarding web UI (http://127.0.0.1:7777).",
    )
    _add_shared_args(dashboard)
    dashboard.add_argument(
        "--host",
        dest="web_host",
        default="127.0.0.1",
        help="Bind address for the dashboard. Defaults to 127.0.0.1 — do "
             "not expose to the network without a reason.",
    )
    dashboard.add_argument(
        "--port",
        dest="web_port",
        type=int,
        default=7777,
        help="Dashboard port (default 7777). Increment if something else "
             "already holds the port.",
    )
    dashboard.add_argument(
        "--no-open-browser",
        dest="open_browser",
        action="store_false",
        default=True,
        help="Do not auto-open a browser tab on startup.",
    )

    # Shared args also live on the root parser so the default (no
    # subcommand) behaviour stays backward-compatible with Phase 1.
    _add_shared_args(parser)
    return parser


# ── Commands ─────────────────────────────────────────────────────────────


def _cmd_serve(cfg: ConnectorConfig) -> int:
    if not has_identity(cfg.config_dir):
        _log.error(
            "No identity found at %s — run `cullis-connector enroll "
            "--requester-name ... --requester-email ...` first.",
            cfg.config_dir,
        )
        return 2

    try:
        identity = load_identity(cfg.config_dir)
    except IdentityNotFound as exc:
        _log.error("Identity load failed: %s", exc)
        return 2

    # Import late so the bare `enroll` command has no MCP dependency.
    from cullis_connector.server import build_server
    from cullis_connector.state import get_state

    state = get_state()
    state.agent_id = identity.metadata.agent_id
    state.extra["identity"] = identity

    _log.info(
        "serving as %s (cert subject %s)",
        identity.metadata.agent_id or "unknown",
        identity.cert.subject.rfc4514_string(),
    )

    server = build_server(cfg)
    server.run(transport="stdio")
    return 0


def _cmd_enroll(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    if not cfg.site_url:
        _log.error(
            "enroll requires --site-url (or CULLIS_SITE_URL env / config.yaml)"
        )
        return 2

    if has_identity(cfg.config_dir):
        _log.error(
            "Identity already present at %s — refusing to overwrite. Remove "
            "the existing files manually if you really want to re-enroll.",
            cfg.config_dir / "identity",
        )
        return 2

    # Import here to keep `--version` + arg parsing fast.
    from cullis_connector.enrollment import (
        EnrollmentFailed,
        RequesterInfo,
        enroll,
    )

    try:
        enroll(
            site_url=cfg.site_url,
            config_dir=cfg.config_dir,
            requester=RequesterInfo(
                name=args.requester_name,
                email=args.requester_email,
                reason=args.reason,
                device_info=args.device_info,
            ),
            verify_tls=cfg.verify_tls,
            request_timeout_s=cfg.request_timeout_s,
        )
    except EnrollmentFailed as exc:
        _log.error("Enrollment failed: %s", exc)
        return 1
    return 0


def _cmd_dashboard(cfg: ConnectorConfig, args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        _log.error(
            "dashboard requires extra deps — install with "
            "`pip install 'cullis-connector[dashboard]'` (adds fastapi, "
            "uvicorn, jinja2)."
        )
        return 2

    # Import late so the dashboard deps stay optional for serve/enroll.
    from cullis_connector.web import build_app

    app = build_app(cfg)

    host = getattr(args, "web_host", "127.0.0.1")
    port = int(getattr(args, "web_port", 7777))
    url = f"http://{host}:{port}"

    if getattr(args, "open_browser", True):
        import threading
        import webbrowser

        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    _log.info("dashboard listening on %s — open it in a browser to enroll", url)
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=cfg.log_level if cfg.log_level != "debug" else "info",
        access_log=False,
    )
    return 0


# ── Entry point ──────────────────────────────────────────────────────────


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for both ``python -m cullis_connector`` and the
    installed ``cullis-connector`` console script."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    cfg = load_config(vars(args))
    setup_logging(cfg.log_level)

    command = args.command or "serve"
    _log.info(
        "connector command=%s version=%s site_url=%s config_dir=%s",
        command,
        __version__,
        cfg.site_url or "(unset)",
        cfg.config_dir,
    )

    if command == "enroll":
        return _cmd_enroll(cfg, args)
    if command == "dashboard":
        return _cmd_dashboard(cfg, args)
    return _cmd_serve(cfg)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
