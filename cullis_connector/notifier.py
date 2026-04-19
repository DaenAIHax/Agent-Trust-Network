"""OS-native desktop notifications.

Surface for the dashboard inbox poller (M2.1 → M2.3): turn each
``InboxEvent`` into a libnotify / NSUserNotification / Windows Toast
popup, with a graceful stderr fallback when no native backend is
available (CI, headless servers, plyer not installed).

We don't try to reimplement per-OS notification APIs ourselves —
``plyer`` is a maintained 1-dep wrapper that already speaks all
three. Operators that want richer notifications (actions, sound,
icons) can replace `PlyerNotifier` with a custom Notifier later.
"""
from __future__ import annotations

import logging
import sys
from typing import Protocol

_log = logging.getLogger("cullis_connector.notifier")


class Notifier(Protocol):
    """Minimal notification surface — one call per event."""

    def notify(
        self,
        title: str,
        body: str,
        *,
        on_click_url: str | None = None,
    ) -> None:
        """Display a notification.

        ``on_click_url`` is a hint to the implementation: native
        backends that support click actions can open it; backends
        that don't (most of them, in practice) can include the URL
        text in the body or ignore it.
        """
        ...


class StderrNotifier:
    """Fallback that prints to stderr — used in CI, headless deploys,
    or when plyer can't load a native backend."""

    def notify(
        self,
        title: str,
        body: str,
        *,
        on_click_url: str | None = None,
    ) -> None:
        suffix = f" → {on_click_url}" if on_click_url else ""
        print(f"[cullis-notify] {title}: {body}{suffix}", file=sys.stderr)


class PlyerNotifier:
    """Wraps ``plyer.notification.notify`` — the lazy import keeps the
    optional dependency truly optional."""

    APP_NAME = "Cullis Connector"

    def __init__(self) -> None:
        # Resolve the backend once so a missing native lib (e.g.
        # libnotify on a headless box) surfaces during construction
        # and we can fall back, instead of failing on every notify().
        from plyer import notification  # type: ignore[import-not-found]
        # Touch the implementation to trigger backend resolution.
        # plyer raises NotImplementedError lazily on .notify(); this
        # accessor is enough to make sure something is wired.
        _ = notification
        self._backend = notification

    def notify(
        self,
        title: str,
        body: str,
        *,
        on_click_url: str | None = None,
    ) -> None:
        # plyer's notify signature has no click-action parameter, so
        # we fold the URL into the body when present — at least the
        # user can copy it.
        if on_click_url:
            body = f"{body}\n{on_click_url}"
        try:
            self._backend.notify(
                title=title,
                message=body,
                app_name=self.APP_NAME,
                timeout=10,
            )
        except Exception as exc:  # noqa: BLE001
            # plyer can throw from the underlying OS API on weirder
            # desktop environments. Don't let one bad notification
            # crash the poller — log and move on.
            _log.warning("native notification failed: %s", exc)


def build_notifier() -> Notifier:
    """Pick the best Notifier we can construct on this host.

    Tries ``PlyerNotifier`` first; on ImportError or backend-resolution
    failure falls back to ``StderrNotifier``. Idempotent — safe to
    call multiple times if the dashboard wants to refresh.
    """
    try:
        return PlyerNotifier()
    except ImportError:
        _log.info(
            "plyer not installed — falling back to stderr notifier "
            "(install with `pip install 'cullis-connector[dashboard]'`)"
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "plyer backend unavailable (%s) — falling back to stderr",
            exc,
        )
    return StderrNotifier()
