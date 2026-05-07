"""SDK-side Guardian client.

NO-OP by default. The env flag ``CULLIS_GUARDIAN_ENABLED=1`` flips the
client to call the local Mastio's ``/v1/guardian/inspect`` endpoint
before encrypting (send) and after decrypting (receive). Phase 1 ships
this as a stand-alone client; Phase 3 wires the calls into the existing
``send_oneshot`` / ``reply`` / ``receive_oneshot`` paths.

The client never touches the network when disabled, so existing
deployments running pinned SDK versions or the env flag off see zero
latency overhead and zero new error modes.
"""
from __future__ import annotations

import base64
import binascii
import logging
import os
from dataclasses import dataclass
from typing import Any, Literal

import httpx
import jwt as jose_jwt

_log = logging.getLogger("cullis_sdk.guardian")

_ENABLED_ENV = "CULLIS_GUARDIAN_ENABLED"
_ALGO = "HS256"
_DEFAULT_TIMEOUT_S = 5.0


Direction = Literal["in", "out"]
Decision = Literal["pass", "redact", "block"]


class GuardianBlocked(Exception):
    """Raised when Mastio returns ``decision=block``.

    Carries the audit_id + reasons so the calling agent code can log
    and surface a meaningful error to the user / upstream system.
    """

    def __init__(
        self,
        *,
        audit_id: str,
        reasons: list[dict[str, Any]],
        direction: Direction,
        peer_agent_id: str,
        msg_id: str,
    ):
        super().__init__(
            f"Guardian blocked {direction} message to/from {peer_agent_id} "
            f"(msg_id={msg_id}, audit_id={audit_id})"
        )
        self.audit_id = audit_id
        self.reasons = reasons
        self.direction = direction
        self.peer_agent_id = peer_agent_id
        self.msg_id = msg_id


@dataclass
class InspectionDecision:
    """Typed view of the Mastio ``/v1/guardian/inspect`` response."""

    decision: Decision
    ticket: str
    ticket_exp: int
    audit_id: str
    redacted_payload: bytes | None = None
    reasons: list[dict[str, Any]] | None = None


def _enabled() -> bool:
    return os.environ.get(_ENABLED_ENV, "0").lower() in ("1", "true", "yes", "on")


def _decode_key(key: str) -> bytes:
    if not key:
        raise ValueError("Guardian ticket key is empty.")
    try:
        return binascii.unhexlify(key)
    except (binascii.Error, ValueError):
        pass
    padded = key + "=" * (-len(key) % 4)
    return base64.urlsafe_b64decode(padded)


def verify_ticket(
    *,
    token: str,
    key: str,
    expected_msg_id: str | None = None,
    expected_agent_id: str | None = None,
) -> dict[str, Any]:
    """Verify a Mastio-issued guardian ticket locally.

    The agent runtime calls this before delivering a decrypted message
    to user code, so a tampered SDK that returned synthetic ``pass``
    without contacting Mastio cannot bypass enforcement: the runtime
    sees an invalid signature and refuses delivery.

    Mismatches on ``msg_id`` or ``agent_id`` (when the caller passes
    expectations) are treated the same as a bad signature: a captured
    ticket from a different message must not be replay-able.
    """
    secret = _decode_key(key)
    try:
        claims = jose_jwt.decode(token, secret, algorithms=[_ALGO])
    except jose_jwt.ExpiredSignatureError:
        raise ValueError("guardian_ticket_expired")
    except jose_jwt.InvalidSignatureError:
        raise ValueError("guardian_ticket_bad_signature")
    except jose_jwt.InvalidTokenError as exc:
        raise ValueError(f"guardian_ticket_malformed: {exc}")
    if expected_msg_id is not None and claims.get("msg_id") != expected_msg_id:
        raise ValueError("guardian_ticket_msg_id_mismatch")
    if expected_agent_id is not None and claims.get("agent_id") != expected_agent_id:
        raise ValueError("guardian_ticket_agent_id_mismatch")
    return claims


class GuardianClient:
    """Per-agent client. NO-OP unless ``CULLIS_GUARDIAN_ENABLED=1``.

    The Mastio URL + agent identity (cert/key for mTLS) are passed in by
    the caller. The class avoids holding state beyond a long-lived
    httpx.AsyncClient so the existing connection pool warmth is reused.
    """

    def __init__(
        self,
        *,
        mastio_url: str,
        http_client: httpx.AsyncClient | None = None,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
    ):
        self._url = mastio_url.rstrip("/") + "/v1/guardian/inspect"
        self._http = http_client
        self._owns_http = http_client is None
        self._timeout = timeout_s

    @property
    def enabled(self) -> bool:
        return _enabled()

    async def aclose(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    async def _http_client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self._timeout)
        return self._http

    async def inspect_before_send(
        self, *, payload: bytes, peer_agent_id: str, msg_id: str,
        content_type: str = "application/json+a2a-payload",
    ) -> InspectionDecision:
        return await self._inspect(
            direction="out",
            payload=payload,
            peer_agent_id=peer_agent_id,
            msg_id=msg_id,
            content_type=content_type,
        )

    async def inspect_before_deliver(
        self, *, payload: bytes, peer_agent_id: str, msg_id: str,
        content_type: str = "application/json+a2a-payload",
    ) -> InspectionDecision:
        return await self._inspect(
            direction="in",
            payload=payload,
            peer_agent_id=peer_agent_id,
            msg_id=msg_id,
            content_type=content_type,
        )

    async def _inspect(
        self, *, direction: Direction, payload: bytes,
        peer_agent_id: str, msg_id: str, content_type: str,
    ) -> InspectionDecision:
        if not self.enabled:
            # NO-OP path: synthesize a pass decision with empty ticket.
            # Callers who never check ``ticket`` keep working; callers
            # that strictly enforce the ticket should treat empty as
            # "guardian disabled, no enforcement available".
            return InspectionDecision(
                decision="pass",
                ticket="",
                ticket_exp=0,
                audit_id="",
                redacted_payload=None,
                reasons=None,
            )

        body = {
            "direction": direction,
            "peer_agent_id": peer_agent_id,
            "msg_id": msg_id,
            "content_type": content_type,
            "payload_b64": base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii"),
        }
        client = await self._http_client()
        resp = await client.post(self._url, json=body)
        if resp.status_code != 200:
            # Surface as a runtime error. The caller (Phase 3 wiring)
            # can decide between fail-open and fail-closed; Phase 1
            # leaves the policy choice to the caller.
            raise RuntimeError(
                f"guardian_inspect_http_{resp.status_code}: {resp.text[:256]}"
            )
        data = resp.json()
        decision: Decision = data["decision"]

        redacted: bytes | None = None
        if data.get("redacted_payload_b64"):
            try:
                redacted = base64.urlsafe_b64decode(
                    data["redacted_payload_b64"]
                    + "=" * (-len(data["redacted_payload_b64"]) % 4),
                )
            except (binascii.Error, ValueError) as exc:
                _log.warning(
                    "guardian redacted_payload_b64 malformed: %s", exc,
                )

        result = InspectionDecision(
            decision=decision,
            ticket=data["ticket"],
            ticket_exp=int(data["ticket_exp"]),
            audit_id=data["audit_id"],
            redacted_payload=redacted,
            reasons=data.get("reasons") or [],
        )
        if decision == "block":
            raise GuardianBlocked(
                audit_id=result.audit_id,
                reasons=result.reasons or [],
                direction=direction,
                peer_agent_id=peer_agent_id,
                msg_id=msg_id,
            )
        return result
