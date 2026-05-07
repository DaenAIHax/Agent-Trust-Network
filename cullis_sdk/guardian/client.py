"""SDK-side Guardian client.

NO-OP by default. The env flag ``CULLIS_GUARDIAN_ENABLED=1`` flips the
client to call the local Mastio's ``/v1/guardian/inspect`` endpoint
before encrypting (send) and after decrypting (receive). Phase 3 wires
the calls into ``CullisClient.send_oneshot`` / ``decrypt_oneshot``.

Both sync and async surfaces are exposed:

- The classic ``CullisClient`` is sync (httpx.Client), so its inline
  hooks call ``inspect_before_send_sync`` / ``inspect_before_deliver_sync``.
- Native-async callers (server-side ASGI apps, agent runtimes built on
  asyncio) keep using ``inspect_before_send`` / ``inspect_before_deliver``.

Both surfaces share body shape, response parsing, and the
``GuardianBlocked`` raise so the contract stays single-source.
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


def _build_body(
    *, direction: Direction, payload: bytes, peer_agent_id: str,
    msg_id: str, content_type: str,
) -> dict[str, Any]:
    return {
        "direction": direction,
        "peer_agent_id": peer_agent_id,
        "msg_id": msg_id,
        "content_type": content_type,
        "payload_b64": base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii"),
    }


def _parse_response(
    *, status_code: int, text: str, json_body: dict[str, Any] | None,
    direction: Direction, peer_agent_id: str, msg_id: str,
) -> InspectionDecision:
    if status_code != 200:
        raise RuntimeError(
            f"guardian_inspect_http_{status_code}: {text[:256]}"
        )
    if json_body is None:
        raise RuntimeError("guardian_inspect_response_not_json")
    data = json_body
    decision: Decision = data["decision"]

    redacted: bytes | None = None
    if data.get("redacted_payload_b64"):
        try:
            redacted = base64.urlsafe_b64decode(
                data["redacted_payload_b64"]
                + "=" * (-len(data["redacted_payload_b64"]) % 4),
            )
        except (binascii.Error, ValueError) as exc:
            _log.warning("guardian redacted_payload_b64 malformed: %s", exc)

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


def _no_op_decision() -> InspectionDecision:
    """NO-OP synthesized pass — used when CULLIS_GUARDIAN_ENABLED is off.

    Callers that strictly enforce ticket presence should treat the
    empty ``ticket`` field as "guardian disabled, no enforcement
    available" and decide their own fail-open / fail-closed policy.
    """
    return InspectionDecision(
        decision="pass",
        ticket="",
        ticket_exp=0,
        audit_id="",
        redacted_payload=None,
        reasons=None,
    )


class GuardianClient:
    """Per-agent client. NO-OP unless ``CULLIS_GUARDIAN_ENABLED=1``.

    Both async (``inspect_before_send`` / ``inspect_before_deliver``)
    and sync (``inspect_before_send_sync`` / ``inspect_before_deliver_sync``)
    surfaces share the same body shape, parsing, and ``GuardianBlocked``
    raise. The async client keeps an httpx.AsyncClient warm; the sync
    client lazy-instantiates an httpx.Client.
    """

    def __init__(
        self,
        *,
        mastio_url: str,
        http_client: httpx.AsyncClient | None = None,
        sync_http_client: httpx.Client | None = None,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
    ):
        self._url = mastio_url.rstrip("/") + "/v1/guardian/inspect"
        self._http = http_client
        self._owns_http = http_client is None
        self._sync_http = sync_http_client
        self._owns_sync_http = sync_http_client is None
        self._timeout = timeout_s

    @property
    def enabled(self) -> bool:
        return _enabled()

    async def aclose(self) -> None:
        if self._owns_http and self._http is not None:
            await self._http.aclose()
            self._http = None

    def close(self) -> None:
        if self._owns_sync_http and self._sync_http is not None:
            self._sync_http.close()
            self._sync_http = None

    async def _async_http_client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=self._timeout)
        return self._http

    def _sync_http_client(self) -> httpx.Client:
        if self._sync_http is None:
            self._sync_http = httpx.Client(timeout=self._timeout)
        return self._sync_http

    # ── async surface ───────────────────────────────────────────────

    async def inspect_before_send(
        self, *, payload: bytes, peer_agent_id: str, msg_id: str,
        content_type: str = "application/json+a2a-payload",
    ) -> InspectionDecision:
        return await self._inspect_async(
            direction="out", payload=payload, peer_agent_id=peer_agent_id,
            msg_id=msg_id, content_type=content_type,
        )

    async def inspect_before_deliver(
        self, *, payload: bytes, peer_agent_id: str, msg_id: str,
        content_type: str = "application/json+a2a-payload",
    ) -> InspectionDecision:
        return await self._inspect_async(
            direction="in", payload=payload, peer_agent_id=peer_agent_id,
            msg_id=msg_id, content_type=content_type,
        )

    async def _inspect_async(
        self, *, direction: Direction, payload: bytes,
        peer_agent_id: str, msg_id: str, content_type: str,
    ) -> InspectionDecision:
        if not self.enabled:
            return _no_op_decision()
        body = _build_body(
            direction=direction, payload=payload, peer_agent_id=peer_agent_id,
            msg_id=msg_id, content_type=content_type,
        )
        client = await self._async_http_client()
        resp = await client.post(self._url, json=body)
        try:
            json_body = resp.json()
        except ValueError:
            json_body = None
        return _parse_response(
            status_code=resp.status_code, text=resp.text, json_body=json_body,
            direction=direction, peer_agent_id=peer_agent_id, msg_id=msg_id,
        )

    # ── sync surface (Phase 3 — used by CullisClient) ───────────────

    def inspect_before_send_sync(
        self, *, payload: bytes, peer_agent_id: str, msg_id: str,
        content_type: str = "application/json+a2a-payload",
    ) -> InspectionDecision:
        return self._inspect_sync(
            direction="out", payload=payload, peer_agent_id=peer_agent_id,
            msg_id=msg_id, content_type=content_type,
        )

    def inspect_before_deliver_sync(
        self, *, payload: bytes, peer_agent_id: str, msg_id: str,
        content_type: str = "application/json+a2a-payload",
    ) -> InspectionDecision:
        return self._inspect_sync(
            direction="in", payload=payload, peer_agent_id=peer_agent_id,
            msg_id=msg_id, content_type=content_type,
        )

    def _inspect_sync(
        self, *, direction: Direction, payload: bytes,
        peer_agent_id: str, msg_id: str, content_type: str,
    ) -> InspectionDecision:
        if not self.enabled:
            return _no_op_decision()
        body = _build_body(
            direction=direction, payload=payload, peer_agent_id=peer_agent_id,
            msg_id=msg_id, content_type=content_type,
        )
        client = self._sync_http_client()
        resp = client.post(self._url, json=body)
        try:
            json_body = resp.json()
        except ValueError:
            json_body = None
        return _parse_response(
            status_code=resp.status_code, text=resp.text, json_body=json_body,
            direction=direction, peer_agent_id=peer_agent_id, msg_id=msg_id,
        )
