"""Shared input-validation helpers used by request schemas.

Two families live here:

* ``validate_payload_depth`` — reusable Pydantic validator that bounds the
  nesting depth AND key-count of free-form ``dict`` payloads. Protects the
  broker from authenticated-DoS attacks that exploit Python's ~990-level
  recursion limit in ``json.loads`` (audit finding F-C-1). The size-in-bytes
  check remains on the call-site validators — this helper only caps shape.

* ``strict_b64url_decode`` / ``canonicalize_b64url`` — strict base64url
  decoder and canonicalizer. Accepts input WITH or WITHOUT trailing ``=``
  padding (per ``feedback_base64url_nopad`` convention) but rejects any
  non-canonical encoding: whitespace, non-url-safe alphabet characters,
  excess padding, or partial-quantum inputs whose trailing byte contains
  "garbage bits" that Python's stdlib silently discards. Used by every
  DPoP / JWK / E2E path where two different encodings of the same bytes
  would break a pinning invariant (audit finding F-C-3).
"""
from __future__ import annotations

import base64
import re
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# Payload depth / key-count validator (F-C-1)
# ─────────────────────────────────────────────────────────────────────────────

# Default caps. Callers override per-field when stricter bounds are needed
# (e.g. SessionRequest.context is 4 / 256).
_DEFAULT_MAX_DEPTH = 8
_DEFAULT_MAX_KEYS = 1024


def validate_payload_depth(
    value: Any,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_keys: int = _DEFAULT_MAX_KEYS,
) -> Any:
    """Validate that ``value`` stays within ``max_depth`` / ``max_keys``.

    Raises ``ValueError`` on violation so Pydantic turns it into a 422.
    Pure-Python iterative walk — never recurses into untrusted data, so
    this validator cannot itself trigger ``RecursionError`` on a crafted
    payload.

    Counts:
      * depth   — nesting level of dict/list. Scalars count as depth 0.
      * keys    — TOTAL string keys across every dict encountered.
    """
    total_keys = 0
    # Each stack item: (obj, depth)
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        obj, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(
                f"payload nesting exceeds maximum depth of {max_depth}"
            )
        if isinstance(obj, dict):
            # Key-count cap — protects audit-log canonicalization from
            # pathologically wide payloads (F-C-2 complement).
            total_keys += len(obj)
            if total_keys > max_keys:
                raise ValueError(
                    f"payload exceeds maximum of {max_keys} total keys"
                )
            for k, v in obj.items():
                if not isinstance(k, str):
                    raise ValueError("payload keys must be strings")
                stack.append((v, depth + 1))
        elif isinstance(obj, list):
            for item in obj:
                stack.append((item, depth + 1))
        # scalars — nothing to do
    return value


# ─────────────────────────────────────────────────────────────────────────────
# Strict base64url decoder (F-C-3)
# ─────────────────────────────────────────────────────────────────────────────

# url-safe base64 alphabet (RFC 4648 §5). Excludes padding — we handle it
# separately so the same regex catches whitespace and ``+``/``/`` leakage
# from vanilla base64.
_B64URL_ALPHABET_RE = re.compile(r"^[A-Za-z0-9_-]*$")


class B64urlError(ValueError):
    """Raised when a base64url string is malformed or non-canonical."""


def strict_b64url_decode(s: str | bytes) -> bytes:
    """Decode a base64url string, rejecting non-canonical encodings.

    Accepts ``s`` with OR without trailing ``=`` padding (the codebase
    convention — TS SDK omits padding, some tests include it). Rejects:

      * Non-alphabet characters (whitespace, ``+``, ``/``, ``\\n``, etc.)
      * Excess padding (e.g. ``AAAA===`` — valid for stdlib, rejected here)
      * Impossible lengths (``len(s.rstrip("=")) % 4 == 1``)
      * Trailing "garbage bits" in partial-quantum inputs — Python's stdlib
        silently zeroes the unused low-order bits of the last char, which
        means ``AAAA`` and ``AAAB`` decode to the same 3 bytes.

    On any violation raises ``B64urlError`` (a ``ValueError`` subclass) so
    callers that wrap in ``except Exception`` continue to work.
    """
    if isinstance(s, bytes):
        try:
            s = s.decode("ascii")
        except UnicodeDecodeError as exc:
            raise B64urlError("base64url input is not ASCII") from exc
    if not isinstance(s, str):
        raise B64urlError(
            f"base64url input must be str/bytes, got {type(s).__name__}"
        )

    # Strip trailing padding (tolerant). ``AAAA==`` and ``AAAA====`` both
    # strip to ``AAAA`` — the over-padded case is caught when we re-pad
    # below (stdlib silently ignores excess padding; we force-match).
    stripped = s.rstrip("=")

    # Reject non-alphabet content — no whitespace, no vanilla +/.
    if not _B64URL_ALPHABET_RE.fullmatch(stripped):
        raise B64urlError("base64url contains non-url-safe characters")

    # Length mod 4 == 1 is impossible in base64 (1 char = 6 bits, no way
    # to complete a byte). Raise explicitly — stdlib would raise too but
    # via the less-specific ``binascii.Error``.
    rem = len(stripped) % 4
    if rem == 1:
        raise B64urlError("base64url length is not valid (length % 4 == 1)")

    # Re-pad to canonical form and decode.
    padded = stripped + ("=" * ((4 - rem) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise B64urlError(f"base64url decode failed: {exc}") from exc

    # Re-encode and compare to catch "garbage bits" in partial-quantum
    # inputs. stdlib silently drops the low-order bits of the last char
    # when they aren't consumed — that means two different input strings
    # can decode to the same bytes, which breaks canonicalization (JKT).
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != stripped:
        raise B64urlError(
            "base64url contains non-canonical trailing bits — "
            "decoded bytes do not round-trip to the input"
        )

    return decoded


def canonicalize_b64url(s: str) -> str:
    """Round-trip a base64url string through strict decode → no-pad encode.

    Used to normalize JWK coordinates (``x``/``y``/``n``/``e``) before
    including them in a ``compute_jkt`` hash. Two wire encodings of the
    same key (e.g. different padding) collapse to the same canonical
    string, so the thumbprint is stable.
    """
    decoded = strict_b64url_decode(s)
    return base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")


__all__ = [
    "B64urlError",
    "canonicalize_b64url",
    "strict_b64url_decode",
    "validate_payload_depth",
]
