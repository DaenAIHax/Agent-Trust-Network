"""Receive_oneshot side-effects on the intent-tool state.

After a successful decrypt, the connector remembers the sender as
the active peer and the msg_id as reply_to so that subsequent
`reply()` / `chat()` tool calls Just Work without asking the user
to repeat themselves. This contract is the bridge between the
oneshot module (low-level wire format) and the intent module
(natural-language UX).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cullis_connector.config import ConnectorConfig
from cullis_connector.state import get_state, reset_state
from cullis_connector.tools import oneshot


class _FakeFastMCP:
    def __init__(self) -> None:
        self.tools: dict[str, object] = {}

    def tool(self):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn
        return decorator


class _FakeClient:
    def __init__(
        self,
        rows: list[dict],
        decoder=None,
        signing_key: str = "PEM",
    ) -> None:
        self._rows = rows
        self._decoder = decoder or (lambda r: {"payload": {"text": "decoded"}})
        self._signing_key_pem = signing_key
        self._pubkey_cache: dict = {}

    def receive_oneshot(self) -> list[dict]:
        return list(self._rows)

    def decrypt_oneshot(self, row: dict) -> dict:
        return self._decoder(row)

    def _egress_http(self, *args, **kwargs):
        # Only invoked by _prime_sender_pubkey_cache; cache hit avoids it.
        class _R:
            status_code = 404
            def raise_for_status(self): pass
            def json(self): return {}
        return _R()


@pytest.fixture(autouse=True)
def _isolate_state(tmp_path: Path):
    reset_state()
    get_state().config = ConnectorConfig(
        site_url="https://mastio.test",
        config_dir=tmp_path,
        verify_tls=False,
        request_timeout_s=2.0,
    )
    yield
    reset_state()


@pytest.fixture
def receive_tool():
    mcp = _FakeFastMCP()
    oneshot.register(mcp)
    return mcp.tools["receive_oneshot"]


def _install_client(rows, decoder=None) -> _FakeClient:
    client = _FakeClient(rows=rows, decoder=decoder)
    # Pre-seed the cache so prime() short-circuits.
    for r in rows:
        client._pubkey_cache[r["sender_agent_id"]] = ("PEM", 0.0)
    get_state().client = client
    return client


def test_receive_updates_last_peer_and_reply_to(receive_tool):
    rows = [{
        "sender_agent_id": "acme::mario",
        "msg_id": "msg-XYZ",
        "correlation_id": "corr-1",
        "reply_to": None,
        "payload_ciphertext": "{}",
    }]
    _install_client(rows)
    out = receive_tool()
    assert "1 one-shot" in out
    assert get_state().last_peer_resolved == "acme::mario"
    assert get_state().last_reply_to == "msg-XYZ"


def test_receive_canonicalizes_bare_sender(receive_tool):
    """Older inbox rows can carry the bare agent name; ensure we
    canonicalize it before storing in last_peer_resolved so reply()
    speaks the form /v1/egress/* expects."""
    # No identity loaded → canonical_recipient returns the input
    # unchanged. Set up state.extra["identity"] with a fake cert
    # whose org name is "acme".
    from unittest.mock import MagicMock
    from cryptography.x509 import NameOID
    fake_attr = MagicMock()
    fake_attr.value = "acme"
    fake_cert = MagicMock()
    fake_cert.subject.get_attributes_for_oid.return_value = [fake_attr]
    fake_identity = MagicMock()
    fake_identity.cert = fake_cert
    get_state().extra["identity"] = fake_identity

    rows = [{
        "sender_agent_id": "mario",
        "msg_id": "msg-A",
        "correlation_id": "corr-A",
        "reply_to": None,
        "payload_ciphertext": "{}",
    }]
    _install_client(rows)
    receive_tool()
    assert get_state().last_peer_resolved == "acme::mario"
    assert get_state().last_reply_to == "msg-A"


def test_receive_only_updates_on_decode_success(receive_tool):
    """If decrypt fails we don't pollute last_peer_resolved with a
    sender we couldn't actually verify."""
    def _broken(_row): raise RuntimeError("bad sig")
    rows = [{
        "sender_agent_id": "acme::mallory",
        "msg_id": "msg-bad",
        "correlation_id": "corr-bad",
        "reply_to": None,
        "payload_ciphertext": "{}",
    }]
    _install_client(rows, decoder=_broken)
    out = receive_tool()
    assert "decrypt failed" in out
    assert get_state().last_peer_resolved is None
    assert get_state().last_reply_to is None


def test_receive_picks_last_decoded_row_when_multiple(receive_tool):
    """Multiple rows decoded → the LAST decoded one wins. That's the
    one the user just read, so it's the most plausible reply target."""
    rows = [
        {
            "sender_agent_id": "acme::alice",
            "msg_id": "msg-1",
            "correlation_id": "corr-1",
            "reply_to": None,
            "payload_ciphertext": "{}",
        },
        {
            "sender_agent_id": "acme::bob",
            "msg_id": "msg-2",
            "correlation_id": "corr-2",
            "reply_to": None,
            "payload_ciphertext": "{}",
        },
    ]
    _install_client(rows)
    receive_tool()
    assert get_state().last_peer_resolved == "acme::bob"
    assert get_state().last_reply_to == "msg-2"


def test_receive_no_messages_leaves_state_alone(receive_tool):
    """Empty inbox = no state change (a previous reply context stays
    valid until something replaces it)."""
    state = get_state()
    state.last_peer_resolved = "acme::previous"
    state.last_reply_to = "msg-prev"
    _install_client([])
    out = receive_tool()
    assert "No one-shot messages" in out
    assert state.last_peer_resolved == "acme::previous"
    assert state.last_reply_to == "msg-prev"
