"""
Tests for the graceful shutdown machinery (Item 4 in plan.md).

Three contracts under test:

  1. /readyz returns 503 with body {"status": "draining"} when the broker
     is in drain mode (after SIGTERM/SIGINT).
  2. ws_manager.disconnect() forwards a custom close code (1012) to the
     underlying WebSocket.
  3. ws_manager.shutdown() iterates every connection and closes each with
     code 1012 ("service restart") instead of the default 1000.

The tests stub the WebSocket and the Redis pubsub so they exercise the
state machine without spinning up real network listeners.
"""
import asyncio
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


# ── /readyz drain behavior ──────────────────────────────────────────────────

async def test_readyz_returns_503_during_drain(client: AsyncClient):
    """When the shutdown event is set, /readyz must return 503 immediately."""
    import app.main as main_module

    # Backup the current event so other tests are not polluted
    original = main_module._shutdown_event
    try:
        main_module._shutdown_event = asyncio.Event()
        main_module._shutdown_event.set()

        resp = await client.get("/readyz")
        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "draining"
    finally:
        main_module._shutdown_event = original


async def test_readyz_normal_when_not_draining(client: AsyncClient):
    """In normal operation, /readyz returns 200 with the dependency checks."""
    import app.main as main_module

    original = main_module._shutdown_event
    try:
        main_module._shutdown_event = None  # explicitly not set

        resp = await client.get("/readyz")
        # Either 200 (all deps reachable) or 503 with a real check error
        # — but never the "draining" body, since we are not in drain mode
        body = resp.json()
        assert body.get("status") != "draining"
    finally:
        main_module._shutdown_event = original


def test_is_draining_helper():
    """The _is_draining helper reflects the module-level event state."""
    import app.main as main_module

    original = main_module._shutdown_event
    try:
        main_module._shutdown_event = None
        assert main_module._is_draining() is False

        main_module._shutdown_event = asyncio.Event()
        assert main_module._is_draining() is False  # event exists but not set

        main_module._shutdown_event.set()
        assert main_module._is_draining() is True
    finally:
        main_module._shutdown_event = original


# ── ws_manager close code propagation ───────────────────────────────────────

class _FakeWebSocket:
    """Minimal WebSocket stub that records the close call arguments."""
    def __init__(self) -> None:
        self.closed_with: tuple[int, str] | None = None

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed_with = (code, reason)

    async def send_json(self, data: dict) -> None:
        pass


async def test_disconnect_default_close_code_1000():
    """Default disconnect closes with code 1000 (normal closure)."""
    from app.broker.ws_manager import ConnectionManager

    cm = ConnectionManager()
    fake_ws = _FakeWebSocket()
    async with cm._lock:
        cm._connections["a1"] = fake_ws

    await cm.disconnect("a1")
    assert fake_ws.closed_with == (1000, "")


async def test_disconnect_with_explicit_close_code():
    """disconnect propagates an explicit code/reason to the WebSocket."""
    from app.broker.ws_manager import ConnectionManager

    cm = ConnectionManager()
    fake_ws = _FakeWebSocket()
    async with cm._lock:
        cm._connections["a2"] = fake_ws

    await cm.disconnect("a2", code=1012, reason="server restarting")
    assert fake_ws.closed_with == (1012, "server restarting")


async def test_shutdown_closes_all_with_1012():
    """shutdown() must close every WebSocket with the service-restart code."""
    from app.broker.ws_manager import ConnectionManager

    cm = ConnectionManager()
    fakes: dict[str, _FakeWebSocket] = {f"agent-{i}": _FakeWebSocket() for i in range(3)}
    async with cm._lock:
        for agent_id, ws in fakes.items():
            cm._connections[agent_id] = ws

    await cm.shutdown()

    for agent_id, ws in fakes.items():
        assert ws.closed_with is not None, f"{agent_id} was not closed"
        code, reason = ws.closed_with
        assert code == 1012
        assert reason == "server restarting"


async def test_shutdown_idempotent_when_no_connections():
    """shutdown() on an empty manager does not raise."""
    from app.broker.ws_manager import ConnectionManager
    cm = ConnectionManager()
    await cm.shutdown()  # should be a no-op without errors


async def test_shutdown_swallows_close_errors():
    """A failing ws.close() does not stop the rest of the shutdown."""
    from app.broker.ws_manager import ConnectionManager

    class _BrokenWebSocket:
        async def close(self, code: int = 1000, reason: str = "") -> None:
            raise RuntimeError("connection already gone")
        async def send_json(self, data: dict) -> None:
            pass

    cm = ConnectionManager()
    broken = _BrokenWebSocket()
    healthy = _FakeWebSocket()
    async with cm._lock:
        cm._connections["broken"] = broken
        cm._connections["healthy"] = healthy

    # Must not raise
    await cm.shutdown()

    # Healthy WS still got the close call
    assert healthy.closed_with == (1012, "server restarting")


# ── notify_shutdown_to_clients idempotence ──────────────────────────────────

async def test_notify_shutdown_returns_count_first_call():
    """First call returns the number of clients notified."""
    from app.broker.ws_manager import ConnectionManager

    cm = ConnectionManager()
    fakes = {f"a{i}": _FakeWebSocket() for i in range(3)}
    async with cm._lock:
        for agent_id, ws in fakes.items():
            cm._connections[agent_id] = ws

    notified = await cm.notify_shutdown_to_clients()
    assert notified == 3
    for ws in fakes.values():
        assert ws.closed_with == (1012, "server restarting")


async def test_notify_shutdown_idempotent_returns_zero_on_second_call():
    """Calling twice does not re-close (no double-close errors on the wire)."""
    from app.broker.ws_manager import ConnectionManager

    cm = ConnectionManager()
    ws = _FakeWebSocket()
    async with cm._lock:
        cm._connections["a"] = ws

    first = await cm.notify_shutdown_to_clients()
    assert first == 1
    assert ws.closed_with == (1012, "server restarting")

    # Reset the recorded close to detect a (wrong) second call
    ws.closed_with = None

    second = await cm.notify_shutdown_to_clients()
    assert second == 0
    assert ws.closed_with is None  # NOT re-closed


async def test_shutdown_after_notify_does_not_double_close():
    """Calling shutdown() after notify_shutdown_to_clients() is a clean no-op."""
    from app.broker.ws_manager import ConnectionManager

    cm = ConnectionManager()
    ws = _FakeWebSocket()
    async with cm._lock:
        cm._connections["a"] = ws

    await cm.notify_shutdown_to_clients()
    assert ws.closed_with == (1012, "server restarting")
    ws.closed_with = None

    await cm.shutdown()
    # No second close — connection is already gone from the dict
    assert ws.closed_with is None


# ── Drain watcher background task ───────────────────────────────────────────

async def test_drain_watcher_fires_when_event_set():
    """The drain watcher must call notify_shutdown_to_clients when the event is set."""
    import app.main as main_module
    from app.broker.ws_manager import ws_manager

    # Reset the manager state for this test
    fake_ws = _FakeWebSocket()
    async with ws_manager._lock:
        ws_manager._connections["drain-test-agent"] = fake_ws
    ws_manager._notified_shutdown = False

    original = main_module._shutdown_event
    try:
        main_module._shutdown_event = asyncio.Event()

        # Spawn the watcher and set the event
        task = asyncio.create_task(main_module._drain_watcher())
        await asyncio.sleep(0)  # let the watcher reach `await event.wait()`
        main_module._shutdown_event.set()
        await asyncio.wait_for(task, timeout=1.0)

        assert fake_ws.closed_with == (1012, "server restarting")
    finally:
        main_module._shutdown_event = original
        # Clean up any leftover state
        async with ws_manager._lock:
            ws_manager._connections.pop("drain-test-agent", None)
        ws_manager._notified_shutdown = False


async def test_drain_watcher_handles_no_event():
    """If _shutdown_event is None, the watcher returns immediately."""
    import app.main as main_module

    original = main_module._shutdown_event
    try:
        main_module._shutdown_event = None
        # Should not raise or hang
        await asyncio.wait_for(main_module._drain_watcher(), timeout=0.5)
    finally:
        main_module._shutdown_event = original


async def test_drain_watcher_cancellable():
    """A clean shutdown (no signal) cancels the watcher; it must not raise."""
    import app.main as main_module

    original = main_module._shutdown_event
    try:
        main_module._shutdown_event = asyncio.Event()
        task = asyncio.create_task(main_module._drain_watcher())
        await asyncio.sleep(0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # If we got here without an exception leaking, the watcher handled
        # cancellation gracefully.
        assert task.cancelled() or task.done()
    finally:
        main_module._shutdown_event = original
