"""ADR-020 Phase 4 — user inbox primitive.

Stand-alone messaging surface for the four-quadrant matrix:

  - A2U: an agent drops a message in a user's inbox (consent-gated)
  - U2A: a user sends to an agent (intra-org with ownership, otherwise consent)
  - U2U: a human sends to another human (intra-org allow, cross-org addressbook)

The store layer (``store.py``) writes to ``user_inbox_messages`` after
``app/policy/reach.py:evaluate_reach_quadrant`` returns allow. The
router layer (``router.py``) exposes:

  GET   /v1/inbox?since=&limit=     list messages for the caller
  POST  /v1/inbox/<msg_id>/ack      mark delivered
  POST  /v1/inbox/<msg_id>/archive  soft hide (UI hint, no chain effect)

WebSocket push (``/v1/inbox/stream``) lands in a follow-up — Phase 4
ships the durable side first so offline drain works on day one.
"""

from app.inbox.store import (
    DeliveryState,
    InboxDelivery,
    enqueue,
    fetch_for_recipient,
    mark_delivered,
    mark_archived,
)

__all__ = [
    "DeliveryState",
    "InboxDelivery",
    "enqueue",
    "fetch_for_recipient",
    "mark_delivered",
    "mark_archived",
]
