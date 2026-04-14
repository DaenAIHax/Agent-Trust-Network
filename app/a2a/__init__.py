"""A2A (Agent2Agent) protocol adapter — ADR-002.

Public interoperability surface that lets non-Cullis A2A clients talk to
Cullis-managed agents using the Linux Foundation A2A v1.0 standard.
Adapter at the edge — internal broker↔proxy and Cullis SDK paths stay
native. See `imp/adr_002_a2a_implementation.md` (worktree-local) for the
full design.

Phase 2a (this slice): read-only AgentCard + directory endpoints.
Phase 2b: SendMessage / GetTask round-trip.
Phase 2c: streaming (SubscribeToTask / SendStreamingMessage) + cancel.
Phase 3: cullis-trust/v1 extension sub-features (E2E, SPIFFE, audit, …).
"""
