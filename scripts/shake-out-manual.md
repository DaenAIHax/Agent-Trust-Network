# Manual Shake-Out — "fresh user" pass

A checklist for a maintainer to burn ~half a day pretending to be someone
who just `git clone`'d Cullis with zero prior context. Automated tests
cover the docker golden path (`demo_network/smoke.sh`) and the Helm
charts (CI `helm-test`), but they don't exercise:

- Browser UX on the 23 Jinja+HTMX dashboard templates
- MCP proxy with a real MCP server + real LLM tool calling
- Cross-org federation across *two separate deploys* (not the same
  docker compose network)
- Setup-wizard interaction (first-boot admin password, invite tokens,
  attach-CA)
- Postgres-backed proxy under even light real usage

Run this **before** inviting an external user or doing customer
discovery. File bugs as you go into `shake-out-notes.md` (gitignored),
then triage P0 (block customer) vs P1 (next sprint) vs defer.

---

## Rules of engagement

- Start from a **clean checkout** in a throwaway directory. Do not
  reuse your dev state.
- Do **not** look at the source to solve problems — only READMEs and
  dashboard UI. If you have to read code to unstick yourself, that's a
  bug in the docs.
- Keep a terminal open with a stopwatch. Note time-to-first-success
  for each leg — friction is the signal.
- Screenshot any UI that confuses you for more than 30 seconds. Those
  are P0 candidates.

---

## Leg 1 — README onboarding (demo path)

**Scope**: the Quickstart path an X/HN visitor would try.

- [ ] `git clone` into a new dir. Delete any local images
      (`docker image prune -a`) to force a fresh build.
- [ ] Follow **only** the README Quickstart, no other docs.
- [ ] `./deploy_demo.sh up` → succeeds first try, no manual fixes.
- [ ] `./deploy_demo.sh send` → message delivered, no warnings in
      stderr that would scare a new user.
- [ ] Open each dashboard URL the script prints. Navigate every top-nav
      link. Note any 500, blank page, or "what does this mean?"
      moment.
- [ ] `./deploy_demo.sh down` leaves a clean state (no dangling
      volumes, no leftover containers).

**Stop if**: Quickstart fails without an obvious fix. That's P0.

---

## Leg 2 — Broker production deploy, browser first-boot

**Scope**: `deploy_broker.sh --prod-*` + setup wizard in the browser.

- [ ] Fresh dir. Run `./deploy_broker.sh` with the prod flags
      documented in the runbook (BYOCA path).
- [ ] Navigate to the broker dashboard in a real browser (Chrome +
      Firefox if possible).
- [ ] First-boot: admin password flow. Does it force rotation? Does
      the copy-paste work? Does the error on weak password make
      sense?
- [ ] Create an invite token for a new org-member. Log out. Log back
      in via the invite flow.
- [ ] Create a **create-org** invite. Use it from a second browser
      profile to stand up a second org (same broker instance).
- [ ] Create an **attach-CA** invite for an already-existing org.
      Complete the flow. Verify the new CA shows up in the org's
      CA list.
- [ ] Try `./reset.sh` after. Does it cleanly reset? Any orphan data?

**Watch for**: base64url padding bugs (we had one 2026-04-12), setup
wizard steps that assume prior knowledge, error messages that say
"check logs" without pointing at what log.

---

## Leg 3 — Real MCP server behind proxy + Claude API tool-calling

**Scope**: does the MCP proxy actually work with a real MCP server
and a real LLM driving tool calls, not just the smoke test's mocks.

- [ ] Pick a real public MCP server (e.g. `@modelcontextprotocol/server-filesystem`
      or similar). Launch it locally.
- [ ] `./deploy_proxy.sh` — register the MCP server in the proxy's
      egress config via the dashboard (not by editing YAML).
- [ ] Write a tiny Python script using the Anthropic SDK with tool-use
      routed through the proxy. Make **at least 3 round-trips** with
      tool calls that return non-trivial payloads (>1KB).
- [ ] Verify audit entries in the proxy dashboard match what the LLM
      actually called. Names, args, timestamps.
- [ ] Try with Guardian `best-effort` (once Phase 2 lands — skip for
      now, note as deferred).

**Watch for**: streaming weirdness (SSE half-closed), large tool-result
payloads, tool names with special chars, timeouts under slow LLM
reasoning.

---

## Leg 4 — Cross-org on TWO separate deploys

**Scope**: federation that isn't cheating via shared docker network.
Smoke.sh runs everything in one compose file — this is the first time
we actually cross a network boundary.

- [ ] Stand up deploy A (broker + proxy + agent) on `localhost:8800`.
- [ ] Stand up deploy B (broker + proxy + agent) on `localhost:18800`
      in a completely separate directory and compose project.
- [ ] Use attach-CA flow to federate B's org into A (or vice versa).
- [ ] Send a cross-org message. Verify it transits A's broker → B's
      broker via the federation path, not via a shared network.
- [ ] Kill A's broker mid-session. Bring it back. Verify B's pending
      messages drain (this exercises M2 durability + M3 session
      reliability).

**Watch for**: hardcoded hostnames, self-signed cert verification
assumptions, DNS/SNI issues, port collisions with the setup wizard's
defaults.

---

## Leg 5 — Postgres-backed proxy under light load

**Scope**: ADR-001 Phase 1.4 just landed — exercise the postgres path
beyond the CI smoke.

- [ ] Bring the proxy up with `PROXY_DB_URL=postgresql+asyncpg://...`
      against a fresh postgres.
- [ ] Run Alembic on startup — watch logs for the stamp-existing
      branch. `\dt local_*` in psql should show all expected tables.
- [ ] Push ~200 messages through the proxy in a loop. Check
      `local_messages` row count, queue depth via dashboard.
- [ ] Stop proxy mid-loop. Restart. Verify no data loss and no
      Alembic re-stamp confusion.
- [ ] Flip back to sqlite (drop `PROXY_DB_URL`, clean volume) — same
      proxy image, no migrations should run on the fresh sqlite.

---

## Leg 6 — Kubernetes Helm path

**Scope**: `docs/k8s-quickstart.md` end-to-end on k3d (we already did
this in the k3d shake-out session, but re-run as a fresh user).

- [ ] Fresh k3d cluster. Install ingress-nginx per doc.
- [ ] `helm install` broker chart. `/healthz` + `/readyz` both 200.
- [ ] `helm install` proxy chart. Same.
- [ ] Port-forward dashboard. Same first-boot flow as Leg 2.
- [ ] Values drift: try flipping `postgres.internal: false` and
      pointing at an external postgres. Does it degrade gracefully
      with a bad URL?

---

## Exit criteria

- All legs complete, OR
- You've filled `shake-out-notes.md` with 10+ bugs and it's time to
  fix a batch before continuing.

Triage rule of thumb:
- **P0** = a stranger would give up. Fix before customer discovery.
- **P1** = a stranger would finish but think "this is rough". Fix
  before a paying pilot.
- **P2** = minor friction, file as issue, move on.
