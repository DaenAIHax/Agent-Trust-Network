#!/usr/bin/env bash
# Enterprise sandbox — smoke test
# Assertion list: imp/enterprise_sandbox_plan.md §smoke
set -euo pipefail

cd "$(dirname "$0")"

PASS=0
FAIL=0
SKIP=0

pass() { echo "  ✓ $1"; PASS=$((PASS+1)); }
fail() { echo "  ✗ $1"; FAIL=$((FAIL+1)); }
skip() { echo "  ~ $1 (skipped: $2)"; SKIP=$((SKIP+1)); }

echo "[smoke] Blocco 1 — shared broker on public-wan"

if docker compose ps --format json | grep -q '"Health":"healthy"'; then
    pass "B1.1 services healthy"
else
    fail "B1.1 services healthy"
fi

if docker run --rm --network cullis-sandbox-wan \
    curlimages/curl:8.10.1 -sf http://broker:8000/health >/dev/null 2>&1; then
    pass "B1.2 broker reachable on public-wan"
else
    fail "B1.2 broker reachable on public-wan"
fi

echo ""
echo "[smoke] Blocco 2 — proxies + attach-ca (2 orgs)"

# B2.1 — 2 orgs registered and active on broker
orgs=$(docker exec enterprise_sandbox-postgres-1 psql -U atn -d agent_trust -Atc \
    "SELECT org_id FROM organizations WHERE status='active' ORDER BY org_id;")
if [[ "$orgs" == $'orga\norgb' ]]; then
    pass "B2.1 orga + orgb active on broker"
else
    fail "B2.1 orgs active (got: $orgs)"
fi

# B2.2 — proxy-a reachable from orga-internal
if docker run --rm --network cullis-sandbox-orga \
    curlimages/curl:8.10.1 -sf http://proxy-a:9100/health >/dev/null 2>&1; then
    pass "B2.2 proxy-a reachable from orga-internal"
else
    fail "B2.2 proxy-a reachable from orga-internal"
fi

# B2.3 — proxy-b reachable from orgb-internal
if docker run --rm --network cullis-sandbox-orgb \
    curlimages/curl:8.10.1 -sf http://proxy-b:9100/health >/dev/null 2>&1; then
    pass "B2.3 proxy-b reachable from orgb-internal"
else
    fail "B2.3 proxy-b reachable from orgb-internal"
fi

# B2.4 — org isolation: orgb-internal cannot reach proxy-a directly
if docker run --rm --network cullis-sandbox-orgb \
    curlimages/curl:8.10.1 -sf --max-time 3 http://proxy-a:9100/health >/dev/null 2>&1; then
    fail "B2.4 org isolation (orgb reached proxy-a directly — LEAK)"
else
    pass "B2.4 org isolation (orgb-internal ⊥ proxy-a direct access)"
fi

# B2.5 — proxy-a CAN reach broker via public-wan (bridge role)
if docker exec enterprise_sandbox-proxy-a-1 \
    python -c "import urllib.request; urllib.request.urlopen('http://broker:8000/health')" 2>/dev/null; then
    pass "B2.5 proxy-a bridges orga-internal → broker (public-wan)"
else
    fail "B2.5 proxy-a bridges to broker"
fi

# Upcoming
skip "B3 Keycloak OIDC"              "Blocco 3 not yet implemented"
skip "B4 SPIRE + SVID agent"         "Blocco 4 not yet implemented"
skip "B5 full 10-assertion smoke"    "Blocco 5 not yet implemented"

echo ""
echo "[smoke] PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[[ $FAIL -eq 0 ]]
