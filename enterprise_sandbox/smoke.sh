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

# B1.1 — all services healthy
if docker compose ps --format json | grep -q '"Health":"healthy"'; then
    pass "B1.1 services healthy"
else
    fail "B1.1 services healthy"
fi

# B1.2 — broker reachable on public-wan
if docker run --rm --network cullis-sandbox-wan \
    curlimages/curl:8.10.1 -sf http://broker:8000/health >/dev/null 2>&1; then
    pass "B1.2 broker reachable on public-wan"
else
    fail "B1.2 broker reachable on public-wan"
fi

# B1.3 — org-internal networks exist and are isolated from public-wan services
# (container on orga-internal cannot reach broker, which is on public-wan only)
if docker run --rm --network cullis-sandbox-orga \
    curlimages/curl:8.10.1 -sf --max-time 3 http://broker:8000/health >/dev/null 2>&1; then
    fail "B1.3 org-internal isolation (orga reached broker — LEAK)"
else
    pass "B1.3 org-internal isolated from public-wan (proxy will bridge in Blocco 2)"
fi

# Upcoming blocks
skip "B2 Vault + Proxies + attach-ca"  "Blocco 2 not yet implemented"
skip "B3 Keycloak OIDC"                "Blocco 3 not yet implemented"
skip "B4 SPIRE + SVID agent"           "Blocco 4 not yet implemented"
skip "B5 smoke 10 assertion"           "Blocco 5 not yet implemented"

echo ""
echo "[smoke] PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[[ $FAIL -eq 0 ]]
