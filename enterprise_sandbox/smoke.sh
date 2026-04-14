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

echo ""
echo "[smoke] Blocco 3 — Keycloak OIDC per org"

# B3.1 — Keycloak-a OIDC discovery reachable from broker
if docker exec enterprise_sandbox-broker-1 python -c "
import urllib.request
urllib.request.urlopen('http://keycloak-a:8080/realms/orga/.well-known/openid-configuration')
" 2>/dev/null; then
    pass "B3.1 keycloak-a realm 'orga' discovery OK"
else
    fail "B3.1 keycloak-a discovery"
fi

# B3.2 — Keycloak-b OIDC discovery reachable from broker
if docker exec enterprise_sandbox-broker-1 python -c "
import urllib.request
urllib.request.urlopen('http://keycloak-b:8080/realms/orgb/.well-known/openid-configuration')
" 2>/dev/null; then
    pass "B3.2 keycloak-b realm 'orgb' discovery OK"
else
    fail "B3.2 keycloak-b discovery"
fi

# B3.3 — Per-org OIDC config wired in broker DB
oidc_a=$(docker exec enterprise_sandbox-postgres-1 psql -U atn -d agent_trust -Atc \
    "SELECT oidc_issuer_url FROM organizations WHERE org_id='orga';")
oidc_b=$(docker exec enterprise_sandbox-postgres-1 psql -U atn -d agent_trust -Atc \
    "SELECT oidc_issuer_url FROM organizations WHERE org_id='orgb';")
if [[ "$oidc_a" == "http://keycloak-a:8080/realms/orga" && "$oidc_b" == "http://keycloak-b:8080/realms/orgb" ]]; then
    pass "B3.3 per-org OIDC config wired in broker DB"
else
    fail "B3.3 OIDC config wired (orga=$oidc_a orgb=$oidc_b)"
fi

# B3.4 — End-to-end: alice@orga obtains id_token with correct issuer
b34=$(docker exec enterprise_sandbox-broker-1 python -c "
import urllib.request, urllib.parse, json, base64
data = urllib.parse.urlencode({
    'grant_type':'password','client_id':'cullis-broker-dashboard',
    'client_secret':'orga-oidc-client-secret-change-me',
    'username':'alice','password':'alice-sandbox','scope':'openid email'
}).encode()
t = json.loads(urllib.request.urlopen('http://keycloak-a:8080/realms/orga/protocol/openid-connect/token', data=data).read())
p = json.loads(base64.urlsafe_b64decode(t['id_token'].split('.')[1]+'==='))
print(p['iss']+'|'+p['email'])
" 2>/dev/null)
if [[ "$b34" == "http://keycloak-a:8080/realms/orga|alice@orga.test" ]]; then
    pass "B3.4 alice@orga OIDC login → id_token valid"
else
    fail "B3.4 alice OIDC login (got: $b34)"
fi

# B3.5 — Tenant isolation: Keycloak-a does NOT have bob, Keycloak-b does NOT have alice
if docker exec enterprise_sandbox-broker-1 python -c "
import urllib.request, urllib.parse, json
data = urllib.parse.urlencode({
    'grant_type':'password','client_id':'cullis-broker-dashboard',
    'client_secret':'orga-oidc-client-secret-change-me',
    'username':'bob','password':'bob-sandbox','scope':'openid'
}).encode()
try: urllib.request.urlopen('http://keycloak-a:8080/realms/orga/protocol/openid-connect/token', data=data); exit(1)
except Exception: exit(0)
" 2>/dev/null; then
    pass "B3.5 tenant isolation (bob rejected by keycloak-a)"
else
    fail "B3.5 tenant isolation (bob accepted by keycloak-a — LEAK)"
fi

# Upcoming
skip "B4 SPIRE + SVID agent"         "Blocco 4 not yet implemented"
skip "B5 full 10-assertion smoke"    "Blocco 5 not yet implemented"

echo ""
echo "[smoke] PASS=$PASS  FAIL=$FAIL  SKIP=$SKIP"
[[ $FAIL -eq 0 ]]
