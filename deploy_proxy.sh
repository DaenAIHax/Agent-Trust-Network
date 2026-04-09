#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis — MCP Proxy deployment (org-level gateway + built-in PDP)
# ═══════════════════════════════════════════════════════════════════════════════
#
# Deploys the MCP Proxy for one organization. Includes a built-in Policy
# Decision Point (PDP) that the broker calls for authorization.
#
# Two modes:
#
#   (no flag)       Expert mode: builds and starts the plain docker-compose.proxy.yml
#                   stack (HTTP on :9100, no Vault, no nginx). Assumes the broker
#                   is reachable on the same Docker network (single-host demo).
#
#   --dev           Cross-VM dev profile: adds nginx HTTPS (9443), Vault as the
#                   secret backend, writes proxy.env with secure defaults, fetches
#                   the broker CA via /v1/.well-known/broker-ca.pem, brings the
#                   stack up, and prints a guided tour the operator follows from
#                   the dashboard (org register, agent create, env download).
#                   Requires --public-url (this proxy) and --broker-url (peer broker).
#
# Usage:
#   ./deploy_proxy.sh                                       # Expert mode (single host)
#   ./deploy_proxy.sh --dev \
#       --public-url https://vm2.cullis.lan:9443 \
#       --broker-url https://vm1.cullis.lan:8443            # Cross-VM dev
#   ./deploy_proxy.sh --down                                # Stop and remove containers
#   ./deploy_proxy.sh --rebuild                             # Rebuild images and restart
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
BLUE='\033[34m'
BOLD='\033[1m'
GRAY='\033[90m'
RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✓${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}!${RESET}  $1"; }
err()  { echo -e "  ${RED}✗${RESET}  $1"; }
die()  { err "$1"; exit 1; }
step() { echo -e "\n${BOLD}── $1 ──${RESET}"; }

# ── Accept either 'docker compose' (plugin) or 'docker-compose' ──────────────
if docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE="docker-compose"
else
    die "docker compose is not installed"
fi

BASE_COMPOSE_FILE="docker-compose.proxy.yml"
DEV_COMPOSE_FILE="docker-compose.proxy.dev.yml"

# ── Parse args ───────────────────────────────────────────────────────────────
ACTION="up"
PROFILE=""                # "" = expert mode | "dev"
ARG_PUBLIC_URL=""
ARG_BROKER_URL=""

print_help() {
    cat <<EOF
Usage: $0 [PROFILE] [OPTIONS]

Profiles:
  (no flag)                   Expert mode: single-host, HTTP only on :9100.
                              Requires the broker on the same Docker network.
  --dev                       Cross-VM dev: nginx HTTPS on :9443, Vault backend,
                              self-signed TLS, broker CA auto-fetched.
                              Requires --public-url and --broker-url.

Options (--dev only):
  --public-url  <URL>         HTTPS URL external agents use to reach THIS proxy.
                              Used for the nginx cert SAN and the dashboard link.
                              Example: https://vm2.cullis.lan:9443
  --broker-url  <URL>         HTTPS URL of the Cullis broker (on the other VM).
                              Used to fetch /v1/.well-known/broker-ca.pem and
                              as the default in the dashboard setup form.
                              Example: https://vm1.cullis.lan:8443

Actions (any profile):
  --down                      Stop and remove containers
  --rebuild                   Rebuild images and restart
  --help, -h                  Show this help and exit

Examples:
  $0
  $0 --dev --public-url https://192.168.1.51:9443 \\
           --broker-url https://192.168.1.50:8443
  $0 --down
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev)          PROFILE="dev"; shift ;;
        --public-url)   ARG_PUBLIC_URL="${2:-}"; shift 2 ;;
        --broker-url)   ARG_BROKER_URL="${2:-}"; shift 2 ;;
        --down)         ACTION="down"; shift ;;
        --rebuild)      ACTION="rebuild"; shift ;;
        --help|-h)      print_help; exit 0 ;;
        *)              die "Unknown argument: $1 (use --help)" ;;
    esac
done

# ── URL parsing helper (used only for --dev) ─────────────────────────────────
# Extracts host from an http(s):// URL and classifies it as IP or DNS.
# Populates two output globals: _URL_HOST and _URL_SAN_ENTRY
#   _URL_HOST        — bare host (no scheme, no port, no path)
#   _URL_SAN_ENTRY   — "IP:<host>" or "DNS:<host>" for openssl SAN
parse_url_host() {
    local url="$1" label="$2"
    [[ -z "$url" ]] && die "${label} is empty"
    [[ ! "$url" =~ ^https?:// ]] && die "${label} must start with http:// or https:// (got '${url}')"
    local noscheme="${url#*://}"
    noscheme="${noscheme%%/*}"
    local host
    if [[ "$noscheme" == *:* ]]; then
        host="${noscheme%:*}"
    else
        host="$noscheme"
    fi
    [[ -z "$host" ]] && die "${label} has empty host: '${url}'"
    _URL_HOST="$host"
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        _URL_SAN_ENTRY="IP:${host}"
    else
        _URL_SAN_ENTRY="DNS:${host}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# DOWN — stop and remove containers (works for both expert and --dev)
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$ACTION" == "down" ]]; then
    step "Stopping MCP Proxy"
    if [[ -f "$DEV_COMPOSE_FILE" ]]; then
        # Bring down with the dev override included if it exists — harmless
        # if the dev stack was never brought up (compose is idempotent).
        $COMPOSE -f "$BASE_COMPOSE_FILE" -f "$DEV_COMPOSE_FILE" down 2>/dev/null \
            || $COMPOSE -f "$BASE_COMPOSE_FILE" down
    else
        $COMPOSE -f "$BASE_COMPOSE_FILE" down
    fi
    ok "Proxy stopped"
    exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════════
# EXPERT MODE — legacy behaviour, untouched
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$PROFILE" == "" ]]; then
    # Warn if --public-url / --broker-url were given without --dev
    if [[ -n "$ARG_PUBLIC_URL" || -n "$ARG_BROKER_URL" ]]; then
        die "--public-url and --broker-url require --dev"
    fi

    step "Deploying Cullis MCP Proxy (expert mode)"

    if [[ "$ACTION" == "rebuild" ]]; then
        echo -e "  ${GRAY}$COMPOSE -f $BASE_COMPOSE_FILE build --no-cache${RESET}"
        $COMPOSE -f "$BASE_COMPOSE_FILE" build --no-cache
        ok "Images rebuilt"
    fi

    echo -e "  ${GRAY}$COMPOSE -f $BASE_COMPOSE_FILE up --build -d${RESET}"
    $COMPOSE -f "$BASE_COMPOSE_FILE" up --build -d
    ok "Containers started"

    # ── Wait for health ──────────────────────────────────────────────────────
    step "Waiting for services"
    PROXY_PORT="${MCP_PROXY_PORT:-9100}"
    echo -n "  Proxy + PDP "
    for i in $(seq 1 30); do
        if curl -sf "http://localhost:${PROXY_PORT}/health" >/dev/null 2>&1; then
            echo -e " ${GREEN}ready${RESET}"
            break
        fi
        echo -n "."
        sleep 1
        if [[ $i -eq 30 ]]; then
            echo -e " ${RED}timeout${RESET}"
            warn "Proxy did not become healthy — check logs: $COMPOSE -f $BASE_COMPOSE_FILE logs mcp-proxy"
        fi
    done

    # ── Summary ──────────────────────────────────────────────────────────────
    echo ""
    echo -e "${GREEN}${BOLD}MCP Proxy deployed!${RESET}"
    echo ""
    echo -e "  ${BOLD}Proxy Dashboard${RESET}  ${GRAY}http://localhost:${PROXY_PORT}/proxy/login${RESET}"
    echo -e "  ${BOLD}Proxy API${RESET}        ${GRAY}http://localhost:${PROXY_PORT}/v1/egress/${RESET}"
    echo -e "  ${BOLD}PDP Webhook${RESET}      ${GRAY}http://mcp-proxy:${PROXY_PORT}/pdp/policy  (Docker internal)${RESET}"
    echo -e "  ${BOLD}Health${RESET}           ${GRAY}http://localhost:${PROXY_PORT}/health${RESET}"
    echo ""
    echo "  Next steps:"
    echo "    1. Open the proxy dashboard at http://localhost:${PROXY_PORT}/proxy/login"
    echo "    2. Broker URL: http://broker:8000 (same Docker network) + invite token"
    echo "    3. Register your organization (certificates auto-generated)"
    echo "    4. Wait for broker admin to approve your organization"
    echo "    5. Create agents and start communicating"
    echo ""
    echo "  Useful commands:"
    echo "    $COMPOSE -f $BASE_COMPOSE_FILE logs -f          # Follow logs"
    echo "    $COMPOSE -f $BASE_COMPOSE_FILE ps               # Container status"
    echo "    $COMPOSE -f $BASE_COMPOSE_FILE down             # Stop"
    echo "    $COMPOSE -f $BASE_COMPOSE_FILE down -v          # Stop + delete data"
    echo ""
    exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════════
# --dev PROFILE — cross-VM, production-shaped local proxy
# ═══════════════════════════════════════════════════════════════════════════════

# ── Validate required flags ──────────────────────────────────────────────────
[[ -z "$ARG_PUBLIC_URL" ]] && die "--dev requires --public-url <URL>  (see --help)"
[[ -z "$ARG_BROKER_URL" ]] && die "--dev requires --broker-url <URL>  (see --help)"

parse_url_host "$ARG_PUBLIC_URL" "--public-url"
PROXY_HOST="$_URL_HOST"
PROXY_SAN_ENTRY="$_URL_SAN_ENTRY"

parse_url_host "$ARG_BROKER_URL" "--broker-url"
BROKER_HOST="$_URL_HOST"

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Prerequisites
# ═══════════════════════════════════════════════════════════════════════════════
step "Checking prerequisites"
command -v docker  &>/dev/null || die "docker is not installed"
ok "docker found"
command -v openssl &>/dev/null || die "openssl is not installed (try nix-shell)"
ok "openssl found"
command -v curl    &>/dev/null || die "curl is not installed"
ok "curl found"
command -v python3 &>/dev/null || command -v python &>/dev/null \
    || warn "python not found — some helper steps may be unavailable"

# ═══════════════════════════════════════════════════════════════════════════════
# 2. Generate proxy.env (idempotent)
# ═══════════════════════════════════════════════════════════════════════════════
step "proxy.env"

PROXY_ENV_FILE="$SCRIPT_DIR/proxy.env"
FRESH_SECRET=""

generate_proxy_env() {
    local admin_secret
    admin_secret="$(openssl rand -hex 24)"
    FRESH_SECRET="$admin_secret"
    cat > "$PROXY_ENV_FILE" <<EOF
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis MCP Proxy — dev profile environment
# Auto-generated by deploy_proxy.sh --dev on $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Safe to commit? NO. Keep this file out of version control.
# ═══════════════════════════════════════════════════════════════════════════════
MCP_PROXY_ENVIRONMENT=development
MCP_PROXY_ADMIN_SECRET=${admin_secret}
MCP_PROXY_DATABASE_URL=sqlite+aiosqlite:////data/mcp_proxy.db
MCP_PROXY_PDP_URL=http://mcp-proxy:9100/pdp/policy
MCP_PROXY_SECRET_BACKEND=vault
MCP_PROXY_VAULT_ADDR=http://vault:8200
MCP_PROXY_VAULT_TOKEN=dev-root-token
MCP_PROXY_VAULT_SECRET_PREFIX=secret/data/mcp-proxy
MCP_PROXY_BROKER_CA_PATH=/etc/cullis/broker-ca.pem
MCP_PROXY_PROXY_PUBLIC_URL=${ARG_PUBLIC_URL}
MCP_PROXY_PORT=9100
EOF
}

if [[ -f "$PROXY_ENV_FILE" ]]; then
    ok "proxy.env already exists — keeping it (delete to regenerate)"
else
    generate_proxy_env
    ok "Generated $PROXY_ENV_FILE"
    echo ""
    echo -e "  ${YELLOW}${BOLD}!! SAVE THIS NOW !!${RESET}"
    echo -e "  ${BOLD}MCP_PROXY_ADMIN_SECRET${RESET}  ${GRAY}${FRESH_SECRET}${RESET}"
    echo -e "  ${GRAY}Also stored in ./proxy.env — you will need it to log into the dashboard.${RESET}"
    echo ""
fi

# Load the admin secret from proxy.env for later printing in the guided tour.
# This handles both the just-generated case and the "already exists" case.
if grep -q '^MCP_PROXY_ADMIN_SECRET=' "$PROXY_ENV_FILE"; then
    ADMIN_SECRET_FROM_ENV="$(grep '^MCP_PROXY_ADMIN_SECRET=' "$PROXY_ENV_FILE" | head -n1 | cut -d= -f2-)"
else
    ADMIN_SECRET_FROM_ENV="(not set — check proxy.env)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 3. Self-signed nginx cert for the proxy dashboard
# ═══════════════════════════════════════════════════════════════════════════════
step "Nginx TLS certificate"

NGINX_CERTS_DIR="$SCRIPT_DIR/nginx-proxy/certs"
mkdir -p "$NGINX_CERTS_DIR"

# Build the SAN string: always include localhost + 127.0.0.1 + the public-url host
PROXY_SAN="DNS:localhost,DNS:${PROXY_HOST},IP:127.0.0.1"
if [[ "$PROXY_SAN_ENTRY" =~ ^IP: ]]; then
    # public URL host is an IP — add it as IP SAN (override the DNS entry above)
    PROXY_SAN="DNS:localhost,IP:127.0.0.1,${PROXY_SAN_ENTRY}"
fi

regen_needed=0
if [[ -f "$NGINX_CERTS_DIR/server.pem" && -f "$NGINX_CERTS_DIR/server-key.pem" ]]; then
    # Reuse if SAN already matches. openssl prints the SAN extension in the text
    # dump — we grep for each expected token.
    existing_san="$(openssl x509 -in "$NGINX_CERTS_DIR/server.pem" -noout -text 2>/dev/null \
        | grep -A1 'Subject Alternative Name' | tail -n1 | tr -d ' ' || true)"
    _san_ok=1
    IFS=',' read -r -a _wanted_entries <<< "$PROXY_SAN"
    for entry in "${_wanted_entries[@]}"; do
        # openssl prints "DNS:localhost, DNS:foo, IP Address:1.2.3.4" — normalise
        probe="${entry/IP:/IPAddress:}"
        if ! echo "$existing_san" | grep -q "$probe"; then
            _san_ok=0
            break
        fi
    done
    if [[ "$_san_ok" -eq 1 ]]; then
        ok "Nginx cert already exists and SAN matches — keeping it"
    else
        warn "Nginx cert SAN changed (${PROXY_SAN}) — regenerating"
        regen_needed=1
    fi
else
    regen_needed=1
fi

if [[ "$regen_needed" -eq 1 ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$NGINX_CERTS_DIR/server-key.pem" \
        -out "$NGINX_CERTS_DIR/server.pem" \
        -days 365 \
        -subj "/CN=${PROXY_HOST}/O=Cullis Proxy Dev" \
        -addext "subjectAltName=${PROXY_SAN}" \
        2>/dev/null
    chmod 600 "$NGINX_CERTS_DIR/server-key.pem"
    ok "Nginx TLS cert generated (SAN: ${PROXY_SAN})"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# 4. Nginx config (overwritten each run to track --public-url changes)
# ═══════════════════════════════════════════════════════════════════════════════
step "Nginx config"

NGINX_CONF_FILE="$SCRIPT_DIR/nginx-proxy/nginx.conf"
cat > "$NGINX_CONF_FILE" <<NGINXEOF
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis — nginx HTTPS terminator for the MCP proxy dashboard (dev profile)
# Auto-generated by deploy_proxy.sh --dev. Do not edit by hand.
# ═══════════════════════════════════════════════════════════════════════════════

server {
    listen 443 ssl;
    server_name ${PROXY_HOST} localhost;

    ssl_certificate     /etc/nginx/certs/server.pem;
    ssl_certificate_key /etc/nginx/certs/server-key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5:!RC4;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    client_max_body_size 2m;

    location / {
        proxy_pass http://mcp-proxy:9100;
        proxy_http_version 1.1;
        proxy_set_header Host               \$host;
        proxy_set_header X-Real-IP          \$remote_addr;
        proxy_set_header X-Forwarded-For    \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto  \$scheme;
        proxy_set_header Upgrade            \$http_upgrade;
        proxy_set_header Connection         \$http_connection;
        proxy_read_timeout                  86400;
    }
}
NGINXEOF
ok "Wrote ${NGINX_CONF_FILE} (server_name ${PROXY_HOST})"

# ═══════════════════════════════════════════════════════════════════════════════
# 5. Fetch broker CA via .well-known
# ═══════════════════════════════════════════════════════════════════════════════
step "Broker CA bootstrap"

BROKER_CA_DEST="$SCRIPT_DIR/certs/broker-ca.pem"
mkdir -p "$SCRIPT_DIR/certs"

_WELL_KNOWN_URL="${ARG_BROKER_URL%/}/v1/.well-known/broker-ca.pem"
echo -e "  ${GRAY}curl -k -sfS ${_WELL_KNOWN_URL}${RESET}"
if ! curl -k -sfS "$_WELL_KNOWN_URL" -o "${BROKER_CA_DEST}.tmp" 2>/dev/null; then
    rm -f "${BROKER_CA_DEST}.tmp"
    err "Failed to fetch broker CA from ${_WELL_KNOWN_URL}"
    echo ""
    echo "  Manual recovery:"
    echo "    scp user@<broker-vm>:$(pwd)/certs/broker-ca.pem  ${BROKER_CA_DEST}"
    echo "    ./deploy_proxy.sh --dev \\"
    echo "        --public-url ${ARG_PUBLIC_URL} \\"
    echo "        --broker-url ${ARG_BROKER_URL}"
    echo ""
    die "broker CA bootstrap failed"
fi

# Verify it's actually a PEM and not an error page.
if ! head -n1 "${BROKER_CA_DEST}.tmp" | grep -q '^-----BEGIN CERTIFICATE-----'; then
    err "Downloaded file is not a PEM certificate (got $(wc -c <"${BROKER_CA_DEST}.tmp") bytes)"
    echo "  Preview: $(head -c 80 "${BROKER_CA_DEST}.tmp")"
    rm -f "${BROKER_CA_DEST}.tmp"
    die "broker CA bootstrap failed — the broker returned an unexpected body"
fi

mv "${BROKER_CA_DEST}.tmp" "$BROKER_CA_DEST"
chmod 644 "$BROKER_CA_DEST"
ok "Broker CA saved to ${BROKER_CA_DEST}"

# ═══════════════════════════════════════════════════════════════════════════════
# 6. Bring up the stack
# ═══════════════════════════════════════════════════════════════════════════════
step "Bringing up proxy + vault + nginx"

COMPOSE_DEV_ARGS="-f $BASE_COMPOSE_FILE -f $DEV_COMPOSE_FILE --env-file proxy.env"

if [[ "$ACTION" == "rebuild" ]]; then
    echo -e "  ${GRAY}$COMPOSE $COMPOSE_DEV_ARGS build --no-cache${RESET}"
    $COMPOSE $COMPOSE_DEV_ARGS build --no-cache
    ok "Images rebuilt"
fi

echo -e "  ${GRAY}$COMPOSE $COMPOSE_DEV_ARGS up --build -d${RESET}"
$COMPOSE $COMPOSE_DEV_ARGS up --build -d
ok "Containers started"

# ── Wait for Vault ───────────────────────────────────────────────────────────
step "Waiting for services"

echo -n "  Vault         "
for i in $(seq 1 30); do
    # Vault's dev-mode health endpoint returns 200 when unsealed, 429 when standby.
    if $COMPOSE $COMPOSE_DEV_ARGS exec -T vault vault status -address=http://localhost:8200 &>/dev/null; then
        echo -e " ${GREEN}ready${RESET}"
        break
    fi
    echo -n "."
    sleep 1
    if [[ $i -eq 30 ]]; then
        echo -e " ${YELLOW}timeout${RESET}"
        warn "Vault did not become healthy — check: $COMPOSE $COMPOSE_DEV_ARGS logs vault"
    fi
done

# ── Wait for mcp-proxy (via internal Docker network, through its own port 9100) ──
echo -n "  MCP proxy     "
for i in $(seq 1 30); do
    # The base compose publishes 9100 on the host, so we can curl it directly.
    if curl -sf "http://localhost:9100/health" >/dev/null 2>&1; then
        echo -e " ${GREEN}ready${RESET}"
        break
    fi
    echo -n "."
    sleep 1
    if [[ $i -eq 30 ]]; then
        echo -e " ${YELLOW}timeout${RESET}"
        warn "mcp-proxy did not become healthy — check: $COMPOSE $COMPOSE_DEV_ARGS logs mcp-proxy"
    fi
done

# ── Wait for nginx-proxy (HTTPS on 9443) ─────────────────────────────────────
echo -n "  Nginx (HTTPS) "
for i in $(seq 1 30); do
    if curl -sfk "https://localhost:9443/health" >/dev/null 2>&1; then
        echo -e " ${GREEN}ready${RESET}"
        break
    fi
    echo -n "."
    sleep 1
    if [[ $i -eq 30 ]]; then
        echo -e " ${YELLOW}timeout${RESET}"
        warn "nginx-proxy did not become healthy — check: $COMPOSE $COMPOSE_DEV_ARGS logs nginx-proxy"
    fi
done

# ═══════════════════════════════════════════════════════════════════════════════
# 7. Post-deploy guided tour
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
printf "${GREEN}${BOLD}╔════════════════════════════════════════════════════════════════════╗${RESET}\n"
printf "${GREEN}${BOLD}║  Cullis proxy deployed in --dev mode                               ║${RESET}\n"
printf "${GREEN}${BOLD}╚════════════════════════════════════════════════════════════════════╝${RESET}\n"
echo ""
printf "  ${BOLD}Proxy dashboard${RESET}  ${BLUE}https://${PROXY_HOST}:9443/proxy/login${RESET}\n"
printf "    ${BOLD}admin secret${RESET}   ${GRAY}${ADMIN_SECRET_FROM_ENV}${RESET}   ${GRAY}(also in ./proxy.env)${RESET}\n"
echo ""
printf "  ${BOLD}─── NEXT STEPS ─────────────────────────────────────────────────────${RESET}\n"
printf "  Follow these ${BOLD}EXACTLY${RESET}. The names must match across both proxy VMs\n"
printf "  and the broker, otherwise bindings will not be created.\n"
echo ""
printf "  ${BOLD}┌── [VM1 — broker admin]  https://${BROKER_HOST}:8443/dashboard ──┐${RESET}\n"
printf "  ${BOLD}│${RESET}   1. Invites → New → label \"milan-site\"    → copy the token   ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}   2. Invites → New → label \"newyork-site\"  → copy the token   ${BOLD}│${RESET}\n"
printf "  ${BOLD}└──────────────────────────────────────────────────────────────────┘${RESET}\n"
echo ""
printf "  ${BOLD}┌── [THIS VM — Milan proxy]  https://${PROXY_HOST}:9443/proxy/login ┐${RESET}\n"
printf "  ${BOLD}│${RESET}   3. /proxy/setup:                                                ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}        broker URL    ${GRAY}${ARG_BROKER_URL}${RESET}                 ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}        invite token  ${GRAY}<paste the 'milan-site' token>${RESET}               ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}        org id        ${GRAY}milan${RESET}                                        ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}        display name  ${GRAY}Milan Site${RESET}                                   ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}        CA mode       ${GRAY}auto-generate${RESET}                                ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}   4. Wait for VM1 admin to approve org 'milan' (status → active)  ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}   5. /proxy/agents → New agent                                    ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}        name          ${GRAY}sender${RESET}                                       ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}        capability    ${GRAY}order.check${RESET}                                  ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}   6. Wait for VM1 admin to approve binding milan::sender          ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}   7. On agent detail page → \"Download env file\" (saves env.sender)${BOLD}│${RESET}\n"
printf "  ${BOLD}└───────────────────────────────────────────────────────────────────┘${RESET}\n"
echo ""
printf "  ${BOLD}┌── [VM3 — New York proxy]  run ./deploy_proxy.sh --dev there ─────┐${RESET}\n"
printf "  ${BOLD}│${RESET}   Repeat steps 3-7 with:                                          ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}        org id        ${GRAY}newyork${RESET}                                      ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}        invite        ${GRAY}<the 'newyork-site' token>${RESET}                   ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}        agent name    ${GRAY}checker${RESET}                                      ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}        capability    ${GRAY}order.check${RESET}                                  ${BOLD}│${RESET}\n"
printf "  ${BOLD}└───────────────────────────────────────────────────────────────────┘${RESET}\n"
echo ""
printf "  ${BOLD}┌── [Fire the conversation from THIS VM] ──────────────────────────┐${RESET}\n"
printf "  ${BOLD}│${RESET}   ${GRAY}python scripts/demo/sender.py \\\\${RESET}                                 ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}   ${GRAY}    --env-file env.sender \\\\${RESET}                                     ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}   ${GRAY}    --target-agent-id newyork::checker \\\\${RESET}                        ${BOLD}│${RESET}\n"
printf "  ${BOLD}│${RESET}   ${GRAY}    --target-org-id newyork${RESET}                                      ${BOLD}│${RESET}\n"
printf "  ${BOLD}└───────────────────────────────────────────────────────────────────┘${RESET}\n"
echo ""
printf "  ${BOLD}─── Troubleshooting ────────────────────────────────────────────────${RESET}\n"
printf "  ${BOLD}•${RESET} \"htu mismatch\" 401 → ${BOLD}BROKER_PUBLIC_URL${RESET} on VM1 must match the URL\n"
printf "    the proxy calls. Check: ${GRAY}docker exec broker env | grep BROKER_PUBLIC${RESET}\n"
printf "  ${BOLD}•${RESET} TLS verify error → ${GRAY}./certs/broker-ca.pem${RESET} was not fetched.\n"
printf "    Manually scp it from VM1:certs/broker-ca.pem and re-run.\n"
printf "  ${BOLD}•${RESET} Vault unhealthy → ${GRAY}$COMPOSE $COMPOSE_DEV_ARGS logs vault${RESET}\n"
echo ""
printf "  ${BOLD}Useful commands:${RESET}\n"
printf "    ${GRAY}$COMPOSE $COMPOSE_DEV_ARGS logs -f${RESET}\n"
printf "    ${GRAY}$COMPOSE $COMPOSE_DEV_ARGS ps${RESET}\n"
printf "    ${GRAY}./deploy_proxy.sh --down${RESET}\n"
echo ""
