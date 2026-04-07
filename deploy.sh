#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# Cullis — Deployment wrapper
# ═══════════════════════════════════════════════════════════════════════════════
#
# Cullis has two components:
#   1. Broker  — the trust network hub (deploy once)
#   2. Proxy   — org-level gateway (deploy per organization)
#
# Usage:
#   ./deploy.sh                  # Interactive — asks what to deploy
#   ./deploy.sh broker [args]    # Deploy broker (passes args to deploy_broker.sh)
#   ./deploy.sh proxy  [args]    # Deploy proxy  (passes args to deploy_proxy.sh)
#   ./deploy.sh --dev            # Shortcut: deploy broker in dev mode
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BOLD='\033[1m'
GREEN='\033[32m'
GRAY='\033[90m'
RESET='\033[0m'

# ── Direct subcommand ────────────────────────────────────────────────────────
if [[ "${1:-}" == "broker" ]]; then
    shift
    exec "$SCRIPT_DIR/deploy_broker.sh" "$@"
elif [[ "${1:-}" == "proxy" ]]; then
    shift
    exec "$SCRIPT_DIR/deploy_proxy.sh" "$@"
elif [[ "${1:-}" == "--dev" || "${1:-}" == "--prod" ]]; then
    # Backward compat: ./deploy.sh --dev still deploys the broker
    exec "$SCRIPT_DIR/deploy_broker.sh" "$@"
fi

# ── Interactive ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Cullis — What would you like to deploy?${RESET}"
echo ""
echo "  1) Broker  — trust network hub (postgres, redis, vault, nginx)"
echo "  2) Proxy   — org-level MCP gateway (per organization)"
echo "  3) Both    — broker first, then proxy"
echo ""
read -rp "  Choose [1/2/3]: " choice

case "$choice" in
    1)
        exec "$SCRIPT_DIR/deploy_broker.sh"
        ;;
    2)
        exec "$SCRIPT_DIR/deploy_proxy.sh"
        ;;
    3)
        "$SCRIPT_DIR/deploy_broker.sh" --dev
        echo ""
        echo -e "${GREEN}${BOLD}Broker deployed. Now deploying proxy...${RESET}"
        echo ""
        "$SCRIPT_DIR/deploy_proxy.sh"
        ;;
    *)
        echo "Invalid choice. Use: $0 broker|proxy or $0 --dev"
        exit 1
        ;;
esac
