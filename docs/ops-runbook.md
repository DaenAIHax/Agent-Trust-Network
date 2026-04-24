# Operations Runbook — Cullis

## Quick Reference

| Action | Command |
|--------|---------|
| Start all services | `docker compose up -d` |
| Stop all services | `docker compose down` |
| View broker logs | `docker compose logs -f broker` |
| Check health | `curl http://localhost:8000/healthz` |
| Check readiness | `curl http://localhost:8000/readyz` |
| Run DB migrations | `docker compose exec broker alembic upgrade head` |
| Backup database | See [Database Backup](#database-backup) |
| **Run full E2E test** | **`tests/e2e/run.sh`** (~3 min, see [E2E Test](#e2e-test)) |

---

## 1. First Deploy

### Prerequisites
- Docker Engine 24+ with Compose v2
- Domain name with DNS pointing to the server
- TLS certificate (Let's Encrypt or CA-issued)

### Steps

```bash
# 1. Clone and configure
git clone https://github.com/cullis-security/cullis.git
cd cullis
cp .env.example .env

# 2. Generate secrets
python3 -c "import secrets; print('ADMIN_SECRET=' + secrets.token_urlsafe(32))" >> .env
python3 -c "import secrets; print('DASHBOARD_SIGNING_KEY=' + secrets.token_urlsafe(32))" >> .env

# 3. Edit .env — set at minimum:
#    - ADMIN_SECRET (generated above)
#    - DASHBOARD_SIGNING_KEY (generated above)
#    - BROKER_PUBLIC_URL (your public URL)
#    - TRUST_DOMAIN (your domain)
#    - ALLOWED_ORIGINS (your frontend URLs)

# 4. Generate broker PKI
python3 generate_certs.py

# 5. Place TLS certs for Nginx
cp /path/to/fullchain.pem nginx/certs/server.pem
cp /path/to/privkey.pem nginx/certs/server-key.pem

# 6. Start
docker compose up -d

# 7. Verify
curl -k https://localhost:8443/healthz    # → {"status": "ok"}
curl -k https://localhost:8443/readyz     # → {"status": "ready", ...}
```

### TLS profiles via `deploy_broker.sh`

The deploy script supports three TLS profiles. All can run unattended via
CLI flags (suitable for CI/CD or Terraform `local-exec`); without flags
the script falls back to the legacy interactive prompts.

**1. Development (self-signed, localhost)**

```bash
./deploy_broker.sh --dev
```

Generates a self-signed cert valid for `localhost` and `127.0.0.1`. The
broker is reachable at `https://localhost:8443`. Suitable only for local
development and demos — no client outside the host will trust this cert.

**2. Production with Let's Encrypt (HTTP-01 challenge)**

```bash
./deploy_broker.sh --prod-acme \
    --domain broker.example.com \
    --email  ops@example.com
```

Requirements:
- Public DNS record for `broker.example.com` pointing at this host
- TCP/80 reachable from the public internet (for the ACME challenge)
- TCP/443 reachable for the renewed cert to be served

The script:
1. Boots nginx with a 1-day temporary self-signed cert so the container starts
2. Runs `certbot certonly --webroot` to obtain the real certificate
3. Reloads nginx pointing at `/etc/letsencrypt/live/<domain>/fullchain.pem`
4. Prints a cron line for renewal — **add it manually**, the script does
   not install crons. Suggested cron:
   ```cron
   0 3 * * * cd /opt/cullis && docker compose -f docker-compose.yml \
       -f docker-compose.prod.yml -f docker-compose.letsencrypt.yml \
       run --rm certbot renew --quiet && \
       docker compose exec nginx nginx -s reload
   ```

**3. Production with Bring Your Own CA**

```bash
./deploy_broker.sh --prod-byoca \
    --domain broker.example.com \
    --cert /etc/ssl/cullis/fullchain.pem \
    --key  /etc/ssl/cullis/privkey.pem
```

Use this when your enterprise CA already issued a certificate. The script
copies both files into `nginx/certs/` (chmod 600 on the key) and writes a
matching `nginx/nginx.conf` for the supplied domain. Renewal is your
responsibility — re-run with the new files when the cert expires.

### <a name="e2e-test"></a>Full-stack E2E test

Per verificare che il flusso completo (broker → 2 proxy → 2 org → 2 agent →
messaggio E2E) funzioni dopo qualsiasi modifica strutturale, c'è una suite
di test pytest opt-in che orchestra docker compose:

```bash
tests/e2e/run.sh
```

Cosa fa, in ~3 minuti:
1. Boota lo stack completo (broker + postgres + vault + redis + 2 mcp_proxy)
   su porte alte (18xxx/19xxx) per non confliggere col tuo dev
2. Genera 2 invite token via `POST /v1/admin/invites`
3. Registra 2 org via i due proxy (riusa `AgentManager.create_agent`
   tramite uno script Python eseguito dentro al container)
4. Approva entrambe le org
5. Verifica cross-org capability discovery
6. Apre una sessione, invia un messaggio E2E criptato, verifica decifratura
7. Tear down completo (`docker compose down -v`)

Quando lanciarlo:
- Prima di un PR su `main` che tocca broker/proxy/auth/persistence
- Prima di un upgrade di dipendenze crittografiche
- Dopo un refactor del graceful shutdown / FK / migration
- Dopo aggiornamenti del SDK egress

Il test è **skip di default** nei test unit (`pytest.ini` ha
`addopts = -m "not e2e"`). Lo lanci esplicitamente con `tests/e2e/run.sh`
o `pytest -m e2e -o addopts="" tests/e2e/`.

Documentazione dettagliata + troubleshooting: [`tests/e2e/README.md`](../tests/e2e/README.md).

### Common pitfalls

- **`Invalid DPoP proof: htu mismatch` 401s after deploy**: the `BROKER_PUBLIC_URL`
  in `.env` does not match how clients actually reach the broker. The DPoP
  proof contains the URL the client used; the broker derives its expected
  `htu` from `BROKER_PUBLIC_URL` (or the request, when unset). They must
  match exactly, including scheme and port. Check with:
  ```bash
  docker compose exec broker env | grep BROKER_PUBLIC_URL
  curl -kvI https://<your-domain>/healthz 2>&1 | grep -E "Host|location"
  ```
  The broker also logs the two values when a mismatch occurs (warning on
  the `agent_trust` logger).

- **Self-signed cert on production demo**: every SDK refuses self-signed
  certs by default. The Python SDK has a `verify_tls=False` option which
  is **only** for `--dev` localhost demos — never set it in production.

---

## 2. Updating

```bash
# Pull latest code
git pull origin main

# Rebuild and restart (zero-downtime with health checks)
docker compose build broker
docker compose up -d broker

# Run pending DB migrations
docker compose exec broker alembic upgrade head

# Verify
curl https://broker.yourcompany.com/readyz
```

---

## 3. Database Backup

### Manual backup
```bash
# Dump to file
docker compose exec postgres pg_dump -U atn agent_trust > backup_$(date +%Y%m%d_%H%M%S).sql

# Restore from file
cat backup_20260405_120000.sql | docker compose exec -T postgres psql -U atn agent_trust
```

### Automated backup (cron)
```bash
# Add to crontab: daily at 3 AM
0 3 * * * cd /path/to/cullis && docker compose exec -T postgres pg_dump -U atn agent_trust | gzip > /backups/atn_$(date +\%Y\%m\%d).sql.gz
```

### What to back up
- **PostgreSQL** — all broker state (agents, orgs, sessions, audit log, RFQ)
- **Vault data** — broker private keys (if using Vault KMS backend)
- **`.env`** — configuration secrets
- **`certs/`** — broker CA key and certificate

---

## 4. Key Rotation

### Broker CA key
The broker CA key signs all JWT access tokens. Rotation requires:
1. Generate new CA key pair
2. Store in Vault (or replace on disk)
3. Restart broker — new tokens signed with new key
4. Old tokens remain valid until expiry (30 min default)

### Agent certificate rotation
```bash
# Via API (the agent or its org calls this)
POST /v1/registry/agents/{agent_id}/rotate-cert
Authorization: DPoP <token>

# Via dashboard
# Navigate to Agents → click "Rotate Cert" on the agent row
```

### Dashboard signing key
Change `DASHBOARD_SIGNING_KEY` in `.env` and restart. All active dashboard sessions are invalidated (users must re-login).

---

## 5. Revoking an Agent

### Revoke certificate (preventive — blocks future logins)
```bash
# Via API
POST /v1/admin/certs/revoke
X-Admin-Secret: <admin_secret>
{"serial_number": "<cert serial>"}
```

### Revoke tokens (immediate — kills active sessions)
```bash
# Via API (org admin revokes their own agent)
POST /v1/auth/revoke-agent/{agent_id}
X-Org-Id: <org_id>
X-Org-Secret: <org_secret>
```

### Revoke binding (removes authorization)
```bash
POST /v1/registry/bindings/{binding_id}/revoke
X-Org-Id: <org_id>
X-Org-Secret: <org_secret>
```
This also closes all active sessions and disconnects WebSocket.

---

## 6. Monitoring

### Health endpoints
- `GET /healthz` — liveness probe (always 200 if the process is running)
- `GET /readyz` — readiness probe (checks DB + Redis + KMS)

### Jaeger traces
Access Jaeger UI at `http://localhost:16686` (or configure external Jaeger).

Key traces to monitor:
- `auth.issue_token` — authentication latency
- `auth.x509_verify` — certificate verification time
- `broker.create_session` — session creation flow
- `pdp.webhook_call` — policy evaluation latency

### Metrics (OpenTelemetry counters)
- `auth.success` / `auth.deny` — authentication attempts
- `session.created` / `session.denied` — session creation
- `policy.allow` / `policy.deny` — policy decisions
- `rate_limit.reject` — rate limit hits

### Log format
Set `LOG_FORMAT=json` in `.env` for structured logging (SIEM-ready):
```json
{"timestamp": "2026-04-05T12:00:00Z", "level": "INFO", "logger": "agent_trust", "message": "..."}
```

---

## 7. Audit Log

The audit log is append-only with a SHA-256 hash chain. No UPDATE or DELETE operations are allowed.

### Query via API
```bash
# Export as NDJSON (admin only)
GET /v1/admin/audit/export?format=ndjson&start=2026-04-01&end=2026-04-05
X-Admin-Secret: <admin_secret>

# Export as CSV
GET /v1/admin/audit/export?format=csv&org_id=acme&event_type=broker.session_created
```

### Verify hash chain integrity
```bash
# Via dashboard: Audit → "Verify Hash Chain" button (admin only)

# Via API
POST /dashboard/audit/verify
```

---

## 8. Troubleshooting

### Broker won't start
```bash
docker compose logs broker | tail -20
# Common issues:
# - "SECURITY: admin_secret is set to the default" → set ADMIN_SECRET in .env
# - "Cannot connect to PostgreSQL" → check postgres container is healthy
# - "Vault connection failed" → check VAULT_ADDR and VAULT_TOKEN
```

### Agent can't authenticate
1. Check certificate is signed by the org's CA: `openssl verify -CAfile org-ca.pem agent.pem`
2. Check binding is approved: `GET /v1/registry/bindings?org_id=<org>&agent_id=<agent>`
3. Check cert is not revoked: `GET /v1/admin/certs/revoked`
4. Check DPoP nonce: agent should retry on 401 with `use_dpop_nonce` error

### Session creation denied
1. Check policy backend: `POLICY_BACKEND` in `.env`
2. Check PDP webhook is reachable from broker container
3. Check audit log: `GET /v1/admin/audit/export?event_type=policy.session_denied`
4. Both orgs' PDPs must return `{"decision": "allow"}` (default-deny)

### WebSocket not connecting
1. Check Nginx config includes WebSocket proxy headers (`Upgrade`, `Connection`)
2. Check `BROKER_PUBLIC_URL` matches the URL the agent uses
3. Check Redis is running (cross-worker WS pub/sub requires Redis)

---

## 8a. Anomaly detector (ADR-013 Phase 4)

The Mastio ships a single-agent anomaly detector that catches
credential-compromise traffic patterns that stay under the aggregate
volume defences (DB pool, global rate limit, DB-latency circuit
breaker).

### Runtime model

Four cooperating background tasks, started by the Mastio lifespan:

| Component | Cadence | Role |
|-----------|---------|------|
| `traffic_recorder`    | 30 s flush      | In-memory counter per agent, flushed to `agent_traffic_samples`. |
| `baseline_rollup`     | Daily 04:00 UTC | Roll 4-week `agent_traffic_samples` into 168 hour-of-week buckets. |
| `anomaly_evaluator`   | 30 s tick       | Dual-signal detection + cycle-level fail-closed meta-breaker. |
| `quarantine_expiry`   | Hourly          | Hard-DELETE `internal_agents` rows whose enforce-mode event has expired. |

Master switch: `MCP_PROXY_ANOMALY_QUARANTINE_MODE ∈ {shadow,enforce,off}`.

- `shadow` *(default)* — detector evaluates, logs, writes audit rows.
  **Never touches `is_active`.** Default on every new deployment.
- `enforce` — detector flips `is_active=0`, stamps 24 h expiry.
- `off` — evaluator task not started. Used only when the detector
  itself is misbehaving and the ceiling isn't catching it.

### Observability

```bash
curl -H "X-Admin-Secret: $ADMIN_SECRET" \
     http://mastio:9100/v1/admin/observability/anomaly-detector | jq
```

Fields worth watching:

- `mode` — must match intent. An unexpected `off` means someone set
  the env var and forgot to unset it.
- `quarantines_last_24h` — enforce-mode events in the window.
  Sustained non-zero values without a known incident are either a
  real compromise or a tuning miss; investigate before dismissing.
- `quarantines_last_24h_shadow_only` — what the detector *would*
  have done in enforce mode. Use this during the shadow-to-enforce
  flip assessment.
- `meta_ceiling_trips_total` — lifetime count. If this climbs in
  production, the detector is mis-tuned; raising the ceiling is
  almost never the right fix.

### Incident response

#### A legitimate agent got quarantined (enforce mode)

1. Pull the event: `SELECT * FROM agent_quarantine_events WHERE
   agent_id = '<id>' ORDER BY quarantined_at DESC LIMIT 1;`
2. Pull the traffic pattern:
   `SELECT bucket_ts, req_count FROM agent_traffic_samples
   WHERE agent_id = '<id>' AND bucket_ts > datetime('now','-1 day');`
3. If the trigger was a one-off (known migration, legit campaign),
   reactivate:
   ```bash
   curl -X POST -H "X-Admin-Secret: $ADMIN_SECRET" \
        http://mastio:9100/v1/admin/agents/<id>/reactivate
   ```
4. If the agent's baseline has shifted permanently (agent changed
   workload shape), let the next daily roll-up at 04:00 UTC
   incorporate the new traffic. There is no per-agent threshold
   override in Phase 4.

If reactivation returns 404 "re-enrollment required", the 24 h
expiry cron already hard-deleted the row. Re-enrol the agent via
the normal Connector flow — this is by design.

#### The detector flags agents that should not be flagged

In shadow mode these are log noise — no action required. If
> 5 % of agents appear in any week, the thresholds are too
aggressive for the shape of this deployment. Tune via env +
redeploy:

```
MCP_PROXY_ANOMALY_RATIO_THRESHOLD=15.0        # was 10.0
MCP_PROXY_ANOMALY_ABSOLUTE_THRESHOLD_RPS=200  # was 100
```

#### Meta-ceiling tripped

One `ERROR` log per trip:
`anomaly_quarantine ceiling exceeded: suppressed N decision(s) …`.
N agents simultaneously crossed threshold in a 30 s cycle — almost
always infrastructure shape, not a coordinated compromise:

- DB hiccup pushed every agent's observed rate up briefly.
- Bad baseline was deployed (roll-up cron bug).
- Time skew makes "now" look like a high-baseline hour.

Action: investigate out-of-band. The detector did zero harm on this
trip — zero quarantines applied — so there is no reactivation
backlog. Raising the ceiling (env var, redeploy) is a last resort.

### Flipping shadow → enforce

1. Run in shadow mode for at least 28 days on the target deployment.
   Review every shadow-mode event:
   ```sql
   SELECT agent_id, quarantined_at, trigger_ratio, trigger_abs_rate
     FROM agent_quarantine_events
    WHERE mode = 'shadow'
    ORDER BY quarantined_at DESC;
   ```
2. Confirm zero false positives in the last 14 days. If any, tune
   thresholds or investigate the flagged agent.
3. Redeploy with `MCP_PROXY_ANOMALY_QUARANTINE_MODE=enforce`.
4. Watch the observability endpoint closely for the first 48 h.

Rollback: set the mode back to `shadow` and redeploy. Enforce-mode
events already written stay in the DB (audit trail); their
`is_active=0` stays until the 24 h cron hard-deletes the row, or an
operator reactivates.

---

## 9. Production Checklist

Before going live, verify:

- [ ] `ADMIN_SECRET` is a strong random value (not the default)
- [ ] `DASHBOARD_SIGNING_KEY` is set
- [ ] `ALLOWED_ORIGINS` is set to specific origins (not `*`)
- [ ] `DATABASE_URL` points to PostgreSQL (not SQLite)
- [ ] `KMS_BACKEND=vault` with HTTPS Vault address
- [ ] `REQUIRE_SPIFFE_SAN=true`
- [ ] TLS certificates are real (not self-signed)
- [ ] `VAULT_ALLOW_HTTP` is NOT set
- [ ] Backup cron is configured
- [ ] `LOG_FORMAT=json` for log aggregation
- [ ] Rate limit buckets are tuned for expected load
- [ ] PDP webhooks are configured for all organizations
- [ ] Jaeger/OTLP endpoint is configured for trace collection
- [ ] Anomaly detector running in `shadow` mode for at least 28 days
      before any flip to `enforce` (`MCP_PROXY_ANOMALY_QUARANTINE_MODE`)
- [ ] Anomaly detector thresholds reviewed against the shadow-mode
      event history (ratio, abs_rps, ceiling_per_min)
