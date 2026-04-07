# Cullis — 3-VM Demo Commands

Three VMs, three organizations, full federated trust.

```
VM1 (broker)  — Cullis broker + admin dashboard
VM2 (buyer)   — ElectroStore — Buyer web console (human-controlled)
VM3 (mfr)     — ChipFactory  — Manufacturer CLI agent (LLM auto-response)
```

---

## 0. Copy repo to VMs

From your local machine:

```bash
rsync -avz --exclude='.venv' --exclude='node_modules' --exclude='.git' \
  --exclude='__pycache__' --exclude='*.db' --exclude='.claude' \
  ~/projects/agent-trust/ broker@192.168.122.154:~/cullis/

rsync -avz --exclude='.venv' --exclude='node_modules' --exclude='.git' \
  --exclude='__pycache__' --exclude='*.db' --exclude='.claude' \
  ~/projects/agent-trust/ electrostore@192.168.122.253:~/cullis/

rsync -avz --exclude='.venv' --exclude='node_modules' --exclude='.git' \
  --exclude='__pycache__' --exclude='*.db' --exclude='.claude' \
  ~/projects/agent-trust/ chipfactory@192.168.122.101:~/cullis/
```

---

## 1. VM1 — Broker

```bash
ssh broker@broker
cd ~/cullis

# Deploy broker (Docker: broker, postgres, redis, vault, nginx, jaeger)
./deploy.sh --dev

# Set broker public URL for multi-VM demo (agents need this to match their BROKER_URL)
echo "BROKER_PUBLIC_URL=http://$(hostname -I | awk '{print $1}'):8000" >> ~/cullis/.env

# Disable policy enforcement for the demo
echo "POLICY_ENFORCEMENT=false" >> ~/cullis/.env

# Restart broker with updated env
docker compose up -d --force-recreate broker

# Verify
curl -s http://localhost:8000/health
```

Dashboard: `http://BROKER-IP:8000/dashboard`
Login: `admin` / password from `.env` (`grep ADMIN_SECRET .env`)

---

## 2. VM3 — ChipFactory (Manufacturer — start first, must be listening before buyer)

```bash
ssh chipfactory@chipfactory
cd ~/cullis/demo/manufacturer

# Step 1: Start Vault (dev mode, token: demo-mfr-token)
docker compose up -d vault
sleep 3

# Step 2: Generate certs, store in Vault, register org on broker
BROKER_URL=http://BROKER-IP:8000 ./bootstrap.sh --register
```

**Go to broker dashboard → Organizations → chipfactory → Approve**

Then upload the CA certificate:
1. Open ChipFactory Vault UI: `http://CHIPFACTORY-IP:8200` (token: `demo-mfr-token`)
2. Navigate: **secret/** → **ca** → copy `cert_pem`
3. Paste in broker dashboard: login as `chipfactory` → Settings → CA Certificate → Upload

```bash
# Step 3: Start manufacturer agent
export BROKER_URL=http://BROKER-IP:8000
export ANTHROPIC_API_KEY=sk-ant-...
docker compose up manufacturer
```

You should see: `[chipfactory::sales] Token JWT ottenuto. Listening for sessions...`

---

## 3. VM2 — ElectroStore (Buyer)

```bash
ssh electrostore@electrostore
cd ~/cullis/demo/buyer

# Step 1: Start Vault (dev mode, token: demo-buyer-token)
docker compose up -d vault
sleep 3

# Step 2: Generate certs, store in Vault, register org on broker
BROKER_URL=http://BROKER-IP:8000 ./bootstrap.sh --register
```

**Go to broker dashboard → Organizations → electrostore → Approve**

Then upload the CA certificate:
1. Open ElectroStore Vault UI: `http://ELECTROSTORE-IP:8200` (token: `demo-buyer-token`)
2. Navigate: **secret/** → **org-ca** → copy `ca_cert_pem`
3. Paste in broker dashboard: login as `electrostore` → Settings → CA Certificate → Upload

```bash
# Step 3: Start buyer console
export BROKER_URL=http://BROKER-IP:8000
export ANTHROPIC_API_KEY=sk-ant-...
docker compose up -d buyer-app
```

Buyer console: `http://ELECTROSTORE-IP:3000`

---

## 4. Run the demo

1. Open browser → `http://ELECTROSTORE-IP:3000`
2. Click **"Connect to Broker"**
3. Type: **"Mi servono 1000 chip ARM Cortex-M4"**
4. Watch the buyer agent:
   - Search suppliers on Cullis network → finds ChipFactory
   - Open a cryptographically secured session
   - Negotiate pricing, delivery, payment terms
   - Report back and ask for confirmation
5. On VM3 terminal, see the manufacturer respond in real-time
6. Confirm the order in the buyer console

---

## What's happening

```
Human (VM2 browser)
  │
  ▼
Buyer LLM (VM2) ──── x509 + DPoP ────► Cullis Broker (VM1)
                                              │
                                        policy check
                                        audit log
                                        E2E relay
                                              │
Manufacturer LLM (VM3) ◄── x509 + DPoP ──────┘
```

Every message is:
- **Signed** twice (RSA-PSS or ECDSA inner + outer)
- **Encrypted** E2E (AES-256-GCM + RSA-OAEP or ECDH)
- **Policy-evaluated** by the broker
- **Audit-logged** (append-only, non-repudiation)
- **Cert-pinned** (SHA-256 thumbprint verified on every request)

Private keys never leave each VM's Vault.

---

## Build & restart (after rsync)

After syncing code changes to the VMs, rebuild and restart:

```bash
# VM1 — Broker
ssh broker@192.168.122.154
cd ~/cullis
docker compose build --no-cache broker
docker compose up -d --force-recreate broker

# VM3 — Manufacturer
ssh chipfactory@192.168.122.101
cd ~/cullis/demo/manufacturer
docker compose build --no-cache manufacturer
docker compose up manufacturer

# VM2 — Buyer
ssh electrostore@192.168.122.253
cd ~/cullis/demo/buyer
docker compose build --no-cache buyer-app
docker compose up buyer-app
```

---

## Tear down

```bash
# VM2 — ElectroStore
ssh electrostore@192.168.122.253 "cd ~/cullis/demo/buyer && docker compose down -v"

# VM3 — ChipFactory
ssh chipfactory@192.168.122.101 "cd ~/cullis/demo/manufacturer && docker compose down -v"

# VM1 — Broker
ssh broker@192.168.122.154 "cd ~/cullis && docker compose down -v"
```

---

## Full reset (after docker compose down -v)

Vault dev mode loses all data on volume removal. Full reset procedure:

```bash
# VM1 — Broker
cd ~/cullis
./deploy.sh --dev
echo "BROKER_PUBLIC_URL=http://192.168.122.154:8000" >> .env
echo "POLICY_ENFORCEMENT=false" >> .env
docker compose up -d --force-recreate broker
# Then: register orgs + agents from dashboard, upload CA certs

# VM3 — Manufacturer
cd ~/cullis/demo/manufacturer
docker compose up -d vault && sleep 3
./bootstrap.sh
export BROKER_URL=http://192.168.122.154:8000 ANTHROPIC_API_KEY=sk-ant-...
docker compose up manufacturer

# VM2 — Buyer
cd ~/cullis/demo/buyer
docker compose up -d vault && sleep 3
./bootstrap.sh
export BROKER_URL=http://192.168.122.154:8000 ANTHROPIC_API_KEY=sk-ant-...
docker compose build --no-cache buyer-app
docker compose up buyer-app
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Connection refused | Check BROKER_URL, firewall (ports 8000, 3000, 8200) |
| Policy denied | Disable policy enforcement on broker dashboard |
| Session not accepted | Manufacturer must be running before buyer sends |
| Vault UI not accessible | Check Vault is running: `docker compose ps` |
| Cert errors | Re-run `./bootstrap.sh --register` to regenerate |
| Org not approved | Approve org on broker dashboard before proceeding |
| Login fails | Use org_id in lowercase (e.g. `chipfactory`, not `ChipFactory`) |
