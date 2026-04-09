# Multi-VM Runbook — Cullis across three VMs

This runbook walks an operator through deploying Cullis across three virtual
machines in the `--dev` profile, using a realistic cross-site scenario:
one broker hosted by the security team of "Acme Corp", plus two MCP proxies
— one for the Milan office, one for the New York office — each running a
single agent that will talk to the other through the broker.

At the end you will have a working end-to-end flow where a sender agent on
the Milan VM opens a session to a checker agent on the New York VM, routed
and authorized through the broker on a third VM. TLS is real (self-signed,
but enforced on every hop), the DPoP bindings are real, the broker CA
private key lives in Vault, and no component is bypassed or mocked. It is
as close as the dev profile gets to a production topology without investing
in real PKI.

What this runbook is **not**: a production hardening guide. Vault runs in
dev mode (in-memory root token, data lost on container restart), the TLS
certificates are self-signed (every SDK and browser will warn), the broker
CA is trusted only inside this three-VM island, and no backups, monitoring,
or high-availability pieces are wired up. The purpose is to prove the
architecture works end to end across real network boundaries **before** you
invest in a real CA, a real Vault cluster, or a real Kubernetes
deployment. If you are after production deployment, stop here and read
[`docs/ops-runbook.md`](ops-runbook.md) and [`enterprise-kit/`](../enterprise-kit/)
instead.

---

## Scenario

Acme Corp wants to let its Milan office send cross-site requests to its
New York office through a single trust broker hosted by the central
security team. Three VMs, one role each:

| Host                           | Example IP   | Role                                          | Admin        |
|--------------------------------|--------------|-----------------------------------------------|--------------|
| `broker.acme.lan`              | `10.0.0.10`  | Cullis broker (network control plane)         | Security     |
| `milan-proxy.acme.lan`         | `10.0.0.20`  | MCP proxy for the Milan office — `sender`    | Milan IT     |
| `newyork-proxy.acme.lan`       | `10.0.0.30`  | MCP proxy for the NY office — `checker`      | New York IT  |

The three VMs must be **mutually reachable** on the ports listed in the
architecture diagram below. See [Network reachability](#network-reachability)
for the honest version of that requirement.

---

## Architecture

```
                           Acme Corp internal network
                            (VPN / private subnet)

   ┌──────────────────────────────────────────────────────────────────┐
   │                                                                  │
   │   VM1 — broker.acme.lan (10.0.0.10)                              │
   │   ┌────────────────────────────────────────────────────────┐     │
   │   │  nginx  :8443 (HTTPS)  ─┐                              │     │
   │   │                         ├─→  broker :8000 (internal)   │     │
   │   │                         ├─→  vault  :8200 (internal)   │     │
   │   │                         └─→  postgres (internal)       │     │
   │   │                              jaeger  :16686 (internal) │     │
   │   └────────────────────────────────────────────────────────┘     │
   │                 ▲                             │                  │
   │                 │ register, DPoP, messages    │ PDP webhook      │
   │                 │ (TLS 8443)                  │ (TLS 9443)       │
   │                 │                             ▼                  │
   │   ┌─────────────┴──────────┐   ┌──────────────────────────┐      │
   │   │ VM2 — milan-proxy      │   │ VM3 — newyork-proxy      │      │
   │   │   10.0.0.20            │   │   10.0.0.30              │      │
   │   │                        │   │                          │      │
   │   │  nginx :9443 ──┐       │   │  nginx :9443 ──┐         │      │
   │   │                ├→ mcp  │   │                ├→ mcp    │      │
   │   │                │  proxy│   │                │  proxy  │      │
   │   │                └→ vault│   │                └→ vault  │      │
   │   │                        │   │                          │      │
   │   │  agent: sender         │   │  agent: checker          │      │
   │   │  cap:   order.check    │   │  cap:   order.check      │      │
   │   └────────────────────────┘   └──────────────────────────┘      │
   │                                                                  │
   └──────────────────────────────────────────────────────────────────┘
```

Ports that matter on the wire:

| From                 | To                 | Port          | Purpose                                         |
|----------------------|--------------------|---------------|-------------------------------------------------|
| VM2, VM3             | VM1                | `8443` (TLS)  | Proxy → broker register / DPoP / messaging      |
| VM1                  | VM2, VM3           | `9443` (TLS)  | Broker → proxy **PDP webhook callback**         |
| Operator's browser   | VM1                | `8443` (TLS)  | Broker dashboard                                |
| Operator's browser   | VM2, VM3           | `9443` (TLS)  | Proxy dashboard                                 |
| (all internal)       | (all internal)     | `8200`        | Vault, only reachable inside the host's Docker  |

### Network reachability

The tempting mental model is "proxies are clients, broker is a server, so
proxies just need to reach the broker." That is **not enough**. Cullis uses
the proxy's Policy Decision Point as a webhook: when VM2 opens a session to
VM3 via the broker on VM1, the broker calls **back** to `https://milan-proxy.acme.lan:9443/pdp/policy`
(and to the New York proxy's `/pdp/policy`) to ask both orgs whether the
session is allowed.

This means **VM1 must be able to reach VM2 and VM3 on port 9443**. If your
proxies sit behind NAT or in a network that the broker cannot originate
connections into, session creation will time out on the PDP call and
everything will look broken for reasons that are not obvious from the logs.

Before you start, make sure of the following:

1. `curl -kfI https://broker.acme.lan:8443/health` from VM2 and VM3 returns 200.
2. `curl -kfI https://milan-proxy.acme.lan:9443/health` from VM1 returns 200.
3. `curl -kfI https://newyork-proxy.acme.lan:9443/health` from VM1 returns 200.

If your offices are behind NAT and you cannot achieve item 2 or 3, either
(a) put all three VMs on the same VPN segment, (b) expose the proxy
dashboards via a reverse SSH tunnel back to the broker, or (c) accept that
this exercise will not work in your topology and stop now. There is no
clean workaround in the dev profile. In production you would run the proxy
in the org's DMZ with a stable inbound rule from the broker network.

---

## Prerequisites

On **all three** VMs:

- Docker Engine 24+ with the Compose v2 plugin (`docker compose version`)
- `openssl` (for the deploy scripts' self-signed cert generation)
- `curl` (health checks and the broker CA fetch)
- `python3` 3.10+ with `httpx` installed (the sender/checker scripts run
  from the host shell, not inside a container)
- ~2 GB free disk and an outbound network for the first-time image build
- A clone of the Cullis repository in the same path everywhere (e.g. `/opt/cullis`)

On the network:

- DNS entries (or matching `/etc/hosts` lines on every VM) for the three
  hostnames above pointing at stable IPs. Pure IP-based deployment also
  works if you pass the IP to `--public-url`, but hostnames make the
  runbook less confusing.
- Mutual reachability on ports 8443 and 9443 (see
  [Network reachability](#network-reachability) above).
- Your operator workstation must be able to reach all three hostnames on
  their respective dashboard ports for the browser steps.

Single host prerequisites that **do not apply** here:

- You do **not** need a public DNS name or a public IP. This runbook runs
  entirely on private addresses.
- You do **not** need a real TLS cert. The dev profile generates
  self-signed certs with the right SANs for you.
- You do **not** need HashiCorp Vault installed on the host — each VM
  boots its own Vault container in dev mode.

---

## Part 1 — VM1: deploy the broker

SSH into `broker.acme.lan`:

```bash
ssh operator@broker.acme.lan
cd /opt/cullis
```

### 1.1 Run the deploy script

```bash
./deploy_broker.sh --dev --public-url https://broker.acme.lan:8443
```

The `--public-url` flag is new in the dev profile and is the most
important single thing on this entire page. What the flag does:

1. **Rewrites the self-signed TLS cert's SAN** to include
   `broker.acme.lan` (not just `localhost` / `127.0.0.1`). Without this,
   every TLS handshake from VM2 / VM3 would fail certificate validation
   because the cert's only SAN would be `localhost`.
2. **Writes `BROKER_PUBLIC_URL=https://broker.acme.lan:8443` into `.env`**
   and exports it into the broker container. The broker uses this value
   to derive the expected `htu` claim on every DPoP proof it receives —
   see the htu binding explanation below.
3. Everything else the `--dev` profile normally does: generate
   `ADMIN_SECRET` and `DASHBOARD_SIGNING_KEY`, generate the broker CA
   (RSA-4096, 10-year validity), boot `broker + postgres + redis + vault + nginx + jaeger`,
   load the broker CA private key into Vault at `secret/data/broker`,
   **delete** the on-disk copy of the broker CA private key so the only
   place it lives now is Vault, and run Alembic migrations.

Expected output ends with something like:

```
Deployment complete!

  Mode        Development
  Dashboard   https://broker.acme.lan:8443/dashboard
  Broker      https://broker.acme.lan:8443
  Vault       http://localhost:8200
  Jaeger      http://localhost:16686
```

### 1.2 Why `--public-url` matters: htu binding

Cullis binds every access token to a DPoP proof (RFC 9449). The proof
contains an `htu` claim with the HTTP URL of the request the client is
making, and the broker rejects the proof unless the `htu` matches what
the broker is expecting. The "expected" value is derived from
`BROKER_PUBLIC_URL`.

If `BROKER_PUBLIC_URL` ends up wrong — e.g. the broker is set to
`https://localhost:8443` but a proxy is calling it at
`https://broker.acme.lan:8443`, or the scheme is `http://` instead of
`https://`, or the port is missing — every request from the proxy will
fail with:

```
HTTP 401 {"detail": "Invalid DPoP proof: htu mismatch"}
```

This is the single most common failure mode people hit when they graduate
from "localhost demo" to "multi-VM". Passing `--public-url` at deploy
time preempts it.

Verify the broker has the right value:

```bash
docker exec cullis-broker-1 env | grep BROKER_PUBLIC_URL
# → BROKER_PUBLIC_URL=https://broker.acme.lan:8443
```

(The container name may differ slightly depending on your Compose project
name — use `docker compose ps` to see the exact value.)

### 1.3 Log into the broker dashboard

Open `https://broker.acme.lan:8443/dashboard` in a browser. Because the
cert is self-signed, every browser will show a "Not secure" warning —
click through, this is expected.

- **Username**: `admin`
- **Password**: the `ADMIN_SECRET` value printed at the top of
  `/opt/cullis/.env` on VM1 (grab it with
  `grep ^ADMIN_SECRET= .env` — keep it out of shell history if you can).

### 1.4 Generate two invite tokens

Inside the broker dashboard go to the **Invites** (or **Onboarding**)
view and generate two single-use invite tokens:

- Label: `milan-site`
- Label: `newyork-site`

Copy each token to a scratchpad. You will paste them into the proxy setup
form on VM2 and VM3 respectively. Each token is single-use; if you
accidentally burn one you can generate another from the same view.

### 1.5 The broker CA is published at a well-known endpoint

The other two VMs need the broker CA **public** certificate so they can
verify TLS and the SPIFFE chain of the broker. Cullis exposes it at:

```
GET https://broker.acme.lan:8443/v1/.well-known/broker-ca.pem
```

This endpoint is **unauthenticated by design**: CA certificates are
public information, nothing sensitive leaks. The proxy deploy script on
VM2 and VM3 will fetch it automatically in the next step. If that fetch
fails for any reason (firewall, DNS), the fallback is:

```bash
# from VM2 or VM3
scp operator@broker.acme.lan:/opt/cullis/certs/broker-ca.pem \
    /opt/cullis/certs/broker-ca.pem
```

That file is the **public** cert (`broker-ca.pem`) — not the private
key, which no longer exists on disk on VM1 after step 1.1.

Do **not** try to copy `broker-ca-key.pem`: as part of the `--dev` deploy
it was loaded into Vault and removed from disk. If you find it still sitting
in `certs/broker-ca-key.pem`, the Vault upload failed — the deploy script
prints a big red CRITICAL warning in that case. Re-run the deploy (it is
idempotent) before moving to Part 2.

---

## Part 2 — VM2: deploy the Milan proxy

SSH into `milan-proxy.acme.lan`:

```bash
ssh operator@milan-proxy.acme.lan
cd /opt/cullis
```

### 2.1 Run the deploy script

```bash
./deploy_proxy.sh --dev \
    --public-url https://milan-proxy.acme.lan:9443 \
    --broker-url https://broker.acme.lan:8443
```

What this does:

1. Generates `proxy.env` next to the compose file with a random admin
   secret for the proxy dashboard (printed to the terminal — **copy it
   now**, it is not stored anywhere else you can easily find).
2. Generates a self-signed TLS cert for nginx with SAN
   `DNS:milan-proxy.acme.lan,IP:127.0.0.1` so the dashboard is reachable
   at `https://milan-proxy.acme.lan:9443` from any browser on the VPN.
3. **Fetches the broker CA public cert** from
   `https://broker.acme.lan:8443/v1/.well-known/broker-ca.pem`
   (cross-reference 1.5) and drops it at `certs/broker-ca.pem` inside the
   proxy tree. This is the file the new `mcp_proxy/auth/broker_http.py`
   module uses as its `verify=` parameter when talking to the broker —
   no more `verify=False` on the egress path.
4. Boots three containers: `vault` (dev mode, in-memory root token),
   `nginx` (terminates 9443 and reverse-proxies into mcp-proxy), and
   `mcp-proxy` itself.
5. Prints a "guided tour" at the end with the dashboard URL, the admin
   secret, and the next recommended step.

Expected output ends with something like:

```
MCP Proxy deployed!

  Proxy Dashboard  https://milan-proxy.acme.lan:9443/proxy/login
  Admin secret     <random string — copy this>
  Broker URL       https://broker.acme.lan:8443
  Broker CA        certs/broker-ca.pem (fetched from /v1/.well-known/broker-ca.pem)
```

If the fetch of `broker-ca.pem` fails, the script stops here with a
pointer to the `scp` fallback from 1.5. Fix the fetch, then re-run the
script.

### 2.2 Log into the proxy dashboard

Open `https://milan-proxy.acme.lan:9443/proxy/login` in the browser.
Again, self-signed cert warning — click through.

- **Username**: `admin`
- **Password**: the admin secret printed at the end of step 2.1.

You will land on an empty proxy dashboard with a "Setup" step at the top.

### 2.3 Fill the Setup wizard

Click **Setup** (or navigate to `/proxy/setup`). The form has four
sections:

**Step 1 — Broker Connection**

- **Broker URL**: `https://broker.acme.lan:8443`
- **Invite Token**: paste the `milan-site` token you generated in 1.4

Click the **Test** button next to the broker URL. It should light up
green (HTTPS handshake + broker `/health` reachable). If it lights up
red, stop here and debug; everything after this will fail.

**Step 2 — Organization + CA**

- **Organization ID**: `milan`
- **Display Name**: `Milan Site`
- **Contact Email**: whatever you want (e.g. `it-milan@acme.lan`)
- **Webhook URL**: leave blank. The proxy's built-in PDP will handle
  policy decisions for this org — this is what the broker will call
  back on port 9443.
- **Organization Certificate Authority**: pick **Generate new (RSA-4096)**.
  The proxy will create a fresh Org CA, store its private key in the
  proxy database, and only send the public cert to the broker.

**Step 3 — Vault (Optional)**

Leave **Enable Vault integration** unchecked in the dev profile. The
proxy's own Vault container is used transparently for secret storage;
you do not need to point the form at it.

**Step 4 — Register on Broker**

Click **Register on Broker**. The proxy calls
`POST /v1/onboarding/join` on the broker with the invite token, the org
metadata, and the Org CA public cert. The broker persists the org in
`pending` status and replies with a provisional org record.

At this point the Milan org **cannot yet create agents**. The dashboard
will show a yellow "Pending broker approval" banner at the top.

### 2.4 Approve the org from VM1

Switch back to the broker dashboard on VM1
(`https://broker.acme.lan:8443/dashboard`). Navigate to **Orgs**
(`/dashboard/orgs`). You should see:

```
  milan      Pending     Milan Site     2 minutes ago
  newyork    —           —              —
```

Click the row for `milan`. On the detail page there is an **Approve**
button near the top of the panel — it is the only button on the page
that is not greyed out. Click it. The status flips to `Active` and the
broker mints the org's signed cert chain.

Back on VM2's proxy dashboard, refresh the page — the yellow banner
should be gone and you should now see **Agents** in the sidebar without a
lock icon.

### 2.5 Create the `sender` agent

On VM2, navigate to **Agents** (`/proxy/agents`) and click **New agent**.
Fill in:

- **Agent name**: `sender`
- **Capabilities**: `order.check`
- Leave everything else at the defaults.

Submit. The proxy issues an x509 leaf cert signed by the Milan Org CA
with SPIFFE SAN `spiffe://atn.local/milan/sender`, mints an API key
(`sk_local_<random>`), and registers the agent + binding on the broker.
The binding lands in `pending` state on the broker side.

### 2.6 Approve the binding from VM1

Back to the broker dashboard on VM1. Go to **Bindings**
(`/dashboard/bindings` — or it may be nested under **Agents** depending on
your version). Find the row for `milan::sender` with status **Pending**,
open it, click **Approve**. Status flips to **Active**.

### 2.7 Download the agent's env file

Back on VM2, navigate to the detail page of `milan::sender` at
`/proxy/agents/sender`. There is a **Download env file** button in the
top-right corner of the detail card. Click it. You will get a file with
contents roughly like:

```
CULLIS_AGENT_ID=milan::sender
CULLIS_API_KEY=sk_local_xxxxxxxxxxxxxxxxxxxxx
CULLIS_PROXY_URL=https://milan-proxy.acme.lan:9443
CULLIS_BROKER_CA_PATH=./certs/broker-ca.pem
```

Save it to `/opt/cullis/env.sender` on VM2. You will `source` it in
Part 4.

---

## Part 3 — VM3: deploy the New York proxy

This is a verbatim repeat of Part 2 with three substitutions:
`milan` → `newyork`, `Milan Site` → `New York Site`, and the Milan
hostname → the New York hostname. The runbook still spells the steps
out because in a live demo you will want to read line by line, not trust
yourself to remember.

### 3.1 Run the deploy script

```bash
ssh operator@newyork-proxy.acme.lan
cd /opt/cullis
./deploy_proxy.sh --dev \
    --public-url https://newyork-proxy.acme.lan:9443 \
    --broker-url https://broker.acme.lan:8443
```

Copy the printed admin secret to your scratchpad. The broker CA is again
fetched from `https://broker.acme.lan:8443/v1/.well-known/broker-ca.pem`.

### 3.2 Log into the proxy dashboard

Open `https://newyork-proxy.acme.lan:9443/proxy/login`.

### 3.3 Fill the Setup wizard

**Step 1 — Broker Connection**

- **Broker URL**: `https://broker.acme.lan:8443`
- **Invite Token**: the `newyork-site` token you generated in 1.4

**Step 2 — Organization + CA**

- **Organization ID**: `newyork`
- **Display Name**: `New York Site`
- **Contact Email**: e.g. `it-ny@acme.lan`
- **Webhook URL**: leave blank (built-in PDP)
- **Organization Certificate Authority**: **Generate new (RSA-4096)**

**Step 3 — Vault**: leave unchecked.

**Step 4**: Click **Register on Broker**.

### 3.4 Approve the org from VM1

VM1 broker dashboard → **Orgs** → click `newyork` → **Approve**.

### 3.5 Create the `checker` agent

VM3 → **Agents** → **New agent**:

- **Agent name**: `checker`
- **Capabilities**: `order.check`

Submit.

### 3.6 Approve the binding from VM1

VM1 broker dashboard → **Bindings** → approve `newyork::checker`.

### 3.7 Download the agent's env file

VM3 → `/proxy/agents/checker` → **Download env file** → save as
`/opt/cullis/env.checker` on VM3:

```
CULLIS_AGENT_ID=newyork::checker
CULLIS_API_KEY=sk_local_xxxxxxxxxxxxxxxxxxxxx
CULLIS_PROXY_URL=https://newyork-proxy.acme.lan:9443
CULLIS_BROKER_CA_PATH=./certs/broker-ca.pem
```

You now have every piece needed to run the end-to-end demo.

---

## Part 4 — Fire the conversation

### 4.1 Start the checker daemon on VM3

On VM3, load the checker env file and start the daemon in the foreground
of a dedicated terminal (so you can watch messages land in real time):

```bash
ssh operator@newyork-proxy.acme.lan
cd /opt/cullis
set -a && source env.checker && set +a
python scripts/demo/checker.py
```

Intended behavior: the script reads `CULLIS_AGENT_ID`, `CULLIS_API_KEY`,
`CULLIS_PROXY_URL`, and `CULLIS_BROKER_CA_PATH` from the environment,
connects to the local proxy's egress API over HTTPS (validating the nginx
self-signed cert against the broker CA pem), and starts polling for
incoming sessions every second. First line of output should be:

```
[newyork::checker] checker daemon started, polling https://newyork-proxy.acme.lan:9443 every 1.0s
```

Leave this terminal open — it is your "inbox tail" for the rest of the
demo.

> **Known gap:** at the time this runbook was written, `checker.py` in
> `scripts/demo/` still had its proxy URL hard-coded to
> `http://localhost:9801` and loaded agent ids from
> `scripts/demo/.state.json`. The behavior described above is the
> intended post-refactor shape. See [Known gaps](#known-gaps) at the end
> for the concrete TODO.

### 4.2 Send one message from VM2

On VM2, in a second terminal:

```bash
ssh operator@milan-proxy.acme.lan
cd /opt/cullis
set -a && source env.sender && set +a
python scripts/demo/sender.py --target newyork::checker
```

Expected output on the sender side (4 lines):

```
[milan::sender] opening session to newyork::checker (capability 'order.check')
[milan::sender] session_id = 7a3c8b12-...
[milan::sender] session is active
[milan::sender] message routed through the broker — done
```

Expected output on the checker terminal (1 new line):

```
[newyork::checker] received from milan::sender (seq 0): {"check": "ok"}
```

If you see those lines on both sides, you have proved the full
cross-VM path: TLS handshake from VM2 to VM1 with a valid SAN,
x509-backed DPoP auth from the Milan proxy to the broker, session
creation on the broker, **PDP webhook callback from VM1 back to VM2 and
VM3 over HTTPS 9443**, both orgs' PDPs returning `allow`, the broker
forwarding the E2E-encrypted payload to VM3, and the New York proxy
decrypting and handing it to the checker agent. That is the architecture
diagram from the README running on real network boundaries.

Run `sender.py` a few more times — each invocation opens a fresh
session, the checker auto-accepts, and one new line prints on the
checker terminal.

### 4.3 Cross-check the audit log

On VM1, open the broker dashboard → **Audit** (`/dashboard/audit`). For
each session you should see a chain of events like:

```
onboarding.join_ok         milan
onboarding.approved        milan
registry.agent_registered  milan::sender
binding.approved           milan::sender
onboarding.join_ok         newyork
onboarding.approved        newyork
registry.agent_registered  newyork::checker
binding.approved           newyork::checker
broker.session_created     milan::sender → newyork::checker
policy.session_allowed     milan::sender → newyork::checker
broker.message_forwarded   milan::sender → newyork::checker  (seq 0)
```

Each row has a SHA-256 hash linked to the previous row — the
**Verify Hash Chain** button on the audit page recomputes the whole chain
and will flash green if nothing has been tampered with. This is worth
showing live; it is the one piece of the stack that is genuinely
hard to fake.

---

## Troubleshooting

Real failures you will hit, in order of likelihood:

### `HTTP 401 {"detail": "Invalid DPoP proof: htu mismatch"}`

`BROKER_PUBLIC_URL` does not match the URL the proxy is calling. The
broker expects `htu` to equal whatever is in `BROKER_PUBLIC_URL`. Check
it on VM1:

```bash
docker exec cullis-broker-1 env | grep BROKER_PUBLIC
```

If it says `https://localhost:8443` you forgot to pass `--public-url` to
the deploy script. Re-run:

```bash
./deploy_broker.sh --dev --public-url https://broker.acme.lan:8443
```

(The script is idempotent — existing PKI and `.env` are preserved except
for the `BROKER_PUBLIC_URL` line.)

### `SSL: CERTIFICATE_VERIFY_FAILED` on proxy → broker calls

The proxy did not fetch `broker-ca.pem` successfully, so it has no
trust anchor for the broker's self-signed cert. Verify:

```bash
# on VM2 or VM3
ls -la certs/broker-ca.pem
openssl x509 -noout -in certs/broker-ca.pem -subject -issuer
# → subject= /CN=Cullis Root CA/O=Cullis
```

If the file is missing or empty, use the `scp` fallback from 1.5:

```bash
scp operator@broker.acme.lan:/opt/cullis/certs/broker-ca.pem \
    ./certs/broker-ca.pem
./deploy_proxy.sh --dev \
    --public-url https://milan-proxy.acme.lan:9443 \
    --broker-url https://broker.acme.lan:8443
```

If it exists but the subject is wrong, you have a stale file from a
previous run — delete it and re-run the deploy script to re-fetch.

### `502 Bad Gateway` from the proxy dashboard

Nginx is up but the `mcp-proxy` container behind it is not healthy.

```bash
docker compose -f docker-compose.proxy.yml ps
docker compose -f docker-compose.proxy.yml logs mcp-proxy | tail -50
```

Most common root causes:

- The proxy cannot reach its own Vault container (check the `vault`
  service logs and that `VAULT_ADDR` in `proxy.env` points at the right
  internal hostname).
- The proxy crashed at startup because `certs/broker-ca.pem` exists but
  is not a valid PEM file — the new `mcp_proxy/auth/broker_http.py`
  validates it at module import and will log a parse error.
- A migration failure — check for `alembic` errors near the top of the
  log.

### `Vault is sealed` on any VM

You should not see this message on any VM in this runbook. The dev
profile runs Vault with `server -dev`, which starts unsealed with a
fixed root token. If you see "sealed", someone (you, probably) started
Vault in server mode instead. Run
`docker compose -f docker-compose.proxy.yml down -v` (on the proxy VMs)
or `docker compose down -v` (on the broker VM) and re-run the deploy
script — this will destroy the dev Vault data, which is fine because it
is ephemeral anyway.

### Broker session stuck in `pending`, checker never sees it

The broker could not reach the proxy's PDP webhook. From VM1:

```bash
docker exec cullis-broker-1 \
    curl -kfI https://milan-proxy.acme.lan:9443/pdp/policy
```

Expected: 405 Method Not Allowed (the endpoint takes POST, not HEAD) —
that means the network path works. If you get a connection timeout or a
TLS error, VM1 cannot reach VM2 on port 9443. Check:

- Firewall rules on VM2 (does anything on VM1's subnet have ingress to
  9443?)
- NAT / VPN routing
- `broker-ca.pem` on VM1 — wait, the broker does **not** need to trust
  the proxy's cert for the PDP call. The PDP webhook TLS context uses a
  looser verification path in the dev profile (the proxy's cert is
  self-signed by the local nginx, not by the broker CA). If you still
  see TLS errors, check the broker logs for the raw exception.

### `Org still pending` after clicking Approve on the broker dashboard

Sometimes the dashboard UI races ahead of the DB commit and shows stale
data. Hit the raw API from inside the proxy container:

```bash
docker exec -it cullis-mcp-proxy-1 \
    curl -k https://broker.acme.lan:8443/v1/registry/orgs/me \
    -H "X-Org-Secret: $(grep ORG_SECRET proxy.env | cut -d= -f2)" \
    -H "X-Org-Id: milan"
```

If the JSON says `"status": "active"` you're fine — refresh the proxy
dashboard. If it still says `"status": "pending"`, the approval never
committed on the broker side; go back to VM1 and try again, then check
the broker's audit log for `org.approved` on `milan`.

### The demo scripts can't find their env / target

See [Known gaps](#known-gaps) below — at the time of writing, `sender.py`
and `checker.py` don't yet accept CLI flags or read from env files.

---

## Security caveats

Everything below is **by design** for the dev profile, and **not safe for
production**. Read this list before showing the demo to anyone who is
going to ask pointed questions.

- **Self-signed TLS certs everywhere.** The broker cert is self-signed by
  its own CA, each proxy cert is self-signed by nginx, and no browser or
  SDK outside this three-VM island will trust any of them without manual
  exceptions. Fine for a demo — not fine for anything else.

- **Vault runs in dev mode.** Each VM's Vault container starts with
  `-dev`, which means an in-memory storage backend, a fixed root token
  (`dev-root-token`), and **no persistence**. If any container restarts,
  all secrets in that Vault instance are gone. The broker will fail to
  sign tokens until you re-run `deploy_broker.sh --dev` (which will
  regenerate a fresh CA and invalidate every existing agent cert).

- **Broker CA private key lives in Vault only — if the upload
  succeeded.** The deploy script ends with a red CRITICAL warning if the
  Vault load step failed. If you saw that warning, the key is still in
  `certs/broker-ca-key.pem` on disk. Fix the Vault upload and re-run the
  script before doing anything else.

- **`GET /v1/.well-known/broker-ca.pem` is unauthenticated.** CA certs
  are public information by design (the whole point of a CA cert is that
  everyone has it), but the endpoint being open is a choice worth
  documenting. Anyone who can reach the broker can download the public
  CA cert. They cannot sign with it; they can only verify things signed
  by it.

- **SPIFFE trust_domain defaults to `atn.local`.** All three VMs must
  agree on this value — `TRUST_DOMAIN` in each `.env` and in each
  `proxy.env`. Changing it after bootstrap will invalidate every
  existing agent certificate because the SPIFFE SAN is derived from it.
  If you need to change it, `deploy_broker.sh --dev` again on VM1 and
  re-register both orgs.

- **The PDP webhook endpoint is reachable from the broker without
  client-side TLS auth.** In production the broker should present a
  client cert signed by a trust anchor the proxy pins. In dev mode the
  callback is just HTTPS with no client cert. A motivated attacker on
  the broker VM's network segment could spoof policy decisions. Not
  acceptable in production.

- **`KMS_BACKEND=vault` on the broker means a broker restart without
  Vault is fatal.** The broker reads the CA private key at startup via
  `VaultKMSProvider`. If Vault is down, or the root token has been
  rotated, the broker will not start. In the dev profile this is a
  bootstrap-once-and-forget situation; in production you want a proper
  Vault cluster with unseal, HA, and auth methods other than a root
  token.

---

## Known gaps

What is **not yet implemented** at the time this runbook is being
written, cross-referenced against the other new pieces landing in
parallel:

1. **`sender.py` and `checker.py` do not yet read CLI flags or env
   files.** Today both scripts hardcode `http://localhost:9800` /
   `http://localhost:9801` and read agent ids from
   `scripts/demo/.state.json` (which only `deploy_demo.sh up` writes).
   Part 4 of this runbook describes the **intended** post-refactor
   shape: flags like `--target newyork::checker` on `sender.py`, and
   `CULLIS_AGENT_ID` / `CULLIS_API_KEY` / `CULLIS_PROXY_URL` /
   `CULLIS_BROKER_CA_PATH` read from the environment (populated by
   `source env.sender`). Until those land, you can still run Part 4 by
   hand-editing the two scripts for the multi-VM URLs.

2. **`deploy_proxy.sh --dev` with `--public-url` and `--broker-url`.**
   Implemented in parallel by Agent C. Until it lands, the manual path
   is: set `BROKER_URL`, `PROXY_PUBLIC_URL` in `proxy.env` by hand, run
   `./deploy_proxy.sh` (no flags), and fetch `broker-ca.pem` yourself
   via `curl -k https://broker.acme.lan:8443/v1/.well-known/broker-ca.pem -o certs/broker-ca.pem`.

3. **`deploy_broker.sh --public-url <URL>` in dev mode.** Implemented in
   parallel by Agent A. Until it lands, edit
   `BROKER_PUBLIC_URL=https://broker.acme.lan:8443` in `.env` by hand
   after the first `deploy_broker.sh --dev` run, then
   `docker compose restart broker` and regenerate the self-signed cert
   with the right SAN manually (`openssl req -x509 ... -addext
   "subjectAltName=DNS:broker.acme.lan,IP:127.0.0.1"`).

4. **`mcp_proxy/auth/broker_http.py`.** New module that centralizes
   every HTTP call the proxy makes to the broker, using
   `certs/broker-ca.pem` as the TLS verify anchor. Previously some
   call sites used `verify=False`. Until this module lands, you may hit
   `verify=False` on paths other than the egress (registration,
   discovery, heartbeats).

5. **`GET /v1/.well-known/broker-ca.pem`.** New broker endpoint that
   publishes the CA public cert. Until it lands, use the `scp` fallback
   (1.5) for every proxy VM.

6. **"Download env file" button on the agent detail page.** The proxy
   dashboard does not yet expose a one-click download. Until it lands,
   build `env.sender` / `env.checker` by hand from the values you see
   on `/proxy/agents/<name>`.

When all six gaps above are closed, this runbook should run as written
end-to-end. File an issue if any step diverges.

---

## Tear down

On each VM, in any order:

```bash
# VM2 and VM3
docker compose -f docker-compose.proxy.yml down -v

# VM1
docker compose down -v
```

`-v` removes the named volumes, which is what you want for a clean
re-run (the dev Vault data is ephemeral anyway). To keep the Postgres
data between runs, drop the `-v`.

Nothing on the host needs uninstalling — Cullis in the dev profile is
entirely containerized. Removing `/opt/cullis` and the Docker images
(`docker image prune -a`) is sufficient to leave no trace.

---

## Where to go next

- [`docs/ops-runbook.md`](ops-runbook.md) — production operations, TLS
  profiles, Let's Encrypt, BYOCA, backup, monitoring.
- [`scripts/demo/README.md`](../scripts/demo/README.md) — the single-host
  scripted equivalent of this runbook. If you want to show the same
  flow without three VMs, that is where to start.
- [`enterprise-kit/`](../enterprise-kit/) — BYOCA guide, OPA policy
  bundles, Prometheus alerts, PDP webhook template.
- [`deploy/helm/cullis/`](../deploy/helm/cullis/) — Kubernetes chart,
  for when the three VMs turn into three Kubernetes namespaces.
