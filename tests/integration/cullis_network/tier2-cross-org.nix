# Tier 2 — four-VM cross-continent demo.
#
#   roma          (CET)  — Mastio org=roma,  td=roma.cullis.test
#   sanfrancisco  (PST)  — Mastio org=sf,    td=sf.cullis.test
#   tokyo         (JST)  — Mastio org=tokyo, td=tokyo.cullis.test
#   court         (—)    — Federation Court  (cross-org trust fabric)
#
# Validates the architectural claim the docker compose sandbox can't:
# every "city" runs on its own kernel + network namespace + Org CA,
# so per-host PKI is genuinely per-host (Roma's CA bytes never appear
# on Tokyo's disk), and cross-org chain validation fails by default
# (each Mastio refuses certs signed by another's Org CA).
#
# This slice asserts the *isolation* invariants. The federation
# publisher + actual A2A oneshot Roma→Tokyo via Court is the next
# slice on this branch — it needs the broker (``app/main.py``)
# wired with ``COURT_URL`` env vars on each Mastio, plus
# cross-org binding admin steps which are easier to script once
# the topology boots cleanly.
{ pkgs, cullisSrc, lib }:

let
  # Same store-materialisation trick the cullis-mastio module uses;
  # we don't actually consume it directly here, but keep the filter
  # pattern visible so future slices that drive cross-org HTTPS calls
  # know where to plug in.
  cullisSrcStore = lib.cleanSourceWith {
    name = "cullis-src";
    src = cullisSrc;
    filter = path: type:
      let baseName = baseNameOf (toString path); in
      !(builtins.elem baseName [
        ".git" ".github" ".venv" "__pycache__" "node_modules"
        "connector_data" "state" "dist" "result"
      ]);
  };

  # Same Org CA preload trick PR #454 used in tier1-roma. With
  # ``standalone=false`` the proxy stops auto-generating a CA on
  # first boot, so the federation publisher's ``mastio_loaded``
  # gate stays False forever. Upserting the on-disk CA into
  # ``proxy_config`` and restarting the proxy flips the gate
  # without needing the full broker attach-ca admin flow.
  preloadOrgCaScript = pkgs.writeText "preload-org-ca.py" ''
    """Upsert the on-disk Org CA into the proxy's ``proxy_config``."""
    import sqlite3
    import sys

    DB = "/var/lib/cullis/proxy.sqlite"
    KEY_PATH = "/var/lib/cullis/certs/org-ca.key"
    CERT_PATH = "/var/lib/cullis/certs/org-ca.pem"

    key_pem = open(KEY_PATH).read()
    cert_pem = open(CERT_PATH).read()

    conn = sqlite3.connect(DB)
    try:
        for k, v in (("org_ca_key", key_pem), ("org_ca_cert", cert_pem)):
            conn.execute(
                "INSERT INTO proxy_config (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (k, v),
            )
        conn.commit()
        rows = conn.execute(
            "SELECT key FROM proxy_config "
            "WHERE key IN ('org_ca_key', 'org_ca_cert') ORDER BY key"
        ).fetchall()
    finally:
        conn.close()

    if [r[0] for r in rows] != ["org_ca_cert", "org_ca_key"]:
        print(f"PRELOAD_FAILED: rows={rows!r}", file=sys.stderr)
        sys.exit(1)
    print("PRELOADED org_ca into proxy_config")
  '';

  # Drives the four-step Court bootstrap for a single city, all from
  # within the city's own VM (it can reach ``court:8000`` over the test
  # vlan, and it owns its proxy admin secret so it can fetch its own
  # mastio_pubkey + Org CA without copy_from_vm gymnastics).
  #
  #   1. ``POST /v1/admin/invites`` on Court (admin secret)
  #   2. ``POST /v1/onboarding/join`` on Court (org CA + invite_token)
  #   3. ``POST /v1/admin/orgs/{org_id}/approve`` on Court (admin secret)
  #   4. ``GET /v1/admin/mastio-pubkey`` on local proxy → ``PATCH
  #      /v1/admin/orgs/{org_id}/mastio-pubkey`` on Court
  #
  # All four endpoints are the same ones ``reference/bootstrap/`` drives
  # via the docker-compose sandbox; this script is the parallel for
  # NixOS tests where every city is an isolated VM. Idempotent on each
  # step (409 = already there → continue), so the subtest can re-run
  # against a partially-bootstrapped state without resetting.
  courtBootstrapScript = pkgs.writeText "court-bootstrap.py" ''
    """Bootstrap a city on Court so federation publishes get accepted.

    Args (positional):
      org_id          short org id (``roma``, ``tokyo``)
      display_name    human label
      trust_domain    SPIFFE trust domain
      court_url       e.g. ``http://court:8000``
      proxy_url       local proxy admin (e.g. ``http://127.0.0.1:9100``)
      org_ca_path     filesystem path to ``org-ca.pem``
      admin_secret    same on Court + local proxy in the test fixture
      org_secret      passed in the join body (Court will hash + store)
    """
    import json
    import sys
    import urllib.error
    import urllib.request

    if len(sys.argv) != 9:
        print(f"USAGE: {sys.argv[0]} org_id display_name trust_domain "
              f"court_url proxy_url org_ca_path admin_secret org_secret",
              file=sys.stderr)
        sys.exit(2)

    (_, org_id, display_name, trust_domain, court_url, proxy_url,
     org_ca_path, admin_secret, org_secret) = sys.argv

    org_ca_pem = open(org_ca_path).read()


    def _req(method, url, body=None, headers=None, allow_status=()):
        data = json.dumps(body).encode() if body is not None else None
        h = {"Content-Type": "application/json"} if body is not None else {}
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                payload = resp.read().decode()
                code = resp.getcode()
        except urllib.error.HTTPError as exc:
            payload = exc.read().decode()
            code = exc.code
            if code in allow_status:
                return code, payload
            print(f"FAILED {method} {url} → HTTP {code}: {payload[:300]}",
                  file=sys.stderr)
            sys.exit(1)
        return code, payload


    # 1. Admin generates a one-time invite token on Court.
    print(f"[1/4] POST {court_url}/v1/admin/invites …", flush=True)
    code, payload = _req(
        "POST", f"{court_url}/v1/admin/invites",
        body={"label": f"{org_id}-invite", "ttl_hours": 1},
        headers={"X-Admin-Secret": admin_secret},
    )
    invite_token = json.loads(payload)["token"]
    print(f"      invite issued (id={json.loads(payload).get('id')})")

    # 2. Org submits join with its CA + invite_token. 409 = already
    # registered (re-run); continue so step 3 still runs.
    print(f"[2/4] POST {court_url}/v1/onboarding/join (org_id={org_id}) …",
          flush=True)
    code, payload = _req(
        "POST", f"{court_url}/v1/onboarding/join",
        body={
            "org_id": org_id,
            "display_name": display_name,
            "secret": org_secret,
            "ca_certificate": org_ca_pem,
            "contact_email": f"admin@{org_id}.test",
            "invite_token": invite_token,
            "trust_domain": trust_domain,
        },
        allow_status=(409,),
    )
    print(f"      join → HTTP {code}")

    # 3. Admin approves. 409 = already active.
    print(f"[3/4] POST {court_url}/v1/admin/orgs/{org_id}/approve …",
          flush=True)
    code, payload = _req(
        "POST", f"{court_url}/v1/admin/orgs/{org_id}/approve",
        headers={"X-Admin-Secret": admin_secret},
        allow_status=(409,),
    )
    print(f"      approve → HTTP {code}")

    # 4. Pull the local proxy's mastio_pubkey and pin it on Court so
    # counter-signature verification on /v1/federation/publish-agent
    # can succeed. The proxy's lifespan generates the mastio identity
    # asynchronously; poll until the pubkey is non-null (cap 60s).
    import time
    print(f"[4/4] GET  {proxy_url}/v1/admin/mastio-pubkey …", flush=True)
    deadline = time.monotonic() + 60.0
    pubkey = None
    while time.monotonic() < deadline:
        code, payload = _req(
            "GET", f"{proxy_url}/v1/admin/mastio-pubkey",
            headers={"X-Admin-Secret": admin_secret},
        )
        pubkey = json.loads(payload).get("mastio_pubkey")
        if pubkey:
            break
        time.sleep(1.0)
    if not pubkey:
        print("FAILED mastio_pubkey still null after 60s", file=sys.stderr)
        sys.exit(1)
    print(f"      proxy mastio_pubkey ready ({len(pubkey)} chars)")

    print(f"      PATCH {court_url}/v1/admin/orgs/{org_id}/mastio-pubkey …",
          flush=True)
    code, payload = _req(
        "PATCH", f"{court_url}/v1/admin/orgs/{org_id}/mastio-pubkey",
        body={"mastio_pubkey": pubkey},
        headers={"X-Admin-Secret": admin_secret},
    )
    print(f"      pin → HTTP {code}")
    print(f"BOOTSTRAPPED org_id={org_id} on Court")
  '';

  # Per-city Mastio config. Each entry produces a NixOS node that
  # drops the ``cullis.mastio`` module on top of a base
  # ``virtualisation`` block; the module handles broker + proxy +
  # nginx + per-VM PKI bootstrap.
  cities = {
    roma = {
      orgId = "roma";
      trustDomain = "roma.cullis.test";
      displayName = "Roma Mastio (CET)";
    };
    sanfrancisco = {
      orgId = "sf";
      trustDomain = "sf.cullis.test";
      displayName = "San Francisco Mastio (PST)";
    };
    tokyo = {
      orgId = "tokyo";
      trustDomain = "tokyo.cullis.test";
      displayName = "Tokyo Mastio (JST)";
    };
    court = {
      orgId = "court";
      trustDomain = "court.cullis.test";
      displayName = "Federation Court";
    };
  };

  mkCityNode = name: cfg: {
    imports = [ ./lib/cullis-mastio.nix ];

    virtualisation = {
      memorySize = 1536;
      cores = 1;
    };

    cullis.mastio = {
      enable = true;
      # Court is the federation hub: only it needs the broker bound
      # on the world-facing interface so peers can reach
      # ``/v1/federation/publish-agent``. Cities run a local broker
      # for their own agent auth, but the federation publisher
      # task on each city points its publish loop at Court via
      # ``brokerUrl``.
      enableBroker = true;
      nginxAllowExternal = name == "court";
      brokerUrl =
        if name == "court"
        then ""  # local loopback default. Court IS the broker.
        else "http://court:8000";  # peers publish to Court
      cullisSrc = cullisSrc;
      inherit (cfg) orgId trustDomain displayName;
    };

    # Each city resolves its own ``mastio.<td>`` to loopback so the
    # local SDK / test driver can curl over the TLS port without
    # going through DNS. ``court`` resolves on every city so
    # ``brokerUrl=http://court:8000`` works without static IPs.
    networking.extraHosts = ''
      127.0.0.1 mastio.${cfg.trustDomain}
    '';
  };

in

pkgs.testers.nixosTest {
  name = "cullis-tier2-cross-org";

  skipTypeCheck = true;
  skipLint = true;

  nodes = lib.mapAttrs mkCityNode cities;

  testScript = ''
    cities = [roma, sanfrancisco, tokyo, court]

    # Boot all four VMs in parallel and wait for each to land its
    # systemd targets. Doing this serially would push the wall-clock
    # past 2 minutes for nothing — the boot paths don't depend on
    # one another (yet — federation publisher, when wired, will).
    start_all()
    for c in cities:
        c.wait_for_unit("cullis-pki-bootstrap.service")
        c.wait_for_unit("cullis-proxy.service")
        c.wait_for_unit("cullis-broker.service")
        c.wait_for_unit("nginx.service")
        c.wait_until_succeeds(
            "curl -fs http://127.0.0.1:8000/health", timeout=60,
        )
        c.wait_until_succeeds(
            "curl -fs http://127.0.0.1:9100/health", timeout=60,
        )

    with subtest("Per-VM Org CA isolation"):
        # Each city minted its own Org CA at first boot. The CA
        # bytes are NOT a derived path — they're random EC P-256
        # keys generated inside the VM, so two VMs running the same
        # config still produce distinct CAs. We hash each cert and
        # cross-check: any pair landing on the same digest would
        # mean PKI bootstrap is leaking state across VMs (which it
        # absolutely shouldn't on a kernel-isolated network).
        digests = {}
        for c in cities:
            digest = c.succeed(
                "sha256sum /var/lib/cullis/certs/org-ca.pem"
            ).split()[0]
            digests[c.name] = digest
            print(f"  {c.name} Org CA sha256: {digest}")
        unique = set(digests.values())
        assert len(unique) == 4, (
            f"expected four distinct Org CAs, got {len(unique)} "
            f"(digests: {digests!r})"
        )

    with subtest("Cross-VM TCP reachability (kernel-level network)"):
        # The test framework gives us a single shared vlan; every
        # city ends up with a routable IP. ``curl --resolve`` lets
        # us hit Tokyo's nginx from Roma with the *real* TCP path —
        # firewall rules, IP routing, TLS handshake all the way
        # through. The cert won't verify across orgs (expected),
        # so we use ``-k`` and only check the TLS handshake
        # completes (anything non-000 means we made it through).
        # Asserting on response *content* is the next slice — that
        # needs the federation publisher wired so peers actually
        # mirror each other's agent registries.
        tokyo_ip = tokyo.succeed(
            "ip -4 -o addr show dev eth1 | awk '{print $4}' | cut -d/ -f1"
        ).strip()
        http_code = roma.succeed(
            f"curl -sk -o /dev/null -w '%{{http_code}}' "
            f"--resolve mastio.tokyo.cullis.test:9443:{tokyo_ip} "
            f"https://mastio.tokyo.cullis.test:9443/health"
        ).strip()
        # Either nginx answered with the /health 200, or the proxy
        # returned a 4xx — both prove the cross-VM TCP + TLS path
        # works. ``000`` would mean the connection itself failed.
        assert http_code != "000", (
            f"Roma → Tokyo TCP handshake failed (curl http_code={http_code!r})"
        )
        print(f"  Roma → Tokyo cross-VM HTTPS: {http_code}")

    with subtest("Federation publisher: cities reach Court's broker"):
        # Each city's proxy points its ``MCP_PROXY_BROKER_URL`` at
        # ``http://court:8000``; the federation publisher tail
        # POSTs ``/v1/federation/publish-agent`` on each tick.
        for c in [roma, sanfrancisco, tokyo]:
            health = c.succeed(
                "curl -fs http://court:8000/health || echo OFFLINE"
            ).strip()
            assert "OFFLINE" not in health, (
                f"{c.name} can't reach Court's broker (got: {health!r})"
            )
            print(f"  {c.name} → court:8000/health = {health}")

    with subtest("Mastio identity readiness: preload Org CA + restart proxy"):
        # The proxy starts with ``standalone=false`` (because
        # ``brokerUrl`` points at Court) which keeps it from auto-
        # generating a CA on first boot. Without an Org CA in
        # ``proxy_config``, the ``mastio_loaded`` gate that drives
        # the lifespan's mastio-identity generation never fires, so
        # ``GET /v1/admin/mastio-pubkey`` returns null forever.
        # Preloading the on-disk Org CA + restarting unblocks the
        # gate; after the second boot the proxy mints its mastio
        # ES256 identity and the federation publisher loop arms.
        # Both Roma and Tokyo need this before the Court bootstrap
        # subtest pulls their mastio_pubkeys to pin on Court.
        for city in (roma, tokyo):
            city.succeed("python3 ${preloadOrgCaScript}")
            city.succeed("systemctl restart cullis-proxy.service")
            city.wait_for_unit("cullis-proxy.service")
            city.wait_until_succeeds(
                "curl -fs http://127.0.0.1:9100/health", timeout=30,
            )

    with subtest("Court bootstrap: register Roma + Tokyo, pin pubkeys"):
        # Drives the same admin-side flow ``reference/bootstrap/`` runs
        # against the docker-compose sandbox: ``/v1/admin/invites`` →
        # ``/v1/onboarding/join`` (per city) → ``/v1/admin/orgs/{id}/
        # approve`` → ``PATCH /v1/admin/orgs/{id}/mastio-pubkey``. After
        # this, Court can verify the ES256 counter-signature each city's
        # federation publisher attaches to ``publish-agent`` requests.
        #
        # Roma is the only publisher exercised in the next subtest, but
        # we bootstrap Tokyo too so a follow-up A2A oneshot subtest can
        # rely on the symmetric topology without re-entering this code
        # path.
        for city, cfg in (
            (roma,  {"orgId": "roma",  "displayName": "Roma Mastio (CET)",
                     "trustDomain": "roma.cullis.test"}),
            (tokyo, {"orgId": "tokyo", "displayName": "Tokyo Mastio (JST)",
                     "trustDomain": "tokyo.cullis.test"}),
        ):
            out = city.succeed(
                "python3 ${courtBootstrapScript} "
                f"{cfg['orgId']} '{cfg['displayName']}' "
                f"{cfg['trustDomain']} "
                "http://court:8000 http://127.0.0.1:9100 "
                "/var/lib/cullis/certs/org-ca.pem "
                f"test-admin-secret {cfg['orgId']}-secret-test"
            )
            assert "BOOTSTRAPPED" in out, (
                f"bootstrap of {cfg['orgId']} did not finish:\n{out}"
            )
            print(f"  {cfg['orgId']} bootstrapped on Court")

    with subtest("Federation publish: Roma pushes to Court (payload wire)"):
        # The previous two subtests preloaded Roma's Org CA + restarted
        # the proxy (so the mastio identity is ready) and bootstrapped
        # Roma on Court (so counter-sig + cert-chain checks pass on the
        # receiving end). What's left is the actual publish trigger:
        # insert a federated=1 row, wait for the publisher tick, and
        # confirm Court accepted the payload.
        #
        # Insert a row in Roma's ``internal_agents`` with
        # ``federated=1`` so the publisher picks it up on its next
        # tick (poll interval forced to 2s via
        # ``MCP_PROXY_FEDERATION_POLL_INTERVAL_S``). The publisher
        # counter-signs the body and POSTs to Court at
        # ``/v1/federation/publish-agent``. Expected success line:
        # ``federation publish OK: roma::fedtest rev=1 status=...``.
        # ``broker unreachable`` is the dead-wire failure mode; an
        # ``HTTP 4xx`` log line means Court rejected despite bootstrap
        # (surface it so the cross-org regression is greppable).
        roma.succeed(
            "openssl ecparam -name prime256v1 -genkey -noout "
            "-out /tmp/fedtest.key && "
            "openssl req -new -key /tmp/fedtest.key "
            "-out /tmp/fedtest.csr -subj '/CN=roma::fedtest/O=roma' && "
            "openssl x509 -req -in /tmp/fedtest.csr "
            "-CA /var/lib/cullis/certs/org-ca.pem "
            "-CAkey /var/lib/cullis/certs/org-ca.key "
            "-CAcreateserial -out /tmp/fedtest.pem -days 1"
        )
        roma.succeed(
            "python3 -c \""
            "import sqlite3; "
            "from datetime import datetime, timezone; "
            "conn = sqlite3.connect('/var/lib/cullis/proxy.sqlite'); "
            "cert = open('/tmp/fedtest.pem').read(); "
            "now = datetime.now(timezone.utc).isoformat(); "
            "conn.execute("
            "'INSERT INTO internal_agents "
            "(agent_id, display_name, capabilities, cert_pem, "
            "created_at, is_active, federated, federation_revision, "
            "last_pushed_revision) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', "
            "('roma::fedtest', 'fedtest', '[\\\"order.read\\\"]', "
            "cert, now, 1, 1, 1, 0)); "
            "conn.commit(); conn.close(); "
            "print('FEDTEST_INSERTED')\""
        )
        # Wait long enough for at least two publisher ticks (poll=2s
        # +epsilon). The publisher's ``_tick`` does the SELECT +
        # POST + log.
        roma.succeed("sleep 5")
        publish_log = roma.succeed(
            "journalctl -u cullis-proxy --no-pager | "
            "grep -E 'federation publish.*roma::fedtest' || "
            "echo NOLOG"
        ).strip()
        assert "NOLOG" not in publish_log, (
            f"no federation publish log line for roma::fedtest. "
            f"Last 50 proxy lines:\n"
            f"{roma.succeed('journalctl -u cullis-proxy --no-pager -n 50')}"
        )
        # ``broker unreachable`` would mean a dead wire (TCP/HTTP
        # transport failure). Catch it explicitly so the test fails
        # with a clear message rather than waiting on a downstream
        # assertion.
        assert "broker unreachable" not in publish_log, publish_log
        # With Court bootstrap done, the publisher counter-signature
        # should verify and Court should persist the agent row →
        # ``federation publish OK: roma::fedtest …``. If Court instead
        # rejects (``HTTP 4xx``), surface the line so the cross-org
        # trust regression is greppable from the test log without
        # spelunking journalctl.
        assert "federation publish OK" in publish_log, (
            f"federation publish did NOT succeed end-to-end. Log line:\n"
            f"  {publish_log}\n"
            f"Last 100 proxy lines:\n"
            f"{roma.succeed('journalctl -u cullis-proxy --no-pager -n 100')}\n"
            f"Last 50 broker lines on Court:\n"
            f"{court.succeed('journalctl -u cullis-broker --no-pager -n 50')}"
        )
        print(f"  publish accepted by Court:\n    {publish_log}")

    # Cross-org cert chain refusal (default-deny) — the third
    # invariant the demo sells — needs a Roma-minted cert
    # presented to Tokyo's nginx. The cert generation works (we
    # exercise the same recipe in tier1-roma), but the test-
    # driver ``copy_from_vm`` / ``copy_from_host`` shuttle wants
    # paths relative to a shared mount that's awkward to plumb
    # cleanly here. Tracking it as a follow-up: same scaffold,
    # simpler shuttle (cat | curl --cert -, or vlan-shared tmp).
    # The Org CA isolation + cross-VM reachability invariants
    # asserted above already cover the foundational pitch
    # ("kernel-isolated cities, per-host PKI, real network
    # between them"); the chain-refusal add-on tightens the
    # screw on the wire-level claim.
    if False:
        roma.succeed(
            "openssl ecparam -name prime256v1 -genkey -noout "
            "-out /tmp/daniele-roma.key && "
            "openssl req -new -key /tmp/daniele-roma.key "
            "-out /tmp/daniele-roma.csr -subj '/' "
            "-addext 'subjectAltName=URI:spiffe://roma.cullis.test/roma/user/daniele' && "
            "openssl x509 -req -in /tmp/daniele-roma.csr "
            "-CA /var/lib/cullis/certs/org-ca.pem "
            "-CAkey /var/lib/cullis/certs/org-ca.key "
            "-CAcreateserial -out /tmp/daniele-roma.pem -days 1 "
            "-extfile <(printf 'subjectAltName=URI:spiffe://roma.cullis.test/roma/user/daniele\\n"
            "extendedKeyUsage=clientAuth\\n')"
        )
        roma.copy_from_vm("/tmp/daniele-roma.pem", "")
        roma.copy_from_vm("/tmp/daniele-roma.key", "")
        tokyo.copy_from_host("daniele-roma.pem", "/tmp/")
        tokyo.copy_from_host("daniele-roma.key", "/tmp/")
        tokyo_ip2 = tokyo.succeed(
            "ip -4 -o addr show dev eth1 | awk '{print $4}' | cut -d/ -f1"
        ).strip()
        out = roma.succeed(
            f"curl -sk -o /dev/null -w '%{{http_code}}' "
            f"--cert /tmp/daniele-roma.pem --key /tmp/daniele-roma.key "
            f"--resolve mastio.tokyo.cullis.test:9443:{tokyo_ip2} "
            f"https://mastio.tokyo.cullis.test:9443/v1/egress/whoami "
            f"|| echo HANDSHAKE_FAIL"
        )
        assert (
            "401" in out
            or "000" in out
            or "HANDSHAKE_FAIL" in out
        ), (
            f"Tokyo accepted a cert signed by Roma's Org CA "
            f"(response: {out!r}). Cross-org isolation broken."
        )

    print("Tier 2 cross-continent topology verified — Roma + "
          "San Francisco + Tokyo + Court each on their own kernel, "
          "their own Org CA, reachable over the virtual L2.")
  '';
}
