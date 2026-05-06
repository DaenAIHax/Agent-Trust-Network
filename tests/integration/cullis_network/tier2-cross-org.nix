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
      # Court is the federation hub — only it needs the broker
      # bound on the world-facing interface so peers can reach
      # ``/v1/federation/publish-agent``. Cities run a local
      # broker just for their own agent auth, but the
      # ``federation publisher`` task on each city points its
      # publish loop at Court via ``brokerUrl``.
      enableBroker = true;
      nginxAllowExternal = name == "court";
      brokerUrl =
        if name == "court"
        then ""  # local loopback default — Court IS the broker
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
        # Probing from inside roma confirms the route is up — the
        # actual publish payload graduates with the agent enroll
        # path (next slice on this branch family).
        for c in [roma, sanfrancisco, tokyo]:
            health = c.succeed(
                "curl -fs http://court:8000/health || echo OFFLINE"
            ).strip()
            assert "OFFLINE" not in health, (
                f"{c.name} can't reach Court's broker (got: {health!r})"
            )
            print(f"  {c.name} → court:8000/health = {health}")

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
