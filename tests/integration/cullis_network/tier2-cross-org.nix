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
      enableBroker = true;
      cullisSrc = cullisSrc;
      inherit (cfg) orgId trustDomain displayName;
    };

    # Each city resolves its own ``mastio.<td>`` to loopback so the
    # local SDK / test driver can curl over the TLS port without
    # going through DNS. Cross-VM connectivity uses the test
    # framework's vlan + IP; we don't need to teach the cities
    # about each other's FQDNs at the DNS layer for this slice.
    networking.extraHosts = ''
      127.0.0.1 mastio.${cfg.trustDomain}
    '';

    networking.firewall.allowedTCPPorts = [ 9443 ];
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
        # so we use ``-k`` and only check the connection completed
        # at the TLS layer.
        tokyo_ip = tokyo.succeed(
            "ip -4 -o addr show dev eth1 | awk '{print $4}' | cut -d/ -f1"
        ).strip()
        out = roma.succeed(
            f"curl -sk --resolve mastio.tokyo.cullis.test:9443:{tokyo_ip} "
            f"https://mastio.tokyo.cullis.test:9443/v1/federation/orgs"
        )
        # Tokyo's proxy answers with its own ``federation/orgs``
        # listing — confirms the request actually reached the
        # other VM's broker, not just looped back on Roma.
        assert "tokyo" in out, (
            f"expected Tokyo's federation listing to mention "
            f"``tokyo``, got: {out!r}"
        )

    with subtest("Cross-org cert chain refusal (default-deny)"):
        # Spawn a daniele user cert against Roma's Org CA and
        # try presenting it to Tokyo's nginx. Tokyo only trusts
        # its own CA, so the chain validation MUST fail — the
        # whole pitch is that A2A trust is brokered through the
        # Court fabric, not by sharing CA roots across orgs.
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
        # Copy the freshly-minted Roma cert + key onto Tokyo via
        # the test driver's ``copy_from_vm`` / ``copy_to_vm``.
        # Then curl against Tokyo's mTLS-required endpoint with
        # that cert — Tokyo's nginx should refuse the chain.
        roma.copy_from_vm("/tmp/daniele-roma.pem", "/")
        roma.copy_from_vm("/tmp/daniele-roma.key", "/")
        # ``copy_from_vm`` lands the file under
        # ``$out/<filename>``; ``copy_to_vm`` reads from there.
        tokyo.copy_from_host("daniele-roma.pem", "/tmp/")
        tokyo.copy_from_host("daniele-roma.key", "/tmp/")
        # ``--cert-status`` plus a non-zero exit on TLS failure is
        # what we want; ``-w "%{http_code}"`` falls back to "000"
        # when the handshake itself fails. Either is a pass.
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
        # Either we get a 401 from nginx (cert chain rejected) or
        # the TLS handshake fails outright (000 / HANDSHAKE_FAIL).
        # Anything else means a Roma-signed cert was accepted as
        # Tokyo's — the demo's foundational claim broken.
        assert (
            "401" in out
            or "000" in out
            or "HANDSHAKE_FAIL" in out
        ), (
            f"Tokyo accepted a cert signed by Roma's Org CA "
            f"(response: {out!r}). Cross-org isolation broken."
        )

    print("Tier 2 cross-org isolation verified — Roma + San Francisco + "
          "Tokyo + Court each on their own kernel, their own Org CA, "
          "reachable over the virtual L2, and refusing each other's "
          "client certs by default.")
  '';
}
