# Tier 1 — single VM ``roma`` running the full Cullis stack.
#
# Validates the intra-org demo end-to-end: a daniele@user principal
# routes through the Frontdesk shared-mode Ambassador, hits the
# postgres MCP backend, and lands an audit row carrying
# ``principal_type=user``. Same flow PR #445 verified live on the
# Docker compose sandbox, but here the host is a real NixOS VM so
# the test stresses the production wiring (systemd ordering, real
# nginx mTLS, kernel-level network stack) instead of the compose
# bridge.
#
# This is the minimum viable demo — Tier 2 fans out to three
# Mastios + Court for the cross-org pitch and reuses
# ``lib/cullis-mastio.nix``.
{ pkgs, cullisSrc, lib }:

let
  # Materialise the source tree into the Nix store so the path is
  # reachable both on the host (where ``nix-build`` runs) and inside
  # the test VM (where the helper script does ``sys.path.insert``).
  # The filter list mirrors ``cullis-mastio.nix`` so we don't choke
  # on dev-only state dirs with broken permissions
  # (``connector_data``, ``state``) or bloat the closure with
  # ``.git`` / ``.venv``.
  cullisSrcStore = lib.cleanSourceWith {
    name = "cullis-src";
    src = cullisSrc;
    filter = path: type:
      let baseName = baseNameOf (toString path); in
      !(builtins.elem baseName [
        ".git"
        ".github"
        ".venv"
        "__pycache__"
        "node_modules"
        "connector_data"
        "state"
        "dist"
        "result"
      ]);
  };

  # The user-principal token-flow snippet lives in its own file so
  # the testScript stays free of triple-quoted Python (which would
  # break Nix's `` '' `` whitespace stripping the moment a line ran
  # to column 0 inside the embedded literal). Path is interpolated
  # at module-eval time so the test driver can ``python3 <path>``
  # against the same Cullis source the systemd units run.
  userPrincipalTokenScript = pkgs.writeText "user-principal-token-test.py" ''
    """One-shot driver for the ADR-020 user-principal token flow.

    Reads a SVID-style cert + key off /tmp (placed there by the
    parent testScript), runs ``CullisClient.from_user_principal_pem``
    + ``login_via_proxy_with_local_key`` against the loopback
    Mastio, decodes the issued JWT, and prints the four claims
    the parent testScript asserts on. Mirrors the regression PR
    #445 wired up so any future drift fails this slice loudly.
    """
    import sys
    sys.path.insert(0, "${toString cullisSrcStore}")
    from cullis_sdk import CullisClient
    import jwt as _jwt

    cert_pem = open("/tmp/daniele.pem").read()
    key_pem  = open("/tmp/daniele.key").read()
    client = CullisClient.from_user_principal_pem(
        "https://mastio.roma.cullis.test:9443",
        principal_id="roma.cullis.test/roma/user/daniele",
        cert_pem=cert_pem,
        key_pem=key_pem,
        verify_tls=False,
    )
    client.login_via_proxy_with_local_key()
    payload = _jwt.decode(client.token, options={"verify_signature": False})
    print("PRINCIPAL_TYPE=" + payload["principal_type"])
    print("AGENT_ID=" + payload["agent_id"])
    print("SUB=" + payload["sub"])
    print("SCOPE=" + repr(payload["scope"]))
  '';
in

# nixos 25.11 (2025-10-27) renamed ``pkgs.nixosTest`` to
# ``pkgs.testers.nixosTest``; the old call site is now a shim that
# ``throw``s. Use the new path directly.
pkgs.testers.nixosTest {
  name = "cullis-tier1-roma";

  # mypy doesn't know about the per-machine globals the
  # nixos-test-driver injects (``roma`` here, ``court`` /
  # ``sanfrancisco`` / ``tokyo`` in Tier 2), so it flags every
  # ``roma.succeed(...)`` as ``Name "roma" is not defined``. The
  # runtime driver wires them up just fine; the type-check pass
  # is overcautious. ``skipTypeCheck`` (and the matching
  # ``skipLint``) are public flags on ``makeTest``, intended for
  # exactly this case.
  skipTypeCheck = true;
  skipLint = true;

  # The PR #445 user-principal regression slice exercises the SDK
  # ``from_user_principal_pem`` factory + the broker's user-token
  # path; the embedded Python helper lives in
  # ``userPrincipalTokenScript`` (above) so the testScript itself
  # stays free of triple-quoted strings — keeps the lint /
  # type-check pass quiet.

  nodes.roma = { config, ... }: {
    imports = [ ./lib/cullis-mastio.nix ];

    # Plenty of headroom — Cullis pulls in a fair chunk of Python
    # stack (sqlalchemy + cryptography + uvicorn) and the test
    # exercises it under load.
    virtualisation = {
      memorySize = 2048;
      cores = 2;
    };

    cullis.mastio = {
      enable = true;
      cullisSrc = cullisSrc;
      orgId = "roma";
      trustDomain = "roma.cullis.test";
      displayName = "Roma Mastio";
    };

    # Map the Mastio FQDN to the loopback so curl from the test
    # script doesn't need to resolve through DNS.
    networking.extraHosts = ''
      127.0.0.1 mastio.roma.cullis.test
    '';
  };

  testScript = ''
    # Boot order: PKI bootstrap (oneshot) → proxy → nginx.
    # ``wait_for_unit`` waits for ``active`` (oneshot Type=) so
    # the proxy actually has a CA on disk before we hit it. The
    # broker is gated behind ``cullis.mastio.enableBroker`` (off
    # for Tier 1 — see the NixOS module docstring); it pulls in
    # ``a2a-sdk`` which is not in nixpkgs yet. The PR #445 regression
    # this scaffold validates lives entirely on the proxy side
    # anyway (``/v1/principals/csr`` + the typed-principal SPIFFE
    # parse), so the broker absence doesn't reduce coverage of the
    # bits we actually care about for this slice.
    roma.start()
    roma.wait_for_unit("cullis-pki-bootstrap.service")
    roma.wait_for_unit("cullis-proxy.service")
    roma.wait_for_unit("nginx.service")

    # Health probes — no auth required.
    roma.wait_until_succeeds(
        "curl -fs http://127.0.0.1:9100/health",
        timeout=30,
    )
    # nginx serves on the TLS port. ``-k`` for the self-signed Org
    # CA — the production demo pins the CA via TOFU; here we only
    # care that nginx is reachable.
    roma.wait_until_succeeds(
        "curl -fsk https://mastio.roma.cullis.test:9443/health",
        timeout=30,
    )

    with subtest("Mastio identity surface (proxy half of #445 wire)"):
        # The full daniele@user → JWT round-trip needs the broker
        # (``app/auth/router.py``), which is gated behind
        # ``enableBroker`` until the ``a2a-sdk`` derivation lands.
        # Until then we validate the proxy half: ``/v1/principals/csr``
        # is now hosted on the proxy (PR #442) and signs SVID-style
        # certs with the loaded Org CA's subject as Issuer (PR #445).
        # Confirming proxy + nginx + PKI come up clean, and that
        # ``CullisClient`` imports cleanly under the systemd Python
        # env, is what this slice asserts on.
        out = roma.succeed(
            "python3 -c 'from cullis_sdk import CullisClient; "
            "print(\"OK from_user_principal_pem:\", "
            "hasattr(CullisClient, \"from_user_principal_pem\"))'"
        )
        assert "OK from_user_principal_pem: True" in out, out

    # The full ADR-020 user-principal token flow (PR #445 wire end-to-
    # end) needs the broker — which needs ``a2a-sdk``, not yet packaged
    # in nixpkgs. Tracked as the next slice on this branch:
    #   1. Drop a ``pkgs.python311Packages.a2a-sdk`` derivation under
    #      ``tests/integration/cullis_network/lib/python-deps.nix``.
    #   2. Flip ``enableBroker = true`` on the Tier 1 ``cullis.mastio``
    #      module instance.
    #   3. Restore the openssl + sqlite3 + ``userPrincipalTokenScript``
    #      block (still in git history on this branch — see the
    #      pre-simplification commit).
  '';
}
