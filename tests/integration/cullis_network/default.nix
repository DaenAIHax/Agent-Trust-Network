# NixOS-test entry point for the Cullis cross-org network demo.
#
# Each scenario is a ``nixosTest`` derivation that boots one or more
# VMs running the live Cullis stack (broker + proxy + frontdesk +
# Cullis Chat + MCP echo) on isolated kernels and exercises the wire
# protocol end-to-end via a Python testScript.
#
# Build a scenario:
#
#     nix-build tests/integration/cullis_network -A tier1-roma
#
# Drop into the interactive driver for manual poking (boot the VMs,
# get a shell, run individual commands):
#
#     $(nix-build tests/integration/cullis_network -A tier1-roma.driverInteractive)/bin/nixos-test-driver
#
# Caller supplies ``pkgs`` so this file does not pin a channel itself —
# CI, the dev shell, and ``nix run`` wrappers all decide their own
# nixpkgs revision. Falls back to ``<nixpkgs>`` for ad-hoc local runs.
{
  pkgs ? import <nixpkgs> { },
  cullisSrc ? ../../..,
}:

let
  lib = pkgs.lib;
  callTest = path: import path { inherit pkgs cullisSrc lib; };
in
{
  tier1-roma = callTest ./tier1-roma.nix;

  # Four VMs (roma + sanfrancisco + tokyo + court). Validates the
  # ``infrastructure cross-org`` invariants: per-VM Org CA isolation,
  # virtual L2 reachability, and default-deny on cross-org client
  # certs. The federation publisher + actual A2A oneshot plumbing
  # is the next slice on top of this scaffold.
  tier2-cross-org = callTest ./tier2-cross-org.nix;
}
