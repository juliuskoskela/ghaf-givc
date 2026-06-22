# SPDX-FileCopyrightText: 2025-2026 TII (SSRC) and the Ghaf contributors
# SPDX-License-Identifier: Apache-2.0
#
# Integration test for coordinator-independent lifecycle delivery (R1/R2/R3):
# `givc-cli ... start service --vm <vm> poweroff.target --direct` delivers a poweroff
# straight to a guest agent's UnitControlService, bypassing the admin coordinator. It must
# return distinct exit codes, fail fast when the agent is unreachable, refuse mismatched
# callers, and — crucially — still power the guest off cleanly while the admin is DOWN.
{
  self,
  lib,
  ...
}:
{
  perSystem =
    { self', ... }:
    let
      tls = true;
      addrs = {
        host = "192.168.101.2";
        adminvm = "192.168.101.10";
        netvm = "192.168.101.4";
      };
      adminTransport = {
        name = "admin-vm";
        addr = addrs.adminvm;
        port = "9001";
        protocol = "tcp";
      };
    in
    {
      vmTests.tests.direct-poweroff = {
        module = {
          nodes = {
            # Minimal admin coordinator (no policy-admin, to keep the test light and offline).
            adminvm = {
              imports = [
                self.nixosModules.admin
                ./snakeoil/gen-test-certs.nix
              ];
              givc-tls-test = {
                inherit (adminTransport) name;
                addresses = adminTransport.addr;
              };
              networking.interfaces.eth1.ipv4.addresses = lib.mkOverride 0 [
                {
                  address = addrs.adminvm;
                  prefixLength = 24;
                }
              ];
              givc.admin = {
                enable = true;
                debug = true;
                inherit (adminTransport) name;
                addresses = [ adminTransport ];
                tls.enable = tls;
              };
            };

            # Host actor: runs givc-cli. Reuses the shared host node (cert SAN = host IP),
            # so a direct dial to a guest passes the agent's source-IP/cert-SAN check.
            hostvm = self.nixosModules.tests-hostvm;

            # Poweroff target: a system-level (root) sysvm agent. Its default whitelist
            # already authorizes poweroff.target, and being a system agent it can actually
            # isolate the shutdown target (unlike the user-session appvm agent).
            netvm = {
              imports = [
                self.nixosModules.sysvm
                ./snakeoil/gen-test-certs.nix
              ];
              givc-tls-test = {
                name = "net-vm";
                addresses = addrs.netvm;
              };
              networking.interfaces.eth1.ipv4.addresses = lib.mkOverride 0 [
                {
                  address = addrs.netvm;
                  prefixLength = 24;
                }
              ];
              givc.sysvm = {
                enable = true;
                debug = true;
                network = {
                  agent.transport = {
                    name = "net-vm";
                    addr = addrs.netvm;
                    port = "9000";
                    protocol = "tcp";
                  };
                  admin.transport = adminTransport;
                  tls.enable = tls;
                };
                # capabilities.services defaults to [ reboot.target poweroff.target ].
              };
            };

            # Caller with a mismatched certificate (cert SAN is .99, real IP is .30): the
            # agent's CertIPVerifyInterceptor must reject it -> DENIED.
            badvm = self.nixosModules.tests-badvm;
          };

          testScript =
            { nodes, ... }:
            let
              cli = "${self'.packages.givc-admin.cli}/bin/givc-cli";
              certFlags =
                if tls then
                  "--cacert /etc/givc/ca-cert.pem --cert /etc/givc/cert.pem --key /etc/givc/key.pem"
                else
                  "--notls";
              target = nodes.netvm.givc.sysvm.network.agent.transport;
              # Direct-mode args: addr/port/name point at the GUEST agent, not the admin.
              directArgs = "--name ${target.name} --addr ${target.addr} --port ${target.port} ${certFlags}";
            in
            ''
              import time

              with subtest("setup: admin, host and target agent up"):
                  adminvm.wait_for_unit("givc-admin.service")
                  hostvm.wait_for_unit("multi-user.target")
                  netvm.wait_for_unit("givc-net-vm.service")
                  badvm.wait_for_unit("multi-user.target")
                  # Give the target agent a moment to bind its listener.
                  time.sleep(3)

              with subtest("direct: unreachable agent fails fast, never hangs"):
                  start = time.time()
                  (rc, out) = hostvm.execute(
                      "${cli} --name net-vm --addr 127.0.0.1 --port 1 ${certFlags} "
                      "start service --vm net-vm poweroff.target --direct --timeout 3"
                  )
                  dt = time.time() - start
                  assert rc in (10, 11), f"expected UNREACHABLE(10)/TIMEOUT(11), got rc={rc}: {out}"
                  assert dt < 10, f"unreachable delivery should fail fast, took {dt:.1f}s"

              with subtest("direct: mismatched-cert caller is denied (12)"):
                  (rc, out) = badvm.execute(
                      "${cli} ${directArgs} "
                      "start service --vm net-vm poweroff.target --direct --timeout 5"
                  )
                  assert rc == 12, f"expected DENIED(12), got rc={rc}: {out}"
                  # The interceptor rejects before any teardown, so the target stays up.
                  netvm.succeed("true")

              with subtest("direct: poweroff succeeds with the admin coordinator DOWN"):
                  # Kill the coordinator to prove delivery does not depend on it.
                  adminvm.succeed("systemctl stop givc-admin.service")
                  adminvm.wait_until_fails("systemctl is-active --quiet givc-admin.service")

                  (rc, out) = hostvm.execute(
                      "${cli} ${directArgs} "
                      "start service --vm net-vm poweroff.target --direct --timeout 8"
                  )
                  assert rc == 0, f"expected ACCEPTED(0) with admin down, got rc={rc}: {out}"

                  # The guest must actually power off (cleanly, via systemd — not SIGKILL).
                  netvm.wait_for_shutdown()
            '';
        };
      };
    };
}
