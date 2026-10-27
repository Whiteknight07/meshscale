# meshscale

[![CI](https://github.com/Whiteknight07/meshscale/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Whiteknight07/meshscale/actions/workflows/ci.yml)

A Go CLI and macOS menu bar app for private networking over [Cloudflare Mesh](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-mesh/). Connect machines, find devices by name, SSH, and share services across your network. Cloudflare carries the traffic; meshscale coordinates account APIs, the official Cloudflare One client, and optional Linux networking features.

**Development software.** There has been no external security audit. The Mac app is ad-hoc signed and is not notarized. Any Cloudflare account can sign in with the bundled public OAuth client; see [account setup](docs/setup.md) to use your own OAuth client or API-token credentials instead. Independent supported-host qualification is still in progress.

This is an independent project, not affiliated with, endorsed by, or supported by Cloudflare or Tailscale. Those names and trademarks belong to their respective owners.

## Features

- Device inventory, Mesh IPs, `.mesh` DNS overrides, access rules, and Linux subnet routes.
- Explicit background daemon/service with reconnect and shared inventory caching.
- Keyless SSH with local authorization policy and private TCP forwarding.
- Linux WireGuard secure mode over Mesh, with optional Linux exit nodes.
- SwiftUI menu bar app for macOS 14 and later.
- Experimental native WireGuard backend and Cloudflare SSH integration.
- Optional certificate/public-service publication workflows; review their [security and ownership requirements](docs/funnel.md) before use.

Implementation is not a promise of complete Tailscale compatibility. Read the [feature inventory](docs/tailscale-parity.md) and [roadmap](docs/roadmap.md) for limitations.

## Requirements and installation

You need a Cloudflare account and permission to manage the required resources; `up` prepares it and links the one required dashboard step if Zero Trust Free is not active. The default backend requires the official Cloudflare One client. Linux secure mode and exit routing require additional kernel/network privileges; exit nodes require kernel WireGuard. Phones use the official Cloudflare One app and cannot run the Linux secure overlay.

The source build requires the Go version declared in [go.mod](go.mod). From a checkout:

```sh
go build -o ./bin/meshscale ./cmd/meshscale
./bin/meshscale version
```

Follow [installation and rollback](docs/install.md) for official-client packages, release archives, the guided Linux installer, and system service setup. Build the Mac app using [macos/README.md](macos/README.md). A Darwin CLI archive alone is not a Mac app installer.

## Quick start

1. **Install** meshscale and the official Cloudflare One client using the [verified installer](docs/install.md#quick-install-release) (or the source instructions while releases are unpublished).
2. **Connect**:

   ```sh
   sudo -H meshscale up
   ```

   Your browser opens for Cloudflare sign-in; over SSH, `up` prints the URL and accepts the callback URL/code. It prepares the account, enrolls this machine and prints `Connected. Mesh IP: …`. If a new account needs Zero Trust Free, follow the single billing link and rerun the same command; the saved login and completed work are reused. `--no-browser` and `--account ACCOUNT-ID` are available when needed.
3. **Done.** Connect another machine the same way; use its `.mesh` name in ordinary apps. To measure the roadmap's **first working peer**, verify a known TCP service:

   ```sh
   sudo -H meshscale ping --port 22 my-peer
   ```

The documented prepared-Linux workflow is now **3 command phases** (install, `up` including browser sign-in, peer verification), down from 4 (install, `login`, `up`, verification). Browser consent is still a real interaction; a fresh account adds the dashboard activation and a retry of `up` (**5 phases**). These are a static action count, not timed independent-user trials; authentication, connection and DNS durations must still be recorded separately under the [roadmap metric](docs/roadmap.md#onboarding-baseline-and-measurement-method).

The root daemon keeps `.mesh` names in a private marked hosts-file block when system DNS cannot resolve them, including when another VPN owns the resolver; [hosts DNS options and limits](docs/install.md#mesh-names-with-another-system-resolver) describe this fallback. `meshscale update --check` checks published releases; `meshscale completion bash|zsh|fish` generates command completion. Read [SSH policy](docs/ssh.md) before enabling an SSH server. Use `meshscale doctor` for diagnosis and review `meshscale bugreport --help` before exporting diagnostics.

Enrollment and VPN connection can change routes and DNS. Evaluate coexistence on a machine you can recover locally; see [Linux host networking](docs/linux-host.md) and [attended Mac enrollment](docs/macos-enrollment.md). Service installation is a separate, explicit step.

## Architecture

```text
Go CLI / local daemon / SwiftUI app
             | account APIs: devices, names, rules, public-key directory
             v
Local applications -> Cloudflare One client -> Cloudflare Mesh -> peer

Linux secure mode: application -> WireGuard -> Mesh -> WireGuard -> peer
Linux exit node:   application -> secure path -> Linux exit -> Internet
```

The default CLI uses the selected Cloudflare account directly and exposes a private local Unix socket. The optional [admin console](docs/admin-console.md) is a separate Cloudflare Worker. meshscale does not build direct device links or NAT traversal.

## Security model

**Ordinary Mesh trusts Cloudflare.** The default client encrypts the carrier to Cloudflare; it does not add device-to-device encryption to arbitrary application traffic. Cloudflare is in the trust boundary and can inspect traffic that lacks its own end-to-end protection. SSH and HTTPS retain their own encryption. Gateway rules govern ordinary Mesh traffic; enrollment permissions and account/token security matter.

**Keyless SSH is meshscale's own SSH server.** It uses Go's `x/crypto/ssh`, not Cloudflare Access for Infrastructure. Plain Mesh callers are identified by a unique active account registration owning the source IP. This trusts Cloudflare routing/source preservation and the registration API. Any process on an enrolled device can use its device identity. With no policy file, active account participants can access any usable non-root local account; root needs an explicit rule. Prefer a narrow [SSH policy](docs/ssh.md). Host keys persist, but the client accepts a new host key on first use and rejects a changed key; verify first-use fingerprints through a trusted channel when required. There is no MFA prompt or command recording, and revocation does not terminate existing sessions. The server has not had an external security audit.

**Secure mode encrypts between Linux devices, with an account/API trust root.** Private WireGuard keys stay local; public keys are distributed through account-owned Gateway lists and joined to active registrations. Account administrators, compromised API credentials, or a compromised key service can substitute public keys. There is no independently signed enrollment or Tailnet Lock equivalent. Cloudflare still sees endpoints, timing, packet sizes and the public-key directory. Explicit `.secure`/secure-IP connections fail rather than downgrade; ordinary Mesh addresses remain plain. Secure SSH uses authenticated WireGuard peer identity and still applies local SSH policy. Gateway cannot inspect or enforce application-level rules inside the encrypted overlay; enforce access on endpoints. See [secure mode](docs/secure.md).

**Exit nodes are deliberate routing changes.** They require Linux root and kernel WireGuard. Selection retains a leak guard when the peer or daemon disappears, with explicit carrier/control-plane and existing-resolver exceptions; resolver settings are retained. The selected exit can observe Internet traffic without application encryption. A handshake alone does not establish working Internet egress. Read [prerequisites, exceptions and recovery](docs/exit-nodes.md).

**Native is experimental.** Its enrollment uses an undocumented device API, can break without notice, and is not a Cloudflare-documented forwarding mechanism. It lacks official-client credential renewal, posture, captive-portal handling and endpoint failover. Review the [native backend caveats](docs/native.md) and applicable Cloudflare terms before opting in. The official client stays the default.

## Documentation and contributing

Start with the [documentation index](docs/README.md). See [CONTRIBUTING.md](CONTRIBUTING.md) for component builds, tests, and isolated Linux integration tests, [SECURITY.md](SECURITY.md) for private vulnerability reporting, and the [code of conduct](CODE_OF_CONDUCT.md) for community expectations.

The project is licensed under [MIT](LICENSE). Third-party dependencies retain their own licenses; the [dependency audit](docs/release/licenses.md) records release obligations and tooling dependencies.
