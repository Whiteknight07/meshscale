# Changelog

## 0.1.0 — 2026-10-27

First public development release. It is not a stable release. Dates and measurements in design documents describe development observations, not supported-platform guarantees.

- Go CLI and local daemon for Cloudflare account setup, enrollment, connection, device inventory, names, access rules, and Linux subnet routes.
- Local keyless SSH server and policy, private service forwarding, and experimental Cloudflare SSH mode.
- **SSH migration:** own SSH now denies every login when its policy is missing.
  Existing SSH-enabled daemons warn on restart; run `sudo meshscale ssh policy init`
  with the daemon's credentials/configuration to grant the verified owner non-root
  access. Root requires explicit `--allow-root`. Existing explicit policies and
  Cloudflare SSH semantics are unchanged. Added offline `ssh policy show|test`,
  `--init-policy` setup, and missing-policy status in the CLI/Mac app.
- Optional Linux WireGuard secure overlay and Linux exit nodes with owned routing/firewall state and recovery tests.
- Experimental native WireGuard backend; the official Cloudflare One client remains the default.
- SwiftUI menu bar app for macOS 14+, currently ad-hoc signed and not notarized.
- Optional Cloudflare Worker admin console and certificate/public-service publication workflows.
- Read-only diagnostics and reviewed diagnostic export workflows.
- CI checks, draft release packaging, checksums, dependency notices, and guided Linux installer.
- MIT licensing, public contribution/security guidance, documentation index, and release privacy/history/dependency audit.

Sign in with Cloudflare uses a public OAuth client that works for any Cloudflare account. Independent host qualification and release artifacts remain release gates. See the [roadmap](docs/roadmap.md) and [release audit](docs/release/history-audit.md).
