# Architecture and design boundaries

meshscale aims to make Cloudflare Mesh approachable through a CLI, a local background service, and a Mac menu bar app. Cloudflare supplies the carrier network. The project does not implement direct links, NAT traversal, or a new hosted VPN data plane.

This is a development design document. Feature availability and platform limits are described in the linked guides; proposed work appears in the [roadmap](roadmap.md).

## Components

- **Go CLI/local daemon:** account setup, official-client orchestration, inventory caching, names, rules, SSH, sharing, and optional Linux networking. It uses account credentials directly and a private local Unix socket.
- **Official Cloudflare One client:** default device enrollment and traffic carrier. Connection must follow successful registration and safe profile validation. See [setup](setup.md) and [Linux coexistence](linux-host.md).
- **SwiftUI app:** macOS front end over the embedded CLI/local service. Enrollment is attended; consumer registrations and other-team registrations need explicit recovery. See [Mac safety](macos-enrollment.md).
- **Optional control Worker:** TypeScript using Effect and Alchemy, behind Cloudflare Access. This is a separate administration surface, not a prerequisite for the solo CLI. See [admin console](admin-console.md).
- **Linux secure overlay:** device-held WireGuard private keys; account-owned public-key directory. See [secure mode](secure.md).

## Identity and onboarding

Account OAuth authorizes administration; device Access enrollment and Mesh connector credentials identify network participants. They are distinct identities. The bundled OAuth client is public, and a brand-new account may need dashboard Zero Trust plan activation. Setup reuses owned resources and should preserve unrelated configuration. Exact APIs, permissions, retries, and limitations belong in [setup.md](setup.md).

Future team enrollment should avoid putting account-administrator credentials on member devices. Roles, governed tags, scoped enrollment, and decommissioning require explicit authorization and acceptance tests; they are not implied by the existence of an admin UI.

## Security boundaries

Ordinary Mesh traffic passes through Cloudflare. SSH/HTTPS provide their own application encryption. Secure mode adds device-to-device WireGuard over Mesh, but account administrators/API credentials remain the public-key distribution trust root. Gateway cannot enforce application policy inside the encrypted overlay. Explicit secure destinations must fail rather than silently downgrade.

Own-mode SSH authenticates a device and applies local account authorization; it is not a human MFA or session-recording service. Cloudflare SSH is a separate experimental integration. Review [SSH policy](ssh.md), [Cloudflare SSH](cloudflare-ssh.md), and the [README security model](../README.md#security-model).

Linux exit nodes are deliberate privileged routing changes with leak-guard and recovery requirements. They do not imply Mac/mobile exit support. See [exit-nodes.md](exit-nodes.md).

## Backend choice

The official client is the default. The experimental native backend uses an undocumented registration API and lacks the official client's supported lifecycle and posture behavior. A successful prototype does not establish vendor support, contractual permission, or cross-platform readiness. See [native.md](native.md).

Direct links are out of scope: they would add a separate security-critical transport and NAT-traversal system. The project instead focuses on safe orchestration, clear trust boundaries, predictable cleanup, diagnostics, and supported-host qualification.

## Validation and evolution

Unit tests use synthetic fixtures. Network tests run in disposable namespaces or isolated containers, with no production route/firewall changes. Live tests need a separate authorized account/device and must verify cleanup. Historical single-host measurements are observations, not performance guarantees.

See [CONTRIBUTING.md](../CONTRIBUTING.md), [roadmap.md](roadmap.md), and [tailscale-parity.md](tailscale-parity.md). Replace orchestration with supported native vendor functionality when it provides the required behavior and has been verified on supported plans/platforms.
