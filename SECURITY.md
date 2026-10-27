# Security policy

## Supported versions

meshscale is pre-release development software. There is no stable release or long-term support promise yet. Security fixes target the current `main` branch; older commits and experimental prototypes are not maintained separately. An external security audit has not been performed.

## Private reporting

Use [GitHub's private vulnerability reporting form](https://github.com/Whiteknight07/meshscale/security/advisories/new) for this repository. Do not open a public issue containing an exploit, credential, private key, or affected account/device information. If the form is unavailable, open a minimal issue asking the maintainers to enable private reporting, without disclosing vulnerability details.

Include the affected commit/version, platform, threat model, minimal reproduction, expected and actual behavior, and impact. Redact unrelated personal data and credentials. Coordinate disclosure with maintainers; response and remediation times are best effort during development.

## Scope

Reports about authorization, local privilege boundaries, SSH identity/policy, credentials and state permissions, tenant isolation, secure-mode downgrade, route/firewall ownership, installer/release integrity, and diagnostic disclosure are in scope. Vendor vulnerabilities should also be reported through the vendor's own security process; include only meshscale-specific impact here.

Cloudflare is part of the default network trust boundary. The optional secure overlay depends on account-authorized public-key distribution, and experimental native transport uses undocumented vendor APIs. Review the [security model](README.md#security-model), [SSH](docs/ssh.md), [secure mode](docs/secure.md), [exit nodes](docs/exit-nodes.md), and [native backend](docs/native.md) before deployment. Use disposable resources for testing and obtain authorization before testing someone else's devices or account.
