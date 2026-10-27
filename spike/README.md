# Research prototypes

These directories contain experimental source, not supported deployment tooling:

- [Native WireGuard feasibility](nativewg/README.md)
- [Cloudflare SSH findings](cfssh/README.md)
- [Exit-node research](exitnode/README.md)
- [Secure performance diagnostics](secureperf/README.md)
- `securebench/`: local secure-transport benchmark source.

Raw live-account logs, resource inventories, packet captures, and host-specific mutation scripts were removed for public release. They exposed identifiers or depended on a developer's live infrastructure. See [removed artifacts](../docs/release/removed-artifacts.md) and [history audit](../docs/release/history-audit.md). Ignored private state is not a distributable artifact; never include it in source archives.

Run integration experiments only in disposable namespaces/VMs and separately authorized accounts. Use the maintained CLI and [user documentation](../docs/README.md) for normal operation.
