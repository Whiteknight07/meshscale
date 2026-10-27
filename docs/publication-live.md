# Historical publication validation — 2026-10-26

This is a sanitized record of a private development-account run. Domains,
account/resource identifiers, personal email, host login details and raw
artifacts are omitted. It does not describe a deployment supplied by this
repository. The OSS hardening review made no Cloudflare account API calls or
production changes; new hardening is covered by local fake-backed tests.

## Scope and results

A separate `daemon --publications-only` process ran alongside the existing
connectivity daemon. No host routing/firewall changes or connectivity-daemon
restart were performed. Of two active zones, the operator selected one
explicitly; the other zone was left untouched. Only the selected publication
namespace was modified.

- A loopback HTTP origin was reachable through the one-label Funnel hostname
  over public HTTPS from both the host and a Mesh container.
- Owner-only sharing returned an Access login redirect anonymously. Its
  self-hosted application had one email allow rule, and cloudflared ingress
  required the application's AUD. Interactive owner sign-in was not tested.
- The opt-in ACME staging test issued a certificate in 17.39 seconds and removed
  its challenge and A record. One production certificate was also issued for a
  development device. It was accepted by the unmodified system CA store over
  Mesh, with TLS 1.3 and hostname verification; no insecure TLS flag was used.
- A Funnel HTTPS origin with a custom hostname suffix passed normal certificate
  verification after DNS propagated.

Ten interleaved fresh curl requests per path measured these TTFBs from the
same development host. They include connection/TLS setup and are not a
geographic user-latency benchmark.

| Path | Successful samples | Median TTFB | Mean TTFB |
| --- | ---: | ---: | ---: |
| Loopback HTTP | 10/10 | 0.8265 ms | 0.8471 ms |
| Public Funnel HTTPS | 10/10 | 61.6305 ms | 60.4160 ms |
| Added latency | | 60.8040 ms | 59.5689 ms |

## Cleanup and retained state

All temporary tunnels, CNAMEs, Access applications and ACME challenge records
were reported removed by their recorded IDs. The final private audit reported
all 40 original DNS records unchanged. One development device's DNS-only A
record, production certificate/key, ACME account key and renewal manifest were
intentionally retained at the operator's request. The temporary publication
supervisor was retained for renewal; it was not installed as a persistent
service. This historical record does not assert those resources still exist.

A temporary publications-only supervisor must be stopped before a full daemon
claims the same publication lock/socket. The OSS changes require creation
nonces for remote mutation and revalidate tunnel ownership and owner-only
Access before restoring a connector. Older resources without nonce markers
need administrator review/manual cleanup; the review did not migrate live
resources or restart the historical supervisor.

See [Funnel](funnel.md) for the current ownership and restart behavior and
[certificates](cert.md) for permissions, renewal, file modes and local tests.
