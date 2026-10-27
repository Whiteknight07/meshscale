# Live fleet release test

This suite is opt-in and uses four existing Docker test containers, a Linux
peer and a Mac peer. Ordinary `go test ./...` skips its container-only checks. It never
installs a host binary, starts a host transport, calls Tailscale, changes account
profiles/policies/settings, or writes to the Mac. Host commands have an explicit
`status`/`doctor`/`ping` allowlist; the Mac allows diagnostic commands and
connectivity probes only.

Build static artifacts in `/tmp`, then run from the project root:

```sh
cd /root/projects/meshscale
CGO_ENABLED=0 go build -o /tmp/meshscale-battle ./cmd/meshscale
CGO_ENABLED=0 go test -c -o /tmp/meshscale-battle-state.test ./test/e2e
MESHSCALE_LIVE_E2E=1 python3 -u test/e2e/run.py --phase baseline --out /tmp/meshscale-e2e-before
MESHSCALE_LIVE_E2E=1 python3 -u test/e2e/run.py --phase exercise --chaos --exit --out /tmp/meshscale-e2e-after
```

Without `MESHSCALE_LIVE_E2E=1`, the runner prints SKIP and exits successfully
without calling Docker or SSH. Live runs return nonzero if any check fails.
`results.md` and `results.json` are rewritten after every check, including
failures. SKIP is separate from PASS. The console is a pass/fail table with
durations; arbitrary child output and API bodies are withheld to protect tokens.

Options (also listed by `python3 test/e2e/run.py --help`):

- `--phase all` (default): capture the baseline, exercise features, then capture
  the final connectivity matrix.
- `--phase baseline`: run only the initial inventory, diagnostics and directed
  ICMP/TCP/name-resolution matrix.
- `--phase exercise`: exercise features and run the final matrix, without the
  initial matrix.
- `--chaos`: add the container-only fault and state tests described below;
  applies in `exercise` or `all` mode.
- `--exit`: add selection, egress, LAN access, withdrawal and registration
  revocation checks using a disposable exit peer; applies in `exercise` or
  `all` mode.
- `--out PATH`: write incremental `results.md`, `results.json` and disposable
  resource ownership records to PATH (default `/tmp/meshscale-e2e-results`).
- `-h` / `--help`: print usage without touching the fleet.

For one complete run with a 35-minute execution limit and three minutes reserved
for interrupt cleanup (GNU `timeout`):

```sh
MESHSCALE_LIVE_E2E=1 timeout --signal=INT --kill-after=180s 2100s \
  python3 -u test/e2e/run.py --phase all --chaos --exit \
  --out /tmp/meshscale-e2e-final > /tmp/meshscale-e2e-final.log 2>&1
```

The runner's `finally` cleanup runs on an interrupt; a forced kill can still
require manual recovery using the ownership record. Reserve additional time
within your overall budget to verify cleanup.

Every phase builds a fresh static binary, saves the four test containers' daemon
and SSH arguments and backend/secure/service settings, then runs that binary as
the daemon before any matrix check. Test SSH listeners on port 22220 supply the
matrix's TCP fixture on all four peers, including the private userspace stack.
Daemon polling uses the production one-minute cadence; directory convergence
allows two refreshes. This avoids manufacturing API rate limits with aggressive
polling. Original executables are retained when their pathname would be replaced;
`original-processes.json` records the saved commands with mode 0600. Cleanup
restores settings, existing SSH client pins, and restarts the saved commands.
Official-client daemons get temporary container-only bootstrap DNS; cleanup
waits for their original connection before restoring the saved resolver.
A test-only user created by this run is removed. New secure keys are retained
for stable identity; originally disabled capabilities are withdrawn. Test SSH
uses a separate host key/policy allowing only `testuser`, creating that container
user if absent. Serve uses ports 28079/28080 with a real HTTP payload.

The retained containers must use Docker's default bridge. Container packages
needed for the full matrix are `curl`, `iproute2`, `procps`, `iputils-ping`,
`iptables`, `nftables`, `openssh-client`, and `openssh-sftp-server`; `meshscale-node-1` also
needs Python 3 for the localhost serve fixture. Install these inside the test
containers, not the host. Rootless native userspace intentionally has no host
ICMP/interface/DNS path; those system checks report SKIP, while CLI TCP/name/SSH
checks still run through its private transport.

Fleet configuration uses environment variables prefixed `MESHSCALE_E2E_`, or
an ignored `test/e2e/local.json` object whose keys omit that prefix. An alternate
JSON file can be selected with `MESHSCALE_E2E_CONFIG`. Environment values win.
Keep credentials in the existing credentials file, never in this JSON file.

| Key | Default | Meaning |
|---|---|---|
| NODE1_IP through NODE4_IP | 192.0.2.2 through 192.0.2.5 | Four container Mesh IPs, in the order listed in `CONTAINERS` |
| HOST | 1 | Include the read-only Linux peer; 0 omits it |
| HOST_IP | 192.0.2.7 | Existing Linux peer Mesh IP |
| HOST_EXIT | host | Existing Linux exit offer name |
| DNS | 1.1.1.1 | DNS for the disposable exit container; prevents inheriting a host-only VPN resolver |
| MAC_SSH | empty | SSH user@host; empty omits the Mac |
| MAC_IP | 192.0.2.6 | Mac Mesh IP |
| MAC_KEY | empty | SSH identity path; empty uses SSH defaults |
| MAC_BIN | meshscale | Existing Mac CLI path |

Defaults are documentation addresses, not a usable fleet. Set actual addresses
locally. The runner does not upgrade external peers. Missing commands in their
older installed binaries are pending deployment and remain visible in results.
Exit egress failures also save container-only route, rule, forwarding-counter,
and handshake evidence in `*-routing.json`. Private WireGuard keys are never
requested. Failures include at most 300 characters of redacted command output; both stdout
and stderr are considered, including timeout output and semantic-check failures.

`--chaos` tests daemon SIGKILL during forwarding configuration, WARP restart
(WARP is PID 1, so Docker restarts it), a second Docker restart (with temporary container-only bootstrap DNS, restored
afterward), default-route
loss/restoration, link flap, concurrent CLI calls, and a destination-scoped
container API firewall outage. Each child command has an in-container 28-second
timeout and an outer 30-second deadline; TCP/Internet probes use shorter limits.
Retries are separate bounded attempts. State tests discover every JSON state
file under each configuration directory and exercise empty, malformed and null
private copies, never live credentials/keys. Runtime sockets/locks, logs and
non-JSON files are not treated as JSON state. Full-disk testing uses a second,
networkless disposable container and a Docker-provisioned 1 MiB tmpfs; a failed
atomic write must preserve prior intent and remove temporary files.

Clock skew is explicitly SKIP: Linux containers share `CLOCK_REALTIME` with
the Linux host. Do not add `CAP_SYS_TIME` or run `date -s`. A future
time-injection test must affect only the tested process. Docker recreation does not by itself
establish that an exit guard is restored before first network traffic; an
early-boot leak capture remains a separate qualification step.

`--exit` selects the configured existing Linux peer offer only from a container. It then
creates **meshscale-battle-exit** using the native image for withdrawal and
registration revocation; the Linux peer's offer is never withdrawn. It creates no
host mounts, profiles or account-wide settings. Credentials are passed with
`--env-file`, defaulting to
`${XDG_CONFIG_HOME:-$HOME/.config}/meshscale/dev.env`; override with
`MESHSCALE_TEST_CREDENTIALS`. Only the newly created node/registration and its
secure-directory record are eligible for deletion. The second optional
container is **meshscale-battle-state**, with no network or credentials.
Existing containers with either name are never adopted. Revocation requires the
created registration to be visible in the device API before deletion; native
enrollment IDs are normalized by removing their `t.` prefix for admin API
lookups. A genuinely absent registration fails qualification.
An absent registration or a DELETE 404 alone cannot prove revocation.

The images default to `meshscale-native-e2e` and `meshscale-e2e`; override with
`MESHSCALE_E2E_NATIVE_IMAGE` / `MESHSCALE_E2E_OFFICIAL_IMAGE`. Running retained
containers can reference old image IDs that no longer exist, so reusable image
tags are used for disposable containers. Dedicated egress waits for the exit to install the client's published v2 IPv4
binding; an IPv6 secure handshake alone cannot establish forwarding readiness. The
read-only Linux peer proves the equivalent source binding with ICMP to the
client's secure IPv4 address before its public egress probe.
Withdrawal tests keep Internet blocked
until explicit deselection. Public-IP equality on this fleet is insufficient
to identify the exit path because the Linux peer and Docker share NAT; route,
guard and forwarding evidence must accompany egress success.

Offline safety checks:

```sh
python3 -m unittest discover -s test/e2e -p 'test_*.py' -v
go test ./test/e2e
```

If interrupted, let the runner finish its cleanup. Inspect only the named test
containers, their `/tmp/meshscale-battle-*` files and this run's owned resource
IDs if cleanup reports failure. Never recover by resetting the shared checkout
or changing host networking. The output directory records observed results
and unresolved release gates.
