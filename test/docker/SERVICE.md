# Service, Serve and device enrollment evidence

Historical verification record; personal account, host and resource identifiers in examples are anonymized.

Verified 2026-10-26. All transports, HTTP/SSH servers, CLI network operations,
Go tests and vet ran inside Docker bridge-network containers. Builds and file
edits ran on the host; no host routes, DNS, WARP, Tailscale, systemd units or
network listeners were changed. Existing containers were not stopped/removed.
The test binary was `/usr/local/bin/meshscale-sim`.

## Daemon reconnect and device polling

Node-2 (`100.96.0.3`):

```sh
meshscale-sim daemon --poll-interval 5s
warp-cli --accept-tos disconnect
```

A temporary `meshscale-svc-test` Mesh node was created and deleted through the
API. It was not enrolled and had no Mesh IP, so its addition/removal triggered
DNS reconciliation without introducing a DNS record. Logs show the device
count going 4 -> 5 -> 4. The initial sync created the two previously absent
owned native-device DNS names; it did not change access/network rules.

```text
meshscale daemon: 2026/10/26 02:25:35 local status socket: /root/.config/meshscale/service/status.sock
meshscale daemon: 2026/10/26 02:25:35 backend connected 
create	meshscale-native-tun.mesh	100.96.0.4
create	meshscale-native-userspace.mesh	100.96.0.5
DNS synced: 2 change(s). Gateway propagation may take about 60 seconds.
meshscale daemon: 2026/10/26 02:25:39 devices changed: reconciled 4 participant(s)
meshscale daemon: 2026/10/26 02:26:20 reconnecting selected backend
meshscale daemon: 2026/10/26 02:26:20 backend disconnected Settings Changed
DNS synced: 0 change(s). Gateway propagation may take about 60 seconds.
meshscale daemon: 2026/10/26 02:26:25 devices changed: reconciled 5 participant(s)
meshscale daemon: 2026/10/26 02:26:25 backend connected 
DNS synced: 0 change(s). Gateway propagation may take about 60 seconds.
meshscale daemon: 2026/10/26 02:27:05 devices changed: reconciled 4 participant(s)
meshscale daemon: 2026/10/26 02:27:39 shutting down
```

Unchanged polls produced no additional DNS sync. Tests also check unchanged
cache inode/mtime and hook retry after errors. SIGTERM exited cleanly and
removed the status socket; WARP was explicitly reconnected after the test.

The private status directory/socket were verified as:

```text
700 /root/.config/meshscale/service
600 /root/.config/meshscale/service/status.sock
```

`curl --unix-socket ... http://meshscale/status` returned:

```json
{
  "mode": "daemon",
  "backend": "warp",
  "connection": {
    "state": "connected",
    "connected": true
  },
  "last_sync": "2026-10-26T02:34:07.936395901Z",
  "devices": 4,
  "forwards": [],
  "ssh": true
}
```

A curl process with UID/GID 65534 could not connect. Duplicate daemon locking,
invalid forward rejection, and socket removal are also tested.

## Serve: official and native

A small Go HTTP server listened only on `127.0.0.1:9000` in node-1. With
`meshscale-sim serve 9000` running in the foreground, node-2 returned:

```text
$ curl --max-time 10 --noproxy '*' -fsS http://meshscale-docker-test.mesh:9000/
meshscale localhost service on node-1
$ meshscale-sim serve status
[{"port":9000,"mesh_port":9000}]
```

`serve off` closed forwarding; a subsequent curl to `100.96.0.2:9000` timed out.
With a node-1 daemon running instead, `serve 9000 --tcp` returned immediately:

```text
Serving mesh port 9000 -> 127.0.0.1:9000 in the running daemon.
```

After SIGTERM and restarting the daemon, the saved forward recovered and the
same node-2 curl succeeded. Startup logs (the backend initially was down):

```text
meshscale daemon: 2026/10/26 02:32:58 local status socket: /root/.config/meshscale/service/status.sock
meshscale daemon: 2026/10/26 02:32:59 restore serve: Mesh backend must be connected before starting sshd
meshscale daemon: 2026/10/26 02:32:59 reconnecting selected backend
meshscale daemon: 2026/10/26 02:32:59 backend disconnected Settings Changed
DNS synced: 0 change(s). Gateway propagation may take about 60 seconds.
meshscale daemon: 2026/10/26 02:33:02 devices changed: reconciled 4 participant(s)
meshscale daemon: 2026/10/26 02:33:04 backend connected 
meshscale daemon: 2026/10/26 02:33:05 serving mesh port 9000 -> 127.0.0.1:9000
```

Native userspace was also exercised without stopping its existing transport.
A localhost server ran in `meshscale-native-1`, with
`meshscale-sim serve 9000 --mesh-port 9001 --tcp`. From node-1:

```text
$ curl --max-time 5 --noproxy '*' -fsS http://100.96.0.5:9001/
meshscale localhost service on node-1
```

(The test server deliberately returns the same fixed response string on both
containers.) `serve off` stopped this lease; its temporary localhost server
was then stopped. Unit tests exercise TCP half-close, cancellation, persistent
configuration, and preventing a queued restore from undoing `serve off`.

## Optional daemon SSH

Node-2 ran `daemon --ssh --ssh-port 2223`; node-1 used OpenSSH with its private
test known-hosts file. A temporary container-only local user was removed after
the test:

```text
$ ssh -o BatchMode=yes -p 2223 meshscale-svc-test@100.96.0.3 whoami
meshscale-svc-test
```

The daemon bound exactly `100.96.0.3:2223` and
`[2606:4700:cf1:1000::3]:2223`. Logs recorded accepted device identity and
policy checks. No real phone was enrolled.

## Enrollment API results

The live API already contained a `warp` app (`00000000-0000-4000-8000-000000000009`)
and a separate owner-only policy. Both were preserved. The API token could not
read `/user` (HTTP 403); account membership verified exactly one accepted Super
Administrator, `owner@example.com`. Setup created one owned user profile
before adding one owned enrollment policy. Existing one-time PIN and GitHub
providers were reused, and repeat `setup --devices` returned the same IDs.

Selected fields from `GET /devices/policy/00000000-0000-4000-8000-000000000012`:

```json
{
  "policy_id": "00000000-0000-4000-8000-000000000012",
  "name": "meshscale user devices",
  "description": "Managed by meshscale device enrollment v1",
  "default": false,
  "enabled": true,
  "match": "identity.email == \"owner@example.com\"",
  "precedence": 50,
  "profile_type": "warp",
  "service_mode_v2": {
    "mode": "warp"
  },
  "tunnel_protocol": "masque",
  "include": [
    {
      "address": "100.96.0.0/12"
    },
    {
      "address": "2606:4700:cf1::/48"
    },
    {
      "host": "example-team.cloudflareaccess.com"
    },
    {
      "host": "github.com"
    },
    {
      "host": "api.github.com"
    }
  ],
  "always_include": [
    {
      "ip": "162.159.197.4"
    },
    {
      "ip": "2606:4700:102::4"
    }
  ],
  "always_exclude": [
    {
      "ip": "162.159.197.3"
    },
    {
      "ip": "2606:4700:102::3"
    }
  ]
}
```

`GET /access/apps/00000000-0000-4000-8000-000000000009/policies/00000000-0000-4000-8000-000000000006`:

```json
{
  "created_at": "2026-10-26T02:24:19Z",
  "decision": "allow",
  "exclude": [],
  "id": "00000000-0000-4000-8000-000000000006",
  "include": [
    {
      "email": {
        "email": "owner@example.com"
      }
    }
  ],
  "name": "meshscale device enrollment: owner@example.com",
  "require": [],
  "uid": "00000000-0000-4000-8000-000000000006",
  "updated_at": "2026-10-26T02:24:19Z",
  "reusable": false,
  "precedence": 2
}
```

The full Default profile response was byte-for-byte identical before/after:

```text
2cf77bb5bed9d9311c51478e9afcab52339800ed40afc8ec3bd173cdd6b10e02  before
2cf77bb5bed9d9311c51478e9afcab52339800ed40afc8ec3bd173cdd6b10e02  after
```

Existing node connectivity after enrollment setup:

```text
MASQUE node-2 -> node-1 :8080:
hello from 100.96.0.2:8080, you are 100.96.0.3:41088
native TUN -> node-1 :8080:
hello from 100.96.0.2:8080, you are 100.96.0.4:45340
native userspace (SOCKS5) -> node-1 :8080:
hello from 100.96.0.2:8080, you are 100.96.0.5:31962
```

Use `--noproxy '' --socks5 127.0.0.1:1080` for the userspace curl: `--noproxy '*'`
would bypass SOCKS and try the container's OS stack instead.

Exact phone steps are in [devices.md](../../docs/devices.md).

## Automated checks and limits

Passed in the new `meshscale-service-checks` container using the existing Go
1.27.3 toolchain:

```sh
go vet ./...
go test ./...
go test -race ./internal/service ./internal/devicesync ./internal/mesh ./internal/config ./internal/cfapi ./cmd/meshscale
```

`git diff --check` and `GOOS=darwin GOARCH=arm64 go build ./cmd/meshscale` passed. Service unit/plist generation, XML validity, ownership
markers, installation idempotency, injected systemctl failure, and uninstall
are covered by tests. `service install --print --ssh` was exercised in node-1;
no real systemd installation was attempted because the existing containers do
not run systemd. launchd was generated/tested as XML; no macOS job was installed.
Native daemon ownership uses the existing tested native lifecycle; the optional
extra live native check exercised Serve through its running netstack, not a
restart of the other worker's native transports.

The temporary Mesh node, container-only SSH user, foreground proxies and test
HTTP/daemon processes were cleaned up. All four existing Mesh participants
were left running/connected. The new checks container is retained for review.

## Files owned by this implementation

- `cmd/meshscale/daemon.go`, `device_sync.go`, `device_sync_test.go`, `serve.go`,
  `serve_test.go`, `service.go`; modified `up.go`, `setup.go`, `dns.go`.
- `internal/service/{control,daemon,install,proxy}.go` and their tests;
  `internal/devicesync/sync.go`, `sync_test.go`.
- `internal/config/service.go`, `internal/cfapi/enrollment.go`,
  `internal/mesh/devices.go`, `devices_test.go`.
- `docs/service.md`, `docs/serve.md`, `docs/devices.md`, this evidence file,
  and the README command list.

Parallel changes under rules/routes/status and the Gateway API were not edited
by this implementation. `go.mod` and `go.sum` were not changed; no commit or push
was made.
