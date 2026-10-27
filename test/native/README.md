# Native container integration

Use containers only on a host reached through Tailscale. Do not run native,
WARP or WireGuard on the host, use host networking, or change host networking.
The official `meshscale-node-1` / `meshscale-node-2` containers stay running.
The retained native containers use Docker's default bridge and have no WARP.

Build on the host (building does not start a transport):

```sh
cd /path/to/meshscale
CGO_ENABLED=0 go build -o test/native/meshscale ./cmd/meshscale
chmod 755 test/native/meshscale
docker build -t meshscale-native-e2e test/native
```

The Docker build context excludes all state files. Supply credentials only at
runtime via `--env-file /absolute/path/to/private-test.env`. Use a prepared account;
the native path does not change profiles, settings, Gateway, IdP or tunnels.
Use only `meshscale-native-` node names for these tests.

For a fresh TUN container, after preparing an owner-only `state-tun` directory:

```sh
docker run -d --name meshscale-native-tun --network bridge --dns 1.1.1.1 \
  --cap-add NET_ADMIN --device /dev/net/tun \
  --env-file /absolute/path/to/private-test.env \
  --mount type=bind,src=/absolute/path/to/meshscale/test/native/state-tun,dst=/state \
  meshscale-native-e2e sleep infinity
docker exec -d meshscale-native-tun sh -c \
  'meshscale up --backend native --hostname meshscale-native-tun --state-dir /state/native >/tmp/native-up.log 2>&1'
```

For userspace, `state-userspace` must be owned by UID/GID 1001, mode 0700:

```sh
docker run -d --name meshscale-native-1 --network bridge --dns 1.1.1.1 \
  --user 1001:1001 --cap-drop ALL --security-opt no-new-privileges \
  --env-file /absolute/path/to/private-test.env \
  --mount type=bind,src=/absolute/path/to/meshscale/test/native/state-userspace,dst=/state \
  meshscale-native-e2e sleep infinity
docker exec -d meshscale-native-1 sh -c \
  'meshscale up --backend native --userspace --hostname meshscale-native-userspace >/tmp/native-up.log 2>&1'
```

Do not reuse these fresh-enrollment commands against a container with different
private state. To reconnect the retained containers use `meshscale up`, without
backend, mode or name flags. Both containers keep credentials on private bind
mounts and use a separate PID 1 so `down` can be tested without Docker killing
its exec process. Only the native containers were stopped/recreated during
implementation.

`--dns 1.1.1.1` applies to the container. Docker initially inherited the host's
Tailscale resolver, `100.100.100.100`, which overlaps the Mesh `/12`; TUN then
routed that resolver through Mesh. Explicit container DNS resolves the overlap
without changing the host's DNS or teaching the backend to alter DNS.

Tests (use the IP printed by `meshscale ip`; this run got `.4` and `.5`):

```sh
docker exec meshscale-native-tun ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new testuser@100.96.0.2 whoami
docker exec meshscale-native-tun curl -sS --http0.9 http://100.96.0.2:8080/
docker exec meshscale-native-1 curl -sS --http0.9 --socks5 127.0.0.1:1080 http://100.96.0.2:8080/
docker exec meshscale-native-1 meshscale ssh testuser@100.96.0.2 whoami
docker exec -d meshscale-native-tun sh -c 'meshscale sshd --state-dir /state/ssh >/tmp/native-sshd.log 2>&1'
docker exec -d meshscale-native-1 sh -c 'meshscale sshd >/tmp/native-sshd.log 2>&1'
docker exec meshscale-node-1 ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new testuser@100.96.0.4 whoami
docker exec meshscale-node-1 ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new testuser@100.96.0.5 whoami
docker exec meshscale-node-2 meshprobe dial 100.96.0.2:8080
```

The port-8080 service is `meshprobe`'s plain TCP greeting, not an HTTP server;
`curl --http0.9` is intentional. The executable was copied from node 1 into
only the TUN container for the reverse TCP probe; it was not run on the host.
Stop/restart tests run `meshscale down`, inspect that `meshscale0`/Mesh routes
are absent, then start plain `meshscale up`; the registration/IP stays the same
and no warning repeats. Restart `sshd` after restarting the daemon.

A separate temporary registration named `meshscale-native-forget` tested
`down --forget`, without deleting either retained native test node. Its local
credential file and control socket were checked absent afterward.

The earlier spike device was deregistered (HTTP **204**) and its node
`meshscale-native-test` deleted (HTTP **200**).
The old spike container was replaced by the main CLI userspace container.
Cloudflare may retain deleted history. The old spike's local revoked key file
was also removed. No other account resources were written.

Real outputs and final checks are retained in [evidence.log](evidence.log).

The complete implementation handoff, file list, dependency versions and binary
size comparison are in [REPORT.md](REPORT.md). [account-after.json](account-after.json)
contains only canonical-result hashes; the historical test compared all four before and after.
