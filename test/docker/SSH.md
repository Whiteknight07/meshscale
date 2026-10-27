# Mesh SSH verification, 2026-10-26

Historical verification record; personal account, host and resource identifiers in examples are anonymized.

Used the existing Ubuntu 24.04 ARM64 participants on Docker's default bridge:

| Container | Mesh IPv4 | Name |
|---|---|---|
| meshscale-node-1 | 100.96.0.2 | meshscale-docker-test |
| meshscale-node-2 | 100.96.0.3 | meshscale-docker-test-2 |

Built in `/path/to/meshscale`:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /path/to/meshscale/bin/meshscale-sim ./cmd/meshscale
```

Copied only to `/usr/local/bin/meshscale-sim` in each container. Installed
`openssh-client` in both and `openssh-sftp-server` in node-1. Ubuntu's package
recommendations also installed openssh-server in node-1; package policy prevented
its startup. No OpenSSH daemon was started. Created `testuser` with `/bin/bash`,
a home directory, and supplementary group `meshscale-ssh-test` in node-1.

Started the test daemon with `docker exec -d`, with PID recorded in
`/run/meshscale-sim-sshd.pid` and stderr in
`/var/log/meshscale-sim-sshd.log`. It remains running, using the default policy
(file absent). The temporary policies used below were removed. The test user's
transfer files and node-2's known_hosts entries remain for inspection.

All following SSH/SCP/SFTP commands ran **inside node-2** using `docker exec`.
No client SSH key was generated or installed.

```text
$ ssh -o BatchMode=yes testuser@100.96.0.2 whoami
testuser

$ ssh -tt -o BatchMode=yes testuser@100.96.0.2 'tty; echo ok'
/dev/pts/0
ok
Connection to 100.96.0.2 closed.

$ meshscale-sim ssh testuser@meshscale-docker-test hostname
meshscale-docker-test

$ ssh -o BatchMode=yes root@100.96.0.2 whoami
Connection closed by 100.96.0.2 port 22
# exit 255; default policy denied root

$ scp -o BatchMode=yes /tmp/meshscale-ssh-upload testuser@100.96.0.2:uploaded-final.txt
$ scp -o BatchMode=yes testuser@100.96.0.2:uploaded-final.txt /tmp/meshscale-ssh-download-final
$ cmp /tmp/meshscale-ssh-upload /tmp/meshscale-ssh-download-final
$ cat /tmp/meshscale-ssh-download-final
meshscale sftp proof

$ printf 'pwd\nls -l uploaded.txt\nget uploaded.txt /tmp/meshscale-sftp-download\nbye\n' | sftp -b - testuser@100.96.0.2
sftp> pwd
Remote working directory: /home/testuser
sftp> ls -l uploaded.txt
-rw-r--r--    ? testuser testuser       21 Oct 26 01:02 uploaded.txt
sftp> get uploaded.txt /tmp/meshscale-sftp-download
sftp> bye

$ ssh -o BatchMode=yes testuser@100.96.0.2 'id; pwd; printf "token=%s\n" "${CLOUDFLARE_API_TOKEN-unset}"'
uid=1001(testuser) gid=1001(testuser) groups=1001(testuser),1002(meshscale-ssh-test)
/home/testuser
token=unset

$ ssh -o BatchMode=yes testuser@100.96.0.2 'exit 7'
# local ssh exit 7

$ ssh -6 -o StrictHostKeyChecking=accept-new -o BatchMode=yes testuser@2606:4700:cf1:1000::2 whoami
testuser

$ printf 'whoami\nexit\n' | ssh -tt -o BatchMode=yes testuser@100.96.0.2
whoami
exit
testuser@meshscale-docker-test:~$ whoami
testuser
testuser@meshscale-docker-test:~$ exit
logout
Connection to 100.96.0.2 closed.
```

Node-1 listener inspection showed only these meshscale SSH listeners:

```text
100.96.0.2:22
[2606:4700:cf1:1000::2]:22
```

`stat` showed mode 700/root on `/var/lib/meshscale` and 600/root on the key.
The same host key survived replacing/restarting only our test daemon:
`SHA256:7MMP5uJ4O8qpp4uMgcn5fagO3FadItJONysyrwA8Mj8`.

Connecting to node-1's bridge address `172.17.0.9:22` from node-2 returned
`Connection refused` (SSH exit 255). Starting a second meshscale-sim sshd in
node-1 returned exit 1 and:

```text
meshscale sshd: listen on Mesh IP 100.96.0.2:22: listen tcp4 100.96.0.2:22: bind: address already in use; if OpenSSH owns this port (including 0.0.0.0 or ::), use --port or configure its ListenAddress to exclude the Mesh IP
```

Policy reload was verified without restarting the server:

1. Wrote root-owned 0600 `/etc/meshscale/ssh.json` with
   `{"rules":[{"from":["meshscale-docker-test-2"],"users":["root","testuser"]}]}`.
   `ssh root@100.96.0.2 whoami` returned `root`.
2. Replaced the rule with `from: ["different-device"]` and `users: ["testuser"]`.
   SSH as testuser was denied, exit 255.
3. Replaced the file with malformed JSON. SSH as testuser was denied, exit 255.
4. Removed the test policy. SSH as testuser returned `testuser`; default restored.

Selected actual audit lines (two accept lines per command are expected: one
for authentication and one for the new session channel):

```text
meshscale 2026/10/26 01:05:08 SSH policy absent: any participant in this account may log in as any non-root local user; create /etc/meshscale/ssh.json to restrict access
meshscale 2026/10/26 01:05:08 SSH listening on 100.96.0.2:22 host_key=SHA256:7MMP5uJ4O8qpp4uMgcn5fagO3FadItJONysyrwA8Mj8 policy="/etc/meshscale/ssh.json"
meshscale 2026/10/26 01:05:29 ssh decision=accept owner="warp_connector@example-team.cloudflareaccess.com" device="meshscale-docker-test-2" registration="00000000-0000-4000-8000-000000000002" ip="100.96.0.3" user="testuser" reason="identity and policy allow login"
meshscale 2026/10/26 01:05:32 ssh decision=deny owner="warp_connector@example-team.cloudflareaccess.com" device="meshscale-docker-test-2" registration="00000000-0000-4000-8000-000000000002" ip="100.96.0.3" user="root" reason="SSH policy does not allow this local user"
meshscale 2026/10/26 01:05:33 ssh decision=accept owner="warp_connector@example-team.cloudflareaccess.com" device="meshscale-docker-test-2" registration="00000000-0000-4000-8000-000000000002" ip="100.96.0.3" user="root" reason="identity and policy allow login"
meshscale 2026/10/26 01:05:33 ssh decision=deny owner="warp_connector@example-team.cloudflareaccess.com" device="meshscale-docker-test-2" registration="00000000-0000-4000-8000-000000000002" ip="100.96.0.3" user="testuser" reason="SSH policy does not allow this local user"
meshscale 2026/10/26 01:05:33 ssh decision=deny owner="warp_connector@example-team.cloudflareaccess.com" device="meshscale-docker-test-2" registration="00000000-0000-4000-8000-000000000002" ip="100.96.0.3" user="testuser" reason="read SSH policy: invalid character 'm' looking for beginning of value"
```

Unit tests cover policy evaluation/parsing, root and UID-0 aliases, protected
policy/key files, key persistence, registration joins and cache expiry/failure,
unknown/revoked/deleted/duplicate registrations, IP ranges, auth decisions and
logs, and complete in-process SSH handshakes with a fake identity source.
Handshake tests use Unix socket pairs without any host TCP listener. They verify
none authentication, default root denial, identity-source errors, forwarding
and agent rejection, environment filtering, exec/exit status, an empty exec
command, PTY resizing, and policy rechecks on an existing connection.

Validation:

```text
go vet ./...                                  PASS
go test ./...                                 PASS
go test -race -timeout 60s ./internal/sshserver ./cmd/meshscale  PASS
```

Only GET requests were made to Cloudflare. The containers, their WARP settings,
host networking, host DNS/routes/firewall and host sshd were left unchanged.
The host never ran WARP or a Mesh SSH listener. `/usr/local/bin/meshscale` in both
containers was preserved; our binary is named `meshscale-sim`.
