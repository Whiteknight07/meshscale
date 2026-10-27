# Share a localhost service with Mesh

Bind your app to `127.0.0.1`, connect Mesh, then:

```sh
meshscale serve 9000
# From another participant:
curl http://my-device.mesh:9000/
```

`meshscale serve <port> [--mesh-port N] [--tcp]` forwards raw TCP from this
device's assigned Mesh addresses to `127.0.0.1:<port>`. The mesh port defaults
to the local port. Flags follow the positional port. HTTP, HTTPS, and other TCP
protocols pass through unchanged; meshscale does not terminate TLS, add HTTP
headers, or use UDP. The proxy preserves TCP half-closes but the localhost app
sees a loopback peer, not the remote participant's address.

```sh
meshscale serve 3000 --mesh-port 8080 --tcp
meshscale serve status
meshscale serve off                 # remove every forward on this device
```

With a running daemon, configuration is saved privately and forwarding runs in
that daemon, returning immediately. It is restored after daemon restart. With
no running daemon and no installed Linux service, `serve` runs in the foreground
until Ctrl-C/SIGTERM or `serve off`. Foreground configuration is temporary. `serve off` also clears saved forwards when
the daemon is stopped; offline status reports the saved configuration. A
stopped installed Linux service causes an error so a transient foreground
process does not silently take over its configuration. Run commands with the
same user and configuration as the daemon.

Official WARP binds explicit, locally assigned Mesh IPv4/IPv6 addresses. Native
userspace leases listeners through the existing native control socket and
netstack; it needs neither a TUN nor root. Native TUN uses OS listeners.
Wildcard/public addresses are never bound. The selected backend must already
be connected and match a unique active registration in the configured account.

A conflicting bind fails without replacing the existing listener. Use a
different `--mesh-port`, or turn forwarding off before changing its target.
Each forward admits at most 128 simultaneous TCP streams. Closing forwarding
also closes active proxied connections. Cloudflare's account network rules and
Mesh enrollment still control reachability; `serve` creates no Gateway rule or
public tunnel. Anyone on the mesh allowed to reach this TCP port can use the
application, so retain the application's own authentication where needed.

`meshscale funnel` is a stub: public sharing is coming later and will require a
domain and Cloudflare Tunnel. It performs no account changes.

See [daemon operation](service.md) and [container evidence](../test/docker/SERVICE.md).
