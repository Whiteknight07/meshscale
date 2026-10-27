# Native WireGuard feasibility prototype

This separate Go module explored client-free registration and a userspace WireGuard/netstack path over Cloudflare Mesh. The maintained opt-in backend, caveats, and supported behavior are documented in [native.md](../../docs/native.md).

Registration uses an undocumented device API. Prototype success does not establish vendor support or permission, renewal behavior, posture compatibility, or macOS VPN readiness. The official client remains the default.

Build-only checks from this directory do not enroll anything:

```sh
go test ./...
go vet ./...
```

Running the binaries can enroll devices or change remote state. Inspect their flags and use only separately authorized disposable resources. Never print or commit the registration state, device bearer, private key, enrollment token, or administrative credentials.

Account-specific evidence and the developer-workspace launcher were removed for public release. Research copies under the ignored `research/` directory are not part of the repository or release. The prototype's API investigation used [wgcf-mesh](https://github.com/AnimMouse/wgcf-mesh), [usque](https://github.com/Diniboy1123/usque), and [wgcf](https://github.com/ViRb3/wgcf) as references; the prototype was independently implemented, as recorded in its original research notes. Any future copied code must retain upstream licensing and attribution.
