# Contributing

Small, focused bug fixes, tests, documentation, and reproducible issue reports are welcome. Discuss substantial architecture or new vendor integrations in an issue before implementing them. Follow the [code of conduct](CODE_OF_CONDUCT.md); report vulnerabilities privately through [SECURITY.md](SECURITY.md).

## Development setup

Use the Go version in `go.mod`, Node/npm for the TypeScript projects, and macOS with the Swift toolchain for the native app. The control project's build/deployment tooling additionally uses Bun. Use disposable Cloudflare accounts/devices for integration work. Unit tests do not need real credentials.

```sh
go build ./cmd/meshscale
gofmt -l .
go vet ./...
GOOS=darwin go vet ./...
go test -race -count=1 ./...
# If installed:
staticcheck ./...
```

`gofmt -l .` must print no files. Keep fixes scoped and add a regression test for behavior changes. Do not update dependency versions or generated files without explaining why.

For the admin console, run from `control/`:

```sh
npm ci
npm test
npm run typecheck
npm run format:check
npm run lint
```

`npm run build` builds the browser bundle and requires Bun. Deploy and destroy scripts write to a Cloudflare account: they are not local validation commands. See [admin-console.md](docs/admin-console.md).

For the design/reference frontend, run from `app/frontend/`:

```sh
npm ci
npm run build
```

For the Swift app, run on a Mac:

```sh
cd macos
./scripts/swift.sh test
```

Follow [macos/README.md](macos/README.md) for bundle builds. Linux cannot validate SwiftUI app builds. Screenshots must use reserved example addresses and synthetic identities; see the [screenshot policy](macos/screenshots/README.md).

## Linux namespace integration tests

These tests require Linux, root or the corresponding namespace/network capabilities, `iproute2`, `util-linux` (`unshare`, `nsenter`), `nftables`, `/dev/net/tun`, and kernel WireGuard where applicable. Run them only on a disposable Linux VM. Never enable live tests in the network namespace of a machine used for remote access.

Compile first, then enter a fresh anonymous network namespace for each invocation. The namespace disappears when its process exits; the host's routes/firewall remain outside it:

```sh
go test -c -o /tmp/meshscale-routing.test ./internal/linuxnetwork
sudo unshare -n sh -c 'ip link set lo up; MESHSCALE_ROUTING_NAMESPACE_TEST=1 /tmp/meshscale-routing.test -test.run "^TestKernelRoutingNamespace$" -test.v'

go test -c -o /tmp/meshscale-secure.test ./internal/secure
sudo unshare -n sh -c 'ip link set lo up; MESHSCALE_TEST_SECURE_TUN=1 /tmp/meshscale-secure.test -test.run "^TestSecureLinuxTUN$" -test.v'

go test -c -o /tmp/meshscale-exit.test ./internal/exitnode
sudo unshare -n sh -c 'ip link set lo up; MESHSCALE_EXIT_NETNS_TEST=1 /tmp/meshscale-exit.test -test.run "^(TestLinuxExitDataPath|TestNFTSyntaxInIsolatedNamespace)$" -test.v'
```

The exit test also creates child namespaces. These commands do not enroll devices or change Cloudflare resources. Other opt-in live tests and scripts may do so: inspect their code and documentation before running them. Docker harnesses in `test/` are integration references, not supported production deployment manifests; never use host networking for them.

## Changes and review

Use imperative commit subjects describing the concrete change, such as `Fix stale device cache after cancellation`. Keep unrelated changes in separate commits. Include the problem, resulting behavior, test commands/results, platform limitations, and any migration or security consequences in the pull request. Update the affected user docs. Do not claim live verification for a unit test or an untested platform.

Do not commit credentials, private keys, account/device identifiers, personal addresses, packet captures, or raw live diagnostics. Use `example.com`, `example-team`, documentation IP ranges, and clearly synthetic UUIDs. Review both staged changes and images before submission. Keep state and environment files outside tracked paths. A scanner passing does not prove a file is safe to publish.
