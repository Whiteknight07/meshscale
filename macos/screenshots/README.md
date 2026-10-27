# Screenshot review and privacy

The retained signed-out/sign-in images contain no account or device data. Account-bearing snapshots and comparison sheets were removed before public release: their fixture email used a real mail domain rather than a reserved example domain. The exact removed files are listed in [removed artifacts](../../docs/release/removed-artifacts.md).

Generate replacement snapshots only after the Swift and web fixtures use synthetic names, reserved `example.com` addresses, and documented example IPs. Inspect every image, including comparison sheets, before committing. Do not include real account names, emails, team domains, device IDs, Mesh/public IPs, or desktop chrome. Generated verification manifests must describe the actual retained images.

On a Mac, see [the app instructions](../README.md) for snapshot/build tooling. The web reference is in [app/frontend](../../app/frontend/README.md). Removing snapshots does not remove their copies from Git history.
