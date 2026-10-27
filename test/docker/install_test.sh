#!/usr/bin/env bash
# Offline installer regressions. Never starts a service or a VPN.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
case $(uname -m) in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
artifacts=$test_root/artifacts
mkdir -p "$artifacts" "$test_root/input"
make_release() {
    printf '%s\n' "$1" > "$test_root/input/meshscale"
    tar -czf "$artifacts/meshscale_linux_$arch.tar.gz" -C "$test_root/input" meshscale
    (cd "$artifacts" && sha256sum "meshscale_linux_$arch.tar.gz" > SHA256SUMS)
}
installer() {
    sh "$repo/scripts/install.sh" --from-dir "$artifacts" --prefix "$test_root/install" "$@" > "$test_root/output" 2>&1
}
expect_failure() {
    if "$@" > "$test_root/output" 2>&1; then
        echo 'Installer unexpectedly succeeded' >&2
        exit 1
    fi
}
make_release version-one
installer
[[ $(cat "$test_root/install/bin/meshscale") == version-one ]]
[[ $(stat -c '%a' "$test_root/install/share/meshscale/install-receipt") == 600 ]]
make_release version-two
installer
[[ $(cat "$test_root/install/bin/meshscale") == version-two ]]
[[ $(cat "$test_root/install/bin/meshscale.prev") == version-one ]]
installer --rollback
[[ $(cat "$test_root/install/bin/meshscale") == version-one ]]
installer --uninstall
[[ ! -e "$test_root/install/bin/meshscale" ]]
# Modified binaries require an explicit force decision.
installer
printf modified > "$test_root/install/bin/meshscale"
expect_failure installer --uninstall
[[ -e "$test_root/install/bin/meshscale" ]]
installer --uninstall --force
# Corrupt archives and duplicate checksums fail before installing a binary.
printf corrupt >> "$artifacts/meshscale_linux_$arch.tar.gz"
expect_failure installer
[[ ! -e "$test_root/install/bin/meshscale" ]]
make_release version-three
cat "$artifacts/SHA256SUMS" > "$test_root/checksum"
cat "$test_root/checksum" >> "$artifacts/SHA256SUMS"
expect_failure installer
[[ ! -e "$test_root/install/bin/meshscale" ]]
make_release version-three
# A symlinked bin, prefix or ancestor must never redirect root installation.
mkdir "$test_root/target"
for level in bin prefix ancestor; do
    candidate=$test_root/symlink-$level
    case $level in
        bin) mkdir "$candidate"; ln -s "$test_root/target" "$candidate/bin" ;;
        prefix) ln -s "$test_root/target" "$candidate" ;;
        ancestor) ln -s "$test_root/target" "$candidate"; candidate=$candidate/child ;;
    esac
    expect_failure sh "$repo/scripts/install.sh" --from-dir "$artifacts" --prefix "$candidate"
    [[ ! -e "$test_root/target/meshscale" && ! -e "$test_root/target/child" ]]
done
mkdir "$test_root/writable"
chmod 0777 "$test_root/writable"
expect_failure sh "$repo/scripts/install.sh" --from-dir "$artifacts" --prefix "$test_root/writable"
[[ ! -e "$test_root/writable/bin" ]]
# Temporary bases require the same trusted ancestors as installation paths.
expect_failure env TMPDIR="$test_root/writable" sh "$repo/scripts/install.sh" --from-dir "$artifacts" --prefix "$test_root/temp-check"
[[ ! -e "$test_root/temp-check" ]]
if [[ $(id -u) == 0 ]]; then
    mkdir "$test_root/foreign"
    chown 65534:65534 "$test_root/foreign"
    expect_failure sh "$repo/scripts/install.sh" --from-dir "$artifacts" --prefix "$test_root/foreign"
    [[ ! -e "$test_root/foreign/bin" ]]
fi
# Dry runs are read-only even when all destinations are absent.
sh "$repo/scripts/install.sh" --from-dir "$artifacts" --prefix "$test_root/dry-run" --dry-run > "$test_root/output"
[[ ! -e "$test_root/dry-run" ]]
echo 'Offline installer regressions passed'
