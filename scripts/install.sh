#!/bin/sh
# Guided release installation. Read-only host detection also runs in dry-run mode.
set -eu

fail() { printf 'meshscale installer: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }
usage() {
    cat <<'EOF'
Usage: install.sh [--version vX.Y.Z|latest] [--prefix DIR] [--from-dir DIR]
                  [--with-cloudflare-client] [--service] [--dry-run] [--force]
       install.sh --rollback|--uninstall [--prefix DIR] [--dry-run] [--force]

Default: latest published release, /usr/local/bin/meshscale. No compiler needed.
--from-dir reads release archives and SHA256SUMS locally, without downloading.
--with-cloudflare-client explicitly permits official repository/package setup.
--service explicitly installs/starts the system meshscale service as root.
--rollback restores bin/meshscale.prev, consuming that backup.
A private share/meshscale/install-receipt records installed paths and hashes.
--force explicitly permits replacing/removing untracked or modified binaries.
--uninstall removes only bin/meshscale and bin/meshscale.prev; clean up network,
service and enrollment first. Cloudflare packages and private state are retained.
--dry-run prints planned commands; no downloads, writes or service operations.
EOF
}

dry_run=false
force=false
with_client=false
service=false
mode=install
version=latest
prefix=/usr/local
from_dir=
while [ "$#" -gt 0 ]; do
    case $1 in
        --version|--prefix|--from-dir)
            [ "$#" -ge 2 ] && [ -n "$2" ] || fail "$1 requires a value"
            case $1 in
                --version) version=$2 ;;
                --prefix) prefix=$2 ;;
                --from-dir) from_dir=$2 ;;
            esac
            shift 2 ;;
        --dry-run) dry_run=true; shift ;;
        --force) force=true; shift ;;
        --with-cloudflare-client) with_client=true; shift ;;
        --service) service=true; shift ;;
        --rollback|--uninstall)
            [ "$mode" = install ] || fail 'choose only one of --rollback and --uninstall'
            mode=${1#--}; shift ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unknown option: $1 (see --help)" ;;
    esac
done
case $prefix in /*) ;; *) fail '--prefix must be an absolute path' ;; esac
prefix=${prefix%/}
[ -n "$prefix" ] || fail '--prefix must not be /'
case $from_dir in ''|/*) ;; *) from_dir=$PWD/$from_dir ;; esac
if [ "$mode" != install ]; then
    [ "$with_client" = false ] && [ "$service" = false ] || fail 'client/service flags require installation'
fi
if [ "$with_client" = true ] || [ "$service" = true ]; then
    [ "$prefix" = /usr/local ] || fail 'client/service setup requires the default /usr/local prefix'
fi

# Quote arguments so that printed commands are also usable with paths containing
# spaces or quotes. Every external operation with side effects goes through run.
print_argument() {
    quoted=$(printf '%s' "$1" | sed "s/'/'\\\\''/g")
    printf " '%s'" "$quoted"
}
print_command() {
    printf '$'
    for argument do
        print_argument "$argument"
    done
}
run() {
    print_command "$@"; printf '\n'
    if [ "$dry_run" = false ]; then "$@"; fi
}
run_to() {
    output=$1; shift
    print_command "$@"; printf ' >'; print_argument "$output"; printf '\n'
    if [ "$dry_run" = false ]; then "$@" > "$output"; fi
}
need() { command -v "$1" >/dev/null 2>&1 || fail "required command missing: $1"; }

os=$(uname -s)
[ "$os" = Linux ] || fail "unsupported OS: $os (this installer requires Linux)"
machine=$(uname -m)
case $machine in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) fail "unsupported architecture: $machine (supported: amd64, arm64)" ;;
esac
[ -r /etc/os-release ] || fail 'unsupported OS: /etc/os-release is missing'
# os-release is supplied by the local OS, never downloaded.
# shellcheck disable=SC1091
. /etc/os-release
distro=${ID:-unknown}
codename=${VERSION_CODENAME:-}
case $distro in
    debian|ubuntu)
        family=deb
        case "$distro:$codename" in
            debian:bookworm|debian:trixie|ubuntu:jammy|ubuntu:noble|ubuntu:resolute) ;;
            *) fail "unsupported distribution: $distro ${VERSION_ID:-unknown}; see https://pkg.cloudflareclient.com/" ;;
        esac ;;
    rhel|centos|rocky|almalinux|ol)
        family=el
        case ${VERSION_ID:-} in
            9|9.*|10|10.*) ;;
            *) fail "unsupported EL version: ${VERSION_ID:-unknown} (requires EL 9 or 10)" ;;
        esac ;;
    *) fail "unsupported distribution: $distro (Debian/Ubuntu or EL 9/10 required)" ;;
esac
note "Detected Linux/$arch, $distro ${VERSION_ID:-unknown}; mode=$mode; prefix=$prefix"
[ "$family" != el ] || note 'EL is a separate qualification track; package dependency failures stop installation.'

bindir=$prefix/bin
binary=$bindir/meshscale
previous=$bindir/meshscale.prev
receipt_dir=$prefix/share/meshscale
receipt=$receipt_dir/install-receipt
# Check every existing ancestor before reading receipts or writing binaries.
# A trusted leaf under an attacker-owned prefix is still replaceable. Sticky
# directories such as /tmp are allowed only above the destination directory.
need stat
installer_uid=$(id -u)
check_directory_path() {
    checked=$1
    destination=$1
    allow_sticky=${2:-false}
    case $checked in /*) ;; *) fail "directory path must be absolute: $checked" ;; esac
    while :; do
        [ ! -L "$checked" ] || fail "refusing directory symlink: $checked"
        if [ -e "$checked" ]; then
            [ -d "$checked" ] || fail "not a directory: $checked"
            directory_uid=$(stat -c '%u' -- "$checked")
            directory_mode=$(stat -c '%a' -- "$checked")
            [ "$directory_uid" = 0 ] || [ "$directory_uid" = "$installer_uid" ] || fail "untrusted directory owner: $checked"
            permissions=$((0$directory_mode))
            if [ "$((permissions & 0022))" -ne 0 ]; then
                { [ "$checked" != "$destination" ] || [ "$allow_sticky" = true ]; } && [ "$((permissions & 01000))" -ne 0 ] || fail "group/other writable directory: $checked"
            fi
        fi
        [ "$checked" != / ] || break
        checked=$(dirname -- "$checked")
    done
}
for path in "$prefix" "$bindir" "$prefix/share" "$receipt_dir"; do
    check_directory_path "$path"
done
for path in "$prefix/share" "$receipt_dir"; do
    [ ! -L "$path" ] || fail "refusing symlink: $path"
    [ ! -e "$path" ] || [ -d "$path" ] || fail "not a directory: $path"
done
[ ! -L "$receipt" ] || fail "refusing symlink: $receipt"
[ ! -e "$receipt" ] || [ -f "$receipt" ] || fail "not a regular file: $receipt"
need sha256sum
need awk

# The receipt contains only fixed relative paths, never executable shell text.
# Validate all entries before consulting a hash, including duplicates.
receipt_valid=false
if [ -f "$receipt" ] && awk -F '\t' '
    NF != 2 || ($1 != "bin/meshscale" && $1 != "bin/meshscale.prev") ||
    length($2) != 64 || $2 ~ /[^0-9a-f]/ || seen[$1]++ { exit 1 }
    END { if (NR == 0) exit 1 }
' "$receipt"; then
    receipt_valid=true
fi
require_owned() {
    owned_path=$1
    relative_path=$2
    [ -e "$owned_path" ] || return 0
    if [ "$force" = true ]; then return 0; fi
    expected=
    if [ "$receipt_valid" = true ]; then
        expected=$(awk -F '\t' -v "path=$relative_path" '$1 == path {print $2}' "$receipt")
    fi
    actual=$(sha256sum < "$owned_path")
    actual=${actual%% *}
    if [ -z "$expected" ] || [ "$actual" != "$expected" ]; then
        fail "refusing untracked or modified path: $owned_path; review and delete it manually, or rerun with --force"
    fi
}
write_receipt() {
    run install -d -m 0755 "$prefix/share"
    run install -d -m 0700 "$receipt_dir"
    # umask applies before the temporary receipt is created; rename is atomic.
    # Positional arguments preserve prefixes containing spaces or shell syntax.
    run sh -c '
        set -eu
        umask 077
        receipt_tmp=$(mktemp "$1/.install-receipt.XXXXXXXX")
        cleanup_receipt() { rm -f "$receipt_tmp"; }
        trap cleanup_receipt EXIT
        for relative in bin/meshscale bin/meshscale.prev; do
            if [ -f "$2/$relative" ]; then
                digest=$(sha256sum < "$2/$relative")
                digest=${digest%% *}
                printf "%s\t%s\n" "$relative" "$digest" >> "$receipt_tmp"
            fi
        done
        chmod 0600 "$receipt_tmp"
        mv -f "$receipt_tmp" "$1/install-receipt"
    ' sh "$receipt_dir" "$prefix"
}
for path in "$binary" "$previous" "$bindir/.meshscale.new" "$bindir/.meshscale.prev.new"; do
    [ ! -L "$path" ] || fail "refusing symlink: $path"
    [ ! -e "$path" ] || [ -f "$path" ] || fail "not a regular file: $path"
done
# Check every affected binary before any mutation, including upgrades and
# dry-runs. --force never bypasses the regular-file/symlink checks above.
require_owned "$binary" bin/meshscale
require_owned "$previous" bin/meshscale.prev
case $mode in
    rollback)
        [ -f "$previous" ] || fail "no previous binary at $previous"
        run mv -f "$previous" "$binary"
        write_receipt
        note 'Previous binary restored. Restart an existing service explicitly when ready.'
        exit 0 ;;
    uninstall)
        # Alternate prefixes are isolated tests and never consult /etc.
        if [ "$prefix" = /usr/local ] && [ "$(id -u)" -eq 0 ]; then
            [ -r /etc/hosts ] || fail 'cannot check hosts DNS cleanup: /etc/hosts is unreadable'
            if awk '/^# BEGIN meshscale hosts v1/ { found=1 } END { exit !found }' /etc/hosts; then
                [ -f "$binary" ] || fail 'run a trusted meshscale dns cleanup-hosts before uninstalling; installed CLI is missing'
                # --force authorizes deletion, never execution of a modified CLI.
                expected=
                if [ "$receipt_valid" = true ]; then
                    expected=$(awk -F '\t' '$1 == "bin/meshscale" {print $2}' "$receipt")
                fi
                actual=$(sha256sum < "$binary")
                actual=${actual%% *}
                [ -n "$expected" ] && [ "$actual" = "$expected" ] || fail 'run a trusted meshscale dns cleanup-hosts before uninstalling an untracked or modified CLI'
                run "$binary" dns cleanup-hosts
            fi
        fi
        note 'Remove only meshscale binaries. Existing services, network state and Cloudflare packages must be managed separately.'
        run rm -f "$binary" "$previous"
        run rm -f "$receipt"
        exit 0 ;;
esac

if [ "$version" != latest ]; then
    case $version in v*) ;; *) version=v$version ;; esac
    case $version in v[0-9]*) ;; *) fail 'version must be latest or a v-prefixed numeric release tag' ;; esac
    case $version in *[!a-zA-Z0-9._+-]*) fail 'invalid characters in version' ;; esac
fi
for command in install mv cp tar gzip sha256sum awk mktemp sed; do need "$command"; done
[ -n "$from_dir" ] || need curl
if [ "$dry_run" = false ] && { [ "$with_client" = true ] || [ "$service" = true ]; }; then
    [ "$(id -u)" -eq 0 ] || fail 'client/service setup requires root; run sudo -H sh install.sh with your flags'
fi

tmp=
check_directory_path "${TMPDIR:-/tmp}" true
cleanup() {
    if [ -n "$tmp" ]; then run rm -rf "$tmp"; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
if [ "$dry_run" = true ]; then
    tmp=${TMPDIR:-/tmp}/meshscale.dry-run
    run mktemp -d "${TMPDIR:-/tmp}/meshscale.XXXXXXXX"
    note "# Dry-run placeholder for the random temporary directory: $tmp"
else
    print_command mktemp -d "${TMPDIR:-/tmp}/meshscale.XXXXXXXX"; printf '\n'
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/meshscale.XXXXXXXX")
fi

asset=meshscale_linux_$arch.tar.gz
if [ -n "$from_dir" ]; then
    run cp "$from_dir/$asset" "$tmp/$asset"
    run cp "$from_dir/SHA256SUMS" "$tmp/SHA256SUMS"
else
    base=https://github.com/Whiteknight07/meshscale/releases
    if [ "$version" = latest ]; then base=$base/latest/download; else base=$base/download/$version; fi
    run curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$tmp/$asset" "$base/$asset"
    run curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$tmp/SHA256SUMS" "$base/SHA256SUMS"
fi
# Select exactly one well-formed digest, ignoring unrelated release assets.
# The dollar expressions below are awk fields, not shell expansion.
# shellcheck disable=SC2016
run_to "$tmp/SHA256SUMS.selected" awk -v "asset=$asset" '
    $2 == asset {
        if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-fA-F]/) exit 1
        print $1 "  " asset
        found++
    }
    END { if (found != 1) exit 1 }
' "$tmp/SHA256SUMS" || fail 'missing, duplicate or malformed archive checksum'
run sh -c 'cd "$1" && sha256sum -c SHA256SUMS.selected' sh "$tmp" || fail 'checksum verification failed; nothing installed'
run tar -xzf "$tmp/$asset" -C "$tmp" meshscale
if [ "$dry_run" = false ]; then
    [ -f "$tmp/meshscale" ] && [ ! -L "$tmp/meshscale" ] || fail 'archive binary is not a regular file'
fi

if command -v warp-cli >/dev/null 2>&1; then
    note 'Official Cloudflare client found (warp-cli).'
else
    note 'Official Cloudflare client missing. Repository instructions: https://pkg.cloudflareclient.com/'
    note 'Install curl and gnupg first on Debian/Ubuntu; enable the appropriate EPEL repository first on EL.'
    note 'These official repository/package commands run ONLY with --with-cloudflare-client:'
    # Print the same commands when consent was not given; restore dry-run after
    # this block so the requested meshscale installation can still proceed.
    requested_dry_run=$dry_run
    if [ "$with_client" = false ]; then dry_run=true; fi
    if [ "$family" = deb ]; then
        if [ "$with_client" = true ]; then need curl; need gpg; need apt-get; fi
        run curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$tmp/cloudflare.gpg" https://pkg.cloudflareclient.com/pubkey.gpg
        run gpg --batch --yes --dearmor --output "$tmp/cloudflare-keyring.gpg" "$tmp/cloudflare.gpg"
        run install -d -m 0755 /usr/share/keyrings /etc/apt/sources.list.d
        run install -m 0644 "$tmp/cloudflare-keyring.gpg" /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        run_to /etc/apt/sources.list.d/cloudflare-client.list printf '%s\n' "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $codename main"
        run apt-get update
        run apt-get install -y cloudflare-warp
    else
        if [ "$with_client" = true ]; then need curl; need rpm; need dnf; fi
        note '# EL requires correctly configured EPEL; no dependency bypass is used.'
        run curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$tmp/cloudflare-warp.repo" https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo
        run curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --output "$tmp/cloudflare.gpg" https://pkg.cloudflareclient.com/pubkey.gpg
        run rpm --import "$tmp/cloudflare.gpg"
        run install -m 0644 "$tmp/cloudflare-warp.repo" /etc/yum.repos.d/cloudflare-warp.repo
        run dnf install -y cloudflare-warp
    fi
    run systemctl enable --now warp-svc
    run warp-cli --version
    dry_run=$requested_dry_run
    if [ "$with_client" = false ]; then
        note 'Client setup skipped. Install it separately or rerun with --with-cloudflare-client before connecting.'
        [ "$service" = false ] || fail '--service requires the official client; add --with-cloudflare-client'
    fi
fi

run install -d -m 0755 "$bindir"
run install -m 0755 "$tmp/meshscale" "$bindir/.meshscale.new"
if [ -f "$binary" ]; then
    run install -m 0755 "$binary" "$bindir/.meshscale.prev.new"
    run mv -f "$bindir/.meshscale.prev.new" "$previous"
fi
run mv -f "$bindir/.meshscale.new" "$binary"
write_receipt
note "Installed binary path: $binary (previous version, if any: $previous)"
if [ "$service" = true ]; then
    need systemctl
    # Match the root HOME used by the documented login/up flow.
    run env HOME=/root XDG_CONFIG_HOME=/root/.config "$binary" service install
else
    note 'Background service skipped. Opt in with --service or meshscale service install after login/up.'
fi
note 'Next: sudo -H meshscale login --no-browser; sudo -H meshscale up --hostname my-linux-node'
