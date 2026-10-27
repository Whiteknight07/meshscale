#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Darwin ]]; then
  echo 'Run this script on macOS with Xcode installed.' >&2
  exit 1
fi
cli_binary="${CLI_BINARY:-$PWD/bin/meshscale}"
app_path="${APP_OUTPUT:-$PWD/meshscale.app}"
bundle_id="${BUNDLE_ID:-com.whiteknight07.meshscale}"
app_version="${APP_VERSION:-0.1.0}"
app_build="${APP_BUILD:-1}"
signing_identity="${SIGNING_IDENTITY:--}"
license_file="${LICENSE_FILE:-$PWD/../LICENSE}"
dependency_notices="${DEPENDENCY_LICENSES_DIR:-}"
if [[ "$app_path" != /* || "$app_path" != *.app || -e "$app_path" || -L "$app_path" ]]; then
  echo 'APP_OUTPUT must be a new absolute .app path. Existing bundles are never overwritten.' >&2
  exit 1
fi
if [[ ! "$bundle_id" =~ ^[A-Za-z][A-Za-z0-9-]*(\.[A-Za-z0-9-]+)+$ ||
      ! "$app_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ || ! "$app_build" =~ ^[1-9][0-9]*$ ]]; then
  echo 'Invalid BUNDLE_ID, APP_VERSION (three numbers), or APP_BUILD (positive integer).' >&2
  exit 1
fi
if [[ ! -f "$cli_binary" ]]; then
  echo 'Missing Darwin CLI. Set CLI_BINARY or cross-build macos/bin/meshscale; see README.md.' >&2
  exit 1
fi
if [[ ! -s "$license_file" || ( -n "$dependency_notices" && ! -d "$dependency_notices" ) ]]; then
  echo 'A project LICENSE and any requested DEPENDENCY_LICENSES_DIR must exist.' >&2
  exit 1
fi
# Reject accidentally packaging a Linux binary or the wrong CPU architecture.
/usr/bin/lipo "$cli_binary" -verify_arch "$(uname -m)"
./scripts/swift.sh build -c release
build_path="$(./scripts/swift.sh build -c release --show-bin-path)"
# Build in a private sibling directory, then move only a verified bundle into place.
mkdir -p "$(dirname "$app_path")"
stage="$(mktemp -d "$(dirname "$app_path")/.meshscale-package.XXXXXXXX")"
trap 'rm -rf "$stage"' EXIT
destination="$app_path"
app_path="$stage/meshscale.app"
mkdir -p "$app_path/Contents/MacOS" "$app_path/Contents/Resources"
cp "$build_path/meshscale-menu" "$app_path/Contents/MacOS/meshscale-menu"
cp "$cli_binary" "$app_path/Contents/Resources/meshscale"
cp "$license_file" "$app_path/Contents/Resources/LICENSE"
if [[ -n "$dependency_notices" ]]; then
  ditto "$dependency_notices" "$app_path/Contents/Resources/third-party-licenses"
fi
# Bundle.module needs only the application's artwork. SwiftPM also creates test
# bundles here; never include those fixtures or other build products in the app.
resource_bundle="$build_path/meshscale_MeshscaleApp.bundle"
if [[ ! -d "$resource_bundle" ]]; then
  echo 'Missing application resource bundle.' >&2
  exit 1
fi
ditto "$resource_bundle" "$app_path/Contents/Resources/$(basename "$resource_bundle")"
chmod +x "$app_path/Contents/MacOS/meshscale-menu" "$app_path/Contents/Resources/meshscale"
cat > "$app_path/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$bundle_id</string>
<key>CFBundleName</key><string>meshscale</string>
<key>CFBundleDisplayName</key><string>meshscale</string>
<key>CFBundleExecutable</key><string>meshscale-menu</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>$app_version</string>
<key>CFBundleVersion</key><string>$app_build</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>LSUIElement</key><true/>
<key>NSHighResolutionCapable</key><true/>
<key>NSAppleEventsUsageDescription</key><string>Open SSH sessions in Terminal.</string>
<key>NSLocalNetworkUsageDescription</key><string>Find and connect to devices on your Cloudflare Mesh network.</string>
</dict></plist>
PLIST
signing_options=(--force --options runtime --sign "$signing_identity")
if [[ "$signing_identity" == - ]]; then
  signing_options+=(--timestamp=none)
else
  signing_options+=(--timestamp)
fi
codesign "${signing_options[@]}" "$app_path/Contents/Resources/meshscale"
codesign "${signing_options[@]}" --entitlements "$PWD/Resources/meshscale.entitlements" "$app_path"
codesign --verify --deep --strict "$app_path"
/usr/bin/plutil -lint "$app_path/Contents/Info.plist"
# Refuse a destination created while Swift was building as well.
if [[ -e "$destination" || -L "$destination" ]]; then
  echo 'APP_OUTPUT appeared during packaging; refusing to overwrite it.' >&2
  exit 1
fi
mv "$app_path" "$destination"
echo "Built $destination"
