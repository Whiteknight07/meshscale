#!/usr/bin/env python3
"""Packaging contract tests; only build temporary bundles, never launch the app."""
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == "darwin", "app packaging requires macOS")
class PackagingTests(unittest.TestCase):
    def run_build(self, output, **overrides):
        env = os.environ.copy()
        env.update(APP_OUTPUT=str(output), BUNDLE_ID="org.example.meshscale", APP_VERSION="1.2.3", APP_BUILD="42", SIGNING_IDENTITY="-")
        env.update(overrides)
        return subprocess.run([str(ROOT / "scripts/build-app.sh")], env=env, capture_output=True, text=True, timeout=300)

    def test_bundle_metadata_signatures_and_existing_output_protection(self):
        with tempfile.TemporaryDirectory(prefix="meshscale-package-test-") as directory:
            output = Path(directory) / "meshscale.app"
            notices = Path(directory) / "notices"
            notices.mkdir()
            (notices / "NOTICE").write_text("Example dependency notice")
            result = self.run_build(output, DEPENDENCY_LICENSES_DIR=str(notices))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            with (output / "Contents/Info.plist").open("rb") as handle:
                info = plistlib.load(handle)
            self.assertEqual(info["CFBundleIdentifier"], "org.example.meshscale")
            self.assertEqual(info["CFBundleShortVersionString"], "1.2.3")
            self.assertEqual(info["CFBundleVersion"], "42")
            self.assertTrue(info["LSUIElement"])
            self.assertEqual(info["LSMinimumSystemVersion"], "14.0")
            self.assertTrue(info["NSAppleEventsUsageDescription"])
            self.assertTrue(info["NSLocalNetworkUsageDescription"])
            self.assertTrue((output / "Contents/Resources/LICENSE").is_file())
            self.assertEqual((output / "Contents/Resources/third-party-licenses/NOTICE").read_text(), "Example dependency notice")
            for path in [output, output / "Contents/Resources/meshscale"]:
                signature = subprocess.run(["/usr/bin/codesign", "-d", "--verbose=4", str(path)], capture_output=True, text=True, check=True)
                self.assertIn("runtime", signature.stderr)
                self.assertIn("Signature=adhoc", signature.stderr)
            entitlements = subprocess.run(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(output)], capture_output=True, check=True)
            self.assertEqual(plistlib.loads(entitlements.stdout), {"com.apple.security.automation.apple-events": True})
            subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(output)], check=True)
            marker = output / "do-not-overwrite"
            marker.write_text("existing app")
            again = self.run_build(output)
            self.assertNotEqual(again.returncode, 0)
            self.assertIn("never overwritten", again.stderr)
            self.assertEqual(marker.read_text(), "existing app")

    def test_invalid_metadata_and_output_are_rejected_before_building(self):
        with tempfile.TemporaryDirectory(prefix="meshscale-package-test-") as directory:
            output = Path(directory) / "meshscale.app"
            for overrides in [{"BUNDLE_ID": "invalid</string>"}, {"APP_VERSION": "1.0</string>"}, {"APP_BUILD": "0"}, {"APP_OUTPUT": "relative.app"}]:
                with self.subTest(overrides=overrides):
                    result = self.run_build(output, **overrides)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())

    def test_only_application_resources_are_packaged(self):
        result = subprocess.run([str(ROOT / "scripts/swift.sh"), "build", "-c", "release", "--show-bin-path"], capture_output=True, text=True, check=True, timeout=300)
        build_path = Path(result.stdout.strip())
        build_path.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="unrelated-tests-", suffix=".bundle", dir=build_path) as unrelated:
            (Path(unrelated) / "test-fixture.json").write_text('{"fixture":true}')
            with tempfile.TemporaryDirectory(prefix="meshscale-package-test-") as directory:
                output = Path(directory) / "meshscale.app"
                result = self.run_build(output)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                bundles = sorted(p.name for p in (output / "Contents/Resources").glob("*.bundle"))
                self.assertEqual(bundles, ["meshscale_MeshscaleApp.bundle"])


if __name__ == "__main__":
    unittest.main()
