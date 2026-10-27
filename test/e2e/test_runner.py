"""Offline tests for the live runner's safety boundary."""
import importlib.util
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("battle_runner", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)


class SafetyTests(unittest.TestCase):
    def test_output_tail_redacts_before_truncating_both_streams(self):
        secret = "s" * 64
        tail = runner.output_tail("prefix " * 70 + "token=" + secret,
                                  "stderr failure Authorization: Bearer short-secret")
        self.assertLessEqual(len(tail), 300)
        self.assertNotIn(secret, tail)
        self.assertNotIn("short-secret", tail)
        self.assertIn("stderr failure", tail)
        self.assertIn("[redacted]", tail)

    def test_short_cli_secrets_are_redacted(self):
        tail = runner.output_tail("command --token short-private --password tiny-private", "")
        self.assertNotIn("short-private", tail)
        self.assertNotIn("tiny-private", tail)

    def test_failed_command_keeps_real_error(self):
        result = subprocess.CompletedProcess(["docker"], 1, "", "connect: connection refused")
        with patch.object(runner.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(AssertionError, "connection refused"):
                runner.run(["docker"])

    def test_timeout_keeps_redacted_partial_bytes(self):
        error = subprocess.TimeoutExpired(["docker"], 2, output=b"partial result",
                                          stderr=b"token=private-value")
        with patch.object(runner.subprocess, "run", side_effect=error):
            with self.assertRaises(AssertionError) as failure:
                runner.run(["docker"], timeout=2)
        self.assertIn("partial result", str(failure.exception))
        self.assertNotIn("private-value", str(failure.exception))

    def test_semantic_failure_keeps_last_command_output(self):
        with tempfile.TemporaryDirectory() as out:
            suite = runner.Suite(Path(out))
            def fail():
                result = subprocess.CompletedProcess(["docker"], 0, "unexpected data", "")
                with patch.object(runner.subprocess, "run", return_value=result):
                    runner.run(["docker"])
                raise AssertionError("invalid response")
            row = suite.case("offline", "semantic failure", fail)
            self.assertEqual(row["result"], "FAIL")
            self.assertIn("unexpected data", row["detail"])

    def test_exit_handshake_without_client_ipv4_binding_is_not_ready(self):
        suite = runner.Suite(Path("/tmp/unused"))
        client = suite.nodes[1]
        local = {"secure": {"running": True, "exit_node": runner.EXTRA, "ipv4": "10.200.1.2"}}
        peer = {"mesh_ip": client.ip, "exit_version": 2, "last_handshake": "recent"}
        remote = {"secure": {"offers_exit_node": True, "peers": [peer]}}
        with patch.object(suite, "local_status", side_effect=[local, remote]):
            with self.assertRaisesRegex(AssertionError, "published IPv4 binding"):
                suite.exit_binding_ready(client)
        peer["ipv4"] = "10.200.1.2"
        with patch.object(suite, "local_status", side_effect=[local, remote]):
            suite.exit_binding_ready(client)

    def test_exit_evidence_is_container_only_and_excludes_keys(self):
        with tempfile.TemporaryDirectory() as out:
            suite = runner.Suite(Path(out))
            suite.extra_created = True
            result = subprocess.CompletedProcess([], 0, "token=private-value", "")
            with patch.object(runner, "container_command", return_value=result) as execute:
                suite.exit_evidence("dedicated")
            self.assertNotIn("private-value", (Path(out) / "dedicated-routing.json").read_text())
            for call in execute.call_args_list:
                self.assertIn(call.args[0], (runner.CONTAINERS[1], runner.EXTRA))
                command = call.args[1]
                if command[0] == "wg":
                    self.assertIn(command[-1], ("latest-handshakes", "transfer"))

    def test_restore_removes_backups_as_the_container_user(self):
        suite = runner.Suite(Path("/tmp/unused"))
        name = runner.CONTAINERS[2]
        suite.original[name] = []
        suite.saved_settings.add(name)
        def execute(target, script, **kwargs):
            if kwargs.get("root") and "rm -rf /tmp/meshscale-battle-settings" in script:
                raise PermissionError("root without CAP_FOWNER cannot unlink another uid's sticky-directory entry")
            return subprocess.CompletedProcess([], 0, "{}", "")
        with patch.object(runner, "shell", side_effect=execute), \
                patch.object(runner, "container_command"), patch.object(runner.time, "sleep"):
            suite.restore_container(name)

    def test_cleanup_records_failure_and_continues_restoring_other_nodes(self):
        with tempfile.TemporaryDirectory() as out:
            suite = runner.Suite(Path(out))
            suite.original = {name: [] for name in runner.CONTAINERS[:2]}
            with patch.object(suite, "restore_container", side_effect=[AssertionError("fixture restore error"), "restored"]):
                suite.cleanup()
            self.assertEqual([row["result"] for row in suite.rows], ["FAIL", "PASS"])

    def test_host_rejects_mutating_commands_before_exec(self):
        node = runner.Node("host", "192.0.2.7", 22)
        for args in (["meshscale", "set", "--advertise-exit-node=false"], ["ip", "route"], ["systemctl", "restart", "warp-svc"], ["tailscale", "status"]):
            with self.subTest(args=args), patch.object(runner, "run") as execute:
                with self.assertRaises(ValueError):
                    node.call(args)
                execute.assert_not_called()

    def test_mac_rejects_writes_before_exec(self):
        node = runner.Node("mac", "192.0.2.6", 22)
        for args in ([runner.MAC_BIN, "up"], ["sudo", "true"], ["sh", "-c", "date -s now"]):
            with self.subTest(args=args), patch.object(runner, "run") as execute:
                with self.assertRaises(ValueError):
                    node.call(args)
                execute.assert_not_called()

    def test_other_projects_cannot_be_mutation_targets(self):
        with patch.object(runner, "run") as execute:
            with self.assertRaises(ValueError):
                runner.container_command("unrelated-project", ["ip", "route", "flush", "table", "all"])
            execute.assert_not_called()

    def test_revocation_requires_a_visible_registration(self):
        s = runner.Suite(Path("/tmp/unused"))
        s.extra_registration = "owned-registration"
        with patch.object(s, "api", return_value=[]) as api:
            with self.assertRaisesRegex(AssertionError, "not visible"):
                s.revoke_extra_registration()
            api.assert_called_once_with("GET", "devices/registrations?per_page=100")

    def test_revocation_deletes_only_the_observed_owned_registration(self):
        s = runner.Suite(Path("/tmp/unused"))
        s.extra_registration = "owned-registration"
        with patch.object(s, "api", side_effect=[[{"id": "owned-registration"}], None]) as api:
            s.revoke_extra_registration()
            self.assertEqual(api.call_args_list[1].args,
                             ("DELETE", "devices/registrations/owned-registration"))

    def test_revocation_uses_observed_canonical_native_registration(self):
        suite = runner.Suite(Path("/tmp/unused"))
        suite.extra_registration = "t.owned-registration"
        with patch.object(suite, "api", side_effect=[[{"id": "owned-registration"}], None]) as api:
            suite.revoke_extra_registration()
            self.assertEqual(api.call_args_list[1].args,
                             ("DELETE", "devices/registrations/owned-registration"))
            self.assertEqual(suite.extra_registration, "owned-registration")

    def test_cleanup_matches_native_secure_directory_identity(self):
        with tempfile.TemporaryDirectory() as out:
            s = runner.Suite(Path(out))
            s.extra_created = True
            s.extra_registration = "t.owned-registration"
            s.extra_node = "owned-node"
            lists = [{"id": "owned-list", "name": "meshscale-secure-v1-owned-registration"},
                     {"id": "other-list", "name": "meshscale-secure-v1-other-registration"}]
            with patch.object(s, "api", side_effect=lambda method, path: lists if method == "GET" else None) as api, \
                    patch.object(runner, "container_command"), patch.object(runner, "run"):
                s.cleanup_extra()
                deletions = [call.args[1] for call in api.call_args_list if call.args[0] == "DELETE"]
                self.assertIn("gateway/lists/owned-list", deletions)
                self.assertNotIn("gateway/lists/other-list", deletions)

    def test_account_writes_are_only_owned_deletions(self):
        s = runner.Suite(Path("/tmp/unused"))
        for method, resource in [("PATCH", "devices/settings"), ("DELETE", "devices/registrations/someone-else"), ("DELETE", "warp_connector/")]:
            with self.subTest(resource=resource):
                with self.assertRaises(AssertionError):
                    s.api(method, resource)


if __name__ == "__main__":
    unittest.main()
