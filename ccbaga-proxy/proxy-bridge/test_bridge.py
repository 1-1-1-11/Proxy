"""Offline contract tests. No real user config, processes, repair or network."""
import copy
import json
from pathlib import Path
import types
import tempfile
import unittest
from unittest.mock import patch
import contextlib
import io
from bridge import BASE, Bridge, Failure, RECOVERING, REQUIRED, TITLES, SUPPORTED_VERSION, main, parse, release


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.rows = [{"id": key, "ok": True, "entries": [e for e in REQUIRED if key in REQUIRED[e]],
                      "detail": "SECRET-DO-NOT-SHOW", "evidence": {"token": "SECRET-DO-NOT-SHOW"}}
                     for key in set.union(*REQUIRED.values())]
        self.raw = {"entries": {e: "READY" for e in REQUIRED}, "checks": self.rows, "notes": ["SECRET-DO-NOT-SHOW"]}
        self.backend = types.SimpleNamespace(
            VERSION=SUPPORTED_VERSION, HERE=Path("not-a-real-installation"),
            run=lambda mode, workspace: copy.deepcopy(self.raw),
            load_policy=lambda: {"entry_port": 17892, "expected_ip": "203.0.113.7", "password": "SECRET-DO-NOT-SHOW"},
            guard_check=lambda: {"ok": True, "evidence": {"age_seconds": 4}},
        )
        self.bridge = Bridge(self.backend)

    def test_complete_evidence_is_ready_and_no_raw_secrets_escape(self):
        report = self.bridge.audit()
        self.assertEqual(set(report["entries"].values()), {"ready"})
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertEqual(report["endpoint"], "http://127.0.0.1:17892")

    def test_missing_worker_cannot_pass_even_if_backend_says_ready(self):
        self.raw["checks"] = [r for r in self.rows if r["id"] != "fixed_egress"]
        self.assertEqual(set(self.bridge.audit()["entries"].values()), {"unknown"})

    def test_failed_exit_blocks_all_entries(self):
        next(r for r in self.rows if r["id"] == "fixed_egress")["ok"] = False
        self.assertEqual(set(self.bridge.audit()["entries"].values()), {"blocked"})

    def test_unknown_guard_revokes_old_ready_report(self):
        self.backend.guard_check = lambda: {"ok": None, "evidence": {"age_seconds": 121}}
        self.assertEqual(set(self.bridge.audit()["entries"].values()), {"unknown"})

    def test_cowork_check_required_only_when_installed(self):
        next(r for r in self.rows if r["id"] == "desktop_protection")["evidence"]["cowork_installed"] = True
        self.assertEqual(self.bridge.audit()["entries"]["desktop"], "unknown")

    def test_launch_rechecks_and_does_not_spawn_on_failure(self):
        self.backend.guard_check = lambda: {"ok": False, "evidence": {"fixed_exit_blocked": True}}
        with patch("bridge.subprocess.Popen") as spawn:
            self.assertEqual(self.bridge.launch("cli")["action"], "blocked")
            spawn.assert_not_called()

    def test_allowed_cli_uses_only_fixed_launcher_with_literal_environment_argument(self):
        with tempfile.TemporaryDirectory(prefix="ccbaga-bridge-") as folder:
            self.backend.HERE = Path(folder)
            (self.backend.HERE / "claude-fixed.cmd").write_text("@echo off\n", encoding="utf8")
            with patch("bridge.subprocess.Popen") as spawn:
                self.assertEqual(self.bridge.launch("cli")["action"], "requested")
                args, kwargs = spawn.call_args
                self.assertEqual(args[0][-2:], ["-Command", "& $env:CCBAGA_FIXED_CLI"])
                self.assertEqual(kwargs["env"]["CCBAGA_FIXED_CLI"], str(self.backend.HERE / "claude-fixed.cmd"))
                self.assertEqual(kwargs["cwd"], Path.home())

    def test_chosen_workspace_is_audited_and_used_as_cli_folder(self):
        with tempfile.TemporaryDirectory(prefix="ccbaga-bridge-") as folder, \
                tempfile.TemporaryDirectory(prefix="ccbaga-project-") as project:
            self.backend.HERE = Path(folder)
            (self.backend.HERE / "claude-fixed.cmd").write_text("@echo off\n", encoding="utf8")
            command, workspace = parse(["launch-cli", project])
            bridge = Bridge(self.backend, workspace)
            with patch.object(self.backend, "run", return_value=copy.deepcopy(self.raw)) as run, \
                    patch("bridge.subprocess.Popen") as spawn:
                self.assertEqual(bridge.dispatch(command)["action"], "requested")
                run.assert_called_once_with("launch", Path(project))
                self.assertEqual(spawn.call_args[1]["cwd"], Path(project))
            self.assertEqual(bridge.status()["workspace"], project)

    def test_workspace_argument_must_be_an_existing_absolute_folder(self):
        with tempfile.TemporaryDirectory(prefix="ccbaga-project-") as project:
            for argv in ([], ["check", "relative"], ["check", str(Path(project) / "missing")],
                         ["check", project, "extra"]):
                with self.subTest(argv=argv), self.assertRaises(ValueError):
                    parse(argv)
            self.assertEqual(parse(["check"]), ("check", None))

    def test_web_entry_and_chrome_profile_commands_are_gone(self):
        with patch("bridge.subprocess.Popen") as spawn:
            with self.assertRaises(ValueError):
                self.bridge.launch("web")
            for command in ("launch-web", "web-profiles", "web-sync"):
                with self.subTest(command=command), self.assertRaises(ValueError):
                    self.bridge.dispatch(command)
            spawn.assert_not_called()

    def test_full_audit_shows_the_browser_gate_verdict(self):
        baseline = copy.deepcopy(self.rows)

        def both():
            return self.bridge.audit()["entries"]["browser"], self.bridge.browser_audit()["entries"]["browser"]

        self.assertEqual(both(), ("ready", "ready"))
        # The dedicated Chrome no longer decides the web entry.
        next(row for row in self.raw["checks"] if row["id"] == "web")["ok"] = False
        self.raw["entries"]["web"] = "NOT_READY"
        self.assertEqual(both(), ("ready", "ready"))
        self.assertEqual(self.bridge.audit()["entries"]["web"], "blocked")
        for key in BASE:
            for ok, expected in [(False, "blocked"), (None, "unknown")]:
                with self.subTest(key=key, ok=ok):
                    self.raw["checks"] = copy.deepcopy(baseline)
                    next(row for row in self.raw["checks"] if row["id"] == key)["ok"] = ok
                    self.assertEqual(both(), (expected, expected))
        self.raw["checks"] = copy.deepcopy(baseline)
        self.backend.guard_check = lambda: {"ok": None, "evidence": {"age_seconds": 121}}
        with patch("bridge.time.sleep"):
            self.assertEqual(both(), ("unknown", "unknown"))
        # Partial audits behind other launches say nothing about the browser.
        self.assertNotIn("browser", self.bridge.audit("launch")["entries"])

    def test_stale_check_cannot_launch(self):
        with patch("bridge.timestamp", side_effect=[1000, 62001, 62002]), patch("bridge.subprocess.Popen") as spawn:
            self.assertEqual(self.bridge.launch("cli")["action"], "blocked")
            spawn.assert_not_called()

    def test_ip_fields_are_addresses_only(self):
        next(r for r in self.rows if r["id"] == "fixed_egress")["evidence"]["probes"] = [{"ip": "token=SECRET"}, {"ip": "203.0.113.7"}]
        self.assertEqual(self.bridge.audit()["observed_ips"], ["203.0.113.7"])

    def test_browser_gate_ignores_only_the_separate_chrome_requirement(self):
        next(row for row in self.rows if row["id"] == "web")["ok"] = False
        self.raw["entries"]["web"] = "NOT_READY"
        with patch.object(self.backend, "run", return_value=copy.deepcopy(self.raw)) as run:
            report = self.bridge.dispatch("check-browser")
            run.assert_called_once_with("web", Path.home())
        self.assertEqual(report["entries"], {"browser": "ready"})
        self.assertEqual(report["schema"], 1)
        self.assertEqual(report["guard"]["state"], "ready")
        self.assertEqual(report["endpoint"], "http://127.0.0.1:17892")
        self.assertIsInstance(report["checked_at"], int)
        self.assertNotIn("web", {row["id"] for row in report["checks"]})
        self.assertNotIn("SECRET", json.dumps(report))
        self.assertEqual(self.bridge.audit("web")["entries"]["web"], "blocked")
        self.raw["entries"] = {}
        self.assertEqual(self.bridge.browser_audit()["entries"]["browser"], "ready")

    def test_browser_gate_requires_each_shared_network_check(self):
        baseline = copy.deepcopy(self.rows)
        for key in REQUIRED["web"] - {"web"}:
            with self.subTest(key=key, outcome="missing"):
                self.raw["checks"] = [row for row in baseline if row["id"] != key]
                self.assertEqual(self.bridge.browser_audit()["entries"]["browser"], "unknown")
            for ok, expected in [(False, "blocked"), (None, "unknown"), (1, "unknown")]:
                with self.subTest(key=key, ok=ok):
                    self.raw["checks"] = copy.deepcopy(baseline)
                    next(row for row in self.raw["checks"] if row["id"] == key)["ok"] = ok
                    self.assertEqual(self.bridge.browser_audit()["entries"]["browser"], expected)

    def test_browser_gate_preserves_policy_failures(self):
        self.raw["checks"] = [{"id": "policy", "ok": False, "entries": ["web"]}]
        self.raw["entries"]["web"] = "NOT_READY"
        self.assertEqual(self.bridge.browser_audit()["entries"]["browser"], "blocked")

    def test_browser_gate_cannot_drop_additional_network_failures(self):
        baseline = copy.deepcopy(self.rows)
        for key in ("traffic", "SECRET-UNKNOWN-CHECK"):
            for ok, expected in [(False, "blocked"), (None, "unknown")]:
                with self.subTest(key=key, ok=ok):
                    self.raw["checks"] = baseline + [{"id": key, "ok": ok, "entries": ["web"], "detail": "SECRET"}]
                    report = self.bridge.browser_audit()
                    self.assertEqual(report["entries"]["browser"], expected)
                    self.assertNotIn("SECRET", json.dumps(report))
        self.raw["checks"] = baseline + [{"id": "unknown", "ok": True, "entries": ["web"]}]
        self.assertEqual(self.bridge.browser_audit()["entries"]["browser"], "unknown")

    def test_browser_gate_rechecks_the_latest_guard(self):
        for row, expected in [
            ({"ok": False, "evidence": {"age_seconds": 121}}, "blocked"),
            ({"ok": None, "evidence": {"age_seconds": 121}}, "unknown"),
            ({"ok": True, "evidence": {"age_seconds": 4, "fixed_exit_blocked": True}}, "blocked"),
            ({"ok": True, "evidence": {"age_seconds": 4, "repair_active": True}}, "unknown"),
        ]:
            with self.subTest(row=row):
                self.backend.guard_check = lambda row=row: row
                self.assertEqual(self.bridge.browser_audit()["entries"]["browser"], expected)

    def test_browser_gate_keeps_sanitized_observed_ips(self):
        next(row for row in self.rows if row["id"] == "fixed_egress")["evidence"]["probes"] = [
            {"ip": "token=SECRET"}, {"ip": "203.0.113.7"}, {"ip": "203.0.113.7"}]
        self.assertEqual(self.bridge.browser_audit()["observed_ips"], ["203.0.113.7"])

    def test_browser_gate_rejects_malformed_network_rows(self):
        for row in [None, {"id": "route", "ok": True, "entries": None}]:
            with self.subTest(row=row):
                self.raw["checks"] = self.rows + [row]
                with self.assertRaises(ValueError):
                    self.bridge.browser_audit()

    def connections_backend(self, records):
        policy = {"fixed_group": "Claude-fixed", "chain_group": "Claude-chain", "password": "SECRET-DO-NOT-SHOW"}
        self.backend.load_policy = lambda: policy
        self.backend.api = lambda path: {"connections": records}
        self.backend.read_clash = lambda: {"ok": True}
        self.backend.routing_mode = lambda clash: {"profile": "claude"}
        self.backend.client_kind = lambda path: "desktop" if "AnthropicClaude" in str(path) else "cli"
        self.backend.describe = lambda row: {"host": row["metadata"].get("host"), "port": row["metadata"].get("destinationPort"),
                                             "route": " -> ".join(reversed(row.get("chains", [])))}
        self.backend.valid_chain = lambda chains, p: p["fixed_group"] in chains and "DIRECT" not in chains

    def test_connections_report_only_claude_traffic_and_flag_what_left_the_fixed_exit(self):
        fixed = ["Claude-chain", "Claude-fixed"]
        self.connections_backend([
            {"metadata": {"inboundName": "claude-fixed-http", "host": "api.anthropic.com", "destinationPort": "443"}, "chains": fixed},
            {"metadata": {"inboundName": "claude-fixed-http", "host": "api.anthropic.com", "destinationPort": "443"}, "chains": fixed},
            {"metadata": {"process": "claude.exe", "processPath": "C:/AnthropicClaude/claude.exe", "host": "claude.ai",
                          "destinationPort": "443"}, "chains": ["DIRECT"]},
            {"metadata": {"process": "chrome.exe", "host": "example.com", "destinationPort": "443"}, "chains": ["DIRECT"]},
            "not a row",
        ])
        report = self.bridge.dispatch("connections")
        self.assertEqual((report["schema"], report["readable"], report["mode"]), (1, True, "claude"))
        self.assertEqual(report["connections"], [
            {"source": "fixed_port", "host": "api.anthropic.com", "port": 443, "fixed": True, "route": None},
            {"source": "desktop", "host": "claude.ai", "port": 443, "fixed": False, "route": "DIRECT"},
        ])
        self.assertNotIn("SECRET", json.dumps(report))

    def test_unreadable_clash_is_reported_not_guessed(self):
        self.connections_backend([])
        self.backend.api = lambda path: (_ for _ in ()).throw(RuntimeError("Timeout"))
        report = self.bridge.connections()
        self.assertEqual((report["readable"], report["connections"], report["mode"]), (False, [], None))

    def test_desktop_protection_state_says_when_protect_would_help(self):
        row = next(r for r in self.rows if r["id"] == "desktop_protection")
        base = {"paths": ["C:/Claude/claude.exe"], "missing": [], "firewall_on": True, "cowork_installed": False}
        for evidence, expected in [
            (base, "protected"),
            ({**base, "missing": ["C:/Claude/claude.exe"]}, "needs_protect"),
            ({**base, "cowork_installed": True, "cowork_blocked": False}, "needs_protect"),
            ({**base, "cowork_installed": True, "cowork_blocked": True}, "protected"),
            ({**base, "firewall_on": False, "missing": ["C:/Claude/claude.exe"]}, "firewall_off"),
            ({**base, "paths": []}, "not_installed"),
            ({"token": "SECRET-DO-NOT-SHOW"}, "unknown"),
        ]:
            with self.subTest(expected=expected, evidence=evidence):
                row["evidence"] = evidence
                report = self.bridge.audit()
                self.assertEqual(report["desktop_protection"], expected)
                self.assertNotIn("C:/Claude", json.dumps(report))
        self.assertNotIn("desktop_protection", self.bridge.audit("launch"))

    def test_protect_runs_the_backend_quietly_and_rechecks_the_desktop_entry(self):
        calls = []
        def protect():
            print("SECRET-DO-NOT-SHOW")
            calls.append(True)
            return 0
        self.backend.protect = protect
        with patch.object(self.backend, "run", wraps=self.backend.run) as run:
            result = self.bridge.dispatch("protect")
        self.assertEqual((result["action"], len(calls)), ("protected", 1))
        run.assert_called_once_with("desktop", Path.home())
        self.backend.protect = lambda: 2
        self.assertEqual(self.bridge.dispatch("protect")["action"], "protect_failed")

    def test_arbitrary_command_rejected(self):
        with self.assertRaises(ValueError):
            self.bridge.dispatch("launch-; calc.exe")

    def test_missing_entries_not_filled_with_ready(self):
        self.raw["entries"] = {}
        # Only the browser's own gate remains: it reads the check rows, never the backend's entries.
        self.assertEqual(self.bridge.audit()["entries"], {"browser": self.bridge.browser_audit()["entries"]["browser"]})

    def test_running_connections_are_reported_apart_and_do_not_decide_launches(self):
        self.raw["checks"] = self.rows + [{"id": "traffic_cli", "ok": False, "entries": ["cli"], "detail": "SECRET"}]
        self.raw["entries"]["cli"] = "NOT_READY"
        report = self.bridge.audit()
        self.assertEqual(report["entries"]["cli"], "ready")
        self.assertEqual(report["running"], {"state": "blocked", "entries": ["cli"]})
        self.assertEqual(next(c for c in report["checks"] if c["id"] == "traffic_cli")["state"], "blocked")
        self.assertNotIn("SECRET", json.dumps(report))
        self.raw["checks"] = self.rows
        self.assertIsNone(self.bridge.audit()["running"])

    def test_unexplained_backend_failure_never_passes(self):
        for verdict in ("NOT_READY", "UNKNOWN", "SOMETHING_NEW"):
            with self.subTest(verdict=verdict):
                self.raw["entries"]["cli"] = verdict
                self.assertEqual(self.bridge.audit()["entries"]["cli"], "unknown")

    def test_unknown_backend_check_is_kept_and_blocks_its_entries(self):
        self.raw["checks"] = self.rows + [{"id": "SECRET-NEW-CHECK", "ok": False, "entries": ["cli"], "detail": "SECRET"}]
        report = self.bridge.audit()
        self.assertEqual(report["entries"]["cli"], "blocked")
        self.assertEqual(report["entries"]["web"], "ready")
        self.assertIn("network_check", {c["id"] for c in report["checks"]})
        self.assertNotIn("SECRET", json.dumps(report))

    def test_recovering_guard_is_unknown_and_a_launch_waits_one_round_for_it(self):
        recovering = {"ok": False, "evidence": {"alive": True, "age_seconds": 900, "fixed_exit_blocked": False}}
        self.backend.guard_check = lambda: recovering
        self.rows[[r["id"] for r in self.rows].index("guard")].update(recovering)
        report = self.bridge.audit()
        self.assertEqual(set(report["entries"].values()), {"unknown"})
        self.assertTrue(report["guard"]["recovering"])
        self.assertEqual(next(c for c in report["checks"] if c["id"] == "guard")["detail"], RECOVERING)
        # Alive but blocking, or not running at all, is never "recovering".
        for row in ({"ok": False, "evidence": {"alive": True, "fixed_exit_blocked": True}},
                    {"ok": False, "evidence": {"alive": False}}):
            self.backend.guard_check = lambda row=row: row
            self.assertFalse(self.bridge.guard()["recovering"])
            self.assertEqual(self.bridge.guard()["state"], "blocked")
        with tempfile.TemporaryDirectory(prefix="ccbaga-bridge-") as folder:
            self.backend.HERE = Path(folder)
            (self.backend.HERE / "claude-fixed.cmd").write_text("@echo off\n", encoding="utf8")
            self.rows[[r["id"] for r in self.rows].index("guard")].update({"ok": True})
            rounds = iter([recovering, recovering, {"ok": True, "evidence": {"age_seconds": 3}}])
            last = {"row": None}
            def guard_check():
                last["row"] = next(rounds, last["row"])
                return last["row"]
            self.backend.guard_check = guard_check
            with patch("bridge.time.sleep") as sleep, patch("bridge.subprocess.Popen"):
                self.assertEqual(self.bridge.launch("cli")["action"], "requested")
                self.assertEqual(sleep.call_count, 2)
            # A guard that never catches up keeps the launch closed after the wait.
            self.backend.guard_check = lambda: recovering
            with patch("bridge.time.sleep"), patch("bridge.time.monotonic", side_effect=[0, 61, 61, 61]), \
                    patch("bridge.subprocess.Popen") as spawn:
                self.assertEqual(self.bridge.launch("cli")["action"], "blocked")
                spawn.assert_not_called()

    def test_status_reads_offchain_connections_and_clash_mode_from_the_guard(self):
        with tempfile.TemporaryDirectory(prefix="ccbaga-guard-") as folder:
            self.backend.GUARD_DIR = Path(folder)
            state = Path(folder) / "network-state.json"
            state.write_text(json.dumps({"claude_offchain": 2, "mode": "global", "tun": False}), encoding="utf8")
            guard = self.bridge.status()["guard"]
            self.assertEqual((guard["offchain"], guard["mode"], guard["tun"]), (2, "global", False))
            state.write_text(json.dumps({"claude_offchain": "SECRET", "mode": "SECRET", "tun": "yes"}), encoding="utf8")
            guard = self.bridge.status()["guard"]
            self.assertEqual((guard["offchain"], guard["mode"], guard["tun"]), (None, None, None))
        del self.backend.GUARD_DIR
        self.assertIsNone(self.bridge.status()["guard"]["mode"])

    def test_known_backend_failures_reach_the_native_side_by_code(self):
        def run(argv):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = main(argv)
            return code, json.loads(out.getvalue())
        for failure, expected in [(Failure("backend_missing"), {"error": "backend_missing"}),
                                  (Failure("backend_version", installed="2026.10.20"),
                                   {"error": "backend_version", "installed": "2026.10.20"}),
                                  (RuntimeError("SECRET"), {"error": "backend_unavailable"})]:
            with self.subTest(failure=failure), patch("bridge.load_backend", side_effect=failure):
                code, data = run(["status"])
                self.assertEqual(code, 2)
                self.assertEqual({k: v for k, v in data.items() if k not in ("schema", "available")}, expected)
                self.assertIs(data["available"], False)
        self.backend.load_policy = lambda: {"entry_port": "SECRET", "expected_ip": "203.0.113.7"}
        with patch("bridge.load_backend", return_value=self.backend):
            self.assertEqual(run(["status"])[1]["error"], "policy_invalid")
        self.assertEqual([release(v) for v in ("2026.10.20", "2026.10.x", "", None, "1" * 17)],
                         ["2026.10.20", None, None, None, None])

    def desktop(self, opened, rounds, unpinned=()):
        self.backend.open_desktop = lambda workspace: opened
        self.backend.desktop_protection = lambda running, port: {"unpinned": [r["pid"] for r in running if r["pid"] in unpinned]}
        sequence = iter(rounds)
        last = {"rows": {}}
        def processes():
            last["rows"] = next(sequence, last["rows"])
            return last["rows"]
        self.backend.claude_processes = processes

    def test_slow_desktop_start_counts_only_once_its_new_process_is_pinned(self):
        old = {7: {"pid": 7, "kind": "desktop"}}
        new = {**old, 8: {"pid": 8, "kind": "desktop"}, 9: {"pid": 9, "kind": "cli"}}
        cases = [(0, [old], (), "requested"),          # Proxy-v2 confirmed it itself
                 (2, [old, old, new], (), "requested"),  # came up pinned after Proxy-v2 gave up
                 (2, [old, new], (8,), "blocked"),       # came up without the dedicated port
                 (2, [old], (), "blocked")]              # never came up
        for opened, rounds, unpinned, expected in cases:
            with self.subTest(opened=opened, rounds=len(rounds), unpinned=unpinned):
                self.desktop(opened, rounds, unpinned)
                clock = iter(range(0, 1000, 7))
                with patch("bridge.time.sleep"), patch("bridge.time.monotonic", side_effect=lambda: next(clock)):
                    self.assertEqual(self.bridge.launch("desktop")["action"], expected)


if __name__ == "__main__":
    unittest.main()
