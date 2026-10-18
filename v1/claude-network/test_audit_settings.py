"""Regression checks for proxy precedence, malformed config and secret output."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import audit_settings as audit


# Test the archived source tree, never a separate workstation deployment.
INSTALL = Path(__file__).resolve().parent
WINDOWS_POWERSHELL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"


def complete_env(browser):
    env = {k: "http://127.0.0.1:17892" for k in
           ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy")}
    env.update(NO_PROXY="localhost,127.0.0.1,::1", no_proxy="localhost,127.0.0.1,::1", BROWSER=str(browser))
    return env


class ConfigurationChecks(unittest.TestCase):
    def setUp(self):
        self.browser = INSTALL / "ClaudeBrowser.exe"

    def check(self, raw, complete=True):
        return audit._audit_projected_env(audit._safe_env(raw, self.browser), "test", "test", 17892, complete)

    def test_correct_settings_pass(self):
        self.assertEqual(self.check(complete_env(self.browser))["status"], "pass")

    def test_lowercase_override_is_not_masked(self):
        env = complete_env(self.browser)
        env["https_proxy"] = "http://127.0.0.1:7892"
        result = self.check(env)
        self.assertEqual(result["status"], "fail")
        self.assertTrue(result["required"])
        evidence = {record["name"]: record["value"] for record in result["evidence"]["env"]}
        self.assertEqual(evidence["HTTPS_PROXY"]["port"], 17892)
        self.assertEqual(evidence["https_proxy"]["port"], 7892)

    def test_wildcard_and_remote_bypass_fail_without_value_leak(self):
        for bypass in ("*", "localhost,anthropic.com", "localhost,SECRET-BYPASS-CANARY"):
            env = complete_env(self.browser)
            env["no_proxy"] = bypass
            result = self.check(env)
            self.assertEqual(result["status"], "fail")
            self.assertNotIn("SECRET-BYPASS-CANARY", json.dumps(result))

    def test_user_missing_required_fields_fails(self):
        result = self.check({})
        self.assertEqual(result["status"], "fail")
        self.assertTrue(result["required"])
        self.assertEqual(self.check({}, complete=False)["status"], "pass")

    def test_proxy_credentials_and_query_are_rejected_and_redacted(self):
        env = complete_env(self.browser)
        env["HTTP_PROXY"] = "http://CANARY-USER:CANARY-PASSWORD@127.0.0.1:17892/?token=CANARY-TOKEN#CANARY-FRAGMENT"
        result = self.check(env)
        self.assertEqual(result["status"], "fail")
        for marker in ("CANARY-USER", "CANARY-PASSWORD", "CANARY-TOKEN", "CANARY-FRAGMENT"):
            self.assertNotIn(marker, json.dumps(result))

    def test_auth_values_and_helper_do_not_escape(self):
        env = audit._safe_env({"ANTHROPIC_AUTH_TOKEN": "CANARY-AUTH", "ANTHROPIC_BASE_URL": "https://relay.example/secret-path?key=CANARY-QUERY"}, self.browser)
        result = audit._audit_identity(env, "identity", helper=True)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["evidence"]["base_url_host"], "relay.example")
        for marker in ("CANARY-AUTH", "secret-path", "CANARY-QUERY"):
            self.assertNotIn(marker, json.dumps(result))

    def test_provider_override_and_api_helper_need_review(self):
        env = audit._safe_env({"CLAUDE_CODE_USE_BEDROCK": "1"}, self.browser)
        self.assertEqual(audit._audit_identity(env, "identity")["status"], "warn")
        self.assertEqual(audit._audit_identity({}, "identity", helper=True)["status"], "warn")

    def test_tls_disable_is_required_failure(self):
        env = audit._safe_env({"NODE_TLS_REJECT_UNAUTHORIZED": "0"}, self.browser)
        result = audit._audit_safety_switches(env, "test")[0]
        self.assertEqual(result["status"], "fail")
        self.assertTrue(result["required"])

    def test_missing_file_is_required_failure_in_public_entrypoint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.json"
            spec = {"path": str(path), "kind": "claude", "complete": True, "label": "missing"}
            with mock.patch.object(audit, "_collect_files", return_value=[spec]), \
                 mock.patch.object(audit, "_read_settings_batch", return_value=({}, None)), \
                 mock.patch.object(audit, "_windows_environment", return_value=({}, [])), \
                 mock.patch.object(audit, "_client_signatures", return_value=[]), \
                 mock.patch.object(audit, "_launcher", return_value=[]), \
                 mock.patch.object(audit, "_tool_proxies", return_value=[]):
                rows = audit.audit_settings(INSTALL, Path(directory))
            row = next(r for r in rows if r["id"] == "settings-0")
            self.assertEqual(row["status"], "fail")
            self.assertTrue(row["required"])

    def test_browser_source_requires_media_router_disable_flag(self):
        original = ["--proxy-server=http://127.0.0.1:17892",
                    "--proxy-bypass-list=localhost;127.0.0.1;[::1]",
                    "--webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-quic"]
        cases = [(original, "fail"),
                 (original + ["--disable-features=MediaRouterExtra"], "fail"),
                 (original + ["--disable-features=MediaRouter"], "pass")]
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            for flags, expected in cases:
                with self.subTest(flags=flags):
                    (folder / "browser_entry.py").write_text("FLAGS = " + repr(flags), encoding="utf8")
                    rows = audit._launcher(folder, "203.0.113.10", 17892)
                    row = next(item for item in rows if item['id'] == 'browser-source-flags')
                    self.assertEqual(row['status'], expected)
                    self.assertTrue(row['required'])


class JSONCProjectionChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (INSTALL / "vendor/jsonc-parser/lib/main.js").is_file():
            raise FileNotFoundError("Bundled JSONC parser missing from the source tree")

    def read(self, text, kind="claude"):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(text, encoding="utf-8")
            rows, error = audit._read_settings_batch(INSTALL, [{"path": str(path), "kind": kind}])
            self.assertIsNone(error)
            return rows[str(path)]

    def test_comments_and_trailing_commas_parse(self):
        row = self.read('{// comment\n"env":{"HTTPS_PROXY":"http://127.0.0.1:17892",},}')
        self.assertTrue(row["data"]["env"]["HTTPS_PROXY"]["valid"])

    def test_bad_json_never_returns_partial_settings(self):
        row = self.read('{"env":{"HTTPS_PROXY":"http://127.0.0.1:17892"}, BROKEN}')
        self.assertEqual(row["error"], "invalid_jsonc")
        self.assertNotIn("data", row)

    def test_invalid_env_type_is_visible(self):
        row = self.read('{"env":[] }')
        result = audit._audit_projected_env(row["data"]["env"], "test", "test", 17892)
        self.assertEqual(result["status"], "fail")

    def test_node_stdout_never_contains_credential_values(self):
        row = self.read(json.dumps({"env": {"ANTHROPIC_API_KEY": "CANARY-API", "HTTPS_PROXY": "http://CANARY-USER:CANARY-PASS@127.0.0.1:17892/?t=CANARY-QUERY"}, "apiKeyHelper": "echo CANARY-HELPER", "unrelated": "CANARY-UNRELATED"}))
        output = json.dumps(row)
        self.assertNotIn("CANARY-", output)
        self.assertTrue(row["data"]["apiKeyHelper"])
        self.assertTrue(row["data"]["env"]["ANTHROPIC_API_KEY"]["present"])

    def test_vscode_duplicate_names_are_rejected(self):
        row = self.read(json.dumps({"claudeCode.environmentVariables": [
            {"name": "HTTPS_PROXY", "value": "http://127.0.0.1:7892"},
            {"name": "HTTPS_PROXY", "value": "http://127.0.0.1:17892"}]}), "vscode")
        result = audit._audit_projected_env(row["data"]["env"], "test", "test", 17892, duplicate_keys=row["data"]["duplicate_keys"])
        self.assertEqual(result["status"], "fail")


class ReportCompatibilityChecks(unittest.TestCase):
    def make_report(self):
        """Exercise each public report location that includes projected env."""
        browser = INSTALL / "ClaudeBrowser.exe"
        raw = complete_env(browser)
        raw["http_proxy"] = "http://CANARY-USER:CANARY-PASS@127.0.0.1:7892/?key=CANARY-QUERY#CANARY-FRAGMENT"
        raw["ANTHROPIC_AUTH_TOKEN"] = "CANARY-AUTH"
        raw["no_proxy"] = "localhost,CANARY-BYPASS"
        projected = audit._safe_env(raw, browser)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text("{}", encoding="utf-8")
            spec = {"path": str(path), "kind": "vscode", "complete": True, "label": "test"}
            data = {"env": projected, "terminalEnv": projected,
                    "externalBrowser": {"matches_expected": True}}
            with mock.patch.object(audit, "_collect_files", return_value=[spec]), \
                 mock.patch.object(audit, "_read_settings_batch", return_value=({str(path): {"data": data}}, None)), \
                 mock.patch.object(audit, "_windows_environment", return_value=({"Process": raw}, [])), \
                 mock.patch.object(audit, "_client_signatures", return_value=[]), \
                 mock.patch.object(audit, "_launcher", return_value=[]), \
                 mock.patch.object(audit, "_tool_proxies", return_value=[]):
                return {"checks": audit.audit_settings(INSTALL, Path(directory))}

    def test_all_environment_report_locations_preserve_variants_and_redaction(self):
        report = self.make_report()
        checks = {row["id"]: row for row in report["checks"]}
        records = (
            checks["settings-0"]["evidence"]["env"],
            checks["settings-0-other-tools"]["evidence"]["terminal.integrated.env.windows"],
            checks["environment-process"]["evidence"]["env"],
        )
        self.assertEqual(checks["settings-0"]["status"], "fail")
        for group in records:
            self.assertIsInstance(group, list)
            values = {row["name"]: row["value"] for row in group}
            self.assertEqual(values["HTTP_PROXY"]["port"], 17892)
            self.assertEqual(values["http_proxy"]["port"], 7892)
            self.assertTrue(values["http_proxy"]["has_credentials"])
            self.assertTrue(values["NO_PROXY"]["valid"])
            self.assertFalse(values["no_proxy"]["valid"])
            self.assertEqual(values["ANTHROPIC_AUTH_TOKEN"], {"present": True})
        self.assertNotIn("CANARY-", json.dumps(report))

    @unittest.skipUnless(WINDOWS_POWERSHELL.is_file(), "Windows PowerShell unavailable")
    def test_report_round_trips_through_windows_powershell_51(self):
        script = r'''$ErrorActionPreference='Stop'
$report = [Console]::In.ReadToEnd() | ConvertFrom-Json
$settings = @($report.checks | Where-Object id -eq 'settings-0')[0]
$terminal = @($report.checks | Where-Object id -eq 'settings-0-other-tools')[0]
$process = @($report.checks | Where-Object id -eq 'environment-process')[0]
$groups = @($settings.evidence.env, $terminal.evidence.'terminal.integrated.env.windows', $process.evidence.env)
$checks = @(foreach ($group in $groups) {
    $upper = @($group | Where-Object { $_.name -ceq 'HTTP_PROXY' })
    $lower = @($group | Where-Object { $_.name -ceq 'http_proxy' })
    if ($upper.Count -ne 1 -or $lower.Count -ne 1) { throw 'Case variant missing' }
    @{ upper = $upper[0].value.port; lower = $lower[0].value.port }
})
@{ version = $PSVersionTable.PSVersion.ToString(); checks = $checks } | ConvertTo-Json -Depth 5 -Compress'''
        run = subprocess.run(
            [str(WINDOWS_POWERSHELL), "-NoProfile", "-NonInteractive", "-Command", script],
            input=json.dumps(self.make_report(), ensure_ascii=True), capture_output=True,
            text=True, encoding="utf-8", errors="replace", timeout=20,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout.lstrip("\ufeff"))
        self.assertTrue(result["version"].startswith("5.1."), result["version"])
        self.assertEqual(result["checks"], [{"upper": 17892, "lower": 7892}] * 3)


if __name__ == "__main__":
    unittest.main()
