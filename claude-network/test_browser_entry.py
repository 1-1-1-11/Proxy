"""Offline browser launch-gate regressions; no browser, network or file writes."""
import contextlib
from pathlib import Path
import unittest
from unittest import mock

import audit_browser
import audit_proxy
import browser_entry as entry


def findings(exit_status='pass', webrtc_status='pass'):
    return [{'id': 'browser_fixed_exit', 'required': True, 'status': exit_status},
            {'id': 'browser_webrtc', 'required': True, 'status': webrtc_status}]


class BrowserPreflightTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.fixed = self.stack.enter_context(mock.patch.object(entry, 'fixed_ready', return_value={'ready': True}))
        self.stack.enter_context(mock.patch.object(entry, 'runtime', return_value={'running': False, 'flags_ok': None}))
        self.stack.enter_context(mock.patch.object(Path, 'is_file', return_value=True))
        self.mkdir = self.stack.enter_context(mock.patch.object(Path, 'mkdir'))
        self.popen = self.stack.enter_context(mock.patch.object(entry.subprocess, 'Popen'))
        self.run = self.stack.enter_context(mock.patch.object(entry.subprocess, 'run',
            side_effect=AssertionError('Real process launch forbidden')))
        self.stack.enter_context(mock.patch.object(audit_proxy, 'load_policy', return_value={
            'entry_port': 17892, 'expected_ip': '103.249.185.229'}))
        self.native = self.stack.enter_context(mock.patch.object(audit_browser, 'browser_audit', return_value=findings()))

    def test_native_webrtc_fail_or_unknown_blocks_ready(self):
        for status in ('fail', 'unknown', 'not_tested', 'warn'):
            with self.subTest(status=status):
                self.native.return_value = findings(webrtc_status=status)
                result = entry.browser_preflight()
                self.assertEqual(result['state'], 'blocked')
                self.assertEqual(result['reason'], 'browser_protection_unverified')
        self.popen.assert_not_called()
        self.mkdir.assert_not_called()
        self.run.assert_not_called()

    def test_missing_or_nonrequired_evidence_cannot_count_as_pass(self):
        cases = [[], findings()[:1], findings()[1:],
                 [{'id': 'browser_fixed_exit', 'required': True, 'status': 'pass'},
                  {'id': 'browser_webrtc', 'required': False, 'status': 'pass'}]]
        for result_rows in cases:
            with self.subTest(rows=result_rows):
                self.native.return_value = result_rows
                self.assertEqual(entry.browser_preflight()['state'], 'blocked')
        self.popen.assert_not_called()
        self.mkdir.assert_not_called()

    def test_two_confirmed_pass_results_are_required_for_ready(self):
        self.native.return_value = findings()
        result = entry.browser_preflight()
        self.assertEqual(result['state'], 'ready')
        self.native.assert_called_once_with(17892, '103.249.185.229', include_dns=False)
        self.native.return_value = findings(exit_status='unknown')
        self.assertEqual(entry.browser_preflight()['state'], 'blocked')
        self.popen.assert_not_called()
        self.mkdir.assert_not_called()

    def test_failed_native_gate_never_launches_or_creates_profile(self):
        for status in ('fail', 'unknown'):
            with self.subTest(status=status):
                self.native.return_value = findings(webrtc_status=status)
                result = entry.launch('https://example.com')
                self.assertEqual(result['state'], 'blocked')
        self.popen.assert_not_called()
        self.mkdir.assert_not_called()
        self.run.assert_not_called()

    def test_successful_gate_launches_with_effective_policy_switch(self):
        result = entry.launch('https://example.com')
        self.assertEqual(result['state'], 'opened')
        self.popen.assert_called_once()
        arguments = self.popen.call_args.args[0]
        self.assertIn('--webrtc-ip-handling-policy=disable_non_proxied_udp', arguments)
        self.assertIn('--disable-features=MediaRouter', arguments)
        self.assertNotIn('--force-webrtc-ip-handling-policy=disable_non_proxied_udp', arguments)
        self.mkdir.assert_called_once_with(parents=True, exist_ok=True)
        self.run.assert_not_called()

    def test_unavailable_fixed_entry_does_not_start_native_test_or_browser(self):
        self.fixed.return_value = {'ready': False}
        self.assertEqual(entry.launch('https://example.com')['state'], 'blocked')
        self.native.assert_not_called()
        self.popen.assert_not_called()
        self.mkdir.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
