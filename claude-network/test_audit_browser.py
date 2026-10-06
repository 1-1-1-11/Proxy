"""Offline trace/DNS regressions; WebRTC is covered by test_webrtc_probe.

All pages, clocks and asynchronous dispatch are fakes. No Chrome is started and
no network site is visited by this suite.
"""
import copy
import json
from pathlib import Path
import types
import unittest
from unittest import mock

import audit_browser as audit
import audit_settings

EXPECTED = '103.249.185.229'


def finish(coroutine):
    """Drive only synchronously-completing fake awaits, without real asyncio IO."""
    try:
        coroutine.send(None)
    except StopIteration as finished:
        return finished.value
    coroutine.close()
    raise AssertionError('A fake test attempted real asynchronous IO')


def dns_snapshot(**changes):
    value = {'summary': 'Found 2 Servers, 1 ISP, 2 Locations', 'completed': True,
             'completion_source': audit._DNS_COMPLETION_SOURCE,
             'structure_valid': True, 'started_observed': True, 'loading': False,
             'rows': [['98.98.124.72', 'Synthetic ISP', 'Singapore, Singapore'],
                      ['8.8.8.8', 'Synthetic ISP', 'Japan, Tokyo']]}
    value.update(changes)
    return value


class TraceParsingTests(unittest.TestCase):
    def test_expected_ip_passes_without_retaining_unrelated_trace_data(self):
        result = audit._parse_trace('ip=' + EXPECTED + '\nloc=JP\nopaque=PRIVATE_TRACE', EXPECTED)
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['evidence']['observed_ip'], EXPECTED)
        self.assertNotIn('PRIVATE_TRACE', json.dumps(result))

    def test_http_success_or_invalid_ip_without_actual_ip_is_unknown(self):
        for text in ('', 'HTTP/1.1 200 OK', 'ip=invalid'):
            with self.subTest(text=text):
                self.assertEqual(audit._parse_trace(text, EXPECTED)['status'], 'unknown')

    def test_different_actual_exit_is_failure(self):
        self.assertEqual(audit._parse_trace('ip=8.8.8.8', EXPECTED)['status'], 'fail')


class DnsParsingTests(unittest.TestCase):
    def test_complete_consistent_stable_result_passes(self):
        result = audit._parse_dns(dns_snapshot(), True)
        self.assertEqual(result['status'], 'pass')
        self.assertFalse(result['required'])
        self.assertEqual(result['evidence']['resolver_count'], 2)
        self.assertEqual(result['evidence']['countries'], ['Japan', 'Singapore'])

    def test_empty_result_never_passes(self):
        for snapshot in ({}, {'summary': 'Found 0 Servers, 0 ISP, 0 Locations', 'completed': True, 'rows': []}):
            self.assertEqual(audit._parse_dns(snapshot, True)['status'], 'unknown')

    def test_result_count_completion_and_stability_are_all_required(self):
        cases = [(dns_snapshot(completed=False), True),
                 (dns_snapshot(summary='Found 50 Servers, 1 ISP, 2 Locations'), True),
                 (dns_snapshot(), False)]
        for snapshot, stable in cases:
            with self.subTest(snapshot=snapshot, stable=stable):
                self.assertEqual(audit._parse_dns(snapshot, stable)['status'], 'unknown')

    def test_completion_requires_observed_start_and_the_real_result_control(self):
        cases = ({'started_observed': False}, {'loading': True}, {'structure_valid': False},
                 {'completion_source': 'guessed_status_element'})
        for changes in cases:
            with self.subTest(changes=changes):
                self.assertEqual(audit._parse_dns(dns_snapshot(**changes), True)['status'], 'unknown')

    def test_distinct_cities_in_one_country_are_distinct_locations(self):
        snapshot = dns_snapshot()
        snapshot['rows'][1][2] = 'Singapore, Tampines'
        result = audit._parse_dns(snapshot, True)
        self.assertEqual(result['status'], 'pass')
        self.assertEqual(result['evidence']['countries'], ['Singapore'])

    def test_mainland_observation_is_warning_even_if_test_not_finished(self):
        snapshot = dns_snapshot(completed=False)
        snapshot['rows'][1][2] = 'China, Shanghai'
        self.assertEqual(audit._parse_dns(snapshot, False)['status'], 'warn')

    def test_dns_evidence_does_not_return_resolver_addresses_or_isp_names(self):
        result = audit._parse_dns(dns_snapshot(), True)
        rendered = json.dumps(result)
        for marker in ('98.98.124.72', '8.8.8.8', 'Synthetic ISP', 'Tokyo'):
            self.assertNotIn(marker, rendered)


class FakeClock:
    def __init__(self): self.now = 100.0
    def monotonic(self): return self.now
    async def sleep(self, duration): self.now += duration


class FakePage:
    def __init__(self, values):
        self.values, self.calls, self.closed = values, 0, False
    async def goto(self, *args, **kwargs): pass
    async def evaluate(self, *args):
        self.calls += 1
        if self.calls > 100:
            raise AssertionError('Unbounded fake polling')
        value = self.values[min(self.calls - 1, len(self.values) - 1)]
        if isinstance(value, Exception): raise value
        return copy.deepcopy(value)
    async def close(self): self.closed = True


class DynamicDnsTests(unittest.TestCase):
    def observe(self, snapshots):
        clock, page = FakeClock(), FakePage(snapshots)
        async def new_page(): return page
        async def close(obj):
            await obj.close()
            return True
        with mock.patch.object(audit, 'time', types.SimpleNamespace(monotonic=clock.monotonic)), \
             mock.patch.object(audit.asyncio, 'sleep', new=clock.sleep), \
             mock.patch.object(audit, '_close', new=close):
            result = finish(audit._probe_dynamic(types.SimpleNamespace(new_page=new_page), 'dns', EXPECTED))
        self.assertTrue(page.closed)
        return result, page, clock

    def test_complete_dns_waits_for_stability(self):
        result, page, clock = self.observe([dns_snapshot(completed=False, loading=True), dns_snapshot()])
        self.assertEqual(result['status'], 'pass')
        self.assertGreaterEqual(clock.now - 100, 6)
        self.assertGreater(page.calls, 2)

    def test_incomplete_dns_has_bounded_unknown_result(self):
        result, page, clock = self.observe([dns_snapshot(completed=False, loading=True)])
        self.assertEqual(result['status'], 'unknown')
        self.assertAlmostEqual(clock.now - 100, 55)
        self.assertLess(page.calls, 100)

    def test_missing_loading_class_without_an_observed_start_is_unknown(self):
        result, _, clock = self.observe([dns_snapshot()])
        self.assertEqual(result['status'], 'unknown')
        self.assertFalse(result['evidence']['started_observed'])
        self.assertFalse(result['evidence']['completion_confirmed'])
        self.assertAlmostEqual(clock.now - 100, 55)

    def test_invalid_loading_control_cannot_arm_later_completion(self):
        result, _, _ = self.observe([dns_snapshot(loading=True, structure_valid=False), dns_snapshot()])
        self.assertEqual(result['status'], 'unknown')
        self.assertFalse(result['evidence']['completion_confirmed'])

    def test_dynamic_reader_rejects_obsolete_webrtc_page_path(self):
        with self.assertRaises(ValueError):
            finish(audit._probe_dynamic(None, 'webrtc', EXPECTED))


class BrowserDispatchTests(unittest.TestCase):
    def test_explicit_no_dns_is_forwarded_without_real_browser(self):
        seen = []
        async def fake_audit(chrome, port, expected, include_dns):
            seen.append((chrome, port, expected, include_dns))
            return [{'id': 'sentinel'}]
        with mock.patch.object(audit, '_chrome_path', return_value=Path('fake-chrome.exe')), \
             mock.patch.object(audit.asyncio, 'get_running_loop', side_effect=RuntimeError), \
             mock.patch.object(audit.asyncio, 'run', side_effect=finish), \
             mock.patch.object(audit, '_browser_audit_async', new=fake_audit):
            self.assertEqual(audit.browser_audit(include_dns=False), [{'id': 'sentinel'}])
        self.assertEqual(seen, [(Path('fake-chrome.exe'), 17892, EXPECTED, False)])

    def test_required_egress_and_webrtc_failures_remain_required(self):
        for ident in ('browser_fixed_exit', 'browser_webrtc'):
            result = audit._result(ident, 'fail', 'Synthetic failure')
            self.assertTrue(result['required'])
            self.assertEqual(result['status'], 'fail')


class BrowserSourceFlagTests(unittest.TestCase):
    def test_current_flag_is_declaration_only_and_legacy_force_flag_fails(self):
        flags = ['--proxy-server=http://127.0.0.1:17892',
                 '--proxy-bypass-list=localhost;127.0.0.1;[::1]',
                 '--webrtc-ip-handling-policy=disable_non_proxied_udp', '--disable-quic',
                 '--disable-features=MediaRouter']

        class FakeInstall:
            def __truediv__(self, name):
                def read_text(**kwargs):
                    if name == 'browser_entry.py': return 'FLAGS = ' + repr(flags)
                    raise FileNotFoundError('Other launcher artifacts not part of this fixture')
                return types.SimpleNamespace(read_text=read_text)

        result = audit_settings._launcher(FakeInstall(), EXPECTED, 17892)[0]
        self.assertEqual(result['status'], 'pass')
        self.assertIn('不证明', result['detail'])
        flags[2] = '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'
        result = audit_settings._launcher(FakeInstall(), EXPECTED, 17892)[0]
        self.assertEqual(result['status'], 'fail')
        self.assertTrue(result['required'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
