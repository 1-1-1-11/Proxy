"""Offline tests for the in-use guard's user alerts; no dialogs or controller calls."""
import importlib.util
import contextlib
from pathlib import Path
import sys
import unittest
from unittest import mock

import network_check  # noqa: F401 - the repository copy must win over the installed one.

_SOURCE = Path(__file__).resolve().parent.parent / 'CodexNetworkGuard' / 'health_monitor.py'
_spec = importlib.util.spec_from_file_location('guard_health_monitor', _SOURCE)
monitor = importlib.util.module_from_spec(_spec)
# The monitor prepends the installed directory to sys.path; keep other tests on repository code.
_saved_path = list(sys.path)
try:
    _spec.loader.exec_module(monitor)
finally:
    sys.path[:] = _saved_path

ROUTED = {'mode': 'rule', 'tun': True, 'fixed_exit_blocked': False}


class AlertTests(unittest.TestCase):
    def test_new_block_alerts_once(self):
        blocked = {**ROUTED, 'fixed_exit_blocked': True}
        self.assertIn('已被阻断', monitor.notice(ROUTED, blocked)[0])
        self.assertIsNone(monitor.notice(blocked, blocked))
        self.assertIsNone(monitor.notice(blocked, ROUTED))

    def test_leaving_rule_mode_alerts_but_domestic_switch_does_not(self):
        for changed in ({**ROUTED, 'mode': 'global'}, {**ROUTED, 'mode': 'direct', 'tun': False}):
            with self.subTest(changed=changed):
                self.assertIn('离开规则模式', monitor.notice(ROUTED, changed)[0])
                self.assertIsNone(monitor.notice(changed, changed))
        domestic = {**ROUTED, 'tun': False}
        self.assertIsNone(monitor.notice(ROUTED, domestic))
        self.assertIsNone(monitor.notice(domestic, ROUTED))

    def test_unknown_states_do_not_alert(self):
        self.assertIsNone(monitor.notice({}, ROUTED))
        self.assertIsNone(monitor.notice(ROUTED, {'network_status': 'waiting_for_physical_network'}))
        self.assertIsNone(monitor.notice(ROUTED, {**ROUTED, 'mode': None}))

    def test_alert_runs_in_background_thread(self):
        with mock.patch.object(monitor.threading, 'Thread') as thread:
            monitor.alert('T', 'X')
        self.assertTrue(thread.call_args.kwargs['daemon'])
        thread.return_value.start.assert_called_once()


class HealthTransitionTests(unittest.TestCase):
    def test_failed_check_and_recovery_require_distinct_completed_probes(self):
        old = {'fixed_ok': True}
        expected = [(False, 1, 0, False), (False, 2, 0, False),
                    (True, 0, 1, True), (True, 0, 2, False)]
        for ok, failed, passed, recovering in expected:
            counters = monitor.fixed_streaks(old, ok)
            self.assertEqual(counters, {'fixed_failed_count': failed,
                'fixed_success_count': passed, 'fixed_recovering': recovering})
            old = {**old, **counters, 'fixed_ok': ok}
        self.assertEqual(monitor.fixed_streaks(old, True)['fixed_success_count'], 2)

    def test_brief_failure_never_inherits_previous_success_count(self):
        old = {'fixed_ok': True, 'fixed_success_count': 2}
        failed = {**monitor.fixed_streaks(old, False), 'fixed_ok': False}
        self.assertTrue(monitor.fixed_streaks(failed, True)['fixed_recovering'])
        # A new failure after the first recovery sample starts a new failed streak.
        recovering = {**monitor.fixed_streaks(failed, True), 'fixed_ok': True}
        self.assertEqual(monitor.fixed_streaks(recovering, False)['fixed_failed_count'], 1)

    def test_initial_and_offline_states_do_not_invent_previous_failures(self):
        for old in ({}, {'fixed_ok': None, 'fixed_failed_count': 0}):
            self.assertEqual(monitor.fixed_streaks(old, False)['fixed_failed_count'], 1)
            self.assertFalse(monitor.fixed_streaks(old, True)['fixed_recovering'])

    def test_stale_history_does_not_confirm_recovery_on_one_new_probe(self):
        stamp = monitor.time.time()
        old = {'time': monitor.datetime.datetime.fromtimestamp(stamp - 121).astimezone().isoformat(),
               'fixed_ok': True, 'fixed_success_count': 2}
        self.assertEqual(monitor.fixed_streaks(old, True, stamp)['fixed_success_count'], 1)
        old.update(fixed_ok=False, fixed_failed_count=2)
        self.assertEqual(monitor.fixed_streaks(old, False, stamp)['fixed_failed_count'], 1)

    def test_raw_failure_and_wrong_ip_protection_are_not_debounced(self):
        # Exercise the real per-round control path without any external I/O.
        import repair_proxy
        for fixed_result, expected_block in (
            ({'curl_exit': 1, 'ip': None, 'error': 'TimeoutError'}, False),
            ({'curl_exit': 0, 'ip': '192.0.2.99'}, True),
        ):
            with self.subTest(result=fixed_result), contextlib.ExitStack() as stack:
                old = {**ROUTED, 'fixed_ok': True, 'physical': {'ready': True},
                       'monitor_pid': monitor.os.getpid(), 'last_heartbeat': monitor.time.time()}
                stack.enter_context(mock.patch.object(monitor, 'read_state', return_value=old))
                stack.enter_context(mock.patch.object(monitor, 'physical_network', return_value={'ready': True}))
                stack.enter_context(mock.patch.object(monitor, 'warmup', side_effect=AssertionError('unexpected warmup')))
                stack.enter_context(mock.patch.object(monitor, 'checked', side_effect=lambda port:
                    {'curl_exit': 0, 'ip': '192.0.2.10'} if port == 7892 else fixed_result))
                stack.enter_context(mock.patch.object(monitor, 'api', side_effect=lambda path:
                    (200, {'mode': 'rule', 'tun': {'enable': True}}) if path == '/configs'
                    else (200, {'proxies': {}})))
                stack.enter_context(mock.patch.object(monitor.pathlib.Path, 'read_text', side_effect=FileNotFoundError))
                write = stack.enter_context(mock.patch.object(monitor, 'write_state'))
                log = stack.enter_context(mock.patch.object(monitor, 'log'))
                stack.enter_context(mock.patch.object(monitor, 'alert'))
                block = stack.enter_context(mock.patch.object(repair_proxy, 'fail_closed'))
                state = monitor.check_once()
                self.assertFalse(state['fixed_ok'])
                self.assertEqual(state['fixed_failed_count'], 1)
                self.assertEqual(state['fixed_exit_blocked'], expected_block)
                self.assertEqual(block.call_count, int(expected_block))
                write.assert_called_once_with(state)
                event = [c for c in log.call_args_list if c.args[0] == 'health'][0]
                self.assertEqual(event.kwargs['fixed'], fixed_result)


class ProbeEvidenceTests(unittest.TestCase):
    def test_backup_keeps_primary_failure_and_its_identity(self):
        first = {'port': 17892, 'curl_exit': 1, 'ip': None, 'error': 'TimeoutError', 'seconds': 6}
        second = {'port': 17892, 'curl_exit': 0, 'ip': network_check.EXPECTED_IP, 'seconds': .4}
        with mock.patch.object(network_check, 'probe', side_effect=[first, second]):
            result = network_check.checked(17892)
        self.assertEqual(result['curl_exit'], 0)
        self.assertEqual(result['attempts'][0], dict(first, endpoint='www.cloudflare.com'))
        self.assertEqual(result['attempts'][1], dict(second, endpoint='api.ipify.org'))
        self.assertNotIn('attempts', second)

    def test_observed_wrong_ip_is_not_hidden_by_retry(self):
        wrong = {'port': 17892, 'curl_exit': 0, 'ip': '192.0.2.99'}
        with mock.patch.object(network_check, 'probe', return_value=wrong) as probe:
            result = network_check.checked(17892)
        probe.assert_called_once_with(17892)
        self.assertEqual(result['ip'], '192.0.2.99')


if __name__ == '__main__':
    unittest.main(verbosity=2)
