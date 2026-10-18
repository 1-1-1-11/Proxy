"""Offline repair-order tests: Claude groups reopen only after the exit is verified."""
import contextlib
import io
import types
import unittest
from unittest import mock

import repair_proxy as repair

GOOD = {'ok': True, 'wrong_exit': False, 'probes': []}
WRONG = {'ok': False, 'wrong_exit': True, 'probes': []}
DOWN = {'ok': False, 'wrong_exit': False, 'probes': []}
HEALTHY = {'daily_ok': True, 'fixed_ok': True, 'wrong_exit': False}


class RepairOrderTests(unittest.TestCase):
    def run_repair(self, verify, was_closed=False):
        events = []
        record = lambda name: (lambda *args, **kwargs: events.append((name, kwargs.get('protected', True))
                                                                      if name == 'select' else name))
        verify = iter(verify)
        patches = {
            'SingleInstance': contextlib.nullcontext, 'atomic': mock.Mock(),
            'Changes': mock.Mock(return_value=types.SimpleNamespace(before=[], folder=None)),
            'settings_plan': mock.Mock(return_value={}), 'build_candidate': mock.Mock(return_value=({}, {})),
            'browser_build_needed': mock.Mock(return_value=False),
            'physical_network': mock.Mock(return_value={'ready': True}),
            'inspect_live': mock.Mock(return_value={'config_drift': False, 'wrong_groups': []}),
            'app_running': mock.Mock(return_value=True), 'warmup': mock.Mock(),
            'protected_closed': mock.Mock(return_value=was_closed),
            'put_config': mock.Mock(side_effect=record('put_config')),
            'fail_closed': mock.Mock(side_effect=record('fail_closed')),
            'select_groups': mock.Mock(side_effect=lambda protected=True: events.append(('select', protected)) or []),
            'verify_exit': mock.Mock(side_effect=lambda: events.append('verify') or next(verify)),
            'health': mock.Mock(side_effect=lambda: events.append('health') or dict(HEALTHY)),
            'route_checks': mock.Mock(return_value={'ok': True}),
            'launch_app': mock.Mock(side_effect=AssertionError('Real Clash launch forbidden')),
        }
        with contextlib.ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(mock.patch.object(repair, name, value))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = repair.execute(types.SimpleNamespace(check_only=False, workspace=None))
        return code, events

    def test_verified_exit_reopens_claude_after_verification(self):
        code, events = self.run_repair([GOOD])
        self.assertEqual(code, 0)
        self.assertEqual(events, [('select', False), 'verify', ('select', True), 'health'])

    def test_wrong_exit_keeps_claude_closed(self):
        code, events = self.run_repair([WRONG])
        self.assertEqual(code, 22)
        self.assertNotIn(('select', True), events)
        self.assertLess(events.index('verify'), events.index('fail_closed'))

    def test_unverifiable_exit_never_reopens_claude(self):
        code, events = self.run_repair([DOWN, DOWN])
        self.assertEqual(code, 20)
        self.assertNotIn(('select', True), events)
        self.assertEqual(events.count('put_config'), 1)

    def test_previously_closed_groups_are_reclosed_after_reload_until_verified(self):
        code, events = self.run_repair([DOWN, GOOD], was_closed=True)
        self.assertEqual(code, 0)
        self.assertEqual(events, ['fail_closed', ('select', False), 'verify', 'put_config', 'fail_closed',
                                  ('select', False), 'verify', ('select', True), 'health'])


class BaselineListenerTests(unittest.TestCase):
    def test_verify_listener_targets_chain_group_not_client_group(self):
        text = (repair.HERE / 'routing-baseline.js').read_text(encoding='utf-8')
        self.assertIn('name: "claude-verify-http"', text)
        self.assertIn('port: 17893, proxy: chainGroup', text)
        self.assertEqual(repair.VERIFY_PORT, 17893)


if __name__ == '__main__':
    unittest.main(verbosity=2)
