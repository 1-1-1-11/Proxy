"""Offline repair-menu tests: no real registry, subprocess or proxy changes."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import audit_actions as actions


ABSENT = {'exists': False, 'value': None, 'type': None}
EXPECTED = {'exists': True, 'value': actions.EXPECTED, 'type': 1}


def registry_state():
    return {'readable': True, 'hkcu': copy.deepcopy(ABSENT),
            'hklm': [copy.deepcopy(ABSENT), copy.deepcopy(ABSENT)],
            'url_policy_present': False}


def policy_report(reason='effective_policy_not_protective'):
    row = {'id': 'browser_webrtc', 'required': True, 'status': 'unknown',
           'evidence': {'reason': reason, 'effective_policy': {'url_overrides_empty': True}}}
    return {'checks': [row], 'blocking_checks': [{'id': 'browser_webrtc'}]}


def proxy_report(identifier='mihomo_core'):
    return {'checks': [{'id': identifier, 'required': True, 'status': 'fail'}],
            'blocking_checks': [{'id': identifier}]}


def option(rows, identifier):
    return next(row for row in rows if row['id'] == identifier)


class ActionsTests(unittest.TestCase):
    def setUp(self):
        actions._prepared.clear()
        self.root = Path(__file__).resolve().parent / 'unused-actions-install'
        self.state = self.patch('_registry_state', return_value=registry_state())
        self.dependencies = self.patch('_restore_dependencies', return_value=[])
        self.current = self.patch('_current', side_effect=AssertionError('Unmocked registry read'))
        self.write = self.patch('_write_current', side_effect=AssertionError('Real registry write forbidden'))
        self.run = self.patch('subprocess.run', side_effect=AssertionError('Real subprocess forbidden'))

    def patch(self, name, **kwargs):
        patcher = mock.patch('audit_actions.' + name, **kwargs)
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def prepare(self, report=None, identifier='chrome_webrtc'):
        return option(actions.repair_options(report or policy_report(), self.root), identifier)

    def test_listing_plan_has_no_write_or_subprocess_and_discloses_scope(self):
        with mock.patch.object(actions, '_write_backup') as backup:
            plan = self.prepare()
        self.assertTrue(plan['available'])
        self.assertIn('全部 Chrome', plan['impact'])
        self.assertIn('WebRTC', plan['impact'])
        self.assertIn('--rollback-backup', plan['rollback'])
        backup.assert_not_called()
        self.write.assert_not_called()
        self.run.assert_not_called()

    def test_healthy_normal_plan_describes_unneeded_restore_and_unchecked_browser(self):
        rows = actions.repair_options({'checks': [], 'blocking_checks': []}, self.root)
        self.assertFalse(any(row['available'] for row in rows))
        self.assertIn('当前未发现需要恢复', option(rows, 'restore_proxy')['reason'])
        self.assertIn('本轮未检查浏览器', option(rows, 'chrome_webrtc')['reason'])
        self.state.assert_not_called()

    def test_passed_browser_plan_explains_no_setting_needed(self):
        report = {'checks': [{'id': 'browser_webrtc', 'required': True, 'status': 'pass'}], 'blocking_checks': []}
        plan = self.prepare(report)
        self.assertFalse(plan['available'])
        self.assertIn('本次保护已通过', plan['reason'])
        self.state.assert_not_called()

    def test_non_policy_webrtc_reason_and_supplier_problem_are_unavailable(self):
        for report in (policy_report('native_ice_incomplete'), proxy_report('fixed_egress')):
            with self.subTest(report=report):
                plans = actions.repair_options(report, self.root)
                self.assertFalse(any(row['available'] for row in plans))
        self.write.assert_not_called()
        self.run.assert_not_called()

    def test_already_correct_hkcu_unknown_observation_is_not_repaired(self):
        self.state.return_value['hkcu'] = copy.deepcopy(EXPECTED)
        plan = self.prepare(policy_report('profile_scope_unverified'))
        self.assertFalse(plan['available'])
        self.assertIn('重新检查', plan['reason'])
        result = actions.execute_option('chrome_webrtc', self.root, self.root)
        self.assertEqual(result['exit_code'], 3)
        self.write.assert_not_called()

    def test_machine_conflict_url_override_or_unreadable_state_refuses(self):
        for change in ({'hklm': [{'exists': True, 'value': 'default', 'type': 1}]},
                       {'url_policy_present': True}, {'readable': False}):
            with self.subTest(change=change):
                self.state.return_value = {**registry_state(), **change}
                self.assertFalse(self.prepare()['available'])
                self.assertEqual(actions.execute_option('chrome_webrtc', self.root, self.root)['exit_code'], 3)
        self.write.assert_not_called()

    def test_unknown_url_override_evidence_cannot_enable_policy_action(self):
        report = policy_report()
        report['checks'][0]['evidence']['effective_policy'] = {}
        self.assertFalse(self.prepare(report)['available'])

    def test_missing_repair_dependencies_disable_restore(self):
        self.dependencies.return_value = ['repair-baseline.dpapi', 'health_monitor.py']
        plan = self.prepare(proxy_report(), 'restore_proxy')
        self.assertFalse(plan['available'])
        self.assertIn('repair-baseline.dpapi', plan['reason'])
        self.assertEqual(actions.execute_option('restore_proxy', self.root, self.root)['exit_code'], 3)
        self.run.assert_not_called()

    def test_execute_requires_recent_plan_and_rechecks_availability(self):
        self.assertEqual(actions.execute_option('chrome_webrtc', self.root, self.root)['exit_code'], 3)
        with mock.patch.object(actions.time, 'monotonic', return_value=0):
            self.prepare()
        with mock.patch.object(actions.time, 'monotonic', return_value=301):
            self.assertEqual(actions.execute_option('chrome_webrtc', self.root, self.root)['exit_code'], 3)
        self.prepare()
        self.state.return_value['url_policy_present'] = True
        self.assertEqual(actions.execute_option('chrome_webrtc', self.root, self.root)['exit_code'], 3)
        self.write.assert_not_called()
        self.run.assert_not_called()

    def test_backup_failure_prevents_registry_write(self):
        self.prepare()
        self.current.side_effect = None
        self.current.return_value = copy.deepcopy(ABSENT)
        with mock.patch.object(actions, '_write_backup', side_effect=OSError('private diagnostic')):
            result = actions.execute_option('chrome_webrtc', self.root, self.root)
        self.assertEqual(result['exit_code'], 3)
        self.assertNotIn('private diagnostic', json.dumps(result))
        self.write.assert_not_called()

    def test_success_requires_backup_then_single_value_write_and_readback(self):
        self.prepare()
        events = []
        self.current.side_effect = [copy.deepcopy(ABSENT), copy.deepcopy(EXPECTED)]
        self.write.side_effect = lambda value: events.append(('write', value))
        backup_path = self.root / 'backups/chrome-webrtc-test.json'

        def backup(root, previous):
            events.append(('backup', previous))
            return backup_path

        with mock.patch.object(actions, '_write_backup', side_effect=backup):
            result = actions.execute_option('chrome_webrtc', self.root, self.root)
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual(events, [('backup', ABSENT), ('write', EXPECTED)])
        self.assertEqual(result['backup'], str(backup_path))
        self.assertIn('--rollback-backup', result['rollback_command'])
        self.assertIn('尚需', result['message'])
        self.run.assert_not_called()
        self.assertEqual(actions.execute_option('chrome_webrtc', self.root, self.root)['exit_code'], 3)

    def test_failed_readback_is_not_success_and_retains_rollback(self):
        self.prepare()
        self.current.side_effect = [copy.deepcopy(ABSENT), copy.deepcopy(ABSENT)]
        self.write.side_effect = None
        with mock.patch.object(actions, '_write_backup', return_value=self.root / 'backups/owned.json'):
            result = actions.execute_option('chrome_webrtc', self.root, self.root)
        self.assertEqual(result['exit_code'], 3)
        self.assertIn('rollback_command', result)

    def test_restore_backend_failure_and_timeout_are_not_reported_as_success(self):
        for outcome in (subprocess.CompletedProcess([], 2, b'secret stdout', b'secret stderr'),
                        subprocess.TimeoutExpired('repair', 180, output=b'secret stdout')):
            with self.subTest(outcome=type(outcome).__name__):
                self.prepare(proxy_report(), 'restore_proxy')
                self.run.side_effect = outcome if isinstance(outcome, Exception) else None
                self.run.return_value = outcome
                result = actions.execute_option('restore_proxy', self.root, self.root)
                self.assertNotEqual(result['exit_code'], 0)
                self.assertNotIn('secret', json.dumps(result))
                self.assertEqual(self.run.call_args.kwargs['timeout'], 180)
                self.assertTrue(self.run.call_args.kwargs['capture_output'])
        self.write.assert_not_called()

    def test_restore_success_still_requires_independent_recheck(self):
        plan = self.prepare(proxy_report('settings-0'), 'restore_proxy')
        self.assertTrue(plan['available'])
        self.assertIn('Clash', ' '.join(plan['changes']))
        self.assertIn('OpenAI', ' '.join(plan['changes']))
        self.run.side_effect = None
        self.run.return_value = subprocess.CompletedProcess([], 0, b'', b'')
        result = actions.execute_option('restore_proxy', self.root, self.root)
        self.assertEqual(result['exit_code'], 0)
        self.assertIn('重检', result['message'])

    def test_restore_target_uses_validated_report_ip_with_safe_fallback(self):
        for ip, expected in (('203.0.113.25', '203.0.113.25'),
                             ('private-token\nexample', '本机策略定义的固定出口'),
                             (None, '本机策略定义的固定出口')):
            with self.subTest(ip=ip):
                report = proxy_report()
                report['checks'].append({'id': 'fixed_egress', 'status': 'unknown', 'required': True,
                                         'evidence': {'expected_ip': ip}})
                plan = self.prepare(report, 'restore_proxy')
                self.assertIn(expected, plan['expected'])
                self.assertNotIn('private-token', plan['expected'])


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='.test-actions-', dir=Path(__file__).resolve().parent)
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name).resolve()
        self.current_patcher = mock.patch.object(actions, '_current', side_effect=AssertionError('Unexpected registry read'))
        self.write_patcher = mock.patch.object(actions, '_write_current', side_effect=AssertionError('Real registry write forbidden'))
        self.current = self.current_patcher.start()
        self.write = self.write_patcher.start()
        self.addCleanup(self.current_patcher.stop)
        self.addCleanup(self.write_patcher.stop)

    def test_backup_records_only_target_single_value_and_publishes_atomically(self):
        previous = {'exists': True, 'type': 1, 'value': 'default_public_interface_only'}
        path = actions._write_backup(self.root, previous)
        data = json.loads(path.read_text(encoding='utf8'))
        self.assertEqual(path.parent, self.root / 'backups')
        self.assertEqual(data['target'], {'hive': 'HKCU', 'key': actions.REG_KEY, 'name': actions.REG_NAME})
        self.assertEqual(data['previous'], previous)
        self.assertEqual(actions._load_backup(self.root, path), previous)
        self.assertEqual(list(path.parent.glob('*.tmp')), [])
        self.write.assert_not_called()

    def test_failed_atomic_publish_leaves_no_partial_backup(self):
        with mock.patch.object(actions.os, 'replace', side_effect=OSError('disk unavailable')):
            with self.assertRaises(OSError):
                actions._write_backup(self.root, ABSENT)
        self.assertEqual(list((self.root / 'backups').iterdir()), [])
        self.write.assert_not_called()

    def test_rollback_preserves_original_absence_or_type_and_value(self):
        for previous in (ABSENT, {'exists': True, 'type': 2, 'value': '%EXAMPLE%'}):
            with self.subTest(previous=previous):
                path = actions._write_backup(self.root, previous)
                self.current.side_effect = [copy.deepcopy(EXPECTED), copy.deepcopy(previous)]
                self.write.side_effect = None
                result = actions.rollback_backup(self.root, path)
                self.assertEqual(result['exit_code'], 0)
                self.write.assert_called_with(previous)

    def test_rollback_rejects_changed_current_policy(self):
        path = actions._write_backup(self.root, ABSENT)
        self.current.side_effect = None
        self.current.return_value = {'exists': True, 'type': 1, 'value': 'later_admin_change'}
        self.assertEqual(actions.rollback_backup(self.root, path)['exit_code'], 3)
        self.write.assert_not_called()

    def test_rollback_rejects_other_folder_or_target_before_registry_access(self):
        path = actions._write_backup(self.root, ABSENT)
        outside = self.root / path.name
        outside.write_text(path.read_text(encoding='utf8'), encoding='utf8')
        self.assertEqual(actions.rollback_backup(self.root, outside)['exit_code'], 3)
        data = json.loads(path.read_text(encoding='utf8'))
        data['target']['hive'] = 'HKLM'
        path.write_text(json.dumps(data), encoding='utf8')
        self.assertEqual(actions.rollback_backup(self.root, path)['exit_code'], 3)
        self.current.assert_not_called()
        self.write.assert_not_called()

    def test_malformed_backup_is_rejected_without_registry_access(self):
        path = actions._write_backup(self.root, ABSENT)
        for payload in ('[]', 'null', '{"previous": null}', '{'):
            with self.subTest(payload=payload):
                path.write_text(payload, encoding='utf8')
                self.assertEqual(actions.rollback_backup(self.root, path)['exit_code'], 3)
        self.current.assert_not_called()
        self.write.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
