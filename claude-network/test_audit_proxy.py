"""Offline evidence regressions: no real network, proxy writes or process launches."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import threading
import types
import unittest
from unittest import mock

import audit_proxy as audit


def fixture():
    policy = {'entry_port': 17892, 'daily_port': 7892, 'expected_ip': '103.249.185.229',
              'fixed_group': 'Claude-固定出口', 'chain_group': '静态出口-自动恢复',
              'provider': '固定出口链路'}
    snap = {'process': {'ok': True, 'items': [{'pid': 10, 'name': 'verge-mihomo.exe'}],
                        'browser': [], 'browser_pids': []},
            'tcp': {'ok': True, 'listeners': [{'pid': 10, 'address': '127.0.0.1', 'port': 17892}],
                    'connections': []},
            'physical': {'ok': True, 'ready': True, 'ipv6_gateway': False},
            'system': {'ok': True}}
    ctl = {'ok': True, 'version': {'version': 'test-only'},
           'configs': {'mode': 'rule', 'tun': {'enable': True}},
           'proxies': {'proxies': {
               policy['fixed_group']: {'now': policy['chain_group'],
                                       'all': [policy['chain_group'], 'REJECT']},
               policy['chain_group']: {'now': 'chain-a', 'all': ['chain-a']}}}}
    disk = {'ok': True, 'candidates': [{'name': 'chain-a', 'front': 'front-a'}],
            'dns': {'enable': True, 'ipv6': False}}
    probes = [{'ok': True, 'ip': policy['expected_ip'], 'source': source}
              for source in ['cloudflare', 'ipify']]
    route = {'ok': True}
    return policy, snap, ctl, disk, probes, route


def by_id(checks):
    return {check['id']: check for check in checks}


def add_claude(snap, port=17892, remote='127.0.0.1', source=50001):
    snap['process']['items'].append({'pid': 20, 'name': 'claude.exe'})
    snap['tcp']['connections'].append({'pid': 20, 'remote': remote,
                                        'port': port, 'source_port': source})


def connection_record(policy, source=50001, host='api.anthropic.com'):
    return {'metadata': {'sourcePort': str(source), 'host': host,
                         'inboundName': 'claude-fixed-http'},
            'chains': ['chain-a', policy['chain_group'], policy['fixed_group']]}


class OfflineCase(unittest.TestCase):
    def setUp(self):
        # Any accidental external I/O is a test error, even if a new test forgets a seam.
        self.guards = contextlib.ExitStack()
        self.addCleanup(self.guards.close)
        self.spawn = self.guards.enter_context(mock.patch.object(
            audit.subprocess, 'run', side_effect=AssertionError('Real process launch forbidden')))
        self.socket = self.guards.enter_context(mock.patch.object(
            audit.socket, 'create_connection', side_effect=AssertionError('Real network forbidden')))
        self.https = self.guards.enter_context(mock.patch.object(
            audit.http.client, 'HTTPSConnection', side_effect=AssertionError('Real HTTP forbidden')))


class PathEvidenceTests(OfflineCase):
    def test_gui_absent_with_real_core_listener_is_proxy_ready(self):
        checks = audit.evaluate_path(*fixture())
        self.assertEqual(by_id(checks)['clash_gui']['status'], 'not_running')
        self.assertEqual(by_id(checks)['mihomo_core']['status'], 'pass')
        self.assertEqual(audit.summarize(checks, mode='preflight')['state'], 'PROXY_READY')
        self.spawn.assert_not_called()

    def test_all_stopped_fails_even_if_stale_probe_objects_say_success(self):
        data = list(fixture())
        data[1]['process']['items'] = []
        data[1]['tcp']['listeners'] = []
        checks = audit.evaluate_path(*data)
        self.assertEqual(by_id(checks)['mihomo_core']['status'], 'fail')
        self.assertEqual(by_id(checks)['listener_owner']['status'], 'fail')
        self.assertEqual(audit.summarize(checks)['exit_code'], 2)

    def test_port_owned_by_other_process_is_not_ready(self):
        data = list(fixture())
        data[1]['tcp']['listeners'][0]['pid'] = 99
        checks = audit.evaluate_path(*data)
        self.assertEqual(by_id(checks)['listener_owner']['status'], 'fail')
        self.assertFalse(audit.summarize(checks)['ready'])

    def test_wildcard_listener_is_not_accepted_as_loopback(self):
        data = list(fixture())
        data[1]['tcp']['listeners'][0]['address'] = '0.0.0.0'
        self.assertEqual(by_id(audit.evaluate_path(*data))['listener_owner']['status'], 'fail')

    def test_disagreeing_public_addresses_fail(self):
        data = list(fixture())
        data[4][1]['ip'] = '192.0.2.1'
        checks = audit.evaluate_path(*data)
        self.assertEqual(by_id(checks)['fixed_egress']['status'], 'fail')
        self.assertEqual(audit.summarize(checks)['state'], 'NOT_READY')

    def test_one_endpoint_timeout_is_incomplete(self):
        data = list(fixture())
        data[4][1] = {'ok': False, 'source': 'ipify', 'error': 'TimeoutError'}
        checks = audit.evaluate_path(*data)
        self.assertEqual(by_id(checks)['fixed_egress']['status'], 'unknown')
        self.assertEqual(audit.summarize(checks)['exit_code'], 3)

    def test_two_copies_of_one_endpoint_do_not_count_as_independent(self):
        data = list(fixture())
        data[4][1] = copy.deepcopy(data[4][0])
        self.assertEqual(by_id(audit.evaluate_path(*data))['fixed_egress']['status'], 'unknown')

    def test_controller_unavailable_cannot_use_good_probes_as_substitute(self):
        data = list(fixture())
        data[2] = {'ok': False, 'error': 'TimeoutError'}
        checks = audit.evaluate_path(*data)
        self.assertEqual(by_id(checks)['controller']['status'], 'unknown')
        self.assertEqual(by_id(checks)['fixed_policy']['status'], 'unknown')
        self.assertEqual(audit.summarize(checks)['state'], 'INCOMPLETE')

    def test_unreadable_process_and_tcp_are_unknown_not_absence(self):
        data = list(fixture())
        data[1]['process'] = {'ok': False}
        data[1]['tcp'] = {'ok': False}
        checks = by_id(audit.evaluate_path(*data))
        self.assertEqual(checks['mihomo_core']['status'], 'unknown')
        self.assertEqual(checks['listener_owner']['status'], 'unknown')

    def test_direct_candidate_is_rejected_even_when_current_exit_is_correct(self):
        data = list(fixture())
        data[2]['proxies']['proxies'][data[0]['chain_group']]['all'].append('DIRECT')
        self.assertEqual(by_id(audit.evaluate_path(*data))['fixed_policy']['status'], 'fail')


class BrowserFeatureFlagTests(OfflineCase):
    def test_media_router_is_an_exact_comma_separated_feature(self):
        cases = [
            ([], False),
            (['--disable-features=MediaRouter'], True),
            (['--disable-features=Other,MediaRouter,Another'], True),
            (['--disable-features=Other, MediaRouter'], True),
            (['--disable-features=MediaRouterExtra'], False),
            (['--disable-features=NotMediaRouter,Other'], False),
            (['--enable-features=MediaRouter'], False),
            (['https://example.test/?value=--disable-features=MediaRouter'], False),
            (['--disable-features', 'MediaRouter'], False),
            (['--disable-features=MediaRouter', '--disable-features=Other'], False),
            (['--disable-features=Other', '--disable-features=MediaRouter'], True),
            (['--', '--disable-features=MediaRouter'], False),
        ]
        for args, expected in cases:
            with self.subTest(arguments=args):
                self.assertIs(audit.browser_media_router_disabled(args), expected)

    def test_snapshot_and_inventory_collect_exact_media_router_state(self):
        import psutil
        for flag, expected in (('--disable-features=Other,MediaRouter', True),
                               ('--disable-features=MediaRouterExtra', False)):
            with self.subTest(flag=flag):
                process = mock.Mock(pid=30, info={'pid': 30, 'name': 'chrome.exe'})
                process.cmdline.return_value = ['chrome.exe',
                    r'--user-data-dir=C:\Users\test\ClaudeNetwork\ChromeData', flag]
                process.ppid.return_value = 1
                raw = {'process': {'ok': True, 'items': [], 'browser': [{'pid': 30}],
                                   'browser_pids': [30]}}
                run = types.SimpleNamespace(returncode=0, stdout=json.dumps(raw))
                with mock.patch.object(psutil, 'Process', return_value=process), \
                     mock.patch.object(psutil, 'process_iter', return_value=[process]), \
                     mock.patch.object(audit, 'run', return_value=run):
                    self.assertIs(audit.snapshot()['process']['browser'][0]['media_router_disabled'], expected)
                    self.assertIs(audit.application_inventory()['browser'][0]['media_router_disabled'], expected)


class ApplicationEvidenceTests(OfflineCase):
    def test_launch_source_classification_and_safe_reporting(self):
        private_marker = 'PRIVATE_TEST_SENTINEL_NOT_A_REAL_SECRET'
        cases = [
            ('inline_standard', ['--setting-sources=user,project,local'], False),
            ('separate_standard', ['--setting-sources', 'user,project,local'], False),
            ('reordered_standard', ['--setting-sources=local,user,project'], False),
            ('empty_sources', ['--setting-sources='], True),
            ('empty_separate_sources', ['--setting-sources', ''], True),
            ('missing_user', ['--setting-sources=project,local'], True),
            ('duplicate_source_arguments', ['--setting-sources=user,project,local',
                                            '--setting-sources=user,project,local'], True),
            ('duplicate_source_value', ['--setting-sources=user,project,local,user'], True),
            ('missing_source_value', ['--setting-sources'], True),
            ('next_option_is_not_source_value', ['--setting-sources', '--verbose'], True),
            ('unknown_source', ['--setting-sources=user,project,local,unknown'], True),
            ('inline_settings', ['--settings={"private":"' + private_marker + '"}'], True),
            ('settings_file', ['--settings', 'C:\\unused\\' + private_marker + '.json'], True),
            ('ordinary_prompt', ['-p', 'Explain --settings and --setting-sources without changing them.'], False),
        ]
        for name, arguments, override in cases:
            with self.subTest(name=name):
                result = audit.classify_launch_arguments(['claude.exe', *arguments])
                self.assertIs(result['launch_override'], override)
                self.assertEqual(result['launch_inspection'], 'complete')
                self.assertNotIn(private_marker, json.dumps(result))
                policy, snap, *_ = fixture()
                snap['process']['items'].append({'pid': 20, 'name': 'claude.exe', **result})
                checks = by_id(audit.applications(policy, snap, []))
                if override:
                    self.assertEqual(checks['launch_override']['status'], 'warn')
                    self.assertTrue(checks['launch_override']['required'])
                elif result['settings_sources_explicit']:
                    self.assertEqual(checks['launch_standard_sources']['status'], 'pass')
                    self.assertNotIn('launch_override', checks)
                else:
                    self.assertNotIn('launch_override', checks)
                self.assertNotIn(private_marker, json.dumps(checks))
        self.spawn.assert_not_called()
        self.socket.assert_not_called()
        self.https.assert_not_called()

    def test_no_applications_cannot_pass_application_checks(self):
        policy, snap, *_ = fixture()
        checks = audit.applications(policy, snap, [])
        self.assertEqual({c['status'] for c in checks}, {'not_running'})
        ready = audit.summarize(audit.evaluate_path(*fixture()) + checks)
        self.assertFalse(ready['ready'])
        self.assertEqual(ready['exit_code'], 3)
        self.assertEqual(ready['network_state'], 'READY')
        self.assertEqual(ready['claude_state'], 'NOT_RUNNING')
        self.assertFalse(ready['applications_observed'])

    def test_running_application_without_connections_is_not_tested(self):
        policy, snap, *_ = fixture()
        snap['process']['items'].append({'pid': 20, 'name': 'claude.exe'})
        self.assertEqual(by_id(audit.applications(policy, snap, []))['claude_runtime']['status'], 'not_tested')

    def test_real_claude_source_port_and_controller_route_correlate(self):
        policy, snap, *_ = fixture()
        add_claude(snap)
        check = by_id(audit.applications(policy, snap, [connection_record(policy)]))['claude_runtime']
        self.assertEqual(check['status'], 'pass')
        self.assertEqual(check['evidence']['observed'][0]['source_port'], '50001')
        self.assertEqual(check['evidence']['observed'][0]['pid'], 20)

    def test_one_cli_request_does_not_verify_idle_vscode_pid(self):
        policy, snap, *_ = fixture()
        add_claude(snap)
        snap['process']['items'][-1]['path'] = r'C:\Users\test\.local\bin\claude.exe'
        snap['process']['items'].append({'pid': 21, 'name': 'claude.exe',
            'path': r'C:\Users\test\.vscode\extensions\anthropic.claude-code-2.0\resources\claude.exe'})
        checks = audit.applications(policy, snap, [connection_record(policy)])
        indexed = by_id(checks)
        self.assertEqual(indexed['claude_pid_20']['evidence']['client_kind'], 'cli')
        self.assertEqual(indexed['claude_pid_21']['evidence']['client_kind'], 'vscode')
        self.assertEqual(indexed['claude_pid_20']['status'], 'pass')
        self.assertEqual(indexed['claude_pid_21']['status'], 'not_tested')
        self.assertEqual(indexed['claude_runtime']['status'], 'partial')
        summary = audit.summarize(audit.evaluate_path(*fixture()) + checks)
        self.assertEqual(summary['claude_state'], 'PARTIAL')
        self.assertEqual(summary['exit_code'], 3)

    def test_every_pid_requires_its_own_correlated_request(self):
        policy, snap, *_ = fixture()
        add_claude(snap)
        snap['process']['items'].append({'pid': 21, 'name': 'claude.exe'})
        snap['tcp']['connections'].append({'pid': 21, 'remote': '127.0.0.1',
                                            'port': 17892, 'source_port': 50002})
        checks = audit.applications(policy, snap, [connection_record(policy), connection_record(policy, source=50002)])
        self.assertEqual(by_id(checks)['claude_runtime']['status'], 'pass')
        self.assertEqual({r['pid'] for r in by_id(checks)['claude_runtime']['evidence']['observed']}, {20, 21})
        summary = audit.summarize(audit.evaluate_path(*fixture()) + checks)
        self.assertEqual(summary['state'], 'CLAUDE_OBSERVED')
        self.assertEqual(summary['claude_state'], 'OBSERVED')
        self.assertEqual(summary['browser_state'], 'NOT_RUNNING')

    def test_one_failing_instance_cannot_be_hidden_by_another_passing_instance(self):
        policy, snap, *_ = fixture()
        add_claude(snap)
        snap['process']['items'].append({'pid': 21, 'name': 'claude.exe'})
        snap['tcp']['connections'].append({'pid': 21, 'remote': '127.0.0.1',
                                            'port': 7892, 'source_port': 50002})
        checks = audit.applications(policy, snap, [connection_record(policy)])
        self.assertEqual(by_id(checks)['claude_runtime']['status'], 'fail')
        self.assertEqual(audit.summarize(checks)['exit_code'], 2)

    def test_browser_tcp_success_does_not_claim_udp_defence(self):
        policy, snap, *_ = fixture()
        snap['process']['browser_pids'] = [30]
        snap['process']['browser'] = [{'pid': 30, 'proxy_ok': True, 'bypass_ok': True,
                                       'quic_off': True, 'media_router_disabled': True,
                                       'webrtc_policy_declared': False}]
        snap['tcp']['connections'].append({'pid': 30, 'remote': '127.0.0.1',
                                            'port': 17892, 'source_port': 50001})
        checks = audit.applications(policy, snap, [connection_record(policy, host='example.com')])
        browser = by_id(checks)['browser_runtime']
        self.assertEqual(browser['status'], 'pass')
        self.assertTrue(browser['evidence']['tcp_only'])
        self.assertFalse(browser['evidence']['udp_protection_verified'])
        self.assertEqual(audit.summarize(checks)['browser_state'], 'TCP_ONLY')

    def test_missing_or_unconfirmed_media_router_flag_blocks_browser_pass(self):
        for state in ('missing', False, None, 'true'):
            with self.subTest(media_router_disabled=state):
                policy, snap, *_ = fixture()
                snap['process']['browser_pids'] = [30]
                root = {'pid': 30, 'proxy_ok': True, 'bypass_ok': True,
                        'quic_off': True, 'webrtc_policy_declared': True}
                if state != 'missing':
                    root['media_router_disabled'] = state
                snap['process']['browser'] = [root]
                snap['tcp']['connections'].append({'pid': 30, 'remote': '127.0.0.1',
                                                    'port': 17892, 'source_port': 50001})
                checks = audit.applications(policy, snap, [connection_record(policy, host='example.com')])
                browser = by_id(checks)['browser_runtime']
                self.assertEqual(browser['status'], 'fail')
                self.assertIn({'reason': 'browser_network_flags_conflict'},
                              browser['evidence']['unexpected_connections'])
                self.assertEqual(audit.summarize(checks)['exit_code'], 2)

    def test_unrelated_source_port_is_not_proof_for_claude(self):
        policy, snap, *_ = fixture()
        add_claude(snap)
        checks = audit.applications(policy, snap, [connection_record(policy, source=50002)])
        self.assertEqual(by_id(checks)['claude_runtime']['status'], 'not_tested')

    def test_unrelated_host_is_not_anthropic_business_evidence(self):
        policy, snap, *_ = fixture()
        add_claude(snap)
        checks = audit.applications(policy, snap, [connection_record(policy, host='example.com')])
        self.assertEqual(by_id(checks)['claude_runtime']['status'], 'not_tested')

    def test_missing_controller_connections_is_unknown(self):
        policy, snap, *_ = fixture()
        add_claude(snap)
        self.assertEqual(by_id(audit.applications(policy, snap, None))['claude_runtime']['status'], 'unknown')

    def test_actual_connection_through_daily_port_fails(self):
        policy, snap, *_ = fixture()
        add_claude(snap, port=7892)
        checks = audit.applications(policy, snap, [])
        self.assertEqual(by_id(checks)['claude_runtime']['status'], 'fail')
        self.assertEqual(audit.summarize(checks)['exit_code'], 2)

    def test_unclassified_loopback_alongside_good_request_cannot_pass(self):
        policy, snap, *_ = fixture()
        add_claude(snap)
        snap['tcp']['connections'].append({'pid': 20, 'remote': '127.0.0.1',
                                            'port': 8888, 'source_port': 50002})
        checks = audit.applications(policy, snap, [connection_record(policy)])
        self.assertNotEqual(by_id(checks)['claude_runtime']['status'], 'pass')

    def test_wrong_inbound_with_good_chain_fails(self):
        policy, snap, *_ = fixture()
        add_claude(snap)
        record = connection_record(policy)
        record['metadata']['inboundName'] = 'mixed-in'
        checks = audit.applications(policy, snap, [record])
        self.assertEqual(by_id(checks)['claude_runtime']['status'], 'fail')

    def test_direct_hop_with_expected_group_labels_fails(self):
        policy, snap, *_ = fixture()
        add_claude(snap)
        record = connection_record(policy)
        record['chains'].append('DIRECT')
        self.assertEqual(by_id(audit.applications(policy, snap, [record]))['claude_runtime']['status'], 'fail')

    def test_browser_route_without_root_flags_cannot_pass(self):
        policy, snap, *_ = fixture()
        snap['process']['browser_pids'] = [30]
        snap['tcp']['connections'].append({'pid': 30, 'remote': '127.0.0.1',
                                            'port': 17892, 'source_port': 50001})
        checks = audit.applications(policy, snap, [connection_record(policy, host='example.com')])
        self.assertEqual(by_id(checks)['browser_runtime']['status'], 'fail')


class SummaryAndCommandTests(OfflineCase):
    def test_audit_launch_and_preflight_modes_have_distinct_acceptance(self):
        checks = audit.evaluate_path(*fixture())
        self.assertEqual(audit.summarize(checks)['exit_code'], 3)
        self.assertEqual(audit.summarize(checks)['network_state'], 'READY')
        self.assertEqual(audit.summarize(checks, mode='preflight')['state'], 'PROXY_READY')
        launch = audit.summarize(checks, mode='launch_check')
        self.assertEqual(launch['state'], 'LAUNCH_READY')
        self.assertEqual(launch['exit_code'], 0)
        self.assertEqual(launch['claude_state'], 'NOT_OBSERVED')
        self.assertFalse(launch['applications_observed'])
        checks.append(audit.item('settings', 'settings', 'unknown', '', required=True, category='configuration'))
        self.assertEqual(audit.summarize(checks, mode='launch_check')['exit_code'], 3)

    def test_application_tcp_and_controller_are_sampled_concurrently(self):
        _, snap, *_ = fixture()
        snap['process']['items'] = [{'pid': 20, 'name': 'claude.exe'}]
        barrier = threading.Barrier(2)

        def tcp(owners):
            self.assertEqual(owners, {20})
            barrier.wait(timeout=2)
            return {'ok': True, 'connections': []}

        def controller(path, install_dir):
            self.assertEqual(path, '/connections')
            barrier.wait(timeout=2)
            return {'connections': []}

        with mock.patch.object(audit, 'application_inventory', return_value=snap['process']), \
                mock.patch.object(audit, 'application_tcp', side_effect=tcp), \
                mock.patch.object(audit, 'api', side_effect=controller):
            sampled, records = audit.application_sample(Path('unused'))
        self.assertTrue(sampled['tcp']['ok'])
        self.assertEqual(records, [])
        window = sampled['sampling_window']
        self.assertEqual(window['method'], 'concurrent_reads')
        self.assertFalse(window['atomic'])
        for source in ('tcp', 'controller'):
            self.assertIsNone(window[source]['error'])
            self.assertLessEqual(window[source]['started_at'], window[source]['finished_at'])

    def test_application_sampling_read_failure_stays_unknown(self):
        policy, snap, *_ = fixture()
        add_claude(snap)
        with mock.patch.object(audit, 'application_inventory', return_value=snap['process']), \
                mock.patch.object(audit, 'application_tcp', return_value=snap['tcp']), \
                mock.patch.object(audit, 'api', side_effect=PermissionError):
            sampled, records = audit.application_sample(Path('unused'))
        self.assertIsNone(records)
        self.assertEqual(sampled['sampling_window']['controller']['error'], 'PermissionError')
        self.assertEqual(by_id(audit.applications(policy, sampled, records))['claude_runtime']['status'], 'unknown')

    def test_launch_collect_checks_settings_without_claiming_live_applications(self):
        policy, snap, ctl, disk, probes, route = fixture()
        settings = types.ModuleType('audit_settings')
        settings.audit_settings = mock.Mock(return_value=[audit.item(
            'settings_ok', '设置', 'pass', '', required=True, category='configuration')])
        with mock.patch.object(audit, 'load_policy', return_value=policy), \
                mock.patch.object(audit, 'snapshot', return_value=snap), \
                mock.patch.object(audit, 'controller', return_value=ctl), \
                mock.patch.object(audit, 'disk_structure', return_value=disk), \
                mock.patch.object(audit, 'probe', side_effect=lambda port, url:
                    probes[1] if 'ipify' in url else probes[0]), \
                mock.patch.object(audit, 'route_probe', return_value=route), \
                mock.patch.object(audit, 'application_sample') as sample, \
                mock.patch.dict(sys.modules, {'audit_settings': settings}):
            report = audit.collect(Path('unused'), launch_check=True)
        settings.audit_settings.assert_called_once()
        sample.assert_not_called()
        self.assertEqual(report['state'], 'LAUNCH_READY')
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual(report['claude_state'], 'NOT_OBSERVED')
        self.assertFalse(report['applications_observed'])
        self.spawn.assert_not_called()

    def test_launch_check_argument_selects_launch_mode_without_repair(self):
        with mock.patch.object(sys, 'argv', ['audit_proxy.py', '--launch-check', '--json']), \
                mock.patch.object(audit, 'collect', return_value={'exit_code': 0}) as collect, \
                mock.patch.object(audit, 'run') as run, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(audit.main(), 0)
        self.assertEqual(collect.call_args.args[2:], (False, False, True))
        run.assert_not_called()

    def test_no_required_checks_is_incomplete(self):
        self.assertEqual(audit.summarize([])['state'], 'INCOMPLETE')
        self.assertFalse(audit.summarize([audit.item('x', 'x', 'pass', 'x')])['ready'])

    def test_required_unknown_prevents_ready(self):
        checks = [audit.item('a', 'a', 'pass', '', required=True),
                  audit.item('b', 'b', 'unknown', '', required=True)]
        self.assertEqual(audit.summarize(checks)['exit_code'], 3)

    def test_failure_is_not_hidden_by_unknown(self):
        checks = [audit.item('a', 'a', 'unknown', '', required=True),
                  audit.item('b', 'b', 'fail', '', required=True)]
        self.assertEqual(audit.summarize(checks)['exit_code'], 2)

    def test_controller_get_failure_is_explicit(self):
        with mock.patch.object(audit, 'api', side_effect=TimeoutError):
            self.assertEqual(audit.controller(Path('unused')), {
                'ok': False, 'error': 'TimeoutError', 'failed_read': 'version'})

    def test_default_main_does_not_repair_launch_or_write(self):
        report = {'exit_code': 3, 'ready': False, 'state': 'INCOMPLETE'}
        with mock.patch.object(sys, 'argv', ['audit_proxy.py']), \
                mock.patch.object(audit, 'collect', return_value=report) as collect, \
                mock.patch.object(audit, 'display') as display, \
                mock.patch.object(audit, 'run') as run, \
                mock.patch.object(Path, 'write_text') as write, \
                mock.patch.object(Path, 'mkdir') as mkdir:
            self.assertEqual(audit.main(), 3)
        collect.assert_called_once()
        self.assertEqual(collect.call_args.args[2:], (False, False, False))
        display.assert_called_once_with(report)
        run.assert_not_called()
        write.assert_not_called()
        mkdir.assert_not_called()
        self.spawn.assert_not_called()

    def test_default_collect_read_only_with_all_io_mocked(self):
        policy, snap, ctl, disk, probes, route = fixture()
        settings = types.ModuleType('audit_settings')
        settings.audit_settings = mock.Mock(return_value=[])
        with mock.patch.object(audit, 'load_policy', return_value=policy), \
                mock.patch.object(audit, 'snapshot', return_value=snap), \
                mock.patch.object(audit, 'controller', return_value=ctl), \
                mock.patch.object(audit, 'disk_structure', return_value=disk), \
                mock.patch.object(audit, 'probe', side_effect=lambda port, url:
                    probes[1] if 'ipify' in url else probes[0]), \
                mock.patch.object(audit, 'route_probe', return_value=route), \
                mock.patch.object(audit, 'application_sample', return_value=(snap, [])) as sample, \
                mock.patch.dict(sys.modules, {'audit_settings': settings}), \
                mock.patch.object(Path, 'write_text') as write, \
                mock.patch.object(Path, 'mkdir') as mkdir:
            report = audit.collect(Path('unused'))
        self.assertTrue(report['read_only'])
        self.assertEqual(report['mode'], 'check')
        self.assertFalse(report['ready'])
        self.assertEqual(report['network_state'], 'READY')
        self.assertEqual(report['exit_code'], 3)
        self.assertFalse(report['applications_observed'])
        sample.assert_called_once_with(Path('unused'))
        write.assert_not_called()
        mkdir.assert_not_called()
        self.spawn.assert_not_called()
        self.socket.assert_not_called()
        self.https.assert_not_called()

    def test_collect_uses_fresh_application_sample_after_settings_work(self):
        policy, initial, ctl, disk, probes, route = fixture()
        fresh = copy.deepcopy(initial)
        add_claude(fresh)
        fresh['sampling_window'] = {'method': 'concurrent_reads', 'atomic': False}
        order = []
        settings = types.ModuleType('audit_settings')

        def read_settings(*args):
            order.append('settings')
            return []

        def sample(*args):
            order.append('application_sample')
            return fresh, [connection_record(policy)]

        settings.audit_settings = read_settings
        with mock.patch.object(audit, 'load_policy', return_value=policy), \
                mock.patch.object(audit, 'snapshot', return_value=initial), \
                mock.patch.object(audit, 'controller', return_value=ctl), \
                mock.patch.object(audit, 'disk_structure', return_value=disk), \
                mock.patch.object(audit, 'probe', side_effect=lambda port, url:
                    probes[1] if 'ipify' in url else probes[0]), \
                mock.patch.object(audit, 'route_probe', return_value=route), \
                mock.patch.object(audit, 'application_sample', side_effect=sample), \
                mock.patch.dict(sys.modules, {'audit_settings': settings}):
            report = audit.collect(Path('unused'))
        self.assertEqual(order, ['settings', 'application_sample'])
        self.assertEqual(report['claude_state'], 'OBSERVED')
        self.assertEqual(report['exit_code'], 0)
        self.assertEqual(report['application_sampling_window'], fresh['sampling_window'])
        self.assertIn('claude_pid_20', by_id(report['checks']))

    def test_full_browser_evidence_runs_despite_unrelated_required_settings_unknown(self):
        policy, snap, ctl, disk, probes, route = fixture()
        settings = types.ModuleType('audit_settings')
        settings.audit_settings = mock.Mock(return_value=[audit.item(
            'settings_audit', '应用配置检查', 'unknown', '配置未完整读取',
            required=True, category='configuration')])
        browser = types.ModuleType('audit_browser')
        browser.browser_audit = mock.Mock(return_value=[audit.item(
            'browser_fixed_exit', '临时浏览器公网出口', 'pass', '独立测试通过',
            required=True, category='browser_test')])
        with mock.patch.object(audit, 'load_policy', return_value=policy), \
                mock.patch.object(audit, 'snapshot', return_value=snap), \
                mock.patch.object(audit, 'controller', return_value=ctl), \
                mock.patch.object(audit, 'disk_structure', return_value=disk), \
                mock.patch.object(audit, 'probe', side_effect=lambda port, url:
                    probes[1] if 'ipify' in url else probes[0]), \
                mock.patch.object(audit, 'route_probe', return_value=route), \
                mock.patch.object(audit, 'application_sample', return_value=(snap, [])), \
                mock.patch.dict(sys.modules, {'audit_settings': settings, 'audit_browser': browser}), \
                mock.patch.object(Path, 'write_text') as write, \
                mock.patch.object(Path, 'mkdir') as mkdir:
            report = audit.collect(Path('unused'), full=True)
        browser.browser_audit.assert_called_once_with(policy['entry_port'], policy['expected_ip'])
        self.assertEqual(by_id(report['checks'])['browser_fixed_exit']['status'], 'pass')
        self.assertEqual(by_id(report['checks'])['settings_audit']['status'], 'unknown')
        self.assertEqual(report['mode'], 'full_check')
        self.assertEqual(report['state'], 'INCOMPLETE')
        self.assertEqual(report['exit_code'], 3)
        self.assertFalse(report['ready'])
        write.assert_not_called()
        mkdir.assert_not_called()
        self.spawn.assert_not_called()
        self.socket.assert_not_called()
        self.https.assert_not_called()

    def test_unexpected_collect_error_returns_incomplete_not_success(self):
        with mock.patch.object(sys, 'argv', ['audit_proxy.py', '--json']), \
                mock.patch.object(audit, 'collect', side_effect=PermissionError), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(audit.main(), 3)
        report = json.loads(output.getvalue())
        self.assertFalse(report['ready'])
        self.assertEqual(report['error'], 'PermissionError')
        self.spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
