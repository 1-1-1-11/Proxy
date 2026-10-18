"""Offline tests for the check: verdicts, chains, Claude traffic and output. No network or writes."""
import contextlib
import io
from pathlib import Path
import unittest
from unittest import mock

import check

P = {'expected_ip': '203.0.113.10', 'entry_port': 17892, 'daily_port': 7892,
     'fixed_group': 'Claude-固定出口', 'chain_group': '静态出口-自动恢复', 'provider': '固定出口链路'}
FIXED = ['静态IP-链式', '静态出口-自动恢复', 'Claude-固定出口']
CLI = r'C:\Users\u\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\bin\claude.exe'
VSCODE = r'C:\Users\u\.vscode\extensions\anthropic.claude-code-2.1.0-win32-x64\resources\native-binary\claude.exe'
DESKTOP = r'C:\Users\u\AppData\Local\AnthropicClaude\app-1.0.0\claude.exe'


def record(path, chains, host='api.anthropic.com', process='claude.exe'):
    return {'metadata': {'process': process, 'processPath': path, 'host': host, 'destinationPort': '443'}, 'chains': chains}


def report(*checks, desktop=False, targets=check.ALL):
    return check.finish({'checks': list(checks), 'notes': [], 'desktop_installed': desktop, 'routing': None,
                         'workspace': 'X'}, targets, 0)


class VerdictTests(unittest.TestCase):
    def test_any_failure_blocks_only_the_entries_it_touches(self):
        r = report(check.check('a', 'A', True, '', check.ALL), check.check('b', 'B', False, '', ('vscode',)))
        self.assertEqual(r['entries'], {'cli': 'READY', 'vscode': 'NOT_READY', 'web': 'READY', 'desktop': 'NOT_INSTALLED'})
        self.assertEqual(r['exit_code'], 2)

    def test_unknown_is_never_ready(self):
        r = report(check.check('a', 'A', None, '', check.ALL))
        self.assertEqual(set(v for k, v in r['entries'].items() if k != 'desktop'), {'UNKNOWN'})
        self.assertEqual(r['exit_code'], 3)

    def test_failure_wins_over_unknown(self):
        r = report(check.check('a', 'A', None, '', check.ALL), check.check('b', 'B', False, '', ('cli',)))
        self.assertEqual(r['entries']['cli'], 'NOT_READY')
        self.assertEqual(r['exit_code'], 2)

    def test_missing_desktop_app_does_not_affect_exit_code(self):
        r = report(check.check('a', 'A', True, '', check.ALL), check.check('d', 'D', False, '', ('desktop',)))
        self.assertEqual(r['entries']['desktop'], 'NOT_INSTALLED')
        self.assertEqual(r['exit_code'], 0)

    def test_installed_desktop_app_counts(self):
        r = report(check.check('d', 'D', False, '', ('desktop',)), desktop=True)
        self.assertEqual(r['entries']['desktop'], 'NOT_READY')
        self.assertEqual(r['exit_code'], 2)

    def test_launch_mode_only_judges_cli(self):
        r = report(check.check('b', 'B', False, '', ('vscode',)), targets=check.TARGETS['launch'])
        self.assertEqual(r['entries'], {'cli': 'READY'})
        self.assertEqual(r['exit_code'], 0)


class ChainTests(unittest.TestCase):
    def test_fixed_chain_required(self):
        self.assertTrue(check.valid_chain(FIXED, P))
        for chains in (['DIRECT'], ['节点', '日常网络-自动恢复', 'Claude-固定出口'], FIXED + ['REJECT'], ['Claude-固定出口'], None):
            with self.subTest(chains=chains):
                self.assertFalse(check.valid_chain(chains, P))

    def test_client_kind_by_location(self):
        self.assertEqual(check.client_kind(CLI), 'cli')
        self.assertEqual(check.client_kind(VSCODE), 'vscode')
        self.assertEqual(check.client_kind(DESKTOP), 'desktop')
        self.assertEqual(check.client_kind(r'C:\Program Files\WindowsApps\Claude_1.0.0_x64__abc\app\claude.exe'), 'desktop')
        self.assertEqual(check.client_kind(None), 'cli')

    def test_loopback(self):
        for address in ('127.0.0.1', '::1', '::ffff:127.0.0.1'):
            self.assertTrue(check.is_loopback(address))
        for address in ('203.0.113.9', '198.18.0.5', 'bad'):
            self.assertFalse(check.is_loopback(address))


class Conn:
    def __init__(self, pid, ip, port=443, status='ESTABLISHED'):
        self.pid, self.status = pid, status
        self.raddr = mock.Mock(ip=ip, port=port)


class TrafficTests(unittest.TestCase):
    def run_traffic(self, processes, records, connections=()):
        psutil = mock.Mock(CONN_ESTABLISHED='ESTABLISHED')
        psutil.net_connections.return_value = list(connections)
        with mock.patch.dict('sys.modules', {'psutil': psutil}):
            return {c['id']: c for c in check.traffic_checks(P, processes, records)}

    def test_all_connections_on_fixed_chain_pass(self):
        processes = {1: {'pid': 1, 'path': CLI, 'kind': 'cli'}, 2: {'pid': 2, 'path': DESKTOP, 'kind': 'desktop'}}
        result = self.run_traffic(processes, [record(CLI, FIXED), record(DESKTOP, FIXED)], [Conn(1, '127.0.0.1', 17892)])
        self.assertTrue(result['traffic_cli']['ok'])
        self.assertTrue(result['traffic_desktop']['ok'])

    def test_desktop_connection_off_chain_fails_desktop_only(self):
        processes = {1: {'pid': 1, 'path': CLI, 'kind': 'cli'}, 2: {'pid': 2, 'path': DESKTOP, 'kind': 'desktop'}}
        result = self.run_traffic(processes, [record(CLI, FIXED), record(DESKTOP, ['DIRECT'], host='sentry.io')])
        self.assertTrue(result['traffic_cli']['ok'])
        self.assertFalse(result['traffic_desktop']['ok'])
        self.assertEqual(result['traffic_desktop']['entries'], ['desktop'])
        self.assertIn('sentry.io', result['traffic_desktop']['detail'])

    def test_desktop_pinned_to_dedicated_port(self):
        processes = {2: {'pid': 2, 'path': DESKTOP, 'kind': 'desktop'}}
        result = self.run_traffic(processes, [], [Conn(2, '127.0.0.1', 17892)])
        self.assertTrue(result['traffic_desktop']['ok'])
        self.assertIn('1 条连接经专用端口', result['traffic_desktop']['detail'])
        # The app may only talk to loopback; any other socket means the firewall did not hold.
        result = self.run_traffic(processes, [], [Conn(2, '198.18.0.9')])
        self.assertFalse(result['traffic_desktop']['ok'])

    def test_cli_connection_skipping_local_proxy_fails(self):
        processes = {1: {'pid': 1, 'path': CLI, 'kind': 'cli'}}
        result = self.run_traffic(processes, [], [Conn(1, '203.0.113.50')])
        self.assertFalse(result['traffic_cli']['ok'])
        self.assertIn('203.0.113.50', result['traffic_cli']['detail'])

    def test_unreadable_records_are_unknown_not_pass(self):
        processes = {1: {'pid': 1, 'path': CLI, 'kind': 'cli'}}
        self.assertIsNone(self.run_traffic(processes, None)['traffic_cli']['ok'])

    def test_other_programs_are_ignored(self):
        result = self.run_traffic({}, [record(r'C:\x\chrome.exe', ['DIRECT'], process='chrome.exe')])
        self.assertEqual(result, {})


class NetworkEvaluationTests(unittest.TestCase):
    def test_egress_retries_silent_sources_and_any_other_ip_blocks(self):
        good = {'curl_exit': 0, 'ip': P['expected_ip']}
        silent = {'curl_exit': 1, 'ip': None}
        wrong = {'curl_exit': 0, 'ip': '198.51.100.7'}
        # Answers per source, in order: first round, then the single retry.
        cases = [({'cloudflare': [good], 'ipify': [good]}, True, 2),
                 ({'cloudflare': [good], 'ipify': [silent, good]}, True, 3),
                 ({'cloudflare': [good], 'ipify': [silent, silent]}, True, 3),
                 ({'cloudflare': [silent, silent], 'ipify': [silent, silent]}, None, 4),
                 ({'cloudflare': [good], 'ipify': [wrong]}, False, 2),
                 ({'cloudflare': [silent, wrong], 'ipify': [good]}, False, 3)]
        for answers, expected, calls in cases:
            queues = {name: list(rows) for name, rows in answers.items()}
            def probe(port, url):
                return dict(queues['cloudflare' if 'cloudflare' in url else 'ipify'].pop(0))
            with self.subTest(answers=answers), mock.patch('network_check.probe', side_effect=probe) as fake:
                row = check.egress(P)
                self.assertIs(row['ok'], expected)
                self.assertEqual(fake.call_count, calls)

    def test_guard_states(self):
        base = {'ok': True, 'alive': True, 'age_seconds': 10, 'fixed_exit_blocked': False, 'repair_active': False}
        self.assertTrue(check.guard_check(base)['ok'])
        self.assertFalse(check.guard_check(dict(base, alive=False))['ok'])
        self.assertFalse(check.guard_check(dict(base, fixed_exit_blocked=True))['ok'])
        self.assertFalse(check.guard_check(dict(base, age_seconds=500))['ok'])
        self.assertIsNone(check.guard_check(dict(base, repair_active=True))['ok'])
        self.assertIsNone(check.guard_check({'ok': False})['ok'])

    def test_fixed_policy_rejects_fallback_outside_fixed_chain(self):
        disk = {'ok': True, 'candidates': [{'name': '静态IP-链式'}]}
        groups = {'Claude-固定出口': {'now': '静态出口-自动恢复', 'all': ['静态出口-自动恢复', 'REJECT']},
                  '静态出口-自动恢复': {'now': '静态IP-链式', 'all': ['静态IP-链式']}}
        clash = {'ok': True, 'proxies': {'proxies': groups}}
        self.assertTrue(check.fixed_policy(P, clash, disk)['ok'])
        groups['Claude-固定出口']['all'].append('DIRECT')
        self.assertFalse(check.fixed_policy(P, clash, disk)['ok'])
        self.assertIsNone(check.fixed_policy(P, {'ok': False, 'error': 'x'}, disk)['ok'])

    def protection(self, **changes):
        base = {'paths': [DESKTOP], 'missing': [], 'firewall_on': True, 'cowork_installed': True,
                'cowork_blocked': True, 'unpinned': [], 'running': [7]}
        return dict(base, **changes)

    def test_desktop_problem_priority(self):
        self.assertIsNone(check.desktop_problem(self.protection()))
        self.assertEqual(check.desktop_problem(self.protection(firewall_on=False, missing=[DESKTOP])), 'firewall_off')
        self.assertEqual(check.desktop_problem(self.protection(missing=[DESKTOP], unpinned=[7])), 'firewall')
        self.assertEqual(check.desktop_problem(self.protection(paths=[])), 'firewall')
        self.assertEqual(check.desktop_problem(self.protection(unpinned=[7])), 'unpinned')
        self.assertEqual(check.desktop_problem(self.protection(), offchain=True), 'offchain')

    def test_cowork_problem(self):
        self.assertIsNone(check.cowork_problem(self.protection()))
        self.assertEqual(check.cowork_problem(self.protection(cowork_blocked=False)), 'cowork')
        self.assertEqual(check.cowork_problem(self.protection(firewall_on=False)), 'firewall_off')
        self.assertIsNone(check.cowork_problem(self.protection(cowork_installed=False, cowork_blocked=False)))

    def test_desktop_checks_report_both_parts(self):
        rows = {r['id']: r for r in check.desktop_checks(self.protection())}
        self.assertTrue(rows['desktop_protection']['ok'] and rows['cowork']['ok'])
        rows = {r['id']: r for r in check.desktop_checks(self.protection(unpinned=[7], cowork_blocked=False))}
        self.assertFalse(rows['desktop_protection']['ok'])
        self.assertIn('固定出口', rows['desktop_protection']['fix'])
        self.assertFalse(rows['cowork']['ok'])
        self.assertIsNone(check.desktop_checks(None)[0]['ok'])

    def test_pinned_uses_last_proxy_switch(self):
        self.assertTrue(check.pinned(['claude.exe', '--proxy-server=http://127.0.0.1:17892']))
        self.assertFalse(check.pinned(['claude.exe']))
        self.assertFalse(check.pinned(['claude.exe', '--proxy-server=http://127.0.0.1:17892', '--proxy-server=http://127.0.0.1:7892']))

    def test_protection_flags_unpinned_main_process_only(self):
        running = [{'pid': 1, 'path': DESKTOP, 'cmdline': [DESKTOP]},
                   {'pid': 2, 'path': DESKTOP, 'cmdline': [DESKTOP, '--type=renderer']}]
        with mock.patch.object(check, 'desktop_executables', return_value=[DESKTOP]), \
                mock.patch.object(check, 'firewall_blocked', return_value=({DESKTOP.lower()}, {'coworkvmservice'})), \
                mock.patch.object(check, 'firewall_enabled', return_value=True), \
                mock.patch.object(check, 'cowork_service_installed', return_value=True):
            result = check.desktop_protection(running)
            self.assertEqual((result['unpinned'], result['missing'], result['cowork_blocked']), ([1], [], True))
            running[0]['cmdline'].append('--proxy-server=http://127.0.0.1:17892')
            self.assertEqual(check.desktop_protection(running)['unpinned'], [])
            other = DESKTOP.replace('1.0.0', '1.0.1')
            with mock.patch.object(check, 'desktop_executables', return_value=[DESKTOP, other]):
                self.assertEqual(check.desktop_protection(running)['missing'], [other])

    def test_routing_mode_profiles(self):
        def mode(m, tun):
            return check.routing_mode({'ok': True, 'configs': {'mode': m, 'tun': {'enable': tun, 'strict-route': True}}})
        self.assertEqual(mode('rule', True)['profile'], 'claude')
        self.assertEqual(mode('rule', False)['profile'], 'domestic')
        self.assertEqual(mode('global', True)['profile'], 'abnormal')
        self.assertIsNone(check.routing_mode({'ok': False}))


class SettingsTests(unittest.TestCase):
    def test_settings_entries_follow_file_owner(self):
        import repair_proxy
        cases = [({Path(r'C:\Users\u\AppData\Roaming\Code\User\settings.json'): b''}, ['vscode']),
                 ({Path(r'C:\Users\u\.claude\settings.json'): b''}, ['cli', 'vscode']), ({}, ['cli', 'vscode'])]
        for plan, entries in cases:
            with self.subTest(plan=plan), mock.patch.object(repair_proxy, 'settings_plan', return_value=plan):
                result = check.settings_check(Path('.'))
                self.assertEqual(result['entries'], entries)
                self.assertIs(result['ok'], not plan)

    def test_repair_refusal_is_a_failure_with_its_reason(self):
        import repair_proxy
        error = repair_proxy.RepairError('设置文件格式有误；为保留原数据，未覆盖该文件。')
        with mock.patch.object(repair_proxy, 'settings_plan', side_effect=error):
            result = check.settings_check(Path('.'))
        self.assertFalse(result['ok'])
        self.assertIn('格式有误', result['detail'])

    def test_api_host_other_than_official_fails(self):
        files = [{'path': 'a.json', 'kind': 'claude'}, {'path': 'b.json', 'kind': 'vscode'}]
        rows = [{'path': 'a.json', 'base_url_host': 'api.anthropic.com', 'overrides': ['ANTHROPIC_API_KEY']},
                {'path': 'b.json', 'base_url_host': 'relay.example.com', 'overrides': []}]
        node = mock.Mock(returncode=0, stdout=__import__('json').dumps(rows))
        with mock.patch.object(check, 'settings_files', return_value=files), \
                mock.patch.object(check.subprocess, 'run', return_value=node), \
                mock.patch.object(check, 'windows_env', return_value=[]):
            result, notes = check.api_override(Path('.'))
        self.assertFalse(result['ok'])
        self.assertEqual(result['entries'], ['vscode'])
        self.assertIn('relay.example.com', result['detail'])
        self.assertIn('ANTHROPIC_API_KEY', notes[0])

    def test_official_api_passes(self):
        node = mock.Mock(returncode=0, stdout='[]')
        with mock.patch.object(check, 'settings_files', return_value=[]), \
                mock.patch.object(check.subprocess, 'run', return_value=node), \
                mock.patch.object(check, 'windows_env', return_value=[]):
            result, notes = check.api_override(Path('.'))
        self.assertTrue(result['ok'])
        self.assertEqual(notes, [])


class OutputTests(unittest.TestCase):
    def render(self, r, details=False):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            check.display(r, details)
        return out.getvalue()

    def test_guard_block_hides_downstream_symptoms(self):
        guard = check.guard_check({'ok': True, 'alive': True, 'age_seconds': 5, 'fixed_exit_blocked': True})
        egress = check.check('fixed_egress', '固定出口 IP', None, '连不上', check.ALL, 'x', expected_ip='1.1.1.1', matched=0)
        text = self.render(report(guard, egress))
        self.assertIn('已自动阻断', text)
        self.assertNotIn('连不上', text)
        self.assertIn('暂不能使用', text)

    def test_ready_output_is_short(self):
        egress = check.check('fixed_egress', '固定出口 IP', True, 'ok', check.ALL, expected_ip='203.0.113.10', matched=2)
        text = self.render(report(egress))
        self.assertIn('结论：可以使用 Claude', text)
        self.assertIn('客户端（桌面端）：未安装', text)
        self.assertNotIn('原因', text)
        self.assertIn('--- 逐项证据 ---', self.render(report(egress), details=True))


if __name__ == '__main__':
    unittest.main(verbosity=2)
