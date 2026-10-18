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
            'physical_network': mock.Mock(return_value={'ready': True}),
            'inspect_live': mock.Mock(return_value={'config_drift': False, 'wrong_groups': []}),
            'app_running': mock.Mock(return_value=True), 'warmup': mock.Mock(),
            'protected_closed': mock.Mock(return_value=was_closed),
            'put_config': mock.Mock(side_effect=record('put_config')),
            'fail_closed': mock.Mock(side_effect=record('fail_closed')),
            'select_groups': mock.Mock(side_effect=lambda protected=True: events.append(('select', protected)) or []),
            'verify_exit': mock.Mock(side_effect=lambda: events.append('verify') or next(verify)),
            'health': mock.Mock(side_effect=lambda: events.append('health') or dict(HEALTHY)),
            'launch_app': mock.Mock(side_effect=AssertionError('Real Clash launch forbidden')),
        }
        with contextlib.ExitStack() as stack:
            for name, value in patches.items():
                stack.enter_context(mock.patch.object(repair, name, value))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = repair.execute(types.SimpleNamespace(workspace=None))
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


class SettingsValueTests(unittest.TestCase):
    def test_browser_points_to_installed_launcher_wherever_code_runs(self):
        from pathlib import Path
        self.assertEqual(repair.VALUES['BROWSER'], str(Path.home() / '.codex/ClaudeNetwork/ClaudeBrowser.exe'))
        self.assertEqual({repair.VALUES[k] for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY')}, {'http://127.0.0.1:17892'})


class BaselineListenerTests(unittest.TestCase):
    def test_verify_listener_targets_chain_group_not_client_group(self):
        text = (repair.HERE / 'routing-baseline.js').read_text(encoding='utf-8')
        self.assertIn('name: "claude-verify-http"', text)
        self.assertIn('port: 17893, proxy: chainGroup', text)
        self.assertEqual(repair.VERIFY_PORT, 17893)

    def test_fixed_chains_follow_their_own_front_order_while_daily_keeps_its_order(self):
        front = {'type': 'hysteria2', 'server': 'front.invalid', 'port': 443}
        exit_node = {'name': '静态IP-链式', 'type': 'socks5', 'server': '192.0.2.10', 'port': 1080}
        cfg = repair.render({'proxies': [dict(front, name=n) for n in repair.FRONTS[:3]] + [exit_node],
                             'proxy-groups': [], 'rules': []})
        chains = cfg['proxy-providers'][repair.PROVIDER]['payload']
        self.assertEqual([c['dialer-proxy'] for c in chains], repair.CHAIN_FRONTS[:3])
        self.assertEqual(chains[0]['name'], '静态IP-链式')
        self.assertEqual({c['server'] for c in chains}, {'192.0.2.10'})
        daily = next(g for g in cfg['proxy-groups'] if g['name'] == repair.DAILY)
        self.assertEqual(daily['proxies'], repair.FRONTS[:3])
        self.assertEqual(repair.render(cfg), cfg)
        self.assertEqual(sorted(repair.CHAIN_FRONTS), sorted(repair.FRONTS))


class DomesticRuleTests(unittest.TestCase):
    DOMESTIC = ['GEOSITE,CN,DIRECT', 'DOMAIN-SUFFIX,globalsign.com,DIRECT']
    TAIL = ['GEOIP,telegram,Telegram,no-resolve', 'DOMAIN-SUFFIX,CN,DIRECT', 'GEOIP,CN,DIRECT,no-resolve',
            'GEOIP,CN,DIRECT', 'MATCH,节点选择']

    def build(self, rules):
        front = {'type': 'hysteria2', 'server': 'front.invalid', 'port': 443}
        exit_node = {'name': '静态IP-链式', 'type': 'socks5', 'server': '192.0.2.10', 'port': 1080}
        return repair.render({'proxies': [dict(front, name=n) for n in repair.FRONTS[:3]] + [exit_node],
                              'proxy-groups': [], 'rules': rules})

    def test_domestic_rules_sit_right_before_the_geoip_tail_and_nothing_above_them_changes(self):
        subscription = ['DOMAIN-SUFFIX,example.org,节点选择', 'DOMAIN-SUFFIX,qq.com,DIRECT'] + self.TAIL
        rules = self.build(subscription)['rules']
        at = rules.index('GEOIP,CN,DIRECT,no-resolve')
        self.assertEqual(rules[at - 2:at], self.DOMESTIC)
        self.assertEqual([r for r in rules if r in subscription], subscription)
        self.assertTrue(rules[0].startswith('PROCESS-NAME,claude.exe,'))
        self.assertLess(rules.index('DOMAIN-SUFFIX,anthropic.com,Claude-固定出口'), rules.index(self.DOMESTIC[0]))
        self.assertLess(rules.index('DOMAIN-SUFFIX,example.org,节点选择'), rules.index(self.DOMESTIC[0]))
        self.assertEqual(rules[-1], 'MATCH,节点选择')

    def test_without_geoip_cn_the_rules_go_before_match_or_to_the_end(self):
        self.assertEqual(self.build(['DOMAIN-SUFFIX,example.org,节点选择', 'MATCH,节点选择'])['rules'][-3:],
                         self.DOMESTIC + ['MATCH,节点选择'])
        self.assertEqual(self.build(['DOMAIN-SUFFIX,example.org,节点选择'])['rules'][-2:], self.DOMESTIC)
        self.assertEqual(self.build(['geoip,cn,DIRECT', 'MATCH,节点选择'])['rules'][-4:],
                         self.DOMESTIC + ['geoip,cn,DIRECT', 'MATCH,节点选择'])

    def test_rendering_again_keeps_exactly_one_copy_in_the_same_place(self):
        cfg = self.build(self.TAIL)
        self.assertEqual(repair.render(cfg), cfg)
        # A copy higher up, for example added by hand, moves to the managed place instead of duplicating.
        self.assertEqual(self.build(['GEOSITE,CN,DIRECT'] + self.TAIL), cfg)
        for rule in self.DOMESTIC:
            self.assertEqual(cfg['rules'].count(rule), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
