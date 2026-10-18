"""Prove that this rewrite leaves the proxy unchanged, before anything is deployed.

1. Data: the installed (old) and this repository's (new) repair code each build the
   Clash configuration and settings plan from the live files; only hashes are compared.
2. Code: every function that writes Clash, settings or protected groups must be
   identical in the repair backend and the in-use guard; other changes are shown as diffs.
3. Read-only: proxy files and Clash processes are fingerprinted around a run of the new check.

An intended proxy change must be named. --expect front-order accepts only a new first-hop
order of the fixed exit chains: every chain keeps its exit node, credentials and fields, the
daily order and everything else stay identical, and the order must actually change.
--expect domestic-rules accepts only two added direct rules (GEOSITE,CN and globalsign.com),
adjacent and right before the GEOIP,CN / MATCH tail: with them removed the configuration must
be identical, and they must actually appear.

Nothing is written outside a temporary staging folder, which is removed afterwards.
Usage: py -X utf8 -B verify_same_proxy.py [--workspace DIR] [--expect front-order|domestic-rules]
"""
import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
NEW = HERE / 'claude-network'
NEW_GUARD = HERE / 'CodexNetworkGuard'
OLD = Path.home() / '.codex' / 'ClaudeNetwork'
OLD_GUARD = Path.home() / '.codex' / 'CodexNetworkGuard'
CLASH = Path(os.environ['APPDATA']) / 'io.github.clash-verge-rev.clash-verge-rev'
# Functions that change Clash, client settings or protected groups, or decide when to.
REPAIR_SAME = ['run', 'ps', 'api', 'load_yaml', 'dump_yaml', 'render', 'safe_node', 'source_node', 'equivalent_yaml',
               'render_settings', 'settings_plan', 'build_candidate', 'physical_network', 'health', 'inspect_live',
               'put_config', 'verify_exit', 'protected_closed', 'select_groups', 'warmup', 'launch_app', 'app_running',
               'fail_closed']
GUARD_SAME = ['now', 'log', 'response', 'api', 'read_state', 'write_state', 'physical_network', 'configured_chains',
              'warmup', 'alert', 'fixed_streaks']
# Direct rules the domestic-rules change adds, in this order.
DOMESTIC = ['GEOSITE,CN,DIRECT', 'DOMAIN-SUFFIX,globalsign.com,DIRECT']
# Named intended changes: the data items, must-match functions and files each one may change.
EXPECTED = {'front-order': {'about': '只允许固定线路的跳板顺序变化',
                            'data': {'candidate', 'clash_plan', 'routing_baseline', 'chain_fronts'},
                            'functions': {'build_candidate'}, 'files': {'routing-baseline.js'}},
            'domestic-rules': {'about': '只允许在 GEOIP,CN 兜底前新增 GEOSITE,CN 与 globalsign.com 两条直连规则',
                               'data': {'candidate', 'front_order_free', 'clash_plan', 'routing_baseline', 'domestic'},
                               'functions': set(), 'files': {'routing-baseline.js'}}}
NOTHING = {'data': set(), 'functions': set(), 'files': set()}

PROBE = r'''
import copy, hashlib, json, os, sys
from pathlib import Path
code, workspace = sys.argv[1], sys.argv[2]
domestic = json.loads(sys.argv[3])
sys.path.insert(0, code); os.chdir(code)
import repair_proxy as r
h = lambda data: hashlib.sha256(data if isinstance(data, bytes) else data.encode('utf-8')).hexdigest()[:16]
cfg, plan = r.build_candidate()
chains = cfg.get('proxy-providers', {}).get(r.PROVIDER, {}).get('payload', [])
def front_order_free(cfg):
    # The fixed chains without their labels and first-hop order; exit node and every other field stay.
    cfg = copy.deepcopy(cfg)
    provider = cfg.get('proxy-providers', {}).get(r.PROVIDER, {})
    provider['payload'] = sorted(({k: v for k, v in c.items() if k != 'name'} for c in provider.get('payload', [])),
                                 key=lambda c: str(c.get('dialer-proxy')))
    return cfg
def domestic_free(cfg):
    # Also without the declared domestic rules; every other rule, group and node stays.
    cfg = front_order_free(cfg)
    cfg['rules'] = [x for x in cfg.get('rules', []) if x not in domestic]
    return cfg
rules = cfg.get('rules', [])
at = [i for i, x in enumerate(rules) if x in domestic]
place = {'rules': [rules[i] for i in at], 'adjacent': at == list(range(at[0], at[0] + len(at))) if at else True,
         'next': rules[at[-1] + 1] if at and at[-1] + 1 < len(rules) else None}
settings = r.settings_plan(workspace)
home = Path.home(); vscode = Path(os.environ['APPDATA']) / 'Code/User/settings.json'
rendered = {}
for path, kind, always in [(home / '.claude/settings.json', 'claude', True), (home / '.claude/settings.local.json', 'claude', False),
                           (vscode, 'vscode', True)]:
    if path.is_file():
        rendered[str(path)] = h(r.render_settings(path.read_text(encoding='utf-8-sig'), kind, always)['text'])
for kind in ('claude', 'vscode'):
    rendered['<empty ' + kind + '>'] = h(r.render_settings('{}\n', kind, True)['text'])
print(json.dumps({'candidate': h(r.dump_yaml(cfg)), 'front_order_free': h(r.dump_yaml(front_order_free(cfg))),
                  'domestic_free': h(r.dump_yaml(domestic_free(cfg))), 'domestic': place,
                  'chain_fronts': [c.get('dialer-proxy') for c in chains],
                  'clash_plan': {str(k): h(v) for k, v in plan.items()},
                  'settings_plan': {str(k): h(v) for k, v in settings.items()}, 'rendered_settings': rendered,
                  'values': r.VALUES, 'select': r.SELECT, 'protected': r.PROTECTED, 'fronts': r.FRONTS,
                  'ids': [r.PROFILE, r.SCRIPT, r.PREPEND], 'verify_port': r.VERIFY_PORT,
                  'routing_baseline': h((Path(code) / 'routing-baseline.js').read_bytes()),
                  'settings_writer': h((Path(code) / 'repair_jsonc.cjs').read_bytes())}))
'''


def functions(path):
    source = path.read_text(encoding='utf-8-sig')
    tree = ast.parse(source)
    found = {node.name: ast.get_source_segment(source, node) for node in tree.body if isinstance(node, ast.FunctionDef)}
    module = '\n'.join(ast.get_source_segment(source, node) for node in tree.body if not isinstance(node, ast.FunctionDef))
    return found, module


def compare_code(old_path, new_path, must_match, label, allowed=frozenset()):
    old, old_module = functions(old_path)
    new, new_module = functions(new_path)
    ok = True
    for name in must_match:
        same = name in old and old.get(name) == new.get(name)
        if not same and name in allowed:
            print('  [预期内] %s.%s 与旧版不同，改动见下' % (label, name))
            continue
        ok &= same
        if not same:
            print('  [不同] %s.%s 必须和旧版一致' % (label, name))
    print('  %s：%d 个写代理/决定何时写代理的函数逐字一致%s' % (label, sum(old.get(n) == new.get(n) for n in must_match),
                                                     '' if ok else '（有不一致，见上）'))
    removed = sorted(set(old) - set(new))
    added = sorted(set(new) - set(old))
    changed = sorted(n for n in set(old) & set(new) if old[n] != new[n])
    if removed:
        print('  删除的函数：' + '、'.join(removed))
    if added:
        print('  新增的函数：' + '、'.join(added))
    for name in changed:
        print('  改动的函数 %s：' % name)
        for line in difflib.unified_diff(old[name].splitlines(), new[name].splitlines(), lineterm='', n=0):
            if not line.startswith(('---', '+++', '@@')):
                print('    ' + line[:160])
    if old_module != new_module:
        print('  模块级语句的改动：')
        for line in difflib.unified_diff(old_module.splitlines(), new_module.splitlines(), lineterm='', n=0):
            if not line.startswith(('---', '+++', '@@')):
                print('    ' + line[:160])
    return ok


def fingerprint():
    paths = [CLASH / name for name in ('clash-verge.yaml', 'profiles.yaml', 'config.yaml', 'verge.yaml')]
    paths += sorted((CLASH / 'profiles').glob('*'))
    paths += [Path.home() / '.claude/settings.json', Path.home() / '.claude/settings.local.json',
              Path(os.environ['APPDATA']) / 'Code/User/settings.json', Path.home() / '.codex/config.toml',
              OLD / 'repair-last-result.json']
    result = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()[:16] if p.is_file() else None for p in paths}
    import psutil
    result['processes'] = sorted((x.info['name'], x.pid) for x in psutil.process_iter(['name'])
                                 if (x.info['name'] or '').lower() in ('clash-verge.exe', 'verge-mihomo.exe'))
    return result


def probe(code_dir, workspace):
    result = subprocess.run([sys.executable, '-X', 'utf8', '-B', '-c', PROBE, str(code_dir), str(workspace),
                             json.dumps(DOMESTIC)], capture_output=True, text=True, encoding='utf-8', timeout=120)
    if result.returncode:
        # The traceback may quote configuration lines; only the exception type is shown.
        last = (result.stderr.strip().splitlines() or ['unknown'])[-1].split(':', 1)[0]
        raise RuntimeError('repair code probe failed in %s (%s)' % (code_dir, last))
    return json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', type=Path, default=Path.cwd())
    parser.add_argument('--expect', choices=sorted(EXPECTED), help='name the one intended proxy change')
    args = parser.parse_args()
    expected = EXPECTED.get(args.expect, NOTHING)
    if args.expect:
        print('声明的预期改动：%s（%s）\n' % (args.expect, expected['about']))
    before = fingerprint()
    staging = Path(tempfile.mkdtemp(prefix='proxy-v2-verify-'))
    ok = True
    try:
        # The new code runs as it would once installed: its files plus the installed private data.
        for item in NEW.iterdir():
            if item.suffix in ('.py', '.js', '.cjs'):
                shutil.copy2(item, staging / item.name)
        shutil.copytree(NEW / 'vendor', staging / 'vendor')
        for name in ('repair-baseline.dpapi', 'audit_policy.json'):
            shutil.copy2(OLD / name, staging / name)
        print('1. 数据层：用旧版和新版修复代码，对当前真实配置各生成一次（只比哈希）')
        old, new = probe(OLD, args.workspace), probe(staging, args.workspace)
        for key in old:
            same = old[key] == new[key]
            if not same and key in expected['data']:
                print('  %-18s 不一致（预期内）' % key)
                continue
            ok &= same
            print('  %-18s %s' % (key, '一致' if same else '不一致'))
        if args.expect == 'front-order':
            print('  固定线路跳板顺序：%s → %s' % (' / '.join(map(str, old['chain_fronts'])),
                                                 ' / '.join(map(str, new['chain_fronts']))))
            if old['chain_fronts'] == new['chain_fronts']:
                # A declared change that does not happen means the flag is stale, not that it passed.
                print('  [错误] 声明了跳板顺序改动，但顺序没有变化')
                ok = False
        if args.expect == 'domestic-rules':
            placed = new['domestic']
            print('  国内直连规则：%s → %s' % (' / '.join(old['domestic']['rules']) or '无', ' / '.join(placed['rules']) or '无'))
            # Exactly these rules, once, adjacent and in front of the tail; anything else means the flag is stale or they moved.
            if (old['domestic']['rules'] or placed['rules'] != DOMESTIC or not placed['adjacent']
                    or not str(placed['next']).upper().startswith(('GEOIP,CN,', 'MATCH,'))):
                print('  [错误] 声明了国内直连规则改动，但新版不是恰好在 GEOIP,CN / MATCH 兜底前新增这两条（紧挨着、各一条）')
                ok = False
        print('  旧版本次会改的 Clash 文件：%d 个；设置文件：%d 个（0 表示当前配置已是受管理状态）'
              % (len(old['clash_plan']), len(old['settings_plan'])))
        print('\n2. 代码层：逐个函数比对')
        ok &= compare_code(OLD / 'repair_proxy.py', NEW / 'repair_proxy.py', REPAIR_SAME, 'repair_proxy',
                           expected['functions'])
        ok &= compare_code(OLD_GUARD / 'health_monitor.py', NEW_GUARD / 'health_monitor.py', GUARD_SAME, 'health_monitor')
        same_files = [name for name in ('routing-baseline.js', 'repair_jsonc.cjs', 'repair_support.py')
                      if (OLD / name).read_bytes() == (NEW / name).read_bytes()]
        print('  逐字节相同的文件：' + '、'.join(same_files))
        differing = [name for name in ('routing-baseline.js', 'repair_jsonc.cjs', 'repair_support.py') if name not in same_files]
        if differing:
            print('  不同的文件：' + '、'.join(name + ('（预期内）' if name in expected['files'] else '') for name in differing))
        ok &= all(name in expected['files'] for name in differing)
        print('\n3. 只读证明：运行一次新版检查，前后对比代理相关文件和 Clash 进程')
        subprocess.run([sys.executable, '-X', 'utf8', '-B', str(NEW / 'check.py'), '--json', '--workspace', str(args.workspace)],
                       capture_output=True, timeout=120)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    after = fingerprint()
    unchanged = before == after
    ok &= unchanged
    print('  %d 个文件和 %d 个 Clash 进程：%s' % (len(before) - 1, len(before['processes']), '没有任何变化' if unchanged else '有变化！'))
    if not unchanged:
        for key in before:
            if before[key] != after[key]:
                print('    变化：' + key)
    passed = '只有声明的改动（%s），可以进入部署评审。' % args.expect if args.expect else '代理没有变化，可以进入部署评审。'
    print('\n结论：' + (passed if ok else '存在不一致，不要部署。'))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
