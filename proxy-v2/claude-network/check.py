"""claude-proxy: can Claude be used through the fixed exit right now?

Checking and watching are read-only: no settings change, no account or model
request, and no connection to Anthropic. Only --repair runs repair_proxy.py,
which verifies the exit before reopening Claude; a full check follows it.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import ctypes
import datetime
import ipaddress
import itertools
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import string
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

VERSION = '2026.10.17'
HERE = Path(__file__).resolve().parent
HOME = Path.home()
INSTALL = HOME / '.codex' / 'ClaudeNetwork'
GUARD_DIR = HOME / '.codex' / 'CodexNetworkGuard'
GUARD_MUTEX = 'Local\\ClashNetworkHealth-example'
GUARD_STARTUP = Path(os.environ.get('APPDATA', str(HOME / 'AppData/Roaming'))) / \
    'Microsoft/Windows/Start Menu/Programs/Startup/CodexNetworkGuard.lnk'
GUARD_STALE_SECONDS = 120
CLASH_YAML = HOME / 'AppData/Roaming/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml'
NODE = Path(r'C:\Program Files\nodejs\node.exe')
LAUNCHER = INSTALL / 'ClaudeBrowser.exe'
OFFICIAL_API = 'api.anthropic.com'
DAILY_GROUP = '日常网络-自动恢复'
OVERRIDE_NAMES = ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN',
                  'CLAUDE_CODE_USE_BEDROCK', 'CLAUDE_CODE_USE_VERTEX', 'CLAUDE_CODE_USE_FOUNDRY')
NAMES = {'cli': 'CLI', 'vscode': 'VS Code', 'web': '登录链接（指纹浏览器）', 'desktop': '客户端（桌面端）'}
WORDS = {'READY': '可以使用', 'NOT_READY': '暂不能使用', 'UNKNOWN': '无法确认，先别用', 'NOT_INSTALLED': '未安装'}
ALL = ('cli', 'vscode', 'web', 'desktop')
TARGETS = {'all': ALL, 'launch': ('cli',), 'web': ('web',), 'desktop': ('desktop',)}
DESKTOP_ALIAS = Path(os.environ.get('LOCALAPPDATA', str(HOME / 'AppData/Local'))) / 'Microsoft/WindowsApps/claude-desktop.exe'
COWORK_SERVICE = 'CoworkVMService'
HIDDEN = 0x08000000 if os.name == 'nt' else 0
REPAIR = '运行 claude-proxy -Repair'
PROTECT = '运行 claude-proxy -Protect（会弹一次管理员确认）'
EXIT_SUPPRESSED_BY_BLOCK = {'fixed_policy', 'fixed_egress', 'route'}
FIREWALL_GROUP = 'Claude local policy'
FIREWALL_RULES = r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
PACKAGES = r'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages'


def check(key, title, ok, detail, entries, fix=None, **evidence):
    """ok is True (passed), False (a definite problem) or None (could not be confirmed)."""
    return {'id': key, 'title': title, 'ok': ok, 'detail': detail, 'entries': list(entries),
            'fix': fix, 'evidence': evidence}


def now():
    return datetime.datetime.now().astimezone().isoformat(timespec='seconds')


def load_policy():
    p = json.loads((HERE / 'audit_policy.json').read_text(encoding='utf-8-sig'))
    if p.get('schema') != 1:
        raise ValueError('Policy schema')
    ipaddress.ip_address(p['expected_ip'])
    for key in ('entry_port', 'daily_port'):
        if type(p[key]) is not int or not 1 <= p[key] <= 65535:
            raise ValueError('Policy port')
    for key in ('fixed_group', 'chain_group', 'provider'):
        if not isinstance(p.get(key), str) or not p[key]:
            raise ValueError('Policy group')
    return p


def api(path, timeout=10):
    """GET from the Mihomo controller; a stalled pipe read is abandoned after the timeout."""
    from repair_support import raw_api
    box = {}

    def read():
        try:
            box['value'] = raw_api(path, 'GET')
        except Exception as exc:
            box['error'] = type(exc).__name__

    worker = threading.Thread(target=read, daemon=True)
    worker.start()
    worker.join(timeout)
    if 'value' not in box:
        raise RuntimeError(box.get('error', 'Timeout'))
    status, body = box['value']
    if status != 200:
        raise RuntimeError('HTTP ' + str(status))
    return body


def valid_chain(chains, p):
    return (isinstance(chains, list) and p['fixed_group'] in chains and p['chain_group'] in chains
            and not {'DIRECT', 'REJECT', DAILY_GROUP}.intersection(chains))


def is_loopback(address):
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_loopback or (ip.version == 6 and ip.ipv4_mapped is not None and ip.ipv4_mapped.is_loopback)
    except ValueError:
        return False


def client_kind(path):
    """CLI, VS Code extension or desktop app, judged by where claude.exe lives."""
    normalized = str(path or '').replace('\\', '/').lower()
    if '/extensions/anthropic.claude-code-' in normalized:
        return 'vscode'
    if any(part in normalized for part in ('/anthropicclaude/', '/programs/claude/',
                                           '/windowsapps/claude', '/windowsapps/anthropic')):
        return 'desktop'
    return 'cli'


def claude_processes():
    import psutil
    found = {}
    for proc in psutil.process_iter(['name', 'exe']):
        if (proc.info.get('name') or '').lower() == 'claude.exe':
            path = proc.info.get('exe')
            row = found[proc.pid] = {'pid': proc.pid, 'path': path, 'kind': client_kind(path)}
            if row['kind'] == 'desktop':
                try:
                    row['cmdline'] = proc.cmdline()
                except psutil.Error:
                    row['cmdline'] = None
    return found


def desktop_installed(processes):
    local = Path(os.environ.get('LOCALAPPDATA', str(HOME / 'AppData/Local')))
    return (any(path.is_dir() for path in (local / 'AnthropicClaude', local / 'Programs/Claude'))
            or any(local.glob('Packages/*Claude*'))
            or any(row['kind'] == 'desktop' for row in processes.values()))


def desktop_executables():
    """Every on-disk path of the installed desktop app and its Chrome bridge (native messaging host);
    a package can live on another volume. Each must be firewalled to loopback."""
    import winreg
    found = set()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, PACKAGES) as root:
        for index in itertools.count():
            try:
                name = winreg.EnumKey(root, index)
            except OSError:
                break
            if not name.lower().startswith('claude_'):
                continue
            try:
                with winreg.OpenKey(root, name) as key:
                    folders = [Path(winreg.QueryValueEx(key, 'PackageRootFolder')[0])]
            except OSError:
                continue
            folders += [Path(letter + ':/WindowsApps') / name for letter in string.ascii_uppercase]
            for folder in folders:
                found |= {str(folder / 'app' / relative) for relative in ('claude.exe', 'resources/chrome-native-host.exe')
                          if (folder / 'app' / relative).is_file()}
    return sorted(found, key=str.lower)


def firewall_blocked():
    """Programs and services our rule group blocks from outbound traffic (readable without admin)."""
    import winreg
    programs, services = set(), set()
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, FIREWALL_RULES) as key:
        for index in itertools.count():
            try:
                _, value, _ = winreg.EnumValue(key, index)
            except OSError:
                break
            fields = dict(part.split('=', 1) for part in str(value).split('|') if '=' in part)
            if (fields.get('EmbedCtxt') != FIREWALL_GROUP or fields.get('Action') != 'Block'
                    or fields.get('Dir') != 'Out' or fields.get('Active') != 'TRUE'):
                continue
            if fields.get('App'):
                programs.add(fields['App'].lower())
            if fields.get('Svc'):
                services.add(fields['Svc'].lower())
    return programs, services


def firewall_enabled():
    """Windows Firewall must be on for every profile; a Group Policy value overrides the local one."""
    import winreg
    base = r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
    policy = r'SOFTWARE\Policies\Microsoft\WindowsFirewall'
    for local, managed in (('DomainProfile', 'DomainProfile'), ('StandardProfile', 'PrivateProfile'),
                           ('PublicProfile', 'PublicProfile')):
        value = None
        for path, name in ((policy + '\\' + managed, 'EnableFirewall'), (base + '\\' + local, 'EnableFirewall')):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                    value = winreg.QueryValueEx(key, name)[0]
                    break
            except OSError:
                continue
        if value != 1:
            return False
    return True


def cowork_service_installed():
    import winreg
    try:
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 'SYSTEM\\CurrentControlSet\\Services\\' + COWORK_SERVICE).Close()
        return True
    except OSError:
        return False


def pinned(arguments, port=17892):
    """Chromium uses the last --proxy-server switch; it must name the dedicated port."""
    values = [a for a in arguments if a.startswith('--proxy-server=')]
    return bool(values) and values[-1] == '--proxy-server=http://127.0.0.1:%d' % port


def desktop_protection(running=None, port=17892):
    """Everything that keeps the desktop app on the fixed exit, read without admin rights."""
    if running is None:
        running = [row for row in claude_processes().values() if row['kind'] == 'desktop']
    paths = sorted(set(desktop_executables()) | {row['path'] for row in running if row.get('path')}, key=str.lower)
    programs, services = firewall_blocked()
    unpinned = []
    for row in running:
        arguments = row.get('cmdline') or []
        if not any(a.startswith('--type=') for a in arguments) and not pinned(arguments, port):
            unpinned.append(row['pid'])
    return {'paths': paths, 'missing': [path for path in paths if path.lower() not in programs],
            'firewall_on': firewall_enabled(), 'cowork_installed': cowork_service_installed(),
            'cowork_blocked': COWORK_SERVICE.lower() in services, 'unpinned': unpinned,
            'running': [row['pid'] for row in running]}


# code -> (what is wrong, what to do). Shared with the in-use guard's alerts.
PROBLEMS = {
    'firewall_off': ('Windows 防火墙被关闭了：客户端和 Cowork 服务可以绕过代理直连。',
                     '在 Windows 安全中心重新打开防火墙（所有网络类型）'),
    'firewall': ('客户端当前版本没有防火墙保护（常见于客户端刚更新）：它可以绕过代理直连。', PROTECT),
    'unpinned': ('客户端不是从「Claude 客户端（固定出口）」打开的，没有固定走专用端口。',
                 '关掉客户端，从桌面「Claude 客户端（固定出口）」或托盘菜单重新打开'),
    'offchain': ('Clash 记录到客户端有连接没走固定出口。', '运行 claude-proxy -Watch 查看，确认原因前不要使用客户端'),
    'cowork': ('Cowork 服务的断网规则不在了：它以系统身份运行，可以直连。', PROTECT),
    'unknown': ('无法确认客户端的保护状态（守护读不到防火墙规则或进程）。', '运行 claude-proxy 查看原因'),
}


def desktop_problem(protection, offchain=False):
    """Why the desktop app must not run right now, or None."""
    if not protection['firewall_on']:
        return 'firewall_off'
    if not protection['paths'] or protection['missing']:
        return 'firewall'
    if protection['unpinned']:
        return 'unpinned'
    return 'offchain' if offchain else None


def cowork_problem(protection):
    if not protection['cowork_installed']:
        return None
    if not protection['firewall_on']:
        return 'firewall_off'
    return None if protection['cowork_blocked'] else 'cowork'


def describe(row):
    m = row.get('metadata', {})
    chains = row.get('chains', []) or []
    return {'host': m.get('host') or m.get('sniffHost') or m.get('destinationIP'),
            'port': m.get('destinationPort'), 'route': ' → '.join(reversed(chains)) or '未知'}


# --- network: shared by every entry -------------------------------------------------

def clash_core(p):
    title = 'Clash 内核与专用端口'
    try:
        import psutil
        cores = {x.pid for x in psutil.process_iter(['name']) if (x.info.get('name') or '').lower() == 'verge-mihomo.exe'}
        listeners = [{'pid': c.pid, 'address': c.laddr.ip} for c in psutil.net_connections(kind='tcp')
                     if c.status == psutil.CONN_LISTEN and c.laddr and c.laddr.port == p['entry_port']]
    except Exception as exc:
        return check('clash_core', title, None, '读不到进程或端口（%s）。' % type(exc).__name__, ALL, '稍后重新检查')
    ok = bool(cores) and bool(listeners) and all(x['pid'] in cores and x['address'] in ('127.0.0.1', '::1')
                                                 for x in listeners)
    detail = ('Clash 内核在运行，专用端口 %d 由它在本机监听。' % p['entry_port'] if ok else
              'Clash 内核没有运行。' if not cores else '专用端口 %d 不是由 Clash 内核在本机监听。' % p['entry_port'])
    return check('clash_core', title, ok, detail, ALL, '打开 Clash Verge；仍不通过就' + REPAIR,
                 core_pids=sorted(cores), listeners=listeners)


def read_clash():
    with concurrent.futures.ThreadPoolExecutor(3) as pool:
        futures = {name: pool.submit(api, '/' + name) for name in ('version', 'configs', 'proxies')}
    data = {}
    for name, future in futures.items():
        try:
            data[name] = future.result()
        except Exception as exc:
            return {'ok': False, 'error': str(exc), 'failed': name}
    return {'ok': True, **data}


def disk_structure(p):
    """Every fixed-chain candidate must reach the same SOCKS5 server at the expected IP."""
    try:
        import yaml
        cfg = yaml.safe_load(CLASH_YAML.read_text(encoding='utf-8-sig'))
        nodes = cfg.get('proxy-providers', {}).get(p['provider'], {}).get('payload', [])
        endpoints = {(n.get('server'), n.get('port'), n.get('type')) for n in nodes}
        # Equality only: credential values never leave this function.
        same_credentials = bool(nodes) and all(
            (n.get('username'), n.get('password')) == (nodes[0].get('username'), nodes[0].get('password')) for n in nodes)
        ok = (bool(nodes) and len(endpoints) == 1 and same_credentials and
              all(n.get('server') == p['expected_ip'] and n.get('type') == 'socks5' and n.get('dialer-proxy')
                  and n.get('username') and n.get('password') for n in nodes))
        return {'ok': ok, 'candidates': [{'name': n.get('name'), 'front': n.get('dialer-proxy')} for n in nodes]}
    except Exception as exc:
        return {'ok': None, 'error': type(exc).__name__, 'candidates': []}


def fixed_policy(p, clash, disk):
    title = '固定出口线路配置'
    if not clash['ok']:
        return check('fixed_policy', title, None, '读不到 Clash 的实时状态（%s）。' % clash['error'], ALL,
                     '打开 Clash Verge；仍不通过就' + REPAIR)
    if disk.get('ok') is None:
        return check('fixed_policy', title, None, '读不到 Clash 配置文件（%s）。' % disk.get('error'), ALL, REPAIR)
    groups = clash['proxies'].get('proxies', {})
    selected, chain = groups.get(p['fixed_group'], {}), groups.get(p['chain_group'], {})
    allowed, members = set(selected.get('all', [])), set(chain.get('all', []))
    names = {x['name'] for x in disk['candidates']}
    ok = (selected.get('now') == p['chain_group'] and bool(allowed) and allowed <= {p['chain_group'], 'REJECT'}
          and bool(members) and members <= names and chain.get('now') in members and disk['ok'])
    return check('fixed_policy', title, ok,
                 'Claude 只能走固定出口链路或被拒绝；每条候选链路都通往同一个固定 IP，没有直连兜底。' if ok else
                 'Clash 里 Claude 固定出口的线路被改动，或和受管理的配置对不上。', ALL, REPAIR,
                 selected=selected.get('now'), chain=chain.get('now'), members=sorted(members), disk_ok=disk['ok'])


def egress(p):
    from network_check import probe
    sources = (('Cloudflare', 'https://www.cloudflare.com/cdn-cgi/trace'), ('ipify', 'https://api.ipify.org?format=json'))
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda source: probe(p['entry_port'], source[1]), sources))
    # A source that did not answer gets one more try; any other IP seen still blocks.
    results = [result if result['curl_exit'] == 0 or result.get('ip') else dict(probe(p['entry_port'], url), retried=True)
               for (_, url), result in zip(sources, results)]
    rows = [dict(result, source=name) for (name, _), result in zip(sources, results)]
    expected = p['expected_ip']
    wrong = sorted({r['ip'] for r in rows if r.get('ip') and r['ip'] != expected})
    matched = sum(1 for r in rows if r['curl_exit'] == 0 and r.get('ip') == expected)
    if wrong:
        ok, detail = False, '固定出口 IP 变成了 %s，不是预期的 %s。' % ('、'.join(wrong), expected)
        fix = '这是线路供应商那边的变化，本机修不了：恢复前不要使用 Claude，联系供应商恢复原 IP。'
    elif matched == len(rows):
        ok, detail, fix = True, '两处独立检测都是预期的固定出口 %s。' % expected, None
    elif matched:
        # Same standard as the in-use guard: one confirmed match and no other IP seen.
        ok, detail, fix = True, '一处检测确认是预期的固定出口 %s，另一处暂时没有回应；没有检测到其他 IP。' % expected, None
    else:
        ok, detail = None, '固定出口线路暂时连不上（%d/%d 处检测成功）。' % (matched, len(rows))
        fix = '确认网络正常，几分钟后重新检查；持续失败请联系线路供应商。'
    return check('fixed_egress', '固定出口 IP', ok, detail, ALL, fix, expected_ip=expected, matched=matched, probes=rows)


def route(p, host='example.com'):
    """A synthetic TLS connection through the dedicated port must land on the fixed chain."""
    title = '专用端口的实际路由'
    conn = None
    try:
        conn = socket.create_connection(('127.0.0.1', p['entry_port']), timeout=6)
        conn.settimeout(7)
        conn.sendall(f'CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n'.encode('ascii'))
        response = b''
        while b'\r\n\r\n' not in response:
            part = conn.recv(1)
            if not part or len(response) > 8192:
                raise RuntimeError('CONNECT unavailable')
            response += part
        if response.split(b' ')[1] != b'200':
            raise RuntimeError('CONNECT rejected')
        conn = ssl.create_default_context().wrap_socket(conn, server_hostname=host)
        source = str(conn.getsockname()[1])
        rows = [r for r in api('/connections').get('connections', [])
                if str(r.get('metadata', {}).get('sourcePort')) == source and r.get('metadata', {}).get('host') == host]
        chains = [r.get('chains', []) for r in rows]
        inbound = [r.get('metadata', {}).get('inboundName') for r in rows]
        ok = bool(chains) and all(valid_chain(c, p) for c in chains) and all(v == 'claude-fixed-http' for v in inbound)
        return check('route', title, ok,
                     '经专用端口的连接实际进入了固定出口链路。' if ok else '经专用端口的连接没有进入固定出口链路。',
                     ALL, REPAIR, chains=chains, inbound=inbound)
    except Exception as exc:
        return check('route', title, None, '路由探测没有完成（%s）。' % type(exc).__name__, ALL,
                     '确认网络正常后重新检查；仍不通过就' + REPAIR)
    finally:
        if conn:
            conn.close()


def _mutex_exists(name):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenMutexW.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_wchar_p]
    kernel.OpenMutexW.restype = ctypes.c_void_p
    handle = kernel.OpenMutexW(0x00100000, False, name)
    if handle:
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle(handle)
        return True
    error = ctypes.get_last_error()
    if error == 2:
        return False
    if error == 5:
        return True
    raise OSError('Mutex query failed')


def guard_state():
    """Liveness and block state of the in-use guard; reads only its state files."""
    try:
        alive = _mutex_exists(GUARD_MUTEX)
    except Exception as exc:
        return {'ok': False, 'error': type(exc).__name__}
    result = {'ok': True, 'alive': alive, 'age_seconds': None, 'fixed_exit_blocked': None, 'repair_active': False}
    try:
        state = json.loads((GUARD_DIR / 'network-state.json').read_text(encoding='utf-8'))
        written = datetime.datetime.fromisoformat(state['time'])
        result['age_seconds'] = round((datetime.datetime.now(written.tzinfo) - written).total_seconds(), 1)
        result['fixed_exit_blocked'] = bool(state.get('fixed_exit_blocked'))
    except (OSError, ValueError, KeyError, TypeError):
        pass
    try:
        active = json.loads((GUARD_DIR / 'repair-active.json').read_text(encoding='utf-8'))
        result['repair_active'] = time.time() < float(active.get('expires', 0))
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return result


def guard_check(state=None):
    g = state if state is not None else guard_state()
    title, age = '使用中守护', g.get('age_seconds')
    if not g.get('ok'):
        ok, detail, fix = None, '读不到使用中守护的状态。', '稍后重新检查'
    elif not g.get('alive'):
        ok, detail = False, '使用中守护没有运行：使用过程中出口变了，不会自动断开 Claude。'
        fix = '运行：Start-Process "%s"（或注销后重新登录 Windows）' % GUARD_STARTUP
    elif g.get('fixed_exit_blocked'):
        ok, detail = False, '守护发现固定出口 IP 不对，已自动阻断 Claude。'
        fix = '先联系线路供应商确认出口恢复，再' + REPAIR + '（修复会先核对 IP，不对就继续阻断）'
    elif g.get('repair_active'):
        ok, detail, fix = None, '修复正在进行，守护暂停核对。', '等 1 分钟后重新检查'
    elif age is None or not 0 <= age <= GUARD_STALE_SECONDS:
        ok, detail, fix = False, '守护在运行，但没有按时更新状态，可能卡住了。', '重启电脑后重新检查'
    else:
        ok, detail, fix = True, '使用中守护在运行：约每 30 秒核对一次出口，不对就自动断开 Claude。', None
    return check('guard', title, ok, detail, ALL, fix, **{k: v for k, v in g.items() if k != 'ok'})


def routing_mode(clash):
    if not clash['ok']:
        return None
    live = clash['configs']
    tun = live.get('tun') or {}
    mode = live.get('mode')
    profile = 'claude' if mode == 'rule' and tun.get('enable') is True else 'domestic' if mode == 'rule' else 'abnormal'
    return {'profile': profile, 'mode': mode, 'tun': tun.get('enable'), 'strict_route': tun.get('strict-route')}


# --- per entry ----------------------------------------------------------------------

def settings_check(workspace):
    """Settings are correct exactly when the repair backend would change nothing."""
    title = 'Claude / VS Code 代理设置'
    try:
        import repair_proxy
        plan = repair_proxy.settings_plan(workspace)
    except Exception as exc:
        message = str(exc) if type(exc).__name__ == 'RepairError' else None
        return check('settings', title, False if message else None,
                     message or '设置检查没有完成（%s）。' % type(exc).__name__, ('cli', 'vscode'),
                     '按上面的原因手动处理后重新检查' if message else '稍后重新检查')
    if not plan:
        return check('settings', title, True, '代理都指向专用端口，打开链接用的浏览器都指向专用启动器。', ('cli', 'vscode'))
    paths = [str(path) for path in plan]
    entries = sorted({'vscode'} | (set() if all(_vscode_file(path) for path in paths) else {'cli'}))
    return check('settings', title, False, '这些设置文件需要校正：' + '；'.join(paths), entries,
                 REPAIR + '（会先备份原文件）', files=paths)


def _vscode_file(path):
    normalized = str(path).replace('\\', '/').lower()
    return '/code/user/' in normalized or '/.vscode/' in normalized


def settings_files(workspace):
    code = Path(os.environ.get('APPDATA', str(HOME / 'AppData/Roaming'))) / 'Code/User'
    rows = [(HOME / '.claude/settings.json', 'claude'), (HOME / '.claude/settings.local.json', 'claude'),
            (code / 'settings.json', 'vscode'), *[(path, 'vscode') for path in code.glob('profiles/*/settings.json')]]
    for base in [workspace, *workspace.parents]:
        rows += [(base / '.claude/settings.json', 'claude'), (base / '.claude/settings.local.json', 'claude'),
                 (base / '.vscode/settings.json', 'vscode')]
    rows += [(Path(os.environ.get('ProgramData', r'C:\ProgramData')) / 'ClaudeCode/managed-settings.json', 'claude'),
             (Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'ClaudeCode/managed-settings.json', 'claude')]
    seen, files = set(), []
    for path, kind in rows:
        key = str(path.resolve()).lower()
        if path.is_file() and key not in seen:
            seen.add(key)
            files.append({'path': str(path), 'kind': kind})
    return files


def windows_env(name):
    found = []
    if name in os.environ:
        found.append(('当前终端的环境变量', os.environ[name]))
    try:
        import winreg
        for label, root, key in (('用户环境变量', winreg.HKEY_CURRENT_USER, 'Environment'),
                                 ('系统环境变量', winreg.HKEY_LOCAL_MACHINE,
                                  r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment')):
            try:
                with winreg.OpenKey(root, key) as handle:
                    found.append((label, winreg.QueryValueEx(handle, name)[0]))
            except OSError:
                pass
    except ImportError:
        pass
    return found


def api_override(workspace):
    """A different ANTHROPIC_BASE_URL means Anthropic sees that relay's IP, not the fixed exit."""
    title = 'Claude API 地址'
    files = settings_files(workspace)
    try:
        result = subprocess.run([str(NODE), str(HERE / 'read_env.cjs')], input=json.dumps(files), capture_output=True,
                                text=True, encoding='utf-8', timeout=20, creationflags=HIDDEN)
        rows = json.loads(result.stdout) if result.returncode == 0 else None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        rows = None
    if not isinstance(rows, list) or len(rows) != len(files):
        return check('api_override', title, None, '读不到设置文件里的 API 地址。', ('cli', 'vscode'), '稍后重新检查'), []
    sources, overrides, unreadable = [], [], []
    for row, spec in zip(rows, files):
        if row.get('error'):
            unreadable.append(spec['path'])
            continue
        entries = ('vscode',) if spec['kind'] == 'vscode' else ('cli', 'vscode')
        if row.get('base_url_host') is not None:
            sources.append((spec['path'], row['base_url_host'], entries))
        overrides += ['%s（%s）' % (name, spec['path']) for name in row.get('overrides', [])]
    for label, value in windows_env('ANTHROPIC_BASE_URL'):
        sources.append((label, urllib.parse.urlsplit(str(value)).hostname or 'invalid', ('cli', 'vscode')))
    for name in OVERRIDE_NAMES:
        overrides += ['%s（%s）' % (name, label) for label, _ in windows_env(name)]
    notes = ['发现认证或供应商覆盖：%s。它不改变出口，只是让你知道。' % '、'.join(overrides)] if overrides else []
    bad = [row for row in sources if row[1] != OFFICIAL_API]
    if bad:
        entries = sorted({entry for row in bad for entry in row[2]})
        places = '；'.join('%s → %s' % (row[0], row[1]) for row in bad)
        return check('api_override', title, False,
                     'API 地址被改成了别的主机（%s）：请求会先到那里，Anthropic 看到的是它的 IP，不是你的固定出口。' % places,
                     entries, '去掉这个 ANTHROPIC_BASE_URL 设置（需要你手动改，工具不会动它）', sources=bad), notes
    if unreadable:
        return check('api_override', title, None, '这些设置文件读不出来：' + '；'.join(unreadable), ('cli', 'vscode'),
                     '修正这些文件的格式后重新检查'), notes
    return check('api_override', title, True, 'Claude 只会连官方 API 地址。', ('cli', 'vscode')), notes


def web_check():
    """Login links: the launcher hands them to CCBaga Proxy's fingerprint browser, which gates itself."""
    from browser_entry import program
    title = '登录链接入口'
    if not LAUNCHER.is_file():
        return check('web', title, False, '登录链接启动器不存在：%s。' % LAUNCHER, ('web',),
                     '按 README「部署」重新部署启动器')
    if program() is None:
        return check('web', title, False, 'CCBaga Proxy 还没有登记指纹浏览器入口。', ('web',),
                     '打开一次 CCBaga Proxy（开机托盘启动也算）')
    return check('web', title, True, '启动器在；登录链接交给 CCBaga Proxy 的指纹浏览器，打开前它再查一次固定出口。', ('web',))


def desktop_checks(protection):
    """The app is firewalled to loopback and pinned to the dedicated port, so Clash's mode does not matter."""
    if protection is None:
        return [check('desktop_protection', '客户端的保护', None, '读不到防火墙规则或客户端进程。', ('desktop',), '稍后重新检查')]
    problem = desktop_problem(protection)
    if problem:
        detail, fix = PROBLEMS[problem]
        rows = [check('desktop_protection', '客户端的保护', False, detail, ('desktop',), fix, **protection)]
    else:
        rows = [check('desktop_protection', '客户端的保护', True,
                      '防火墙只准客户端连本机；它固定走专用端口，与 Clash 模式无关，代理失效时直接断网。'
                      + ('' if protection['running'] else '（客户端没在运行：从桌面「Claude 客户端（固定出口）」打开。）'),
                      ('desktop',), **protection)]
    problem = cowork_problem(protection)
    if protection['cowork_installed']:
        rows.append(check('cowork', 'Cowork 服务断网', not problem, PROBLEMS[problem][0] if problem else
                          'Cowork 服务被防火墙按服务名断网，开机自启也连不上网。', ('desktop',),
                          PROBLEMS[problem][1] if problem else None))
    return rows


def traffic_checks(p, processes, records):
    """Every claude.exe connection Clash sees must be on the fixed chain, and no Claude
    program may hold a connection that skips the local proxy entirely."""
    off, seen = {}, {}
    for row in records or []:
        m = row.get('metadata', {})
        if (m.get('process') or '').lower() != 'claude.exe':
            continue
        kind = client_kind(m.get('processPath'))
        seen[kind] = seen.get(kind, 0) + 1
        if not valid_chain(row.get('chains', []), p):
            off.setdefault(kind, []).append(describe(row))
    bypass, via_port, os_readable = {}, {}, True
    try:
        import psutil
        for c in psutil.net_connections(kind='tcp'):
            info = processes.get(c.pid)
            if not info or c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                continue
            if not is_loopback(c.raddr.ip):
                bypass.setdefault(info['kind'], []).append({'pid': c.pid, 'remote': c.raddr.ip, 'port': c.raddr.port})
            elif c.raddr.port == p['entry_port']:
                via_port[info['kind']] = via_port.get(info['kind'], 0) + 1
    except Exception:
        os_readable = False
    results = []
    for kind in sorted({row['kind'] for row in processes.values()} | set(off)):
        title = '运行中的 %s 连接' % NAMES[kind]
        pids = sorted(pid for pid, row in processes.items() if row['kind'] == kind)
        if off.get(kind):
            sample = '；'.join('%s:%s 经 %s' % (x['host'], x['port'], x['route']) for x in off[kind][:5])
            results.append(check('traffic_' + kind, title, False, '有连接没走固定出口：' + sample, (kind,),
                                 '先停止使用这个 Claude 程序，再' + REPAIR + '；之后还出现，说明规则没覆盖它，需要你决定是否调整代理',
                                 pids=pids, off_chain=off[kind]))
        elif bypass.get(kind):
            sample = '；'.join('PID %d → %s:%d' % (x['pid'], x['remote'], x['port']) for x in bypass[kind][:5])
            results.append(check('traffic_' + kind, title, False, '有连接绕过了本机代理：' + sample, (kind,),
                                 '关掉这个 Claude，从桌面的固定出口图标或 VS Code 重新打开', pids=pids,
                                 bypass=bypass[kind]))
        elif records is None or not os_readable:
            results.append(check('traffic_' + kind, title, None, '读不到连接记录，没法核对。', (kind,), '稍后重新检查', pids=pids))
        else:
            results.append(check('traffic_' + kind, title, True,
                                 '%d 个进程；此刻 %d 条连接经专用端口，没有绕开本机代理的连接。' % (len(pids), via_port.get(kind, 0)),
                                 (kind,), pids=pids))
    return results


# --- run, verdict, output -----------------------------------------------------------

def run(mode='all', workspace=None):
    started = time.monotonic()
    workspace = Path(workspace or Path.cwd()).resolve()
    targets = TARGETS[mode]
    report = {'version': VERSION, 'mode': mode, 'time': now(), 'workspace': str(workspace),
              'checks': [], 'notes': [], 'routing': None, 'desktop_installed': False}
    try:
        p = load_policy()
    except Exception as exc:
        report['checks'].append(check('policy', '本机策略文件', False, 'audit_policy.json 缺失或格式错误（%s）。'
                                      % type(exc).__name__, ALL, '恢复 audit_policy.json（需要人工处理）'))
        return finish(report, targets, started)
    processes = {}
    if mode in ('all', 'desktop'):
        try:
            processes = claude_processes()
        except Exception as exc:
            processes = None
            report['checks'].append(check('traffic', '运行中的 Claude 连接', None, '读不到运行中的 Claude 进程（%s）。'
                                          % type(exc).__name__, ('cli', 'vscode', 'desktop'), '稍后重新检查'))
        report['desktop_installed'] = desktop_installed(processes or {})
    clients = {'cli', 'vscode'} & set(targets)
    with concurrent.futures.ThreadPoolExecutor(10) as pool:
        jobs = {'core': pool.submit(clash_core, p), 'clash': pool.submit(read_clash), 'disk': pool.submit(disk_structure, p),
                'egress': pool.submit(egress, p), 'route': pool.submit(route, p), 'guard': pool.submit(guard_check)}
        if clients:
            jobs['settings'] = pool.submit(settings_check, workspace)
            jobs['api'] = pool.submit(api_override, workspace)
        if 'web' in targets:
            jobs['web'] = pool.submit(web_check)
        if processes is not None and mode == 'all':
            jobs['records'] = pool.submit(lambda: api('/connections').get('connections', []))
        done = {}
        for name, job in jobs.items():
            try:
                done[name] = job.result()
            except Exception:
                done[name] = None
    clash = done['clash'] or {'ok': False, 'error': 'Unavailable'}
    report['routing'] = routing_mode(clash)
    checks = report['checks']
    checks += [done['core'], fixed_policy(p, clash, done['disk'] or {'ok': None, 'error': 'Unavailable', 'candidates': []}),
               done['egress'], done['route'], done['guard']]
    if clients:
        checks.append(done['settings'])
        api_result, notes = done['api'] or (check('api_override', 'Claude API 地址', None, '没有完成。', ('cli', 'vscode')), [])
        checks.append(api_result)
        report['notes'] += notes
    if 'web' in targets:
        checks.append(done['web'])
    if report['desktop_installed']:
        try:
            protection = desktop_protection([row for row in (processes or {}).values() if row['kind'] == 'desktop'],
                                            p['entry_port'])
        except OSError:
            protection = None
        checks += desktop_checks(protection)
    if processes is not None and mode == 'all':
        checks += traffic_checks(p, processes, done.get('records'))
    if report['routing'] and report['routing']['profile'] == 'abnormal':
        report['notes'].append('Clash 不在规则模式：普通浏览器里的 Claude 不受保护。在 Clash Verge 切回「规则」。')
    report['checks'] = [c for c in checks if c]
    return finish(report, targets, started)


def verdict(checks, entry):
    related = [c for c in checks if entry in c['entries']]
    if any(c['ok'] is False for c in related):
        return 'NOT_READY'
    if any(c['ok'] is None for c in related):
        return 'UNKNOWN'
    return 'READY'


def finish(report, targets, started):
    entries = {}
    for entry in targets:
        if entry == 'desktop' and not report['desktop_installed']:
            entries[entry] = 'NOT_INSTALLED'
        else:
            entries[entry] = verdict(report['checks'], entry)
    counted = [state for state in entries.values() if state != 'NOT_INSTALLED']
    report['entries'] = entries
    report['exit_code'] = 2 if 'NOT_READY' in counted else 3 if 'UNKNOWN' in counted else 0
    report['seconds'] = round(time.monotonic() - started, 1)
    return report


def reasons(report):
    """Blocking reasons for the shown entries, without repeating symptoms of a guard block."""
    shown = {key for key, state in report['entries'].items() if state != 'NOT_INSTALLED'}
    blocked = any(c['id'] == 'guard' and c['evidence'].get('fixed_exit_blocked') for c in report['checks'])
    rows, seen = [], set()
    for c in report['checks']:
        if c['ok'] is True or not shown.intersection(c['entries']):
            continue
        if blocked and c['id'] in EXIT_SUPPRESSED_BY_BLOCK:
            continue
        if (c['detail'], c['fix']) not in seen:
            seen.add((c['detail'], c['fix']))
            rows.append(c)
    return rows


def display(report, details=False):
    counted = {k: v for k, v in report['entries'].items() if v != 'NOT_INSTALLED'}
    states = set(counted.values())
    if states == {'READY'}:
        headline = '可以使用 Claude'
    elif 'READY' in states:
        headline = '部分可用，见下表'
    elif 'NOT_READY' in states:
        headline = '暂不能使用 Claude，按下面的「处理」恢复'
    else:
        headline = '无法确认，先别用 Claude，按下面的「处理」操作后重新检查'
    print('\n结论：' + headline)
    for key, state in report['entries'].items():
        print('  %s：%s' % (NAMES[key], WORDS[state]))
    routing = report.get('routing')
    if routing:
        print('当前模式：' + {'claude': 'Claude 模式（虚拟网卡开）',
                              'domestic': '国内模式（虚拟网卡关）：普通浏览器里的 Claude 不受保护，其他入口见上表',
                              'abnormal': '异常：Clash 在「%s」模式' % routing['mode']}[routing['profile']])
    egress_row = next((c for c in report['checks'] if c['id'] == 'fixed_egress'), None)
    if egress_row:
        print('固定出口：%s；两处检测 %d/2 一致' % (egress_row['evidence']['expected_ip'], egress_row['evidence']['matched']))
    for c in reasons(report):
        print('原因：' + c['detail'])
        if c['fix']:
            print('处理：' + c['fix'])
    for note in report['notes']:
        print('提示：' + note)
    if details:
        labels = {True: '通过', False: '未通过', None: '无法确认'}
        print('\n--- 逐项证据 ---')
        for c in report['checks']:
            print('[%s] %s：%s' % (labels[c['ok']], c['title'], c['detail']))
            if c['ok'] is not True and c['evidence']:
                print('  ' + json.dumps(c['evidence'], ensure_ascii=False, default=str)[:600])
        print('工作目录：' + report['workspace'])
    print('用时 %.1f 秒 · 退出码 %d%s' % (report['seconds'], report['exit_code'],
                                      '' if details else ' · 逐项证据：claude-proxy -Details'))


# Elevated and reversible: Remove-NetFirewallRule -Group 'Claude local policy'.
# Loopback stays reachable, so the app can still use the local proxy ports and nothing else.
PROTECT_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$result = $args[0]
try {
    # One path per line: Windows PowerShell 5.1 does not unroll JSON arrays.
    $programs = @(Get-Content -LiteralPath $args[1] | Where-Object { $_ })
    # New rules first, old ones afterwards: a failure can only leave extra blocking, never less.
    $old = @(Get-NetFirewallRule -Group 'Claude local policy' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'ClaudeDesktopNoDirect-*' -or $_.Name -like 'ClaudeCoworkNoNetwork-Program*' })
    $stamp = Get-Date -Format 'yyyyMMddHHmmss'
    $remote = @('0.0.0.0-126.255.255.255', '128.0.0.0-255.255.255.255', '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
    $index = 0
    foreach ($exe in $programs) {
        New-NetFirewallRule -Name ('ClaudeDesktopNoDirect-' + $stamp + '-' + $index) -DisplayName ('Claude desktop: local only (' + (Split-Path $exe -Leaf) + ')') `
            -Group 'Claude local policy' -Direction Outbound -Action Block -Program $exe -RemoteAddress $remote -Profile Any | Out-Null
        $cowork = Join-Path (Split-Path $exe) 'resources\cowork-svc.exe'
        if (Test-Path -LiteralPath $cowork) {
            New-NetFirewallRule -Name ('ClaudeCoworkNoNetwork-Program-' + $stamp + '-' + $index) -DisplayName 'Claude Cowork service: no network (program)' `
                -Group 'Claude local policy' -Direction Outbound -Action Block -Program $cowork -Profile Any | Out-Null
        }
        $index++
    }
    $old | Remove-NetFirewallRule
    if (-not (Get-NetFirewallRule -Name 'ClaudeCoworkNoNetwork-Service' -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -Name 'ClaudeCoworkNoNetwork-Service' -DisplayName 'Claude Cowork service: no network (service)' `
            -Group 'Claude local policy' -Direction Outbound -Action Block -Service 'CoworkVMService' -Profile Any | Out-Null
    }
    'OK' | Set-Content -LiteralPath $result -Encoding UTF8
} catch {
    ('ERROR: ' + $_.Exception.Message) | Set-Content -LiteralPath $result -Encoding UTF8
}
'''


def protect():
    """Firewall the installed desktop app (every path of the current version) to the local proxy."""
    running = [row['path'] for row in claude_processes().values() if row['kind'] == 'desktop' and row['path']]
    paths = sorted(set(desktop_executables()) | set(running), key=str.lower)
    if not paths:
        print('没有找到已安装的客户端，不需要设置。')
        return 0
    # Not mkdtemp: its owner-only ACL makes files written by the elevated process unreadable here.
    folder = Path(tempfile.gettempdir()) / ('claude-protect-' + datetime.datetime.now().strftime('%Y%m%d%H%M%S%f'))
    folder.mkdir()
    try:
        script, listing, result = folder / 'protect.ps1', folder / 'programs.txt', folder / 'result.txt'
        script.write_text(PROTECT_SCRIPT, encoding='utf-8-sig')
        listing.write_text('\n'.join(paths) + '\n', encoding='utf-8')
        print('设置客户端防火墙保护：会弹出一次管理员确认，请点「是」。', flush=True)
        arguments = '-NoProfile -ExecutionPolicy Bypass -File "%s" "%s" "%s"' % (script, result, listing)
        subprocess.run(['powershell.exe', '-NoProfile', '-Command',
                        "Start-Process -FilePath powershell.exe -Verb RunAs -Wait -ArgumentList '%s'" % arguments.replace("'", "''")],
                       timeout=300)
        outcome = (result.read_text(encoding='utf-8-sig', errors='replace').strip() if result.is_file()
                   else '没有完成（管理员确认被取消？）')
    finally:
        shutil.rmtree(folder, ignore_errors=True)
    protection = desktop_protection([])
    for path in paths:
        print(('  已保护：' if path not in protection['missing'] else '  未保护：') + path)
    if protection['cowork_installed']:
        print('  Cowork 服务断网：' + ('是' if protection['cowork_blocked'] else '否'))
    ok = (outcome == 'OK' and not protection['missing']
          and (protection['cowork_blocked'] or not protection['cowork_installed']))
    print('结果：' + ('完成。客户端只能经本机代理上网；更新客户端后再运行一次 claude-proxy -Protect。' if ok else outcome))
    return 0 if ok else 2


def open_desktop(workspace):
    """Close a desktop app that is not pinned, check the fixed exit, then start it on the dedicated port."""
    p = load_policy()
    switch = '--proxy-server=http://127.0.0.1:%d' % p['entry_port']
    import psutil
    desktop = [row for row in claude_processes().values() if row['kind'] == 'desktop']
    if desktop_protection(desktop, p['entry_port'])['unpinned']:
        print('客户端已经在运行，但没有固定走专用端口：先把它关掉。', flush=True)
        for row in desktop:
            try:
                psutil.Process(row['pid']).kill()
            except psutil.Error:
                pass
        time.sleep(2)
    print('正在检查固定出口（只读）……', flush=True)
    report = run('desktop', workspace)
    display(report)
    if report['entries'].get('desktop') != 'READY':
        print('客户端没有打开：先按上面的「处理」操作。')
        return 2
    if not DESKTOP_ALIAS.exists():
        print('找不到客户端的启动命令：%s。' % DESKTOP_ALIAS)
        return 2
    # Detached, so the app outlives this console window.
    subprocess.Popen([str(DESKTOP_ALIAS), switch], creationflags=0x00000008 | 0x00000200,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(20):
        time.sleep(0.5)
        running = [row for row in claude_processes().values() if row['kind'] == 'desktop']
        if running and not desktop_protection(running, p['entry_port'])['unpinned']:
            print('已打开 Claude 客户端：它只走专用端口 %d（固定出口），与 Clash 模式无关。' % p['entry_port'])
            return 0
    print('客户端没有按预期启动，或启动后没有固定走专用端口；守护会关闭这种实例。')
    return 2


REPAIR_CODES = {10: '没有连上 Wi-Fi / 网线', 20: '外部线路仍未恢复，没有改用其他出口',
                21: 'Clash 启动后控制接口仍不可用', 22: '实测出口 IP 不对，已保持阻断',
                23: '本机恢复数据缺失', 24: '系统管理策略里有不同的代理设置，工具不会覆盖'}


def repair(workspace, details=False):
    print('\n开始修复：可能会重启 Clash。修复先在检查端口核对出口 IP，不对就保持阻断，不会改用别的出口。', flush=True)
    try:
        code = subprocess.run([sys.executable, '-X', 'utf8', '-B', str(HERE / 'repair_proxy.py'),
                               '--workspace', str(workspace)], timeout=180).returncode
    except subprocess.TimeoutExpired:
        code = 30
    print('\n修复结束，重新检查……', flush=True)
    report = run('all', workspace)
    report['repair_exit'] = code
    if code:
        report['exit_code'] = 2
        report['notes'].insert(0, '修复没有正常完成（代码 %d）：%s。' % (code, REPAIR_CODES.get(code, '详见上面的修复输出')))
    display(report, details)
    return report


def watch(minutes):
    """Show, live, where Claude programs connect and whether each goes through the fixed exit."""
    p = load_policy()
    print('正在观察 Claude 程序的网络连接，共 %g 分钟（只读；按 Ctrl+C 提前结束）。' % minutes)
    print('能看到的是经过 Clash 的连接；Claude 模式（虚拟网卡开）下，所有连接都会经过 Clash。')
    try:
        mode = routing_mode(read_clash())
        processes = claude_processes()
    except Exception:
        mode, processes = None, {}
    if any(row['kind'] == 'desktop' for row in processes.values()) and (not mode or mode['profile'] != 'claude'):
        print('注意：客户端正在运行，但现在不是 Claude 模式，它的连接可能不经过 Clash，这里看不到。')
    seen, off_chain, failures = set(), 0, 0
    deadline = time.monotonic() + minutes * 60
    try:
        while time.monotonic() < deadline:
            try:
                records = api('/connections').get('connections', [])
            except Exception:
                records, failures = [], failures + 1
                if failures in (1, 30):
                    print('读不到 Clash 的连接记录，继续重试……')
            for row in records:
                m = row.get('metadata', {})
                # Clash records no program name on the dedicated port; everything there is pinned to the fixed exit.
                if m.get('inboundName') == 'claude-fixed-http':
                    source = '专用端口（CLI / VS Code / 指纹浏览器）'
                elif (m.get('process') or '').lower() == 'claude.exe':
                    source = NAMES[client_kind(m.get('processPath'))]
                else:
                    continue
                target, ok = describe(row), valid_chain(row.get('chains', []), p)
                key = (source, target['host'], target['port'], ok)
                if key in seen:
                    continue
                seen.add(key)
                off_chain += not ok
                print('%s  %s  %s:%s  %s' % (datetime.datetime.now().strftime('%H:%M:%S'), source, target['host'],
                                             target['port'], '固定出口' if ok else '× 没走固定出口：' + target['route']))
            time.sleep(1)
    except KeyboardInterrupt:
        print()
    if not seen:
        print('\n这段时间没有看到 Claude 的连接（空闲时正常；可以边用 Claude 边观察）。')
    else:
        print('\n共看到 %d 个不同的目标；%s。' % (len(seen), '全部走固定出口' if not off_chain else '%d 个没走固定出口' % off_chain))
    children = sorted(_desktop_children())
    if children:
        print('客户端启动的其他程序：%s。它们不叫 claude.exe，按普通规则上网，不在上面的列表里。' % '、'.join(children))
    return 2 if off_chain else 0


def _desktop_children():
    names = set()
    try:
        import psutil
        for pid, row in claude_processes().items():
            if row['kind'] == 'desktop':
                for child in psutil.Process(pid).children(recursive=True):
                    if child.name().lower() != 'claude.exe':
                        names.add(child.name())
    except Exception:
        pass
    return names


def main():
    parser = argparse.ArgumentParser(description='检查 Claude 能否经固定出口使用。')
    parser.add_argument('--workspace', type=Path, default=Path.cwd())
    parser.add_argument('--repair', action='store_true', help='修复受管理的代理配置，然后重新检查')
    parser.add_argument('--details', action='store_true', help='显示逐项证据')
    parser.add_argument('--json', action='store_true', help='输出 JSON')
    parser.add_argument('--launch', action='store_true', help='只检查 CLI 的启动条件')
    parser.add_argument('--offer-repair', action='store_true', help='检查不通过时询问是否修复')
    parser.add_argument('--watch', type=float, nargs='?', const=5.0, metavar='MINUTES',
                        help='观察 Claude 程序连了哪里（默认 5 分钟）')
    parser.add_argument('--protect', action='store_true', help='给客户端加防火墙保护：只能经本机代理上网（需要管理员）')
    parser.add_argument('--open-desktop', action='store_true', help='检查后打开客户端，固定走专用端口')
    args = parser.parse_args()
    try:
        if args.watch is not None:
            return watch(max(args.watch, 0.1))
        if args.protect:
            return protect()
        if args.open_desktop:
            return open_desktop(args.workspace)
        if not args.json:
            print('正在检查（只读，不会修改任何设置）……', flush=True)
        report = run('launch' if args.launch else 'all', args.workspace)
        if args.json:
            if args.repair:
                raise SystemExit('--json 不能和 --repair 一起用。')
            print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
            return report['exit_code']
        display(report, args.details)
        if args.repair or (args.offer_repair and report['exit_code'] and sys.stdin.isatty()
                           and input('\n要现在修复吗？输入 R 后回车修复，直接回车结束：').strip().lower() == 'r'):
            report = repair(args.workspace, args.details)
        return report['exit_code']
    except KeyboardInterrupt:
        print('\n已取消。')
        return 3
    except Exception as exc:
        # Do not echo exception messages: parsed configuration may contain credentials.
        print('检查没有完成：%s。没有修改任何设置。' % type(exc).__name__)
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
