"""Fresh proxy evidence. Changes require --repair or a confirmed menu action.

No account request, credentials file, browser profile or previous PASS is used.
Default checks validate the environment before Claude is opened. Only explicit
runtime mode requires live request evidence from every running Claude instance.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

VERSION = '2026.10.07.2'
HERE = Path(__file__).resolve().parent
HIDDEN = 0x08000000 if os.name == 'nt' else 0
JST = datetime.timezone(datetime.timedelta(hours=9))
BAD = {'fail', 'unknown', 'not_tested', 'not_running', 'warn', 'partial'}
# The in-use guard (CodexNetworkGuard/health_monitor.py) blocks Claude when the
# exit changes. Its single-instance mutex is the liveness signal.
GUARD_DIR = Path.home() / '.codex' / 'CodexNetworkGuard'
GUARD_MUTEX = 'Local\\ClashNetworkHealth-example'
GUARD_STALE_SECONDS = 120


def item(key, title, status, detail, evidence=None, required=False, category='network'):
    return dict(id=key, title=title, status=status, detail=detail,
                evidence=evidence or {}, required=required, category=category)


def run(command, *, timeout=20, input=None):
    return subprocess.run([str(v) for v in command], input=input, capture_output=True,
                          encoding='utf-8', errors='replace', timeout=timeout,
                          creationflags=HIDDEN)


def load_policy(install_dir=HERE):
    p = json.loads((Path(install_dir) / 'audit_policy.json').read_text(encoding='utf-8-sig'))
    if p.get('schema') != 1:
        raise ValueError('Policy schema')
    ipaddress.ip_address(p['expected_ip'])
    for key in ('entry_port', 'daily_port'):
        if type(p[key]) is not int or not 1 <= p[key] <= 65535:
            raise ValueError('Policy port')
    for key in ('fixed_group', 'chain_group', 'provider'):
        if not isinstance(p.get(key), str) or not p[key] or len(p[key]) > 100:
            raise ValueError('Policy group')
    return p


def api(path, install_dir=HERE):
    # The pipe may stall: isolate the read in a process with a hard deadline.
    result = run([sys.executable, '-X', 'utf8', '-B', HERE / 'audit_proxy.py',
                  '--internal-rpc', '--install-dir', install_dir],
                 input=json.dumps(path), timeout=10)
    if result.returncode:
        raise RuntimeError('Controller read unavailable')
    status, data = json.loads(result.stdout)
    if status != 200:
        raise RuntimeError('Controller response unavailable')
    return data


def controller(install_dir):
    data = {}
    for name in ('version', 'configs', 'proxies'):
        try:
            data[name] = api('/' + name, install_dir)
        except Exception as exc:
            return {'ok': False, 'error': type(exc).__name__, 'failed_read': name}
    return {'ok': True, **data}


def classify_launch_arguments(arguments):
    """Return safe classification only; argument values never enter reports."""
    source_values = []
    settings_present = False
    for index, argument in enumerate(arguments):
        if argument == '--settings' or argument.startswith('--settings='):
            settings_present = True
        if argument == '--setting-sources':
            source_values.append(arguments[index + 1] if index + 1 < len(arguments) else '')
        elif argument.startswith('--setting-sources='):
            source_values.append(argument.split('=', 1)[1])
    expected = {'user', 'project', 'local'}
    sources = source_values[0].split(',') if len(source_values) == 1 else []
    standard_sources = len(sources) == 3 and set(sources) == expected
    return {'launch_override': settings_present or bool(source_values) and not standard_sources,
            'settings_argument_present': settings_present,
            'settings_sources_explicit': bool(source_values),
            'settings_sources': sorted(set(sources) & expected),
            'launch_inspection': 'complete'}


def browser_media_router_disabled(arguments):
    """Inspect the exact final switch value; never search arbitrary command text."""
    disabled = ''
    for argument in arguments:
        if argument == '--':
            break
        if argument == '--disable-features':
            disabled = ''
        elif argument.startswith('--disable-features='):
            disabled = argument.split('=', 1)[1]
    return 'MediaRouter' in {feature.strip() for feature in disabled.split(',')}


def _mutex_exists(name):
    import ctypes
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
    result = {'ok': True, 'alive': alive, 'age_seconds': None, 'fixed_exit_blocked': None,
              'repair_active': False}
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


def snapshot():
    """Return only selected process/network fields; never raw command lines."""
    script = r'''
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$result=@{}
try {
 $all=@(Get-CimInstance Win32_Process -Filter "Name='claude.exe' OR Name='clash-verge.exe' OR Name='verge-mihomo.exe' OR Name='chrome.exe' OR Name='Code.exe'")
 $processes=@($all | Where-Object {$_.Name -ne 'chrome.exe' -and $_.Name -ne 'Code.exe'} | ForEach-Object {
  @{pid=[int]$_.ProcessId;name=$_.Name;path=$_.ExecutablePath;launch_override=($_.Name -eq 'claude.exe' -and $_.CommandLine -match '--settings(?:=|\s)|--setting-sources(?:=|\s)')}
 })
 $roots=@($all | Where-Object {$_.Name -eq 'chrome.exe' -and $_.CommandLine -notmatch '--type=' -and $_.CommandLine -match 'ClaudeNetwork[\\/]ChromeData'} | ForEach-Object {
  $c=$_.CommandLine
  @{pid=[int]$_.ProcessId;proxy_ok=($c -match '--proxy-server=http://127\.0\.0\.1:17892(?:["\s]|$)');bypass_ok=($c -match [regex]::Escape('--proxy-bypass-list=localhost;127.0.0.1;[::1]'));quic_off=($c -match '--disable-quic');webrtc_policy_declared=($c -match '--webrtc-ip-handling-policy=disable_non_proxied_udp');media_router_disabled=$null}
 })
 $owned=@($roots.pid)
 for($i=0;$i -lt 6;$i++) {$owned=@($owned + @($all | Where-Object {$_.Name -eq 'chrome.exe' -and $_.ParentProcessId -in $owned}).ProcessId | Sort-Object -Unique)}
 $result.process=@{ok=$true;items=$processes;browser=$roots;browser_pids=$owned}
} catch {$result.process=@{ok=$false;error=$_.Exception.GetType().Name}}
try {
 $ports=@(Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in @(17892,7892)} | ForEach-Object {@{pid=[int]$_.OwningProcess;address=$_.LocalAddress;port=[int]$_.LocalPort}})
 $owners=@($result.process.items | Where-Object {$_.name -eq 'claude.exe'} | ForEach-Object {$_.pid})+@($result.process.browser_pids)
 $connections=@(Get-NetTCPConnection -State Established | Where-Object {$_.OwningProcess -in $owners} | ForEach-Object {@{pid=[int]$_.OwningProcess;source_port=[int]$_.LocalPort;remote=$_.RemoteAddress;port=[int]$_.RemotePort}})
 $result.tcp=@{ok=$true;listeners=$ports;connections=$connections}
} catch {$result.tcp=@{ok=$false;error=$_.Exception.GetType().Name}}
try {
 $adapters=@(Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'})
 $physical=@();$v6=$false
 foreach($a in $adapters){$n=Get-NetIPConfiguration -InterfaceIndex $a.ifIndex;if($n.IPv4DefaultGateway -or $n.IPv6DefaultGateway){$physical+=$a.Name};if($n.IPv6DefaultGateway){$v6=$true}}
 $result.physical=@{ok=$true;ready=($physical.Count -gt 0);interfaces=$physical;ipv6_gateway=$v6}
} catch {$result.physical=@{ok=$false;error=$_.Exception.GetType().Name}}
try {$p=Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings';$result.system=@{ok=$true;proxy_enabled=[bool]$p.ProxyEnable;pac_present=[bool]$p.AutoConfigURL;timezone=(Get-TimeZone).Id}} catch {$result.system=@{ok=$false}}
$result | ConvertTo-Json -Depth 7 -Compress
'''
    try:
        result = run([os.environ.get('SystemRoot', r'C:\Windows') + r'\System32\WindowsPowerShell\v1.0\powershell.exe',
                      '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], timeout=25)
        if result.returncode:
            raise RuntimeError('Windows inspection unavailable')
        data = json.loads(result.stdout.lstrip('\ufeff'))
        for process in data.get('process', {}).get('items', []):
            if process.get('launch_override'):
                try:
                    import psutil
                    process.update(classify_launch_arguments(psutil.Process(process['pid']).cmdline()))
                except Exception:
                    # Keep the original required warning if exact parsing is unavailable.
                    process['launch_inspection'] = 'unavailable'
        for browser in data.get('process', {}).get('browser', []):
            try:
                import psutil
                browser['media_router_disabled'] = browser_media_router_disabled(psutil.Process(browser['pid']).cmdline())
            except Exception:
                browser['media_router_disabled'] = None
        data['guard'] = guard_state()
        return data
    except Exception as exc:
        return {'process': {'ok': False}, 'tcp': {'ok': False},
                'physical': {'ok': False}, 'guard': guard_state(), 'error': type(exc).__name__}


def claude_client_kind(path):
    normalized = str(path or '').replace('\\', '/').lower()
    if '/extensions/anthropic.claude-code-' in normalized:
        return 'vscode'
    return 'cli' if normalized.endswith('/claude.exe') else 'unknown'


def application_inventory():
    """Refresh app identities; command lines are inspected only in memory."""
    result = {'ok': True, 'claude_ok': True, 'browser_ok': True,
              'items': [], 'browser': [], 'browser_pids': []}
    try:
        import psutil
        chrome = []
        for process in psutil.process_iter(['pid', 'name']):
            name = (process.info.get('name') or '').lower()
            if name not in ('claude.exe', 'chrome.exe'):
                continue
            try:
                if name == 'claude.exe':
                    path = process.exe()
                    result['items'].append({'pid': process.pid, 'name': name, 'path': path,
                        'created_at': process.create_time(), 'client_kind': claude_client_kind(path),
                        **classify_launch_arguments(process.cmdline())})
                else:
                    args = process.cmdline()
                    chrome.append({'pid': process.pid, 'parent': process.ppid()})
                    managed = any('claudenetwork/chromedata' in arg.replace('\\', '/').lower() for arg in args)
                    if managed and not any(arg.startswith('--type=') for arg in args):
                        result['browser'].append({'pid': process.pid,
                            'proxy_ok': '--proxy-server=http://127.0.0.1:17892' in args,
                            'bypass_ok': '--proxy-bypass-list=localhost;127.0.0.1;[::1]' in args,
                            'quic_off': '--disable-quic' in args,
                            'media_router_disabled': browser_media_router_disabled(args),
                            'webrtc_policy_declared': '--webrtc-ip-handling-policy=disable_non_proxied_udp' in args})
            except psutil.NoSuchProcess:
                continue
            except Exception:
                result['claude_ok' if name == 'claude.exe' else 'browser_ok'] = False
        owned = {row['pid'] for row in result['browser']}
        for _ in range(len(chrome)):
            updated = owned | {row['pid'] for row in chrome if row['parent'] in owned}
            if updated == owned:
                break
            owned = updated
        result['browser_pids'] = sorted(owned)
    except Exception as exc:
        result.update(ok=False, claude_ok=False, browser_ok=False, error=type(exc).__name__)
    return result


def application_tcp(pids):
    try:
        import psutil
        rows = []
        for connection in psutil.net_connections(kind='tcp'):
            if connection.pid not in pids or connection.status != psutil.CONN_ESTABLISHED or not connection.raddr:
                continue
            rows.append({'pid': connection.pid, 'source_address': connection.laddr.ip,
                         'source_port': connection.laddr.port, 'remote': connection.raddr.ip,
                         'port': connection.raddr.port})
        return {'ok': True, 'connections': rows}
    except Exception as exc:
        return {'ok': False, 'error': type(exc).__name__, 'connections': []}


def application_sample(install_dir):
    """Read TCP and controller concurrently, without settings work between them."""
    started = datetime.datetime.now(JST).isoformat()
    start = time.monotonic()
    inventory = application_inventory()
    owners = {row['pid'] for row in inventory['items']} | set(inventory['browser_pids'])

    def timed(read):
        begin = datetime.datetime.now(JST).isoformat()
        begin_tick = time.monotonic()
        try:
            value, error = read(), None
        except Exception as exc:
            value, error = None, type(exc).__name__
        return value, {'started_at': begin, 'finished_at': datetime.datetime.now(JST).isoformat(),
                       'duration_ms': round((time.monotonic() - begin_tick) * 1000, 2), 'error': error}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        tcp_future = pool.submit(timed, lambda: application_tcp(owners))
        records_future = pool.submit(timed, lambda: api('/connections', install_dir)['connections'])
        tcp, tcp_window = tcp_future.result()
        records, controller_window = records_future.result()
    if not isinstance(records, list):
        records = None
    window = {'started_at': started, 'finished_at': datetime.datetime.now(JST).isoformat(),
              'duration_ms': round((time.monotonic() - start) * 1000, 2),
              'tcp': tcp_window, 'controller': controller_window,
              'method': 'concurrent_reads', 'atomic': False}
    return {'process': inventory, 'tcp': tcp or {'ok': False, 'connections': []},
            'sampling_window': window}, records


def probe(port, url):
    start = time.monotonic()
    conn = None
    host = urllib.parse.urlsplit(url)
    try:
        # Explicit CONNECT, independent of inherited proxy/NO_PROXY variables.
        conn = http.client.HTTPSConnection('127.0.0.1', port, timeout=7)
        conn.set_tunnel(host.hostname, 443)
        conn.request('GET', (host.path or '/') + ('?' + host.query if host.query else ''),
                     headers={'Connection': 'close', 'User-Agent': 'ClaudeProxyAudit/' + VERSION})
        response = conn.getresponse()
        body = response.read(16384).decode('utf-8', 'replace')
        fields = json.loads(body) if host.hostname == 'api.ipify.org' else dict(
            line.split('=', 1) for line in body.splitlines() if '=' in line)
        address = str(ipaddress.ip_address(fields.get('ip', '')))
        return {'ok': response.status == 200, 'http': response.status, 'ip': address,
                'country': fields.get('loc'), 'source': host.hostname, 'entry': port,
                'seconds': round(time.monotonic() - start, 2)}
    except Exception as exc:
        return {'ok': False, 'error': type(exc).__name__, 'source': host.hostname,
                'entry': port, 'seconds': round(time.monotonic() - start, 2)}
    finally:
        if conn:
            conn.close()


def valid_chain(chain, p):
    return (isinstance(chain, list) and p['fixed_group'] in chain and
            p['chain_group'] in chain and not {'DIRECT', 'REJECT', '日常网络-自动恢复'}.intersection(chain))


def route_probe(p, install_dir, host='example.com'):
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
        rows = [row for row in api('/connections', install_dir).get('connections', [])
                if str(row.get('metadata', {}).get('sourcePort')) == source
                and row.get('metadata', {}).get('host') == host]
        chains = [row.get('chains', []) for row in rows]
        inbound = [row.get('metadata', {}).get('inboundName') for row in rows]
        return {'ok': bool(chains) and all(valid_chain(c, p) for c in chains)
                and all(v == 'claude-fixed-http' for v in inbound),
                'host': host, 'entry': p['entry_port'], 'chains': chains, 'inbound': inbound}
    except Exception as exc:
        return {'ok': False, 'host': host, 'error': type(exc).__name__}
    finally:
        if conn:
            conn.close()


def disk_structure(p):
    try:
        import yaml
        path = Path.home() / 'AppData/Roaming/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml'
        cfg = yaml.safe_load(path.read_text(encoding='utf-8-sig'))
        nodes = cfg.get('proxy-providers', {}).get(p['provider'], {}).get('payload', [])
        endpoints = {(n.get('server'), n.get('port'), n.get('type')) for n in nodes}
        # Equality only: credential values never leave this function.
        same_credentials = bool(nodes) and all(
            (n.get('username'), n.get('password')) == (nodes[0].get('username'), nodes[0].get('password'))
            for n in nodes)
        return {'ok': bool(nodes) and len(endpoints) == 1 and
                all(n.get('server') == p['expected_ip'] and n.get('type') == 'socks5'
                    and n.get('dialer-proxy') and n.get('username') and n.get('password') for n in nodes)
                and same_credentials,
                'candidates': [{'name': n.get('name'), 'front': n.get('dialer-proxy')} for n in nodes],
                'same_credentials': same_credentials,
                'listeners': [{k: n.get(k) for k in ('name', 'type', 'listen', 'port', 'proxy')}
                              for n in cfg.get('listeners', [])],
                'dns': {k: cfg.get('dns', {}).get(k) for k in ('enable', 'ipv6', 'enhanced-mode', 'respect-rules')},
                'tun': {k: cfg.get('tun', {}).get(k) for k in ('enable', 'auto-route', 'strict-route', 'dns-hijack')}}
    except Exception as exc:
        return {'ok': False, 'error': type(exc).__name__}


def evaluate_path(p, snap, ctl, disk, probes, route):
    checks = []
    process = snap.get('process', {})
    items = process.get('items', [])
    core_ids = {x['pid'] for x in items if x.get('name', '').lower() == 'verge-mihomo.exe'}
    gui_ids = [x['pid'] for x in items if x.get('name', '').lower() == 'clash-verge.exe']
    checks.append(item('clash_gui', 'Clash 界面', 'pass' if gui_ids else 'not_running' if process.get('ok') else 'unknown',
                       '界面进程正在运行。' if gui_ids else '界面未运行或无法读取；界面关闭不等于服务内核停止。',
                       {'pids': gui_ids}, category='runtime'))
    checks.append(item('mihomo_core', 'Mihomo 内核', 'pass' if core_ids else 'fail' if process.get('ok') else 'unknown',
                       '读取实际内核进程，不根据窗口或旧报告推测。', {'pids': sorted(core_ids)}, True, 'runtime'))
    tcp = snap.get('tcp', {})
    listeners = [x for x in tcp.get('listeners', []) if x.get('port') == p['entry_port']]
    ownership = bool(core_ids and listeners) and all(x.get('pid') in core_ids and x.get('address') in ('127.0.0.1', '::1') for x in listeners)
    checks.append(item('listener_owner', '专用端口及所属进程', 'pass' if ownership else 'fail' if tcp.get('ok') and process.get('ok') else 'unknown',
                       '专用端口必须由已观察到的 Mihomo 内核在回环地址监听。', {'listeners': listeners}, True, 'runtime'))
    checks.append(item('controller', 'Mihomo 实时控制接口', 'pass' if ctl.get('ok') else 'unknown',
                       '只执行有超时限制的 GET；失败不使用缓存结果替代。',
                       {'version': ctl.get('version', {}).get('version'), 'error': ctl.get('error')}, True))
    groups = ctl.get('proxies', {}).get('proxies', {})
    selected = groups.get(p['fixed_group'], {})
    fallback = groups.get(p['chain_group'], {})
    allowed = set(selected.get('all', []))
    names = {x['name'] for x in disk.get('candidates', [])}
    members = set(fallback.get('all', []))
    policy_ok = (selected.get('now') == p['chain_group'] and bool(allowed)
                 and allowed <= {p['chain_group'], 'REJECT'} and bool(members)
                 and members <= names and fallback.get('now') in members and disk.get('ok'))
    checks.append(item('fixed_policy', '固定出口策略和候选链', 'pass' if policy_ok else 'fail' if ctl.get('ok') else 'unknown',
                       '检查当前选择、全部候选、共同 SOCKS5 出口及前置；不允许日常线路或 DIRECT 兜底。',
                       {'selected': selected.get('now'), 'chain': fallback.get('now'), 'members': sorted(members),
                        'same_endpoint_and_auth': disk.get('ok', False)}, True))
    good = [x for x in probes if x.get('ok') and x.get('ip') == p['expected_ip']]
    wrong = [x for x in probes if x.get('ip') and x['ip'] != p['expected_ip']]
    both = len(probes) == 2 and len(good) == 2 and len({x.get('source') for x in good}) == 2
    checks.append(item('fixed_egress', '两处独立公网出口检测', 'pass' if both and not wrong else 'fail' if wrong else 'unknown',
                       '两处都必须成功且为预期 IP；一处超时不能算完整通过。',
                       {'expected_ip': p['expected_ip'], 'probes': probes}, True))
    checks.append(item('probe_route', '未知域名的实际入口与路由', 'pass' if route.get('ok') else 'unknown',
                       '将本次 TLS 探测源端口与 Mihomo 连接记录对应；它不冒充 Claude 的真实业务请求。', route, True))
    live = ctl.get('configs', {})
    mode, tun = live.get('mode'), live.get('tun', {}).get('enable')
    # CLI, VS Code and the dedicated browser use the pinned port in every Clash mode.
    # TUN plus rule mode ("Claude mode") additionally catches Claude traffic that does
    # not use the port (desktop app, ordinary browsers); "domestic mode" turns TUN off.
    if not ctl.get('ok'):
        profile, status, detail = None, 'unknown', '无法读取 Clash 模式。'
    elif mode == 'rule' and tun is True:
        profile, status, detail = 'claude', 'pass', 'Claude 模式：规则模式且虚拟网卡开启，没走专用端口的 Claude 流量也按规则进入固定出口。'
    elif mode == 'rule':
        profile, status, detail = 'domestic', 'pass', '国内模式：虚拟网卡关闭；CLI、VS Code、专用浏览器照常经专用端口走固定出口，桌面端和普通浏览器不受保护。'
    else:
        profile, status, detail = 'abnormal', 'warn', ('Clash 在' + str(mode) + '模式，规则不生效；CLI、VS Code、专用浏览器仍走固定出口，'
                                                       '桌面端和普通浏览器可能不走。')
    checks.append(item('routing_mode', 'Clash 模式', status, detail,
                       {'profile': profile, 'mode': mode, 'tun_enabled': tun,
                        'strict_route': live.get('tun', {}).get('strict-route'), 'system': snap.get('system', {})}))
    guard = snap.get('guard', {})
    age = guard.get('age_seconds')
    if not guard.get('ok'):
        guard_status, guard_detail = 'unknown', '无法读取使用中守护的状态。'
    elif not guard.get('alive'):
        guard_status, guard_detail = 'fail', '使用中守护没有运行；使用过程中出口变化时不会自动断开 Claude。'
    elif guard.get('fixed_exit_blocked'):
        guard_status, guard_detail = 'fail', '守护发现固定出口 IP 不符，已阻断 Claude。'
    elif guard.get('repair_active'):
        guard_status, guard_detail = 'unknown', '修复正在进行，守护暂停核对；修复结束后重新检查。'
    elif age is None or not 0 <= age <= GUARD_STALE_SECONDS:
        guard_status, guard_detail = 'fail', '使用中守护在运行但没有按时更新状态，可能已卡住。'
    else:
        guard_status, guard_detail = 'pass', '使用中守护在运行：约每 30 秒核对出口，不符时自动断开 Claude。'
    checks.append(item('usage_guard', '使用中守护', guard_status, guard_detail, guard, True, 'runtime'))
    physical = snap.get('physical', {})
    checks.append(item('physical', '物理网络', 'pass' if physical.get('ready') else 'warn' if physical.get('ok') else 'unknown',
                       '物理网卡与网关单独记录；探测不通过时不自动重启代理。', physical))
    checks.append(item('dns_ipv6', 'DNS 与 IPv6 配置', 'warn' if physical.get('ipv6_gateway') else 'pass' if disk.get('dns') else 'unknown',
                       '静态配置不等于无泄漏证明；完整模式另做临时浏览器测试。',
                       {'dns': disk.get('dns'), 'dns_hijack': live.get('tun', {}).get('dns-hijack'),
                        'mihomo_ipv6': live.get('ipv6'), 'physical_ipv6_gateway': physical.get('ipv6_gateway')}))
    return checks


def applications(p, snap, records):
    process = snap.get('process', {})
    tcp = snap.get('tcp', {})
    result = []

    def inspect(kind, pids):
        connections = [x for x in tcp.get('connections', []) if x.get('pid') in pids]
        bad = [x for x in connections if x.get('remote') not in ('127.0.0.1', '::1')
               or x.get('port') == p['daily_port']]
        unclassified = [x for x in connections if x.get('remote') in ('127.0.0.1', '::1')
                        and x.get('port') not in (p['entry_port'], p['daily_port'])]
        local = [x for x in connections if x.get('remote') in ('127.0.0.1', '::1') and x.get('port') == p['entry_port']]
        observed = []
        for row in records or []:
            m = row.get('metadata', {})
            matches = [connection for connection in local
                       if str(m.get('sourcePort')) == str(connection['source_port'])
                       and (not m.get('sourceIP') or not connection.get('source_address')
                            or m['sourceIP'] == connection['source_address'])]
            if len(matches) != 1 or str(m.get('network', 'tcp')).lower() != 'tcp':
                continue
            host = m.get('host', '')
            if kind == 'claude' and not (host == 'api.anthropic.com' or host.endswith('.anthropic.com') or host.endswith('.claude.ai')):
                continue
            observed.append({'target_class': 'Anthropic' if kind == 'claude' else 'browser_request',
                             'pid': matches[0]['pid'], 'source_port': m.get('sourcePort'),
                             'inbound': m.get('inboundName'), 'chains': row.get('chains', [])})
        routing_ok = bool(observed) and all(valid_chain(r['chains'], p) and r['inbound'] == 'claude-fixed-http' for r in observed)
        if kind == 'browser':
            roots = process.get('browser', [])
            flags = bool(roots) and all(all(r.get(k) is True for k in
                ('proxy_ok', 'bypass_ok', 'quic_off', 'media_router_disabled')) for r in roots)
            if not flags:
                bad.append({'reason': 'browser_network_flags_conflict'})
        readable = process.get('ok') and process.get(kind + '_ok', True) and tcp.get('ok') and records is not None
        state = ('fail' if bad or observed and not routing_ok else 'unknown' if not readable else
                 'warn' if unclassified else 'pass' if routing_ok else 'not_tested')
        evidence = {'pids': sorted(pids), 'entry_connections': len(local), 'unexpected_connections': bad,
                    'unclassified_loopback': unclassified, 'observed': observed,
                    'sampling_window': snap.get('sampling_window')}
        if kind == 'browser':
            evidence.update(tcp_only=True, udp_protection_verified=False,
                            media_router_disabled=[r.get('media_router_disabled') for r in process.get('browser', [])],
                            webrtc_policy_declared=[bool(r.get('webrtc_policy_declared')) for r in process.get('browser', [])])
        return state, evidence

    claudes = [x for x in process.get('items', []) if x.get('name', '').lower() == 'claude.exe']
    instances = []
    for instance in claudes:
        pid = instance['pid']
        state, evidence = inspect('claude', {pid})
        evidence.update(pid=pid, client_kind=instance.get('client_kind') or claude_client_kind(instance.get('path')),
                        executable_path=instance.get('path'), created_at=instance.get('created_at'))
        detail = ('该实例的 TCP 与 Mihomo 请求已对应。' if state == 'pass' else
                  '该实例有错误连接或路由。' if state == 'fail' else
                  '该实例没有完整的实时连接证据；其他实例的请求不替代本实例验收。')
        result.append(item('claude_pid_' + str(pid), 'Claude ' + evidence['client_kind'] + ' PID ' + str(pid),
                           state, detail, evidence, required=state == 'fail', category='application'))
        instances.append({'pid': pid, 'client_kind': evidence['client_kind'], 'status': state,
                          'executable_path': instance.get('path')})
    states = [instance['status'] for instance in instances]
    readable = process.get('ok') and process.get('claude_ok', True) and tcp.get('ok') and records is not None
    claude_status = ('fail' if 'fail' in states else 'unknown' if not readable else
                     'not_running' if not states else 'pass' if all(s == 'pass' for s in states) else
                     'partial' if 'pass' in states else 'unknown' if 'unknown' in states else
                     'warn' if 'warn' in states else 'not_tested')
    result.append(item('claude_runtime', '所有运行中的 Claude 实例', claude_status,
                       '每个运行实例均已分别关联实际请求；只证明本次采样。' if claude_status == 'pass' else
                       '逐 PID 查看证据；未运行、空闲、读取失败或仅部分实例有请求均不算完整验收。',
                       {'instances': instances, 'pids': [x['pid'] for x in instances],
                        'observed': [r for row in result if row['id'].startswith('claude_pid_') for r in row['evidence']['observed']],
                        'sampling_window': snap.get('sampling_window')},
                       required=claude_status == 'fail', category='application'))
    browser_pids = set(process.get('browser_pids', []))
    if not process.get('ok') or not process.get('browser_ok', True):
        browser_status, evidence = 'unknown', {'sampling_window': snap.get('sampling_window')}
    elif not browser_pids:
        browser_status, evidence = 'not_running', {'sampling_window': snap.get('sampling_window')}
    else:
        browser_status, evidence = inspect('browser', browser_pids)
    result.append(item('browser_runtime', '专用浏览器 TCP 连接', browser_status,
                       '仅核对 TCP 和代理启动参数；WebRTC 参数声明不证明 UDP 防护生效。', evidence,
                       required=browser_status == 'fail', category='application'))
    overrides = [x['pid'] for x in process.get('items', []) if x.get('launch_override')]
    if overrides:
        result.append(item('launch_override', 'Claude 启动参数覆盖', 'warn',
                           '发现额外 settings 配置、来源被排除/重复，或无法解析；静态检查范围可能不足。', {'pids': overrides}, True, 'application'))
    normal_sources = [x['pid'] for x in process.get('items', [])
                      if x.get('settings_sources_explicit') and not x.get('launch_override')]
    if normal_sources:
        result.append(item('launch_standard_sources', 'Claude 启动设置来源', 'pass',
                           '启动参数保留 user、project、local 三个标准来源；它本身不是额外配置覆盖。',
                           {'pids': normal_sources, 'sources': ['user', 'project', 'local']}, category='application'))
    return result


def desktop_app():
    """Claude desktop installation only; it is not pinned to the dedicated port."""
    local = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / 'AppData/Local')))
    paths = [p for p in (local / 'AnthropicClaude/claude.exe', local / 'Programs/Claude/Claude.exe') if p.is_file()]
    paths += sorted(p for p in local.glob('Packages/*Claude*') if p.is_dir())
    installed = bool(paths)
    return item('desktop_app', 'Claude 桌面端', 'not_tested' if installed else 'not_running',
                '已安装；桌面端不走专用端口，只靠 Clash 规则进入固定出口，未做专项验证。' if installed else '未安装 Claude 桌面端。',
                {'installed': installed, 'paths': [str(p) for p in paths]}, category='application')


def client_owners(checks):
    """Map client-specific configuration checks to 'cli' or 'vscode'; others are shared."""
    titles = {c['id']: c.get('title', '') for c in checks}
    owners = {}
    for c in checks:
        base = re.match(r'settings-\d+', c['id'])
        title = titles.get(base.group(0), '') if base else c.get('title', '')
        if 'VS Code' in title or 'VS Code' in c.get('title', ''):
            owners[c['id']] = 'vscode'
        elif 'CLI' in title:
            owners[c['id']] = 'cli'
    return owners


def summarize(checks, mode='check'):
    checks = list(checks)
    full = mode in ('full_check', 'runtime_full_check')
    runtime = mode in ('runtime_check', 'runtime_full_check')
    browser_ids = {'browser_fixed_exit', 'browser_webrtc', 'browser_dns'}
    browser_required_ids = {'browser_fixed_exit', 'browser_webrtc'}
    if full and not browser_required_ids.issubset({c['id'] for c in checks if c.get('required')}):
        if not any(c['id'] == 'browser_tests' and c.get('required') and c['status'] != 'pass' for c in checks):
            checks.append(item('browser_tests', '完整浏览器检查', 'unknown',
                               '浏览器出口或 WebRTC 的必要结果缺失。', required=True, category='browser_test'))
    network = [x for x in checks if x.get('required') and x.get('category') in ('network', 'runtime')]
    network_state = ('NOT_READY' if any(x['status'] == 'fail' for x in network) else
                     'INCOMPLETE' if not network or any(x['status'] != 'pass' for x in network) else 'READY')
    claude = next((x['status'] for x in checks if x['id'] == 'claude_runtime'), 'not_tested')
    browser = next((x['status'] for x in checks if x['id'] == 'browser_runtime'), 'not_tested')
    webrtc = next((x['status'] for x in checks if x['id'] == 'browser_webrtc'), 'not_tested')
    states = {'pass': 'OBSERVED', 'fail': 'FAILED', 'partial': 'PARTIAL', 'unknown': 'UNKNOWN',
              'not_running': 'NOT_RUNNING', 'not_tested': 'NOT_OBSERVED', 'warn': 'INCOMPLETE'}
    split = {'network_state': network_state, 'claude_state': states.get(claude, 'UNKNOWN'),
             'browser_state': 'FAILED' if 'fail' in (browser, webrtc) else
                              'OBSERVED_AND_UDP_TESTED' if browser == webrtc == 'pass' else
                              'TCP_ONLY' if browser == 'pass' else states.get(browser, 'UNKNOWN'),
             'browser_udp_state': states.get(webrtc, 'UNKNOWN'),
             'applications_observed': claude == browser == 'pass'}
    required = [x for x in checks if x.get('required')]
    # Launcher source/build checks also belong to the actual CLI launch gate.
    browser_only = browser_ids | {'browser_tests', 'browser_runtime'}
    owners = client_owners(checks)
    client_checks = [c for c in required if c['id'] not in browser_only and c.get('category') != 'browser_test']
    cli_checks = [c for c in client_checks if owners.get(c['id']) != 'vscode']
    vscode_checks = [c for c in client_checks if owners.get(c['id']) != 'cli']
    def launch_state(rows):
        if network_state == 'NOT_READY' or any(c['status'] == 'fail' for c in rows):
            return 'NOT_READY'
        if network_state != 'READY' or any(c['status'] != 'pass' for c in rows):
            return 'INCOMPLETE'
        return 'READY'
    cli_launch = launch_state(cli_checks)
    vscode_launch = launch_state(vscode_checks)
    browser_launch = launch_state([c for c in required if c['id'] not in owners])
    if browser_launch == 'READY' and not full:
        browser_launch = 'NOT_CHECKED'
    desktop = next((c for c in checks if c['id'] == 'desktop_app'), None)
    profile = next((c['evidence'].get('profile') for c in checks if c['id'] == 'routing_mode'), None)
    desktop_state = ('NOT_CHECKED' if desktop is None else
                     'NOT_INSTALLED' if not desktop.get('evidence', {}).get('installed') else
                     'NOT_READY' if network_state == 'NOT_READY' or profile in ('domestic', 'abnormal') else
                     'UNVERIFIED' if network_state == 'READY' and profile == 'claude' else 'INCOMPLETE')
    if mode == 'launch_check':
        # The CLI launcher only needs CLI-relevant evidence; VS Code-only settings do not block it.
        required = cli_checks
    blockers = [c for c in required if c['status'] != 'pass']
    if runtime and claude != 'pass' and not any(c['id'] == 'claude_runtime' for c in blockers):
        blockers.append(next((c for c in checks if c['id'] == 'claude_runtime'),
                             item('claude_runtime', '运行后请求核验', 'not_tested', '尚无 Claude 实例的真实请求证据。')))
    split.update(cli_launch_state=cli_launch, vscode_launch_state=vscode_launch, browser_launch_state=browser_launch,
                 entries={'cli': cli_launch, 'vscode': vscode_launch, 'web': browser_launch, 'desktop': desktop_state},
                 assessment='runtime' if runtime else 'before_use',
                 blocking_checks=[{k: c.get(k) for k in ('id', 'title', 'status', 'detail')} for c in blockers])
    failures = [x for x in required if x['status'] == 'fail']
    missing = [x for x in required if x['status'] != 'pass' and x['status'] != 'fail']
    if failures:
        return {**split, 'state': 'NOT_READY', 'exit_code': 2, 'ready': False,
                'message': '未通过：存在明确错误；没有执行自动修复。'}
    if missing or network_state != 'READY' or (runtime and claude != 'pass'):
        return {**split, 'state': 'INCOMPLETE', 'exit_code': 3, 'ready': False,
                'message': '运行后请求证据或必要检查不足。' if runtime else '使用前的必要检查证据不足；具体受影响的入口和原因见下方。'}
    if mode in ('preflight', 'launch_check'):
        return {**split, 'state': 'LAUNCH_READY' if mode == 'launch_check' else 'PROXY_READY',
                'exit_code': 0, 'ready': True,
                'message': '启动条件检查通过；没有据此证明尚未启动应用的真实流量。'}
    return {**split, 'state': 'CLAUDE_OBSERVED' if runtime else 'ENVIRONMENT_READY', 'exit_code': 0, 'ready': True,
            'message': '本次运行中的 Claude 实例均有对应请求。' if runtime else '使用前环境检查通过，无需先启动 Claude。'}


def collect(install_dir=HERE, workspace=None, full=False, preflight=False, launch_check=False, runtime=False):
    install_dir = Path(install_dir)
    started = time.monotonic()
    mode = 'preflight' if preflight else 'launch_check' if launch_check else 'full_check' if full else 'check'
    if runtime:
        mode = 'runtime_full_check' if full else 'runtime_check'
    report = {'schema': 4, 'version': VERSION, 'started_at': datetime.datetime.now(JST).isoformat(),
              'mode': mode,
              'read_only': True, 'workspace': str(Path(workspace or Path.cwd()).resolve()),
              'checks': [], 'limitations': ['不请求账号或模型，不验证 Pro 权益、支付、地区资格或封禁风险。',
                                           '不停止真实代理做故障注入；本次通过不证明重启、断网恢复或长期稳定。',
                                           '第三方工具、MCP、WSL、SSH 及所有未来请求未被强制统一出口。']}
    try:
        p = load_policy(install_dir)
    except Exception as exc:
        report['checks'] = [item('policy', '检查策略', 'fail', '策略缺失或格式错误，未回退到硬编码默认值。', {'error': type(exc).__name__}, True)]
        report.update(summarize(report['checks'], mode))
        return report
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        fs = pool.submit(snapshot)
        fc = pool.submit(controller, install_dir)
        fd = pool.submit(disk_structure, p)
        probes = [pool.submit(probe, p['entry_port'], u) for u in
                  ('https://www.cloudflare.com/cdn-cgi/trace', 'https://api.ipify.org?format=json')]
        fr = pool.submit(route_probe, p, install_dir)
        snap, ctl, disk = fs.result(), fc.result(), fd.result()
        measured, route = [f.result() for f in probes], fr.result()
    checks = evaluate_path(p, snap, ctl, disk, measured, route)
    path_ready = summarize(checks, mode='preflight')['ready']
    if not preflight:
        try:
            from audit_settings import audit_settings
            checks += audit_settings(install_dir, Path(report['workspace']), p['expected_ip'], p['entry_port'])
        except Exception as exc:
            checks.append(item('settings_audit', '应用配置检查', 'unknown', '配置检查未完成。', {'error': type(exc).__name__}, True, 'configuration'))
        if not launch_check:
            # Fresh TCP and controller reads share a window after configuration
            # work. The early machine snapshot is not reused as application proof.
            app_snapshot, records = application_sample(install_dir)
            report['application_sampling_window'] = app_snapshot.get('sampling_window')
            checks += applications(p, app_snapshot, records)
            checks.append(desktop_app())
        daily = probe(p['daily_port'], 'https://www.cloudflare.com/cdn-cgi/trace')
        # Daily network failure does not redefine fixed egress, but is reported.
        checks.append(item('daily_network', '日常网络入口', 'pass' if daily.get('ok') else 'warn',
                           '日常线路独立检查；可以与 Claude 使用不同出口。', daily))
        checks.append(item('all_tool_coverage', '任意工具统一出口', 'not_tested',
                           'HTTP 代理设置不强制所有程序使用它；当前规则允许日常线路，不宣称全机同一出口。'))
        # Browser probes use their own explicit settings; unrelated application
        # configuration gaps must not suppress this independent evidence.
        if full and path_ready and not launch_check:
            try:
                from audit_browser import browser_audit
                checks += browser_audit(p['entry_port'], p['expected_ip'])
            except Exception as exc:
                checks.append(item('browser_tests', '临时浏览器检查', 'unknown', '完整模式的浏览器测试未完成。', {'error': type(exc).__name__}, True, 'browser_test'))
        else:
            checks.append(item('browser_tests', '临时浏览器 WebRTC / DNS', 'not_tested',
                               '先取得必要网络证据再执行 -Full。' if full else '使用 -Full 补做；不会使用你的登录资料。', required=full and not launch_check, category='browser_test'))
    report['checks'] = checks
    report.update(summarize(checks, mode))
    report['finished_at'] = datetime.datetime.now(JST).isoformat()
    report['duration_seconds'] = round(time.monotonic() - started, 2)
    return report


def preflight(install_dir=HERE):
    report = collect(install_dir=install_dir, preflight=True)
    return {'ready': report['ready'], 'state': report['state'], 'checked_at': report.get('finished_at'),
            'failed_checks': [c['id'] for c in report['checks'] if c.get('required') and c['status'] != 'pass']}


RESTORE_STEP = '运行 claude-proxy，选 R →「恢复本机代理配置」。'
BROWSER_IDS = {'browser_fixed_exit', 'browser_webrtc', 'browser_dns', 'browser_tests', 'browser_runtime',
               'browser-source-flags', 'browser-build-baseline'}


def guidance(check, checks):
    """Plain-language reason and one next step for a blocking check."""
    key, title = check.get('id', ''), check.get('title', '')
    full = next((c for c in checks if c.get('id') == key), check)
    evidence = full.get('evidence', {}) or {}
    if key == 'usage_guard':
        if full.get('status') == 'unknown':
            return '修复正在进行，或无法读取使用中守护的状态。', '稍等 1 分钟后重新检查。'
        if not evidence.get('alive'):
            return ('使用中守护没有运行：使用过程中出口变化时，不会自动断开 Claude。',
                    '运行 claude-proxy，选 R →「启动使用中守护」。')
        if evidence.get('fixed_exit_blocked'):
            return ('守护发现固定出口 IP 不符，已自动阻断 Claude。',
                    '先联系线路供应商确认出口恢复，再' + RESTORE_STEP + '修复会先核对 IP，不符时继续阻断。')
        return '使用中守护没有按时更新状态，可能已卡住。', '重启电脑（守护随开机启动）后重新检查。'
    if key == 'fixed_egress':
        expected = evidence.get('expected_ip')
        wrong = sorted({p['ip'] for p in evidence.get('probes', []) if p.get('ip') and p['ip'] != expected})
        if wrong:
            return ('固定出口 IP 变成了 ' + '、'.join(wrong) + '，不是预期的 ' + str(expected) + '。',
                    '这是线路供应商那边的变化，本机修不了：恢复前不要使用 Claude，联系供应商恢复原 IP。')
        return ('固定出口线路暂时连不上（供应商或网络问题）。',
                '确认网络正常，几分钟后重新检查；持续失败请联系线路供应商。')
    if key in ('mihomo_core', 'listener_owner', 'controller'):
        return 'Clash 没有运行，或 Claude 专用端口不可用。', '打开 Clash Verge；仍不通过时' + RESTORE_STEP
    if key in ('fixed_policy', 'probe_route'):
        return 'Clash 里 Claude 固定出口的线路配置被改动或无法确认。', RESTORE_STEP
    if key == 'policy':
        return '本机检查策略文件缺失或损坏。', '恢复 audit_policy.json 后重新检查；这一步需要人工处理。'
    if key in BROWSER_IDS:
        return ('专用浏览器的防护没有确认（' + title + '）。',
                'CLI / VS Code 不受影响；需要专用浏览器时，运行 claude-proxy，选 R 查看浏览器方案。')
    if full.get('category') == 'configuration':
        return title + '未通过。', '加 -Details 查看具体位置；运行 claude-proxy，选 R 查看能否自动恢复。'
    return title + '：' + check.get('detail', ''), None


def display(report, details=False):
    cli = report.get('cli_launch_state', 'INCOMPLETE')
    browser = report.get('browser_launch_state', 'INCOMPLETE')
    runtime = report.get('assessment') == 'runtime'
    entries = report.get('entries') or {'cli': cli, 'vscode': cli, 'web': browser}
    clients = [entries.get(k) for k in ('cli', 'vscode', 'web')]
    usable = [s for s in clients if s == 'READY']
    blocked = [s for s in clients if s in ('NOT_READY', 'INCOMPLETE')]
    if runtime:
        verdict = '运行后请求核验通过' if report['ready'] else '运行后请求核验未通过或证据不足'
    elif usable and not blocked:
        verdict = '可以使用 Claude'
    elif usable:
        verdict = '部分可用：见下表'
    elif 'NOT_READY' in clients:
        verdict = '暂不能使用 Claude：按下方「处理」恢复'
    else:
        verdict = '无法确认，暂不要使用 Claude：按下方「处理」操作后重新检查'
    print('\n结论：' + verdict)
    words = {'READY': '可以使用', 'NOT_READY': '暂不能使用', 'INCOMPLETE': '无法确认，暂不要使用'}
    rows = [('CLI', words.get(entries.get('cli'), '无法确认，暂不要使用')),
            ('VS Code', words.get(entries.get('vscode'), '无法确认，暂不要使用')),
            ('网页版', '可以使用（只用桌面「Claude 专用浏览器」）' if entries.get('web') == 'READY' else
                       '未检查：打开「Claude 专用浏览器」时会自动检查' if entries.get('web') == 'NOT_CHECKED' else
                       words.get(entries.get('web'), '无法确认，暂不要使用'))]
    desktop = entries.get('desktop')
    if desktop in ('NOT_INSTALLED', 'UNVERIFIED', 'NOT_READY', 'INCOMPLETE'):
        rows.append(('桌面端', {'NOT_INSTALLED': '未安装',
                               'UNVERIFIED': '未专门验证：只靠 Clash 规则保护，建议改用上面三种',
                               'NOT_READY': '不受保护：只有 Claude 模式（虚拟网卡开）下才走固定出口'}.get(desktop) or words[desktop]))
    if not runtime:
        routing = next((c for c in report['checks'] if c['id'] == 'routing_mode'), {})
        profile = routing.get('evidence', {}).get('profile')
        print('当前模式：' + {'claude': 'Claude 模式（虚拟网卡开）',
                              'domestic': '国内模式（虚拟网卡关）：CLI、VS Code、专用浏览器照常走固定出口',
                              'abnormal': '异常：Clash 不在规则模式；在 Clash Verge 切回「规则」'}.get(profile, '未知'))
        for name, state in rows:
            print('  ' + name + '：' + state)
    print('检查时间：' + report['started_at'] + ' | 版本 ' + report.get('version', VERSION))
    fixed = next((c for c in report['checks'] if c['id'] == 'fixed_egress'), None)
    if fixed:
        e = fixed.get('evidence', {})
        matched = sum(bool(p.get('ok') and p.get('ip') == e.get('expected_ip')) for p in e.get('probes', []))
        print('固定出口：' + str(e.get('expected_ip') or '未取得') + '；独立检测 ' + str(matched) + '/2 通过')
    labels = {'pass': '通过', 'fail': '失败', 'warn': '注意', 'unknown': '证据不足',
              'not_running': '未运行', 'not_tested': '未验证', 'partial': '部分已观察'}
    tested = [c for c in report['checks'] if c['id'] in ('browser_fixed_exit', 'browser_webrtc', 'browser_dns')]
    if tested:
        names = {'browser_fixed_exit': '出口', 'browser_webrtc': 'WebRTC', 'browser_dns': 'DNS'}
        print('临时浏览器：' + '；'.join(names[c['id']] + ' ' + labels.get(c['status'], c['status']) for c in tested))
    blockers = report.get('blocking_checks', [])
    guard_blocked = any(c.get('id') == 'usage_guard' and c.get('evidence', {}).get('fixed_exit_blocked')
                        for c in report['checks'] if c.get('status') == 'fail')
    shown = set()
    for c in blockers:
        # A guard block makes the fixed group REJECT; its downstream symptoms are not separate causes.
        if guard_blocked and c['id'] in ('fixed_policy', 'fixed_egress', 'probe_route'):
            continue
        reason, step = guidance(c, report['checks'])
        if (reason, step) in shown:
            continue
        shown.add((reason, step))
        print('原因：' + reason)
        if step:
            print('处理：' + step)
    if runtime:
        print('运行后核验是可选补充；使用前检查直接运行 claude-proxy，无需启动 Claude。')
    print('状态：' + report['state'] + '；退出码 ' + str(report['exit_code']))
    if not details:
        print('逐项证据：claude-proxy ' + ('-Full ' if 'full' in report.get('mode', '') else '') +
              ('-Runtime ' if runtime else '') + '-Details')
        return
    print('\n--- 逐项证据 ---')
    print(f"Claude 代理检查 {VERSION} | {report['started_at']}")
    print(f"模式：{report['mode']}；检查过程不启动 Clash、不改配置、不切节点。")
    print(f"工作目录：{report['workspace']}")
    labels = {'pass': '通过', 'fail': '失败', 'warn': '注意', 'unknown': '未知',
              'not_running': '未运行', 'not_tested': '未验证', 'partial': '部分已观察'}
    for check in report['checks']:
        print(f"[{labels.get(check['status'], check['status'])}] {check['title']}：{check['detail']}")
        if check['id'] == 'fixed_egress':
            for row in check['evidence']['probes']:
                print('  ' + row['source'] + ' → ' + (row.get('ip') or row.get('error', '未取得结果')))
        if check['id'] in ('clash_gui', 'mihomo_core'):
            print('  PID: ' + str(check['evidence'].get('pids', [])))
        if check['id'].startswith('claude_pid_'):
            print('  程序: ' + str(check['evidence'].get('executable_path') or '未取得'))
            print('  已关联请求数: ' + str(len(check['evidence'].get('observed', []))))
        if check['id'] == 'browser_webrtc':
            evidence = check.get('evidence', {})
            print('  检测出口: ' + str(evidence.get('observed_ip') or '未取得') +
                  '；预期出口: ' + str(evidence.get('expected_ip') or '未取得'))
            print('  公网候选: ' + str(evidence.get('public_candidate_ips', [])) +
                  '；本地候选: ' + str(evidence.get('local_candidate_ips', [])))
            print('  观测结论: ' + str(evidence.get('test_verdict', evidence.get('reason', 'unknown'))) +
                  '；ICE 完成: ' + str(evidence.get('completion_confirmed', False)))
            policy = evidence.get('effective_policy', {})
            print('  生效策略: ' + str(policy.get('value', 'unknown')) +
                  '；来源: ' + str(policy.get('sources', [])))
            control = evidence.get('stun_control', {})
            print('  独立 Python STUN 正对照: ' + str(control.get('ok', False)) +
                  '；此对照的出口 ' + str(control.get('address') or '未取得') + ' 不属于浏览器流量')
            udp = evidence.get('owned_browser_udp', {})
            print('  浏览器 UDP 可读取: ' + str(udp.get('readable', False)) +
                  '；关联 STUN 记录数: ' + str(len(udp.get('records', []))))
    print('\n结论：' + report['state'] + ' — ' + report['message'])
    print('网络: ' + str(report.get('network_state', 'UNKNOWN')) + '；Claude: ' +
          str(report.get('claude_state', 'UNKNOWN')) + '；浏览器: ' + str(report.get('browser_state', 'UNKNOWN')) +
          '；临时浏览器 UDP 测试: ' + str(report.get('browser_udp_state', 'UNKNOWN')))
    print('退出码：' + str(report['exit_code']) + '；0=本模式要求满足，2=错误，3=必要证据不足。')
    print('正常终端可选修复方案；-Repair 仅恢复已有代理配置，不能处理全部浏览器问题。')
    browser_problem = any(c['id'] == 'browser_webrtc' and c['status'] != 'pass' for c in report['checks'])
    if browser_problem:
        print('WebRTC 未通过：依据候选 IP、收集完成状态和实际 UDP 路由判断；现有证据不能证明防护生效。')
    for limit in report['limitations']:
        print('范围：' + limit)


def interactive(report, args):
    """Show plans before changes. EOF/cancel always preserves the current report."""
    from audit_actions import repair_options, execute_option
    repair_in_progress = False
    def recheck(previous):
        current = collect(args.install_dir, args.workspace, args.full, runtime=args.runtime)
        if previous.get('read_only') is False:
            current['read_only'] = False
        for key in ('repair', 'repairs'):
            if key in previous:
                current[key] = previous[key]
        return current
    display(report, args.details)
    while True:
        try:
            choice = input('\n[R] 查看修复方案  [D] 查看详细证据  [C] 重新检查  [Q] 结束\n请选择：').strip().lower()
            if choice in ('q', ''):
                return report
            if choice == 'd':
                display(report, details=True)
                continue
            if choice == 'c':
                print('正在重新检查；不会启动 Claude 或自动修复。', flush=True)
                report = recheck(report)
                display(report)
                continue
            if choice != 'r':
                print('请输入 R、D、C 或 Q。')
                continue
            options = repair_options(report, args.install_dir)
            if not options:
                print('当前没有适用的自动修复方案。可用 C 重新检查，或 D 查看具体原因。')
                continue
            print('\n修复方案（查看不会修改配置）：')
            for index, option in enumerate(options, 1):
                print(str(index) + '. ' + option['title'] + (' [可执行]' if option['available'] else ' [不能自动处理]'))
                if option.get('reason'):
                    print('   ' + option['reason'])
            selected = input('输入方案编号查看影响，或按 Enter 返回：').strip()
            if not selected:
                continue
            if not selected.isdigit() or not 1 <= int(selected) <= len(options):
                print('未选择有效方案，未作修改。')
                continue
            option = options[int(selected) - 1]
            print('\n方案：' + option['title'])
            for change in option['changes']:
                print('将执行：' + change)
            for key, label in (('impact', '影响'), ('expected', '预期结果'), ('rollback', '恢复方式')):
                print(label + '：' + option[key])
            if not option['available']:
                print('该方案当前不能自动执行；未作修改。')
                continue
            confirmed = input('确认执行此方案请输入 YES；其他输入均取消：').strip()
            if confirmed != 'YES':
                print('已取消，未作修改。')
                continue
            print('正在执行已确认的方案；完成后自动重新检查。', flush=True)
            previous_repairs = report.get('repairs', [report['repair']] if 'repair' in report else [])
            report['read_only'] = False
            report['repair'] = {'requested': True, 'option': option['id'], 'state': 'in_progress'}
            report['repairs'] = previous_repairs + [report['repair']]
            repair_in_progress = True
            result = execute_option(option['id'], args.install_dir, args.workspace)
            print(result['message'])
            if result.get('backup'):
                print('备份：' + str(result['backup']))
            if result.get('rollback_command'):
                print('恢复命令：' + result['rollback_command'])
            report = recheck(report)
            report['repair'] = {'requested': True, 'option': option['id'], **result}
            report['repairs'] = previous_repairs + [report['repair']]
            report['read_only'] = False
            if result['exit_code']:
                report['checks'].append(item('repair_result', '修复结果', 'fail',
                                             '修复未正常完成；请查看方案结果，不把重新探测成功当作修复成功。', required=True))
                report.update(summarize(report['checks'], report['mode']))
            repair_in_progress = False
            display(report)
        except (EOFError, KeyboardInterrupt):
            if repair_in_progress:
                report['repair']['state'] = 'interrupted'
                report['checks'].append(item('repair_interrupted', '修复被中断', 'unknown',
                                             '不能确认修复完成或当前环境；请重新运行检查。', required=True))
                report.update(summarize(report['checks'], report['mode']))
                display(report)
            print('\n已结束交互。')
            return report


def main():
    parser = argparse.ArgumentParser(description='默认检查使用前环境；修复需显式参数或菜单确认。')
    parser.add_argument('--install-dir', type=Path, default=HERE)
    parser.add_argument('--workspace', type=Path, default=Path.cwd())
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--repair', action='store_true')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--details', action='store_true', help='显示逐项检查及详细证据。')
    parser.add_argument('--runtime', action='store_true', help='可选的运行后逐实例请求核验；不会启动 Claude。')
    parser.add_argument('--no-prompt', action='store_true', help='不显示交互菜单，适用于脚本。')
    parser.add_argument('--output', type=Path)
    gate = parser.add_mutually_exclusive_group()
    gate.add_argument('--preflight', action='store_true')
    gate.add_argument('--launch-check', action='store_true', help='只检查网络和配置启动条件，不宣称实际应用流量已验证。')
    parser.add_argument('--internal-rpc', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if (args.preflight or args.launch_check) and (args.full or args.repair or args.runtime):
        parser.error('启动条件检查不能与 --full 或 --repair 同用。')
    if args.runtime and args.repair:
        parser.error('--runtime 不能与 --repair 同用。')
    if args.internal_rpc:
        try:
            path = json.load(sys.stdin)
            if path not in ('/configs', '/version', '/proxies', '/connections'):
                return 1
            sys.path.insert(0, str(args.install_dir))
            from repair_support import raw_api
            print(json.dumps(raw_api(path, 'GET'), ensure_ascii=True))
            return 0
        except Exception:
            return 1
    try:
        if not args.json:
            print('正在检查使用前环境，无需打开 Claude；不会自动修复。' +
                  (' 将用临时未登录浏览器补测，通常约 1 分钟。' if args.full else '') if not args.runtime else
                  '正在核验已运行实例的请求；不会启动 Claude 或自动修复。', flush=True)
        report = collect(args.install_dir, args.workspace, args.full and not args.repair, args.preflight, args.launch_check, args.runtime)
        if args.repair:
            # Keep the existing credential-preserving backend, then independently re-audit.
            before = {k: report[k] for k in ('state', 'ready', 'started_at')}
            if not args.json:
                display(report, args.details)
                print('\n已明确选择 -Repair：现在才允许启动/重载 Clash 和恢复已有受管理配置。', flush=True)
            try:
                repaired = run([sys.executable, '-X', 'utf8', '-B', args.install_dir / 'repair_proxy.py',
                                '--workspace', args.workspace], timeout=180)
                repair_code = repaired.returncode
            except Exception as exc:
                repair_code = 30
                before['repair_error'] = type(exc).__name__
            report = collect(args.install_dir, args.workspace, args.full)
            report['repair'] = {'requested': True, 'before': before, 'backend_exit': repair_code}
            if repair_code:
                report['checks'].append(item('repair_result', '修复后端结果', 'fail',
                                             '修复后端未正常完成，未把最后一次网络成功当成完整修复。', {'exit_code': repair_code}, True))
                report.update(summarize(report['checks'], report['mode']))
            report['read_only'] = False
        prompted = not args.json and not args.no_prompt and not args.preflight and not args.launch_check and sys.stdin.isatty() and sys.stdout.isatty()
        if prompted:
            report = interactive(report, args)
        if args.output:
            # Reports are opt-in; never overwrite the legacy last-repair result on a check.
            path = args.output.resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            if not prompted:
                display(report, args.details)
            if args.output:
                print('报告：' + str(args.output.resolve()))
        return report['exit_code']
    except Exception as exc:
        # Do not echo arbitrary exception messages, environment values or parsed configs.
        if args.json:
            print(json.dumps({'state': 'INCOMPLETE', 'ready': False, 'exit_code': 3, 'error': type(exc).__name__}))
        else:
            print('检查未完成：' + type(exc).__name__ + '。没有自动修复，也没有判为通过。')
        return 3


if __name__ == '__main__':
    raise SystemExit(main())
