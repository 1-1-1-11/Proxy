"""Fresh, read-only proxy evidence. Only --repair invokes the separate repair backend.

No account request, credentials file, browser profile or previous PASS is used.
Normal exit 0 requires live evidence for every running Claude instance as well
as the required checks. Launch/preflight modes validate prerequisites only.
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
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

VERSION = '2026.10.06.6'
HERE = Path(__file__).resolve().parent
HIDDEN = 0x08000000 if os.name == 'nt' else 0
JST = datetime.timezone(datetime.timedelta(hours=9))
BAD = {'fail', 'unknown', 'not_tested', 'not_running', 'warn', 'partial'}


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
        return data
    except Exception as exc:
        return {'process': {'ok': False}, 'tcp': {'ok': False},
                'physical': {'ok': False}, 'error': type(exc).__name__}


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
    checks.append(item('routing_mode', 'TUN、模式与系统代理', 'pass' if ctl.get('ok') else 'unknown',
                       '这是路由状态记录；开启 TUN 不代表所有流量使用固定出口。',
                       {'mode': live.get('mode'), 'tun_enabled': live.get('tun', {}).get('enable'),
                        'strict_route': live.get('tun', {}).get('strict-route'), 'system': snap.get('system', {})}))
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


def summarize(checks, mode='check'):
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
    failures = [x for x in checks if x.get('required') and x['status'] == 'fail']
    missing = [x for x in checks if x.get('required') and x['status'] in BAD and x['status'] != 'fail']
    if failures:
        return {**split, 'state': 'NOT_READY', 'exit_code': 2, 'ready': False,
                'message': '未通过：存在明确错误；没有执行自动修复。'}
    if missing or network_state != 'READY' or (mode not in ('preflight', 'launch_check') and claude != 'pass'):
        return {**split, 'state': 'INCOMPLETE', 'exit_code': 3, 'ready': False,
                'message': '检查不完整：必要检查或逐实例 Claude 实际流量证据不足；代理就绪不等于应用验收完成。'}
    if mode in ('preflight', 'launch_check'):
        return {**split, 'state': 'LAUNCH_READY' if mode == 'launch_check' else 'PROXY_READY',
                'exit_code': 0, 'ready': True,
                'message': '启动条件检查通过；没有据此证明尚未启动应用的真实流量。'}
    return {**split, 'state': 'CLAUDE_OBSERVED', 'exit_code': 0, 'ready': True,
            'message': '必要检查通过，所有本次运行中的 Claude 实例均有对应请求。浏览器及 UDP 状态单独列出；不保证未来流量。'}


def collect(install_dir=HERE, workspace=None, full=False, preflight=False, launch_check=False):
    install_dir = Path(install_dir)
    started = time.monotonic()
    mode = 'preflight' if preflight else 'launch_check' if launch_check else 'full_check' if full else 'check'
    report = {'schema': 3, 'version': VERSION, 'started_at': datetime.datetime.now(JST).isoformat(),
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


def display(report):
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
    print('退出码：' + str(report['exit_code']) + '；0=本模式要求满足，2=错误，3=证据不足；启动检查不代表实际流量验收。')
    print('修复需明确执行 claude-proxy -Repair；浏览器补测用 claude-proxy -Full。')
    browser_problem = any(c['id'] == 'browser_webrtc' and c['status'] != 'pass' for c in report['checks'])
    if browser_problem:
        print('WebRTC 未通过：依据候选 IP、收集完成状态和实际 UDP 路由判断；现有证据不能证明防护生效。')
    for limit in report['limitations']:
        print('范围：' + limit)


def main():
    parser = argparse.ArgumentParser(description='默认只检查，显式 --repair 才修复。')
    parser.add_argument('--install-dir', type=Path, default=HERE)
    parser.add_argument('--workspace', type=Path, default=Path.cwd())
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--repair', action='store_true')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--output', type=Path)
    gate = parser.add_mutually_exclusive_group()
    gate.add_argument('--preflight', action='store_true')
    gate.add_argument('--launch-check', action='store_true', help='只检查网络和配置启动条件，不宣称实际应用流量已验证。')
    parser.add_argument('--internal-rpc', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if (args.preflight or args.launch_check) and (args.full or args.repair):
        parser.error('启动条件检查不能与 --full 或 --repair 同用。')
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
            print('正在读取实时状态并探测出口；默认不启动 Clash、不修复配置。' +
                  (' 完整模式还会启动临时未登录浏览器，通常需要约 1 分钟。' if args.full else ''), flush=True)
        report = collect(args.install_dir, args.workspace, args.full and not args.repair, args.preflight, args.launch_check)
        if args.repair:
            # Keep the existing credential-preserving backend, then independently re-audit.
            before = {k: report[k] for k in ('state', 'ready', 'started_at')}
            if not args.json:
                display(report)
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
                report.update(summarize(report['checks']))
            report['mode'] = 'repair_then_check'
            report['read_only'] = False
        if args.output:
            # Reports are opt-in; never overwrite the legacy last-repair result on a check.
            path = args.output.resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        if args.json:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            display(report)
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
