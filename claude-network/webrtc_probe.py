"""Native ICE plus effective Chrome policy and a working UDP STUN control.

No third-party result page is parsed. No-candidates alone is never success.
Only small network fields leave the browser; SDP and user preferences do not.
"""
import asyncio
import ipaddress
import json
from pathlib import Path

EXPECTED_POLICY = 'disable_non_proxied_udp'
STUN_HOST = 'stun.cloudflare.com'
STUN_PORT = 3478

ICE_JS = r'''async ({host,port}) => {
 const r={completed:false,timed_out:false,offer_created:false,candidates:[],errors:[],states:[]};
 let pc,finish,timer;
 try {
  pc=new RTCPeerConnection({iceServers:[{urls:`stun:${host}:${port}`}],iceTransportPolicy:'all'});
  const done=new Promise(resolve=>finish=resolve);
  pc.onicecandidate=e=>{if(e.candidate){const c=e.candidate;
   r.candidates.push({type:c.type,protocol:c.protocol,address:c.address,port:c.port,related_port:c.relatedPort});}};
  pc.onicecandidateerror=e=>r.errors.push({code:e.errorCode});
  pc.onicegatheringstatechange=()=>{r.states.push(pc.iceGatheringState);
   if(pc.iceGatheringState==='complete'){r.completed=true;finish();}};
  pc.createDataChannel('fixed-exit-audit');
  timer=setTimeout(()=>{r.timed_out=true;finish();},16000);
  await pc.setLocalDescription(await pc.createOffer());
  r.offer_created=!!pc.localDescription && /^v=0/.test(pc.localDescription.sdp||'');
  await done;
 } catch (_) {r.error='native_ice_error';}
 finally {if(timer)clearTimeout(timer);window.__proxyAuditPeer=pc;}
 return r;
}'''


def project_policy(data):
    found = {}
    def visit(value, prefix=''):
        if not isinstance(value, dict):
            return
        for key, child in value.items():
            path = prefix + '.' + key if prefix else key
            if path in ('webrtc.ip_handling_policy', 'webrtc.ip_handling_url'):
                found[path] = child
            elif isinstance(child, dict):
                visit(child, path)
    visit(data)
    main = found.get('webrtc.ip_handling_policy', {})
    urls = found.get('webrtc.ip_handling_url', {})
    raw = main.get('value') if isinstance(main, dict) else None
    metadata = main.get('metadata', []) if isinstance(main, dict) else []
    overrides = urls.get('value') if isinstance(urls, dict) else None
    # Chrome's prefs-internals distinguishes the controlling store from whether
    # an extension may override it. In particular, command_line_controlled plus
    # extension_modifiable does not mean an extension currently controls it.
    allowed = {'managed', 'managed_by_custodian', 'extension_controlled',
               'command_line_controlled', 'user_controlled', 'recommended',
               'user_modifiable', 'extension_modifiable', 'default',
               'extension', 'command_line'}
    return {'value': raw if raw in ('default', 'default_public_and_private_interfaces', 'default_public_interface_only', EXPECTED_POLICY) else 'unrecognized',
            'sources': [x for x in metadata if x in allowed] if isinstance(metadata, list) else [],
            'url_override_count': len(overrides) if isinstance(overrides, list) else None,
            'url_overrides_empty': isinstance(overrides, list) and not overrides}


def _forced_extension_ids():
    import winreg
    ids = set()
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(hive, r'SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist', 0,
                                    winreg.KEY_READ | view) as key:
                    for index in range(winreg.QueryInfoKey(key)[1]):
                        value = winreg.EnumValue(key, index)[1]
                        if isinstance(value, str) and value.split(';', 1)[0]:
                            ids.add(value.split(';', 1)[0].strip())
            except FileNotFoundError:
                continue
    return ids


def profile_extension_scope(root=None, forced=None):
    """Extensions in the dedicated profile that could override the command-line WebRTC setting.

    Only extensions holding the privacy permission (or a stored WebRTC preference) can
    take precedence over a command-line value. Sync and policy can add extensions later,
    so this is read at every check. Only extension IDs and names enter the report.
    """
    result = {'readable': False, 'profiles': [], 'capable': [], 'missing_forced': []}
    try:
        if root is None:
            from browser_entry import PROFILE
            root = PROFILE
        root = Path(root)
        forced = _forced_extension_ids() if forced is None else set(forced)
        names = []
        if (root / 'Local State').is_file():
            names = list(json.loads((root / 'Local State').read_text(encoding='utf-8'))
                         .get('profile', {}).get('info_cache', {}))
        elif root.is_dir():
            names = [p.parent.name for p in root.glob('*/Preferences')]
        # Chrome's internal System/Guest profiles never load user extensions.
        names = sorted(set(names) - {'System Profile', 'Guest Profile'})
        for name in names:
            settings = {}
            for filename in ('Preferences', 'Secure Preferences'):
                path = root / name / filename
                if path.is_file():
                    data = json.loads(path.read_text(encoding='utf-8'))
                    for ident, row in data.get('extensions', {}).get('settings', {}).items():
                        settings.setdefault(ident, {}).update(row)
            result['profiles'].append(name)
            for ident, row in settings.items():
                granted = set((row.get('active_permissions') or {}).get('api', [])) | \
                          set((row.get('granted_permissions') or {}).get('api', []))
                stored = [key for field in ('preferences', 'regular_only_preferences', 'incognito_preferences')
                          for key in (row.get(field) or {}) if 'webrtc' in key.lower()]
                if 'privacy' in granted or stored:
                    result['capable'].append({'profile': name, 'id': ident,
                                              'name': (row.get('manifest') or {}).get('name')})
            # A forced extension not yet installed has unknown permissions.
            result['missing_forced'] += [{'profile': name, 'id': ident} for ident in sorted(forced - set(settings))]
        if not names and forced:
            result['missing_forced'] = [{'profile': None, 'id': ident} for ident in sorted(forced)]
        result['readable'] = True
    except (OSError, ValueError, TypeError, AttributeError, ImportError) as exc:
        result['error'] = type(exc).__name__
    return result


def classify(evidence, expected_ip):
    policy = evidence.get('effective_policy', {})
    native = evidence.get('native_ice', {})
    control = evidence.get('stun_control', {})
    addresses = []
    for candidate in native.get('candidates', []):
        try:
            address = ipaddress.ip_address(candidate.get('address'))
        except (TypeError, ValueError):
            continue
        addresses.append(str(address))
    evidence['candidate_ips'] = sorted(set(addresses))
    evidence['public_candidate_ips'] = sorted({a for a in addresses if ipaddress.ip_address(a).is_global})
    evidence['local_candidate_ips'] = sorted({a for a in addresses if not ipaddress.ip_address(a).is_global})
    evidence['expected_ip'] = expected_ip
    bad = [a for a in evidence['public_candidate_ips'] if a != expected_ip]
    if bad:
        return 'fail', '直接 ICE 观察到不同于固定出口的公网候选地址。', 'foreign_public_candidate'
    if policy.get('value') != EXPECTED_POLICY:
        return ('unknown' if policy.get('value') in (None, 'unrecognized') else 'fail'), 'Chrome 实际生效的 WebRTC 策略未确认限制非代理 UDP。', 'effective_policy_not_protective'
    if not policy.get('url_overrides_empty'):
        return 'unknown', '存在或无法读取按 URL 的 WebRTC 策略，不能用全局值替代实际覆盖。', 'url_override_unverified'
    sources = policy.get('sources', [])
    command_line = 'command_line_controlled' in sources or 'command_line' in sources
    scope = evidence.get('profile_scope', {})
    # The dedicated browser starts with the same switch; only an extension in its
    # profile could take precedence over it, so a clean profile carries the result.
    profile_clean = bool(scope.get('readable')) and not scope.get('capable') and not scope.get('missing_forced')
    if 'managed' not in sources and not (command_line and profile_clean):
        if command_line and scope.get('capable'):
            names = '、'.join(sorted({str(row.get('name') or row.get('id')) for row in scope['capable']}))
            detail = '专用浏览器资料中有能改写 WebRTC 设置的扩展（' + names + '），命令行设置可能被覆盖。'
        elif command_line and scope.get('missing_forced'):
            detail = '有策略强制安装但尚未装入专用资料的扩展，无法确认其权限。'
        elif command_line:
            detail = '本次临时浏览器的 WebRTC 设置由命令行控制，但无法读取专用浏览器资料中的扩展。'
        elif 'extension_controlled' in sources or 'extension' in sources:
            detail = '本次临时浏览器的 WebRTC 设置由扩展控制，未读到 managed 强制策略；尚不能据此确认现有专用资料受到强制保护。'
        else:
            detail = '本次临时浏览器未读到 managed 强制策略；extension_modifiable 只表示设置可被扩展覆盖，不表示扩展正在控制它。'
        if not command_line:
            detail += ' 应核对运行用户的策略和 Chrome 实际加载结果；来源差异的原因尚未确定。'
        return 'unknown', detail, 'profile_scope_unverified'
    if not control.get('ok'):
        return 'unknown', '独立 STUN 正对照未取得有效响应；零候选不能证明防护生效。', 'stun_control_unavailable'
    if not native.get('offer_created') or not native.get('completed') or native.get('timed_out') or native.get('error'):
        return 'unknown', '原生 ICE 未成功完成；没有把未返回候选当成通过。', 'native_ice_incomplete'
    udp = evidence.get('owned_browser_udp', {})
    if not udp.get('readable'):
        return 'unknown', '无法核对本次测试浏览器的 UDP 连接，保留未验证。', 'browser_udp_unreadable'
    if udp.get('records'):
        return 'fail', '本次测试浏览器仍发出了 STUN UDP；保护与实际行为不一致。', 'browser_stun_udp_observed'
    if evidence['local_candidate_ips']:
        return 'warn', '原生 ICE 显示本地地址候选；未将其冒充为公网泄漏，也不判完整通过。', 'local_candidate_observed'
    basis = '有效强制策略' if 'managed' in sources else '命令行设置生效且专用资料中没有能覆盖它的扩展'
    return 'pass', '已确认' + basis + '、STUN 正对照可用、原生 ICE 完成；未发现测试浏览器的非代理 STUN UDP 或异常公网候选。', 'policy_and_native_ice_verified'


def owned_udp_records(root_pids):
    """Match the test browser tree's actual UDP source ports, not all Chrome."""
    try:
        import psutil
        from audit_proxy import api
        owned = set(int(p) for p in root_pids)
        for pid in list(owned):
            try:
                owned.update(c.pid for c in psutil.Process(pid).children(recursive=True))
            except psutil.NoSuchProcess:
                continue
        ports = {c.laddr.port for c in psutil.net_connections(kind='udp') if c.pid in owned and c.laddr}
        rows = api('/connections').get('connections', [])
        records = []
        for row in rows:
            m = row.get('metadata', {})
            if m.get('network') != 'udp' or str(m.get('sourcePort')) not in {str(p) for p in ports}:
                continue
            if str(m.get('destinationPort')) != str(STUN_PORT):
                continue
            records.append({'source_port': m.get('sourcePort'), 'destination_port': m.get('destinationPort'),
                            'inbound': m.get('inboundName'), 'rule': row.get('rule'), 'chains': row.get('chains', [])})
        return {'readable': bool(owned), 'browser_pids': sorted(owned), 'udp_source_ports': sorted(ports), 'records': records}
    except Exception as exc:
        return {'readable': False, 'error': type(exc).__name__, 'records': []}


async def native_check(context, expected_ip):
    evidence = {'scope': 'temporary_browser_shared_managed_policy', 'result_source': 'native_ice_and_effective_policy',
                'control_scope': 'independent_python_udp_not_browser_traffic'}
    page = None
    try:
        from stun_probe import probe_stun
        cdp = await context.browser.new_browser_cdp_session()
        processes = await cdp.send('SystemInfo.getProcessInfo')
        root_pids = [p['id'] for p in processes.get('processInfo', []) if p.get('type') == 'browser']
        page = await context.new_page()
        await page.goto('chrome://prefs-internals', wait_until='load', timeout=8000)
        await page.wait_for_function("() => {try {const v=JSON.parse(document.body.innerText);return !!(v.webrtc?.ip_handling_policy || v['webrtc.ip_handling_policy']);} catch (_) {return false;}}", timeout=8000)
        evidence['effective_policy'] = project_policy(json.loads(await page.locator('body').inner_text()))
        evidence['profile_scope'] = await asyncio.to_thread(profile_extension_scope)
        await page.goto('https://www.cloudflare.com/cdn-cgi/trace', wait_until='domcontentloaded', timeout=15000)
        trace = dict(line.split('=', 1) for line in (await page.locator('body').inner_text()).splitlines() if '=' in line)
        evidence['observed_ip'] = str(ipaddress.ip_address(trace.get('ip', '')))
        async def udp_observations():
            gathered = []
            for _ in range(3):
                gathered.append(await asyncio.to_thread(owned_udp_records, root_pids))
                await asyncio.sleep(0.35)
            valid = all(r.get('readable') for r in gathered)
            unique = {json.dumps(r, sort_keys=True):r for x in gathered for r in x.get('records', [])}
            return {'readable':valid, 'browser_pids':root_pids, 'records':list(unique.values()), 'samples':len(gathered)}
        evidence['stun_control'], evidence['native_ice'], evidence['owned_browser_udp'] = await asyncio.gather(
            asyncio.to_thread(probe_stun, STUN_HOST, STUN_PORT, 4),
            page.evaluate(ICE_JS, {'host': STUN_HOST, 'port': STUN_PORT}), udp_observations())
        # Keep the native PeerConnection alive until this final owner/port lookup.
        final_udp = await asyncio.to_thread(owned_udp_records, root_pids)
        evidence['owned_browser_udp']['readable'] &= final_udp.get('readable', False)
        previous_records = evidence['owned_browser_udp']['records'] + final_udp.get('records', [])
        evidence['owned_browser_udp']['records'] = list({json.dumps(r, sort_keys=True):r for r in previous_records}.values())
        evidence['owned_browser_udp']['samples'] += 1
        # Do not retain mDNS names or opaque candidate fields in the report.
        for c in evidence['native_ice'].get('candidates', []):
            try: c['address'] = str(ipaddress.ip_address(c.get('address')))
            except (ValueError, TypeError): c['address'] = '<mdns-or-unparsed>'
        status, detail, reason = classify(evidence, expected_ip)
        if evidence['observed_ip'] != expected_ip:
            status, detail, reason = 'fail', '浏览器网页出口与固定出口不符。', 'browser_http_exit_mismatch'
        evidence['reason'] = reason
        evidence['completion_confirmed'] = evidence['native_ice'].get('completed', False)
        evidence['test_verdict'] = status
        return status, detail, evidence
    except Exception as exc:
        evidence['error'] = type(exc).__name__
        return 'unknown', '原生 WebRTC 或有效策略检查未完成，未判为通过。', evidence
    finally:
        if page:
            try:
                await page.evaluate('() => {window.__proxyAuditPeer?.close(); delete window.__proxyAuditPeer;}')
            except Exception:
                pass
            try:
                await page.close()
            except Exception:
                pass
