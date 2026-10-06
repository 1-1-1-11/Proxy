"""Native ICE plus effective Chrome policy and a working UDP STUN control.

No third-party result page is parsed. No-candidates alone is never success.
Only small network fields leave the browser; SDP and user preferences do not.
"""
import asyncio
import ipaddress
import json

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
    allowed = {'managed', 'extension', 'command_line', 'user_modifiable', 'extension_modifiable', 'default'}
    return {'value': raw if raw in ('default', 'default_public_and_private_interfaces', 'default_public_interface_only', EXPECTED_POLICY) else 'unrecognized',
            'sources': [x for x in metadata if x in allowed] if isinstance(metadata, list) else [],
            'url_override_count': len(overrides) if isinstance(overrides, list) else None,
            'url_overrides_empty': isinstance(overrides, list) and not overrides}


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
    if 'managed' not in policy.get('sources', []):
        return 'unknown', '临时浏览器仅有可被扩展覆盖的设置；尚不能将它作为现有专用资料的强制保护证明。', 'profile_scope_unverified'
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
    return 'pass', '已确认有效强制策略、STUN 正对照可用、原生 ICE 完成；未发现测试浏览器的非代理 STUN UDP 或异常公网候选。', 'policy_and_native_ice_verified'


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
