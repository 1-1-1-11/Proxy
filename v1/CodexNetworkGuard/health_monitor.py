"""Local network recovery: native failover first, bounded full reload second.
Does not select individual nodes, change account data or fall back to DIRECT.
"""
import concurrent.futures,ctypes,datetime,http.client,io,json,os,pathlib,re,subprocess,sys,threading,time,urllib.parse
import yaml
HERE=pathlib.Path(__file__).parent
ROOT=pathlib.Path.home()/'AppData/Roaming/io.github.clash-verge-rev.clash-verge-rev'
sys.path.insert(0,str(pathlib.Path.home()/'.codex/ClaudeNetwork'))
from network_check import checked,EXPECTED_IP
LOCK=threading.Lock();LOGLOCK=threading.Lock()
def now():return datetime.datetime.now().astimezone().isoformat()
def clean(message):
    message=re.sub(r'https?://[^\s"<>]+','[url]',str(message))
    return re.sub(r'(?i)((?:token|password|secret|authorization)\s*[:=]\s*)[^\s,]+',r'\1[redacted]',message)[:1000]
def log(kind,**fields):
    with LOGLOCK:
        p=HERE/'network-health.jsonl'
        if p.exists() and p.stat().st_size>1048576:
            old=HERE/'network-health.1.jsonl'
            older=HERE/'network-health.2.jsonl'
            if old.exists():os.replace(old,older)
            os.replace(p,old)
        with p.open('a',encoding='utf-8') as f:f.write(json.dumps({'time':now(),'event':kind,**fields},ensure_ascii=False)+'\n')
def response(path,method='GET',data=None):
    prefix='\\\\.\\pipe\\';pipe=prefix+next(n for n in os.listdir(prefix) if n.startswith('verge-mihomo-production-'))
    for i in range(20):
        try:f=open(pipe,'r+b',buffering=0);break
        except OSError:
            if i==19:raise
            time.sleep(.1)
    body=json.dumps(data,ensure_ascii=False).encode() if data is not None else b''
    class Sock:
        def makefile(self,*a,**kw):return io.BufferedReader(f)
    try:
        packet=(f'{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n').encode()+body
        offset=0
        while offset<len(packet):offset+=f.write(packet[offset:])
        r=http.client.HTTPResponse(Sock());r.begin();return f,r
    except BaseException:f.close();raise
def api(path,method='GET',data=None):
    with LOCK:
        f,r=response(path,method,data)
        try:
            body=r.read();return r.status,json.loads(body) if body else None
        finally:r.close();f.close()
def stream():
    recent={}
    while True:
        f=r=None
        try:
            f,r=response('/logs?level=warning')
            while True:
                line=r.readline()
                if not line:break
                event=json.loads(line);msg=clean(event.get('payload',''))
                stamp=time.monotonic()
                # Bound repeated warning bursts; do not record successful browsing.
                key=re.sub(r':\d+',':PORT',msg)
                if stamp-recent.get(key,0)>30:
                    log('core_warning',level=event.get('type'),message=msg);recent[key]=stamp
                if len(recent)>300:recent={k:v for k,v in recent.items() if stamp-v<120}
        except Exception as e:log('log_stream_reconnect',error=type(e).__name__)
        finally:
            if r:r.close()
            if f:f.close()
        time.sleep(5)
def read_state():
    try:return json.loads((HERE/'network-state.json').read_text(encoding='utf-8'))
    except (OSError,ValueError):return {}
def write_state(state):
    p=HERE/'network-state.json';tmp=p.with_suffix('.tmp')
    tmp.write_text(json.dumps(state,ensure_ascii=False,indent=2),encoding='utf-8');os.replace(tmp,p)
def physical_network():
    # Association and a gateway are prerequisites. Do not use ping: many routers
    # ignore it, and internet reachability belongs to the HTTPS checks below.
    script='''$ErrorActionPreference='Stop'
    [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
    $physicalAdapters=@(Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'})
    $available=@()
    foreach($adapter in $physicalAdapters) {
      $ipState=Get-NetIPConfiguration -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue
      if($ipState.IPv4DefaultGateway -or $ipState.IPv6DefaultGateway) {$available += $adapter.Name}
    }
    @{ready=($available.Count -gt 0);interfaces=$available}|ConvertTo-Json -Compress'''
    try:
        exe=str(pathlib.Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
        p=subprocess.run([exe,'-NoLogo','-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,encoding='utf-8',timeout=12,creationflags=0x08000000)
        if p.returncode:raise RuntimeError('Physical interface query failed')
        return json.loads(p.stdout.lstrip('\ufeff'))
    except Exception as e:return {'ready':None,'error':type(e).__name__}
def configured_chains(payload):
    nodes=list(payload.get('proxies',[]))
    nodes.extend(payload.get('proxy-providers',{}).get('固定出口链路',{}).get('payload',[]))
    return [p for p in nodes if p.get('name')=='静态IP-链式' or p.get('name','').startswith('静态出口·')]
def warmup():
    results={}
    paths={
        'daily':'/group/'+urllib.parse.quote('日常网络-自动恢复',safe='')+'/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=4000',
        'fixed':'/providers/proxies/'+urllib.parse.quote('固定出口链路',safe='')+'/healthcheck',
    }
    for name,path in paths.items():
        try:results[name]=api(path)[0]
        except Exception as e:results[name]=type(e).__name__
    log('network_ready_warmup',status=results)
def notice(old,state):
    # Alert only on transitions, so the user hears about a block once, not every 30 seconds.
    if state.get('fixed_exit_blocked') and not old.get('fixed_exit_blocked'):
        return ('Claude 已被阻断','固定出口 IP 不符，守护已断开 Claude 的固定出口连接。\n\n恢复前不要使用 Claude。双击桌面「代理网络检查」查看处理办法。')
    # Turning TUN off is the deliberate switch to domestic mode; only leaving rule mode is unexpected.
    if old.get('mode')=='rule' and state.get('mode') not in (None,'rule'):
        return ('Clash 已离开规则模式','Clash 被切到了全局或直连模式：Claude 分流规则不再生效，桌面端和普通浏览器里的 Claude 可能不走固定出口。CLI、VS Code 和专用浏览器不受影响。\n\n在 Clash Verge 切回「规则」模式。')
    return None
def alert(title,text):
    # A modal box in its own thread: visible until dismissed, never blocks the checks.
    threading.Thread(target=lambda:ctypes.windll.user32.MessageBoxW(None,text,title,0x30|0x1000|0x10000),daemon=True).start()
def fixed_streaks(old,fixed_ok,checked_at=None):
    """Count completed probes, never tray refreshes. Two samples confirm a transition.

    These counters only affect the indicator. Raw readiness and IP blocking remain immediate.
    Counts saturate at two so a stable state does not generate a log every cycle.
    """
    if checked_at is not None:
        try:
            age=checked_at-datetime.datetime.fromisoformat(old['time']).timestamp()
            if not 0<=age<=120:old={}
        except (KeyError,TypeError,ValueError):old={}
    if fixed_ok:
        successes=min(2,int(old.get('fixed_success_count',0))+1) if old.get('fixed_ok') is True else 1
        recovering=bool(old.get('fixed_ok') is False or old.get('fixed_recovering')) and successes<2
        return {'fixed_failed_count':0,'fixed_success_count':successes,'fixed_recovering':recovering}
    failures=min(2,int(old.get('fixed_failed_count',0))+1) if old.get('fixed_ok') is False else 1
    return {'fixed_failed_count':failures,'fixed_success_count':0,'fixed_recovering':False}
def check_once():
    old=read_state();start=time.time()
    # A manual repair owns configuration changes for at most five minutes.
    # The expiry prevents a crashed repair process from disabling recovery forever.
    try:
        active=json.loads((HERE/'repair-active.json').read_text(encoding='utf-8'))
        if start<float(active.get('expires',0))<=start+300:return old
    except (OSError,ValueError,TypeError):pass
    physical=physical_network()
    if physical.get('ready') is False:
        state={'time':now(),'monitor_pid':os.getpid(),'network_status':'waiting_for_physical_network','physical':physical,
               'daily_ok':None,'fixed_ok':None,'fixed_ip':None,'both_failed_count':0,'daily_failed_count':0,
               'fixed_failed_count':0,'fixed_success_count':0,'fixed_recovering':False,
               'last_reload':old.get('last_reload',0),'last_heartbeat':old.get('last_heartbeat',0)}
        if old.get('network_status')!=state['network_status'] or start-float(state['last_heartbeat'])>600:
            log('waiting_for_physical_network',reason='No connected physical adapter with a gateway; proxy reload skipped')
            state['last_heartbeat']=start
        write_state(state);return state
    became_ready=physical.get('ready') is True and (old.get('monitor_pid')!=os.getpid() or old.get('physical',{}).get('ready') is not True)
    if became_ready:
        warmup()
        old['both_failed_count']=0;old['daily_failed_count']=0
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        a=ex.submit(checked,7892);b=ex.submit(checked,17892);daily=a.result();fixed=b.result()
    daily_ok=daily['curl_exit']==0
    fixed_ok=fixed['curl_exit']==0 and fixed.get('ip')==EXPECTED_IP
    wrong_exit=bool(fixed.get('ip') and fixed['ip']!=EXPECTED_IP)
    # Keep the block until an explicit repair produces the expected public exit.
    exit_blocked=wrong_exit or (bool(old.get('fixed_exit_blocked')) and not fixed_ok)
    failures=0 if daily_ok or fixed_ok else int(old.get('both_failed_count',0))+1
    daily_failures=0 if daily_ok else int(old.get('daily_failed_count',0))+1
    state={'time':now(),'monitor_pid':os.getpid(),'network_status':'connected' if physical.get('ready') else 'physical_state_unknown','physical':physical,'daily_ok':daily_ok,'fixed_ok':fixed_ok,'fixed_ip':fixed.get('ip'),'both_failed_count':failures,'daily_failed_count':daily_failures,'last_reload':old.get('last_reload',0),'last_heartbeat':old.get('last_heartbeat',0),'daily':daily,'fixed':fixed}
    state.update(fixed_streaks(old,fixed_ok,start))
    try:
        cfg=api('/configs')[1];proxies=api('/proxies')[1]['proxies']
        state['tun']=cfg.get('tun',{}).get('enable');state['mode']=cfg.get('mode')
        state['daily_selected']=proxies.get('日常网络-自动恢复',{}).get('now')
        state['fixed_selected']=proxies.get('静态出口-自动恢复',{}).get('now')
        state['fixed_exit_blocked']=exit_blocked
        if exit_blocked:
            from repair_proxy import fail_closed
            fail_closed()
            if not old.get('fixed_exit_blocked'):
                log('fixed_exit_blocked',reason='Unexpected public exit; protected new and existing connections closed')
        # Let the core's 30s full-chain checks act first. Never repeatedly restart on an upstream outage.
        if daily_failures>=3 and start-float(state['last_reload'])>=600:
            payload=yaml.safe_load((ROOT/'clash-verge.yaml').read_text(encoding='utf-8'))
            groups={g['name']:g for g in payload.get('proxy-groups',[])}
            chains=configured_chains(payload)
            if len(chains)<2 or not all(p.get('dialer-proxy') and p.get('server')==EXPECTED_IP for p in chains):
                log('recovery_refused',reason='Fixed chain invariant missing; config preserved')
            elif '日常网络-自动恢复' not in groups or '静态出口-自动恢复' not in groups:
                log('recovery_refused',reason='Managed fallback groups missing; config preserved')
            else:
                payload['mode']=cfg['mode'];payload.setdefault('tun',{})['enable']=bool(state['tun'])
                code,_=api('/configs?force=true','PUT',{'payload':yaml.safe_dump(payload,allow_unicode=True,sort_keys=False)})
                if exit_blocked:
                    from repair_proxy import fail_closed
                    fail_closed()
                state['last_reload']=start;state['both_failed_count']=0;state['daily_failed_count']=0
                log('automatic_full_reload',status=code,reason='Daily HTTPS path failed three consecutive checks after two independent probes per check',tun=state['tun'])
    except Exception as e:
        state['control_error']=type(e).__name__
    message=notice(old,state)
    if message:
        alert(*message);log('user_alert',title=message[0])
    keys=['network_status','daily_ok','fixed_ok','fixed_exit_blocked','fixed_failed_count','fixed_success_count','fixed_recovering','daily_selected','fixed_selected','tun','mode','control_error']
    if any(old.get(k)!=state.get(k) for k in keys) or start-float(state['last_heartbeat'])>600:
        log('health',**{k:state.get(k) for k in keys},fixed_ip=state['fixed_ip'],failures=failures,daily=daily,fixed=fixed)
        state['last_heartbeat']=start
    write_state(state)
    return state
def main():
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_bool,ctypes.c_wchar_p];kernel.CreateMutexW.restype=ctypes.c_void_p
    handle=kernel.CreateMutexW(None,False,'Local\\ClashNetworkHealth-example')
    if not handle or ctypes.get_last_error()==183:return
    try:
        if '--once' in sys.argv:
            print(json.dumps(check_once(),ensure_ascii=False));return
        log('monitor_start',pid=os.getpid(),interval=30,consecutive_failure_threshold=3,reload_cooldown_seconds=600)
        threading.Thread(target=stream,daemon=True).start()
        while True:
            try:check_once()
            except Exception as e:log('monitor_error',error=type(e).__name__)
            time.sleep(30)
    finally:
        kernel.CloseHandle.argtypes=[ctypes.c_void_p];kernel.CloseHandle(handle)
if __name__=='__main__':main()
