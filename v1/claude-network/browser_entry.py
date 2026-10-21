"""Domain-independent browser entry. Never log URLs, tokens, or page contents."""
import datetime,json,os,pathlib,subprocess,sys,urllib.parse
from network_check import fixed_ready
from repair_support import atomic

HERE=pathlib.Path(__file__).resolve().parent
CHROME=pathlib.Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe')
PROFILE=pathlib.Path(os.environ.get('LOCALAPPDATA', str(pathlib.Path.home() / 'AppData/Local')))/'ClaudeNetwork/ChromeData'
FLAGS=['--proxy-server=http://127.0.0.1:17892',
       '--proxy-bypass-list=localhost;127.0.0.1;[::1]',
       '--webrtc-ip-handling-policy=disable_non_proxied_udp','--disable-quic',
       '--disable-features=MediaRouter']

def valid_url(url):
    if not isinstance(url,str) or not url or len(url)>32700 or any(ord(c)<32 or c in '\\"<>' for c in url):
        raise ValueError('Invalid URL')
    target=urllib.parse.urlsplit(url)
    if target.scheme not in ('http','https') or not target.hostname or target.username or target.password:
        raise ValueError('Expected an HTTP(S) URL without embedded credentials')
    return url

def runtime(include_connections=False):
    # Return only process IDs and the managed switches, never browser URLs or titles.
    script=r'''[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
    $items=@(Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" | Where-Object {$_.CommandLine -notmatch '--type=' -and $_.CommandLine -match 'ClaudeNetwork[\\/]ChromeData'} | ForEach-Object {
      $c=$_.CommandLine
      @{pid=$_.ProcessId;proxy_ok=($c -match '--proxy-server=http://127\.0\.0\.1:17892(?:["\s]|$)');bypass_ok=($c -match [regex]::Escape('--proxy-bypass-list=localhost;127.0.0.1;[::1]'));quic_off=($c -match '--disable-quic');webrtc_restricted=($c -match '--webrtc-ip-handling-policy=disable_non_proxied_udp');media_router_disabled=($c -match '--disable-features=(?:[^"\s,]+,)*MediaRouter(?:,|["\s]|$)')}
    })
    $connections=@()
    if (INCLUDE_CONNECTIONS -and $items.Count -gt 0) {
      $all=@(Get-CimInstance Win32_Process -Filter "Name='chrome.exe'")
      $owned=@($items.pid)
      for($i=0;$i -lt 5;$i++) {$owned=@($owned + @($all | Where-Object {$_.ParentProcessId -in $owned}).ProcessId | Sort-Object -Unique)}
      $connections=@(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {$_.OwningProcess -in $owned} | ForEach-Object {
        @{source_port=$_.LocalPort;entry_port=$_.RemotePort;loopback=($_.RemoteAddress -in @('127.0.0.1','::1'))}
      })
    }
    @{items=$items;connections=$connections}|ConvertTo-Json -Depth 5 -Compress'''.replace('INCLUDE_CONNECTIONS','$true' if include_connections else '$false')
    result=subprocess.run([os.environ['SystemRoot']+r'\System32\WindowsPowerShell\v1.0\powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,encoding='utf8',timeout=10,creationflags=0x08000000)
    if result.returncode:raise RuntimeError('Browser process inspection failed')
    data=json.loads(result.stdout.lstrip('\ufeff'));items=data['items']
    # Read the effective (last) disable-features switch, not a substring from
    # an earlier duplicate switch. Raw command lines never enter the report.
    from audit_proxy import browser_media_router_disabled
    import psutil
    for process in items:
        process['media_router_disabled']=browser_media_router_disabled(psutil.Process(process['pid']).cmdline())
    return {'running':bool(items),'processes':items,'connections':data['connections'],'flags_ok':all(all(p.get(k) for k in ['proxy_ok','bypass_ok','quic_off','webrtc_restricted','media_router_disabled']) for p in items) if items else None}

def browser_preflight():
    check=fixed_ready()
    if not check['ready']:return {'state':'blocked','reason':'fixed_exit_unavailable','check':check}
    current=runtime()
    if current['running'] and current['flags_ok'] is not True:return {'state':'blocked','reason':'existing_browser_flags_conflict'}
    if not CHROME.is_file():return {'state':'blocked','reason':'chrome_missing'}
    from audit_browser import browser_audit
    from audit_proxy import load_policy
    policy=load_policy()
    results=browser_audit(policy['entry_port'],policy['expected_ip'],include_dns=False)
    required={row['id']:row for row in results if row.get('required')}
    expected={'browser_fixed_exit','browser_webrtc'}
    if set(required)!=expected or any(required[name]['status']!='pass' for name in expected):
        return {'state':'blocked','reason':'browser_protection_unverified','check':check,'browser_checks':results}
    return {'state':'ready','check':check,'browser_checks':results}

def launch(url):
    valid_url(url)
    check=browser_preflight()
    if check['state']!='ready':return check
    PROFILE.mkdir(parents=True,exist_ok=True)
    subprocess.Popen([str(CHROME),'--user-data-dir='+str(PROFILE),*FLAGS,'--no-first-run','--no-default-browser-check','--new-window',url],creationflags=0x08000000,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    return {'state':'opened','check':check}

def main():
    try:result=browser_preflight() if '--check-only' in sys.argv else launch(sys.stdin.read(32768))
    except Exception as error:result={'state':'blocked','reason':type(error).__name__}
    result['time']=datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).isoformat()
    if '--check-only' in sys.argv:print(json.dumps(result,ensure_ascii=False,indent=2))
    else:atomic(HERE/'browser-entry-status.json',json.dumps(result,ensure_ascii=False).encode())
    return 0 if result['state'] in ('opened','ready') else 2

if __name__=='__main__':raise SystemExit(main())
