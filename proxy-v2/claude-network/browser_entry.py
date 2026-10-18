"""Login-link entry: hand the URL to CCBaga Proxy's fingerprint browser only when the fixed exit checks pass.

Never logs URLs, tokens or page contents. ClaudeBrowser.exe passes the URL on stdin. CCBaga Proxy
records its own program in ENTRY at every start; its --browser entry runs its own fixed-exit gate
and opens the URL in the current identity's fingerprint browser profile.
"""
import datetime,json,os,pathlib,subprocess,sys,urllib.parse
from repair_support import atomic

HERE=pathlib.Path(__file__).resolve().parent
ENTRY=pathlib.Path(os.environ.get('APPDATA',str(pathlib.Path.home()/'AppData/Roaming')))/'local.proxy.ccbaga/browser-entry.json'
PROGRAM='requirement-french.exe'

def valid_url(url):
    if not isinstance(url,str) or not url or len(url)>32700 or any(ord(c)<32 or c in '\\"<>' for c in url):
        raise ValueError('Invalid URL')
    target=urllib.parse.urlsplit(url)
    if target.scheme not in ('http','https') or not target.hostname or target.username or target.password:
        raise ValueError('Expected an HTTP(S) URL without embedded credentials')
    return url

def program():
    """CCBaga Proxy's recorded program, or None: an absolute path to its own executable that exists."""
    try:data=json.loads(ENTRY.read_text(encoding='utf-8'))
    except (OSError,ValueError):return None
    value=data.get('program') if isinstance(data,dict) and data.get('schema')==1 else None
    if not isinstance(value,str):return None
    path=pathlib.Path(value)
    return path if path.is_absolute() and path.name.lower()==PROGRAM and path.is_file() else None

def gate():
    from check import run
    report=run('web')
    problems=[c['id'] for c in report['checks'] if c['ok'] is not True and 'web' in c['entries']]
    return {'state':'ready' if report['entries']['web']=='READY' else 'blocked','problems':problems,'report':report}

def launch(url):
    valid_url(url)
    result=gate()
    if result['state']!='ready':return result
    target=program()
    if target is None:return {'state':'blocked','problems':['entry']}
    # A running CCBaga Proxy receives the URL through its single-instance handoff; otherwise this starts it.
    subprocess.Popen([str(target),'--browser',url],creationflags=0x08000000,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    return {'state':'opened','problems':[]}

def main():
    check_only='--check-only' in sys.argv
    try:result=gate() if check_only else launch(sys.stdin.read(32768))
    except Exception as error:result={'state':'blocked','problems':[type(error).__name__]}
    if check_only:
        from check import display
        if 'report' in result:display(result['report'])
        else:print('检查没有完成：'+'、'.join(result['problems']))
    else:
        status={'state':result['state'],'problems':result['problems'],'time':datetime.datetime.now().astimezone().isoformat(timespec='seconds')}
        atomic(HERE/'browser-entry-status.json',json.dumps(status,ensure_ascii=False).encode())
    return 0 if result['state'] in ('opened','ready') else 2

if __name__=='__main__':raise SystemExit(main())
