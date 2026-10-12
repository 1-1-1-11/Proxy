"""Verified HTTPS proxy checks; no account requests or proxy mutations."""
import concurrent.futures,datetime,http.client,json,sys,time,urllib.parse
from pathlib import Path
# One non-secret policy source. Missing/invalid policy is an error, not a fallback.
_POLICY=json.loads(Path(__file__).with_name('audit_policy.json').read_text(encoding='utf-8-sig'))
EXPECTED_IP=_POLICY['expected_ip']
def probe(port,url='https://www.cloudflare.com/cdn-cgi/trace'):
    target=urllib.parse.urlsplit(url);conn=None;start=time.monotonic()
    try:
        conn=http.client.HTTPSConnection('127.0.0.1',port,timeout=6)
        conn.set_tunnel(target.hostname,443)
        path=(target.path or '/')+('?' + target.query if target.query else '')
        conn.request('GET',path,headers={'Connection':'close','User-Agent':'LocalNetworkHealth/1.0'})
        response=conn.getresponse();body=response.read(16384).decode('utf-8','replace')
        fields=json.loads(body) if target.hostname=='api.ipify.org' else dict(s.split('=',1) for s in body.splitlines() if '=' in s)
        ok=response.status==200 and bool(fields.get('ip'))
        return {'port':port,'curl_exit':0 if ok else 1,'http':response.status,'ip':fields.get('ip'),'country':fields.get('loc'),'seconds':round(time.monotonic()-start,2)}
    except Exception as exc:return {'port':port,'curl_exit':1,'ip':None,'error':type(exc).__name__,'seconds':round(time.monotonic()-start,2)}
    finally:
        if conn:conn.close()
def checked(port):
    result=probe(port)
    attempts=[dict(result,endpoint='www.cloudflare.com')]
    if result['curl_exit'] or not result.get('ip'):
        result=probe(port,'https://api.ipify.org?format=json')
        attempts.append(dict(result,endpoint='api.ipify.org'))
    # Keep the original failure when a second endpoint succeeds or also fails.
    # Only fixed public endpoints and structured results are recorded; no URLs or credentials.
    return dict(result,attempts=attempts)
def fixed_ready():
    from audit_proxy import preflight
    result=preflight(Path(__file__).parent)
    result['expected_ip']=EXPECTED_IP
    return result
def main():
    if '--fixed-only' in sys.argv:
        r=fixed_ready();print(json.dumps(r,ensure_ascii=False));return 0 if r['ready'] else 2
    from audit_proxy import collect,display
    result=collect(Path(__file__).parent)
    display(result)
    return result['exit_code']
if __name__=='__main__':raise SystemExit(main())
