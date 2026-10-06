"""TLS connection routing evidence for arbitrary hosts; no account endpoints."""
import concurrent.futures,json,pathlib,socket,ssl,subprocess,sys
from browser_entry import runtime

def api(path):
    p=subprocess.run([sys.executable,'-X','utf8','-B',str(pathlib.Path(__file__).with_name('repair_proxy.py')),'--rpc'],input=json.dumps([path,'GET',None]),capture_output=True,text=True,encoding='utf8',timeout=12,creationflags=0x08000000)
    if p.returncode:raise RuntimeError('Controller unavailable')
    status,body=json.loads(p.stdout)
    if status!=200:raise RuntimeError('Controller response failed')
    return body

def route(host,port=17892):
    connection=None
    try:
        connection=socket.create_connection(('127.0.0.1',port),timeout=6)
        connection.settimeout(8)
        connection.sendall(('CONNECT '+host+':443 HTTP/1.1\r\nHost: '+host+':443\r\n\r\n').encode('ascii'))
        response=b''
        while b'\r\n\r\n' not in response:
            chunk=connection.recv(1)
            if not chunk or len(response)>8192:raise RuntimeError('CONNECT failed')
            response+=chunk
        if response.split(b' ')[1]!=b'200':raise RuntimeError('CONNECT rejected')
        connection=ssl.create_default_context().wrap_socket(connection,server_hostname=host)
        source_port=str(connection.getsockname()[1])
        rows=[c for c in api('/connections').get('connections',[]) if str(c.get('metadata',{}).get('sourcePort'))==source_port]
        chains=[c.get('chains',[]) for c in rows]
        ok=bool(chains) and all('Claude-固定出口' in chain and '静态出口-自动恢复' in chain and 'DIRECT' not in chain and '日常网络-自动恢复' not in chain for chain in chains)
        return {'host':host,'entry':port,'ok':ok,'chains':chains}
    except Exception as error:return {'host':host,'entry':port,'ok':False,'error':type(error).__name__}
    finally:
        if connection:connection.close()

def verify():
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures=[pool.submit(route,host) for host in ['clau.de','example.com']]
        browser=pool.submit(runtime,True)
        routes=[f.result() for f in futures]
        state=browser.result()
    connections=state['connections']
    state['unexpected_tcp_count']=sum(not c['loopback'] or c['entry_port']==7892 for c in connections)
    ports={str(c['source_port']) for c in connections if c['loopback'] and c['entry_port']==17892}
    chains=[c.get('chains',[]) for c in api('/connections').get('connections',[]) if str(c.get('metadata',{}).get('sourcePort')) in ports]
    # No hostnames, URLs or browser history are retained in the regular check.
    state['observed_chains']=chains
    state['connection_check']='observed' if chains else 'idle_or_not_observed'
    state['route_ok']=(state['unexpected_tcp_count']==0 and all('Claude-固定出口' in chain and '静态出口-自动恢复' in chain for chain in chains)) if chains else None
    no_observed_violation=(not state['running'] or state['flags_ok'] is True) and state['unexpected_tcp_count']==0 and state['route_ok'] is not False
    return {'ok':all(r['ok'] for r in routes) and no_observed_violation,'scope':'synthetic_routes_and_observed_browser_only','routes':routes,'browser':state}

if __name__=='__main__':
    result=verify();print(json.dumps(result,ensure_ascii=False,indent=2));raise SystemExit(0 if result['ok'] else 20)
