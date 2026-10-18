"""Offline-capable, idempotent repair of this workstation's Claude proxy.

Credentials stay in existing Clash files or Windows DPAPI snapshots. Controller
operations run in bounded subprocesses, so an unresponsive pipe cannot hang this
command indefinitely. No account/model request is made.
"""
import argparse,concurrent.futures,copy,datetime,importlib.util,json,os,pathlib,subprocess,sys,time,urllib.parse
import yaml
from repair_support import Changes,SingleInstance,atomic,protect,raw_api
from network_check import EXPECTED_IP,checked,probe

HERE=pathlib.Path(__file__).resolve().parent
USER=pathlib.Path.home()
# BROWSER always names the installed launcher, wherever this file runs from.
INSTALL=USER/'.codex/ClaudeNetwork'
ROOT=USER/'AppData/Roaming/io.github.clash-verge-rev.clash-verge-rev'
GUARD=USER/'.codex/CodexNetworkGuard'
NODE=pathlib.Path(r'C:\Program Files\nodejs\node.exe')
PS=pathlib.Path(os.environ['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe'
APP=pathlib.Path(r'C:\Tools\ClashVerge\clash-verge.exe')
CORE=APP.with_name('verge-mihomo.exe')
PROFILE='example-profile';SCRIPT='example-script';PREPEND='example-prepend'
PROVIDER='固定出口链路';FIXED='静态出口-自动恢复';DAILY='日常网络-自动恢复'
FRONTS=['Example-JP-HY2','Example-KR-HY2','Example-SG-A','Example-US-A']
# Same order as chainPreferred in routing-baseline.js: first hop of the fixed exit chains.
CHAIN_FRONTS=['Example-KR-HY2','Example-JP-HY2','Example-SG-A','Example-US-A']
SELECT={'Claude-固定出口':FIXED,'Google-固定出口':FIXED,'X-固定出口':FIXED,'OpenAI-日常代理':DAILY,'节点选择':DAILY,'自动选择':DAILY,'ChatGPT':DAILY,'Gemini':FIXED,'Twitter':FIXED,'谷歌服务':FIXED}
VALUES={k:'http://127.0.0.1:17892' for k in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']}
VALUES.update(NO_PROXY='localhost,127.0.0.1,::1',no_proxy='localhost,127.0.0.1,::1')
VALUES['BROWSER']=str(INSTALL/'ClaudeBrowser.exe')
PROTECTED=['Claude-固定出口','Google-固定出口','X-固定出口']
VERIFY_PORT=17893
JST=datetime.timezone(datetime.timedelta(hours=9))

class RepairError(Exception):
    def __init__(self,message,code=30):super().__init__(message);self.code=code

def say(text):print(text,flush=True)
def run(command,input=None,timeout=20):
    return subprocess.run([str(x) for x in command],input=input,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout,creationflags=0x08000000)
def ps(script,timeout=20):
    p=run([PS,'-NoLogo','-NoProfile','-NonInteractive','-Command',"[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"+script],timeout=timeout)
    if p.returncode:raise RepairError('Windows 操作未成功；已隐藏可能包含敏感信息的原始输出。')
    return p.stdout.lstrip('\ufeff')
def api(path,method='GET',data=None,timeout=16):
    p=run([sys.executable,'-X','utf8','-B',__file__,'--rpc'],json.dumps([path,method,data],ensure_ascii=False),timeout)
    if p.returncode:raise RepairError('Clash 控制接口暂不可用。')
    return json.loads(p.stdout)
def load_yaml(path):return yaml.safe_load(pathlib.Path(path).read_text(encoding='utf-8-sig')) or {}
def dump_yaml(value):return yaml.safe_dump(value,allow_unicode=True,sort_keys=False).encode('utf-8')
def render(cfg):
    js=(HERE/'routing-baseline.js').read_text(encoding='utf-8')
    runner=js+'\nprocess.stdout.write(JSON.stringify(main(JSON.parse(require("fs").readFileSync(0,"utf8")))));'
    p=run([NODE,'-e',runner],json.dumps(cfg,ensure_ascii=False))
    if p.returncode:raise RepairError('固定出口规则生成失败，原始配置内容未输出。')
    return json.loads(p.stdout)
def safe_node(n):return isinstance(n,dict) and n.get('type')=='socks5' and n.get('server')==EXPECTED_IP and n.get('port')==443 and bool(n.get('username')) and bool(n.get('password'))
def source_node(cfg):
    nodes=list(cfg.get('proxies',[]))+cfg.get('proxy-providers',{}).get(PROVIDER,{}).get('payload',[])
    return next((copy.deepcopy(n) for n in nodes if n.get('name')=='静态IP-链式' and safe_node(n)),None)
def equivalent_yaml(path,value):
    try:return load_yaml(path)==value
    except Exception:return False
def render_settings(text,kind,always=False):
    request={'text':text,'kind':kind,'values':VALUES,'always':always}
    p=run([NODE,HERE/'repair_jsonc.cjs'],json.dumps(request,ensure_ascii=False))
    if p.returncode:raise RepairError('设置文件解析工具运行失败；文件保持原样。')
    result=json.loads(p.stdout)
    if not result.get('ok'):raise RepairError('设置文件格式有误；为保留原数据，未覆盖该文件。')
    return result

def settings_plan(workspace):
    paths={(USER/'.claude/settings.json'):('claude',True)}
    local=USER/'.claude/settings.local.json'
    if local.exists():paths[local]=('claude',False)
    vscode=USER/'AppData/Roaming/Code/User'
    for p in [vscode/'settings.json',*vscode.glob('profiles/*/settings.json')]:
        if p.exists() or p==vscode/'settings.json':paths[p]=('vscode',True)
    if workspace:
        w=pathlib.Path(workspace).resolve()
        if not w.is_dir():raise RepairError('Workspace 必须是本机的项目目录。')
        for base in [w,*w.parents]:
            for relative,kind in [('.claude/settings.json','claude'),('.claude/settings.local.json','claude'),('.vscode/settings.json','vscode')]:
                p=base/relative
                if p.exists():paths[p]=(kind,p==USER/'.claude/settings.json')
    plan={}
    for p,(kind,always) in paths.items():
        text=p.read_text(encoding='utf-8-sig') if p.exists() else '{}\n'
        result=render_settings(text,kind,always)
        if result['changes']:plan[p]=result['text'].encode('utf-8')
    managed=pathlib.Path(os.environ.get('ProgramData',r'C:\ProgramData'))/'ClaudeCode/managed-settings.json'
    if managed.exists() and render_settings(managed.read_text(encoding='utf-8-sig'),'claude')['changes']:
        raise RepairError('系统管理策略包含不同的代理设置；该命令不会擅自覆盖管理策略。',24)
    return plan
def build_candidate():
    profiles=load_yaml(ROOT/'profiles.yaml');items={x['uid']:x for x in profiles.get('items',[])}
    if not all(k in items for k in [PROFILE,SCRIPT,PREPEND]):raise RepairError('已验证订阅或脚本记录缺失，无法安全猜测其他订阅。',23)
    baseline=yaml.safe_load(protect((HERE/'repair-baseline.dpapi').read_bytes(),True))
    try:current=load_yaml(ROOT/'clash-verge.yaml')
    except Exception:current=copy.deepcopy(baseline)
    if not isinstance(current,dict):current=copy.deepcopy(baseline)
    preload=load_yaml(ROOT/'profiles'/items[PREPEND]['file'])
    node=next((copy.deepcopy(n) for n in preload.get('prepend',[])+preload.get('append',[]) if safe_node(n)),None)
    node=node or source_node(current) or source_node(baseline)
    if not node:raise RepairError('本机没有可恢复的固定出口凭据。',23)
    node.update(name='静态IP-链式',udp=False)
    raw=load_yaml(ROOT/'profiles'/items[PROFILE]['file'])
    fresh={p['name']:p for p in raw.get('proxies',[]) if p.get('name') in FRONTS}
    if not fresh:raise RepairError('当前订阅中找不到已验证的前置节点；没有切换到其他出口。',23)
    cfg=copy.deepcopy(current)
    existing=cfg.get('proxies',[])
    cfg['proxies']=[copy.deepcopy(fresh.get(n.get('name'),n)) for n in existing if n.get('name')!='静态IP-链式' and (n.get('name') not in FRONTS or n.get('name') in fresh)]
    present={n.get('name') for n in cfg['proxies']}
    cfg['proxies'] += [copy.deepcopy(n) for name,n in fresh.items() if name not in present]+[node]
    cfg=render(cfg);cfg['mixed-port']=7892
    verge=load_yaml(ROOT/'verge.yaml')
    cfg.setdefault('tun',{})['enable']=bool(verge.get('enable_tun_mode',current.get('tun',{}).get('enable',False)))
    chains=cfg.get('proxy-providers',{}).get(PROVIDER,{}).get('payload',[])
    if not chains or not all(safe_node(p) and p.get('dialer-proxy') in fresh for p in chains):raise RepairError('候选配置未通过固定出口约束检查。')
    if render(cfg)!=cfg:raise RepairError('规则生成不满足重复运行一致性检查。')
    plan={}
    script=ROOT/'profiles'/items[SCRIPT]['file'];wanted_script=(HERE/'routing-baseline.js').read_bytes()
    if not script.exists() or script.read_bytes()!=wanted_script:plan[script]=wanted_script
    profiles['current']=PROFILE
    items[PROFILE].setdefault('option',{}).update(script=SCRIPT,proxies=PREPEND)
    selected=items[PROFILE].setdefault('selected',[]);known={s.get('name'):s for s in selected}
    for name,target in SELECT.items():
        if name in known:known[name]['now']=target
        else:selected.append({'name':name,'now':target})
    if not equivalent_yaml(ROOT/'profiles.yaml',profiles):plan[ROOT/'profiles.yaml']=dump_yaml(profiles)
    # Restore the credential source too, so subsequent app regeneration remains correct.
    preload['prepend']=[n for n in preload.get('prepend',[]) if n.get('name')!='静态IP-链式']+[dict(node,**{'dialer-proxy':next(name for name in CHAIN_FRONTS if name in fresh)})]
    preload['append']=[n for n in preload.get('append',[]) if n.get('name')!='静态IP-链式']
    if not equivalent_yaml(ROOT/'profiles'/items[PREPEND]['file'],preload):plan[ROOT/'profiles'/items[PREPEND]['file']]=dump_yaml(preload)
    base=load_yaml(ROOT/'config.yaml');base.update(mode='rule',**{'mixed-port':7892})
    if not equivalent_yaml(ROOT/'config.yaml',base):plan[ROOT/'config.yaml']=dump_yaml(base)
    if not equivalent_yaml(ROOT/'clash-verge.yaml',cfg):plan[ROOT/'clash-verge.yaml']=dump_yaml(cfg)
    return cfg,plan
def physical_network():
    spec=importlib.util.spec_from_file_location('existing_network_health',GUARD/'health_monitor.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module.physical_network()
def health():
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures=[pool.submit(checked,7892),pool.submit(probe,17892),pool.submit(probe,17892,'https://api.ipify.org?format=json')]
        results=[f.result() for f in futures]
    fixed=results[1:]
    return {'daily':results[0],'fixed':fixed,'daily_ok':results[0]['curl_exit']==0,
            'fixed_ok':any(p['curl_exit']==0 and p.get('ip')==EXPECTED_IP for p in fixed) and not any(p.get('ip') and p['ip']!=EXPECTED_IP for p in fixed),
            'wrong_exit':any(p.get('ip') and p['ip']!=EXPECTED_IP for p in fixed)}
def inspect_live(cfg):
    current=api('/configs')[1];groups=api('/proxies')[1]['proxies']
    status,provider=api('/providers/proxies/'+urllib.parse.quote(PROVIDER,safe=''))
    expected=cfg['proxy-providers'][PROVIDER]['payload']
    observed={n['name']:n for n in (provider or {}).get('proxies',[])} if status==200 else {}
    mismatch=current.get('mixed-port')!=7892 or current.get('mode')!='rule' or any(observed.get(n['name'],{}).get('dialer-proxy')!=n['dialer-proxy'] for n in expected)
    wrong_groups=[n for n,target in SELECT.items() if n in groups and groups[n].get('now')!=target]
    for n in ['Claude-固定出口','Google-固定出口','X-固定出口','OpenAI-日常代理']:
        if n not in groups:mismatch=True
    return {'config_drift':mismatch,'wrong_groups':wrong_groups,'tun':current.get('tun',{}).get('enable')}
def put_config(cfg):
    code,_=api('/configs?force=true','PUT',{'payload':yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False)})
    if code!=204:raise RepairError('Clash 拒绝新配置，未忽略该错误。')
def verify_exit():
    # The verify listener reaches the fixed chain directly, so the exit is known before Claude is reopened.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda url:probe(VERIFY_PORT,url),['https://www.cloudflare.com/cdn-cgi/trace','https://api.ipify.org?format=json']))
    return {'probes':results,'ok':all(p['curl_exit']==0 and p.get('ip')==EXPECTED_IP for p in results),
            'wrong_exit':any(p.get('ip') and p['ip']!=EXPECTED_IP for p in results)}
def protected_closed():
    # Closed now (guard block or REJECT) means it must stay closed until verify_exit passes.
    try:
        if json.loads((GUARD/'network-state.json').read_text(encoding='utf-8')).get('fixed_exit_blocked'):return True
    except (OSError,ValueError,AttributeError):pass
    try:
        groups=api('/proxies')[1]['proxies']
        return any(groups.get(name,{}).get('now')=='REJECT' for name in PROTECTED)
    except Exception:return False
def select_groups(protected=True):
    groups=api('/proxies')[1]['proxies'];changed=[]
    for name,target in SELECT.items():
        if not protected and name in PROTECTED:continue
        if name in groups and groups[name].get('now')!=target:
            code,_=api('/proxies/'+urllib.parse.quote(name,safe=''),'PUT',{'name':target})
            if code!=204:raise RepairError('Clash 未接受受管理代理组的选择。')
            changed.append(name)
    return changed
def warmup():
    for path in ['/group/'+urllib.parse.quote(DAILY,safe='')+'/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=4000','/providers/proxies/'+urllib.parse.quote(PROVIDER,safe='')+'/healthcheck']:
        try:api(path)
        except Exception:pass
def launch_app(restart=False):
    script="$ErrorActionPreference='Stop';"
    if restart:
        script+="$targets=@(Get-Process -Name 'clash-verge' -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq 'C:\\Tools\\ClashVerge\\clash-verge.exe'}); foreach($target in $targets) {Stop-Process -Id $target.Id -ErrorAction Stop; if(-not $target.WaitForExit(10000)) {throw 'Clash GUI did not stop'}};"
    script+="if(-not (Get-Process -Name 'clash-verge' -ErrorAction SilentlyContinue)) {Start-Process -FilePath 'C:\\Tools\\ClashVerge\\clash-verge.exe' -WindowStyle Hidden}"
    ps(script)
    # Do not mistake the old service core for completion of a fresh GUI startup.
    time.sleep(3)
    for _ in range(8):
        try:
            if app_running() and api('/version',timeout=4)[0]==200:return
        except Exception:pass
        time.sleep(2)
    raise RepairError('Clash 启动后控制接口仍不可用；请查看 Clash 启动错误。',21)
def app_running():
    return ps("[bool](Get-Process -Name 'clash-verge' -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq 'C:\\Tools\\ClashVerge\\clash-verge.exe'})").strip().lower()=='true'
def fail_closed():
    protected=PROTECTED
    for name in protected:
        code,_=api('/proxies/'+urllib.parse.quote(name,safe=''),'PUT',{'name':'REJECT'})
        if code!=204:raise RepairError('发现出口变化，但未能确认封锁受保护通道；请停止使用 Claude。',22)
    status,body=api('/connections')
    if status!=200:raise RepairError('已阻止新请求，但无法确认旧连接已关闭。',22)
    for connection in body.get('connections',[]):
        if set(protected).intersection(connection.get('chains',[])):
            code,_=api('/connections/'+urllib.parse.quote(connection['id'],safe=''),'DELETE')
            if code not in (204,404):raise RepairError('已阻止新请求，但部分旧连接未能关闭。',22)

def execute(args):
    result={'time':datetime.datetime.now(JST).isoformat(),'expected_ip':EXPECTED_IP,'changed_files':[]}
    changes=Changes(HERE/'repair-backups'/datetime.datetime.now(JST).strftime('%Y%m%d-%H%M%S'))
    with SingleInstance():
        active=GUARD/'repair-active.json'
        atomic(active,json.dumps({'pid':os.getpid(),'expires':time.time()+300}).encode())
        try:
            say('[1/4] 检查本机 Claude / VS Code 代理设置和 Clash 持久配置……')
            setting_changes=settings_plan(args.workspace);cfg,clash_changes=build_candidate()
            result['drift_files']=[str(p) for p in [*setting_changes,*clash_changes]]
            for p in result['drift_files']:say('  发现需校正的配置：'+p)
            physical=physical_network();result['physical']=physical
            try:live=inspect_live(cfg)
            except Exception:live={'unavailable':True}
            result['live_before']=live
            was_closed=protected_closed();result['protected_closed_before']=was_closed
            for p,data in setting_changes.items():changes.write(p,data)
            if clash_changes:
                say('[2/4] 保存加密恢复副本，恢复规则并验证 Clash 配置……')
                for p,data in clash_changes.items():changes.write(p,data)
                try:validation=run([CORE,'-t','-d',ROOT,'-f',ROOT/'clash-verge.yaml'],timeout=20)
                except Exception:
                    changes.restore_existing();raise RepairError('候选配置校验未完成；本次改动的原有文件已恢复。')
                if validation.returncode:
                    changes.restore_existing();raise RepairError('候选配置校验失败；本次改动的原有文件已恢复。')
                # Refresh the GUI's in-memory model as well, preventing a later GUI action
                # from writing its obsolete configuration over the repaired file.
                launch_app(restart=True)
            elif live.get('unavailable'):
                say('[2/4] 重新启动本机 Clash……');launch_app(restart=True)
            elif not app_running():
                say('[2/4] 启动 Clash 应用界面及配置管理……');launch_app()
            else:say('[2/4] 持久代理规则正确，无需重启 Clash。')
            current=inspect_live(cfg)
            if current.get('config_drift'):put_config(cfg)
            # A restart or reload may restore a saved selection; a closed group stays closed until verified.
            if was_closed:fail_closed()
            result['groups_corrected']=select_groups(protected=False)
            result['changed_files']=[str(p) for p in changes.before]
            result['backup_dir']=str(changes.folder) if changes.before else None
            if physical.get('ready') is False:
                say('Wi-Fi / 网线尚未连接。已修正本地配置；不会用重载代理代替物理联网。')
                return finish(result,10)
            say('[3/4] 先在检查专用端口核对固定出口，确认无误后才放行 Claude……')
            warmup();verified=verify_exit()
            if not verified['ok'] and not verified['wrong_exit']:
                # One bounded reload is allowed, not an unending reset/retry loop.
                say('首次核对未通过，执行一次配置重载和完整链路复测……')
                put_config(cfg)
                if was_closed:fail_closed()
                select_groups(protected=False);warmup();verified=verify_exit()
            result['verify']=verified
            if verified['wrong_exit']:
                fail_closed();result['health']=health();return finish(result,22)
            if not verified['ok']:
                # Exit unknown: protected groups are not reopened by this repair.
                result['health']=health();return finish(result,20)
            result['groups_corrected']+=select_groups()
            status=health()
            if status['wrong_exit']:fail_closed()
            result['health']=status
            result['live_after']=inspect_live(cfg)
            result['app_running']=app_running()
            code=22 if status['wrong_exit'] else (0 if result['app_running'] and status['daily_ok'] and status['fixed_ok'] and not result['live_after']['config_drift'] and not result['live_after']['wrong_groups'] else 20)
            return finish(result,code)
        except RepairError as e:
            result['error']=str(e);result['changed_files']=[str(p) for p in changes.before]
            return finish(result,e.code)
        except Exception as e:
            # Do not print arbitrary exception strings: parsed config can contain credentials.
            result['error_type']=type(e).__name__;result['changed_files']=[str(p) for p in changes.before]
            return finish(result,30)
        finally:
            atomic(active,b'{"expires":0}')
def finish(result,code):
    result['exit_code']=code
    atomic(HERE/'repair-last-result.json',json.dumps(result,ensure_ascii=False,indent=2).encode('utf-8'))
    if code==0:
        say('[4/4] PASS：日常网络可用；Claude 专用入口 127.0.0.1:17892 可用，出口为 '+EXPECTED_IP+'。')
        say('这是本机代理与出口验证，不代表已验证 Claude 登录或模型回答。')
    elif code==10:say('WAIT：没有已连接的物理网络。请恢复 Wi-Fi / 网线后再运行；无需手动修改代理规则。')
    elif code==20:say('FAIL：配置已检查，但外部链路仍未恢复。未改用其他公网出口；详见本地结果文件。')
    elif code==22:say('BLOCKED：实测固定出口不符合预期，已尝试阻断受保护通道；不要继续登录 Claude。')
    else:say('FAIL：'+result.get('error','检查未完成（'+result.get('error_type','unknown')+'）；未输出敏感配置。'))
    if result.get('changed_files') and any('.claude' in p or 'Code\\User' in p for p in result['changed_files']):
        say('Claude 设置已修正：已有 VS Code 会话请执行 Developer: Reload Window；终端 Claude 请重新启动。')
    say('结果文件：'+str(HERE/'repair-last-result.json'))
    return code
def main():
    if '--rpc' in sys.argv:
        try:print(json.dumps(raw_api(*json.load(sys.stdin)),ensure_ascii=True));return 0
        except Exception:return 1
    parser=argparse.ArgumentParser();parser.add_argument('--workspace')
    return execute(parser.parse_args())
if __name__=='__main__':raise SystemExit(main())
