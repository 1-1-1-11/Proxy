// Offline UI fixture: no native actions, account data or external network.
import {createRoot} from 'react-dom/client';
import {mockIPC} from '@tauri-apps/api/mocks';
import {MotionRoot, TooltipProvider} from 'cromma-ui';
import {ProxyPanel} from '../src/proxy';
import {setLocale} from '../src/i18n';
import '../src/index.css';
import '../src/style.css';
type Mode = 'ready'|'blocked'|'error'|'stale'|'heartbeat-error'|'launch-race'|'recovering'|'warnings'|'chrome-broken';
let mode:Mode = 'ready', workspace = 'C:\\Fixture', timezone = 'Asia/Shanghai';
const measuredAt = Date.now();
let protection = 'protected';
const account = () => ({account:'person@example.invalid'});
const commands:{command:string; args:unknown}[] = [];
const busy:boolean[] = [], identity:boolean[] = [];
const wait = (ms:number) => new Promise(resolve => setTimeout(resolve, ms));
const report = () => ({schema:1, available:true, version:'offline-fixture', observed_at:Date.now(),
  checked_at:Date.now() - (mode === 'stale' ? 61_000 : 0), workspace,
  endpoint:'http://127.0.0.1:17892', expected_ip:'203.0.113.7', observed_ips:['203.0.113.7'],
  // 'recovering': the watchdog is alive but has not reported since sleep, so every entry waits.
  // 'warnings': launches pass, but a running CLI is off the fixed exit and Clash left Rule mode.
  // 'chrome-broken': Proxy-v2's login-link launcher fails; the web entry (fingerprint browser) does not depend on it.
  guard:{state:mode === 'blocked' ? 'blocked' : mode === 'recovering' ? 'unknown' : 'ready', age_seconds:mode === 'recovering' ? 900 : 3,
    blocked:mode === 'blocked', repair_active:false, recovering:mode === 'recovering',
    offchain:mode === 'warnings' ? 1 : 0, mode:mode === 'warnings' ? 'global' : 'rule', tun:true},
  entries:Object.fromEntries(['cli','vscode','web','desktop','browser'].map(entry =>
    [entry, mode === 'recovering' ? 'unknown' : mode === 'blocked' && entry === 'cli' ? 'blocked'
      : mode === 'chrome-broken' && entry === 'web' ? 'blocked' : 'ready'])),
  checks:[{id:'fixed_egress', title:'固定出口 IP',state:mode === 'blocked' ? 'blocked':'ready',entries:['cli','vscode','web','desktop']},
    {id:'guard',title:'使用中守护',state:mode === 'recovering' ? 'unknown' : 'ready',entries:['cli','vscode','web','desktop']},
    ...(mode === 'warnings' ? [{id:'traffic_cli',title:'CLI 连接',state:'blocked',entries:['cli']}] : []),
    ...(mode === 'chrome-broken' ? [{id:'web',title:'登录链接入口',state:'blocked',entries:['web']}] : [])],
  running:mode === 'warnings' ? {state:'blocked', entries:['cli']} : null,
  desktop_protection:protection,
});
mockIPC(async (command, args) => {
  commands.push({command,args});
  if (mode === 'error' && command === 'proxy_check') throw Error('fixture check failed');
  if (mode === 'heartbeat-error' && command === 'proxy_status') throw Error('fixture watchdog unavailable');
  if (command === 'proxy_status') return report();
  // Slow enough for the test to observe the screen while an action is pending.
  if (command === 'proxy_check') { await wait(400); return report(); }
  if (command === 'proxy_launch') { await wait(400); return {action:mode === 'launch-race' ? 'blocked' : 'requested', report:report()}; }
  if (command === 'proxy_repair_plan') return {token:'fixture-confirmation',effects:['调用现有 Proxy-v2 修复脚本，可能重启 Clash 和受保护应用。']};
  if (command === 'proxy_protect') { await wait(300); protection = 'protected'; return {action:'protected', report:report()}; }
  if (command === 'proxy_repair') { await wait(400); return {action:'repaired',report:report()}; }
  if (command === 'proxy_workspace_choose') { workspace = 'D:\\Projects\\demo'; return workspace; }
  if (command === 'proxy_exit_region') return {country:'US', timezone:'America/Los_Angeles', region:'us-west', label:'美国 · 洛杉矶'};
  if (command === 'proxy_account') return account();
  if (command === 'system_read') return {timezone, location_enabled:false};
  // The fingerprint browser already follows the exit; its start page measured before the computer was aligned.
  if (command === 'browser_read') return {running:true, config:{follow_machine:false, language:'en-US', timezone:'America/Los_Angeles'},
    machine:{timezone, languages:['zh-Hans']}, report:{language:'en-US', timezone:'America/Los_Angeles', exit:{country:'US'}, error:''},
    report_received_at:measuredAt};
  if (command === 'system_set_timezone') { await wait(200); timezone = (args as {timezone:string}).timezone; return {message:'时区已成功应用并核验。'}; }
  throw Error('Unexpected fixture command: '+command);
});
const root=createRoot(document.getElementById('fixture')!);
const render=(active:boolean)=>root.render(<MotionRoot><TooltipProvider><main className="app-shell"><aside className="app-sidebar"><div className="app-brand"><strong>CCBaga Proxy</strong></div><p style={{padding:16,fontSize:12}}>离线界面验收<br/>Offline test fixture</p></aside><div className="workspace cleaner-slot"><ProxyPanel active={active} onBusy={value=>busy.push(value)} onIdentity={()=>identity.push(true)}/></div></main></TooltipProvider></MotionRoot>);
render(true);
Object.assign(window,{proxyFixture:{commands,busy,identity,mode:(next:Mode)=>{mode=next;},protection:(next:string)=>{protection=next;},active:render,language:setLocale,unmount:()=>root.unmount()}});
