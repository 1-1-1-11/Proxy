// [INPUT]: Sanitized Proxy-v2 summaries, typed native actions, the natively chosen CLI folder, exit region,
//          the current Claude account and the computer's time zone/location.
// [OUTPUT]: Home: can Claude be used, as whom, from where; launches (web = fingerprint browser), environment
//           alignment and explicit repair.
// [POS]: Presentation only; every launch is checked again by the native backend, so cached results only inform.
import {useEffect, useRef, useState, type ReactNode} from 'react';
import {invoke} from '@tauri-apps/api/core';
import {Button} from 'cromma-ui';
import {AppDialog} from './dialog';
import {useI18n} from './i18n';
import {alerts, canLaunch, entryVerdict, environment, failing, fresh, type BrowserView, type Computer, type Consistency, type Entry, type ExitRegion,
  type Protection, type ProxyReport, type ProxyStatus, type Verdict} from './proxy-state';
import './proxy.css';

const labels: Record<Entry, string> = {cli:'Claude CLI', browser:'网页版', desktop:'Claude 桌面客户端', vscode:'VS Code', web:'登录链接'};
const launches = ['cli', 'desktop', 'browser'] as const;
const words: Record<Verdict, string> = {ready:'已通过', blocked:'未通过', unknown:'待确认', not_installed:'未安装'};
type Plan = {token:string; effects:string[]};
type ActionResult = {action:string; report:ProxyReport; repair_exit?:number};
type Busy = '' | 'plan' | 'repair' | 'protect' | `launch:${Entry}`;
type Account = {account:string|null};

export function ProxyPanel({active = true, onBusy, onIdentity}:{active?:boolean; onBusy?:(busy:boolean)=>void; onIdentity?:()=>void}) {
  const {t, locale} = useI18n();
  const [status, setStatus] = useState<ProxyStatus|null>(null);
  const [report, setReport] = useState<ProxyReport|null>(null);
  const [error, setError] = useState(''), [statusError, setStatusError] = useState('');
  const [busy, setBusy] = useState<Busy>(''), [checking, setChecking] = useState(false);
  const [note, setNote] = useState<{text:string; values?:Record<string,string>}|null>(null);
  const [now, setNow] = useState(Date.now()), [plan, setPlan] = useState<Plan|null>(null);
  const [exit, setExit] = useState<ExitRegion|null>(null);
  const [who, setWho] = useState<Account|null>(null), [machine, setMachine] = useState<Computer|null>(null);
  const [browserView, setBrowserView] = useState<BrowserView|null>(null);
  const [adjusting, setAdjusting] = useState<''|'timezone'|'location'>('');
  const live = useRef(true), gate = useRef(false), auditing = useRef(false);
  const latest = useRef<ProxyReport|null>(null), attempted = useRef(0), located = useRef(false);
  // When the watchdog started recovering: after sleep it reports within a round; minutes means stuck.
  const recoveringSince = useRef<number|null>(null);
  useEffect(() => { recoveringSince.current = status?.guard.recovering ? recoveringSince.current ?? Date.now() : null; }, [status]);
  // Only a repair changes the machine for minutes; checks and launches keep navigation free.
  useEffect(() => { onBusy?.(busy === 'repair' || busy === 'protect'); return () => onBusy?.(false); }, [busy, onBusy]);
  // Launches return partial checks; the desktop protection state stays as last seen until a check says otherwise.
  const [protection, setProtection] = useState<Protection|null>(null), [protecting, setProtecting] = useState(false);
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  // Action results are momentary; the summary carries the lasting state.
  useEffect(() => { if (!note) return; const timer = window.setTimeout(() => setNote(null), 8000); return () => window.clearTimeout(timer); }, [note]);
  function accept(next: ProxyReport) {
    if (!live.current) return;
    latest.current = next;
    setReport(next);
    if (next.desktop_protection) setProtection(next.desktop_protection);
    setStatus(old => !old || next.observed_at >= old.observed_at ? next : old);
    setNow(Date.now());
    if (!located.current && next.checks.some(check => check.id === 'fixed_egress' && check.state === 'ready')) {
      located.current = true;
      void invoke<ExitRegion>('proxy_exit_region').then(value => {if (live.current) setExit(value);}).catch(() => {located.current = false;});
    }
  }
  // A check keeps the previous result on screen; the summary only changes when the answer does.
  async function check() {
    if (auditing.current) return;
    auditing.current = true; attempted.current = Date.now(); setChecking(true);
    try { accept(await invoke<ProxyReport>('proxy_check')); if (live.current) setError(''); }
    catch (e) { if (live.current) setError(String(e)); }
    finally { auditing.current = false; if (live.current) setChecking(false); }
  }
  async function run(kind: Exclude<Busy, ''>, token = '') {
    if (gate.current) return;
    gate.current = true; setBusy(kind); setError(''); setNote(null);
    try {
      if (kind === 'plan') {
        const next = await invoke<Plan>('proxy_repair_plan'); if (live.current) setPlan(next);
      } else if (kind === 'protect') {
        const result = await invoke<ActionResult>('proxy_protect');
        accept(result.report);
        if (live.current) result.action === 'protected' ? setNote({text:'客户端保护已设置并复查。'}) : setError('客户端保护没有完成（管理员确认被取消？），可以再试一次。');
      } else {
        const entry = kind === 'repair' ? null : kind.slice(7) as Entry;
        const result = await invoke<ActionResult>(entry ? 'proxy_launch' : 'proxy_repair', entry ? {entry} : {token});
        accept(result.report);
        if (live.current) {
          // The CLI opens a console that runs its own last check; only the console is certain here.
          if (result.action === 'requested' && entry === 'cli') setNote({text:'已打开 Claude CLI 控制台，在控制台中继续。'});
          else if (result.action === 'requested' && entry) setNote({text:'已启动 {name}。', values:{name:t(labels[entry])}});
          // The browser reports its measurement from its start page a few seconds after it opens.
          if (result.action === 'requested' && entry === 'browser') window.setTimeout(() => {if (live.current) void surroundings();}, 8000);
          else if (result.action === 'repaired') setNote({text:'修复完成，已重新检查。'});
          else setError(result.action === 'repair_failed' ? '修复未正常完成，请查看现有 Proxy-v2 的诊断结果。' : '启动前检查未通过，已停止启动。');
        }
      }
    } catch (e) { if (live.current) setError(String(e)); }
    finally { gate.current = false; if (live.current) setBusy(''); }
  }
  async function chooseWorkspace() {
    try {
      const chosen = await invoke<string|null>('proxy_workspace_choose');
      if (!chosen || !live.current) return;
      setStatus(old => old && {...old, workspace:chosen});
      void check();
    } catch (e) { if (live.current) setError(String(e)); }
  }
  // Account and computer can change on other pages or outside the app; reread them whenever home is shown.
  async function surroundings() {
    const [login, computer, browser] = await Promise.allSettled([invoke<Account>('proxy_account'), invoke<Computer>('system_read'), invoke<BrowserView>('browser_read')]);
    if (!live.current) return;
    setWho(login.status === 'fulfilled' ? login.value : null);
    setMachine(computer.status === 'fulfilled' ? computer.value : null);
    setBrowserView(browser.status === 'fulfilled' ? browser.value : null);
  }
  useEffect(() => { if (active) void surroundings(); }, [active]);
  async function adjust(kind: 'timezone'|'location') {
    if (adjusting) return;
    setAdjusting(kind); setNote(null); setError('');
    try {
      const result = await invoke<{message?:string}>(kind === 'timezone' ? 'system_set_timezone' : 'system_disable_location', kind === 'timezone' ? {timezone:exit?.timezone} : {});
      if (live.current && result.message) setNote({text:result.message});
    } catch (e) { if (live.current) setNote({text:String(e)}); }
    finally { if (live.current) setAdjusting(''); void surroundings(); }
  }
  // Heartbeat only while visible. An expired result refreshes itself when the user is looking.
  useEffect(() => {
    if (!active) return;
    let pending = false, stopped = false;
    const stale = () => !latest.current || Date.now() - latest.current.checked_at > 60_000 || Date.now() < latest.current.checked_at;
    const wake = (gap: number) => {
      if (!stopped && !gate.current && document.visibilityState !== 'hidden' && stale() && Date.now() - attempted.current > gap) void check();
    };
    const poll = async () => {
      if (pending) return; pending = true;
      try {
        const next = await invoke<ProxyStatus>('proxy_status');
        if (live.current) {setStatus(old => !old || next.observed_at >= old.observed_at ? next : old); setStatusError('');}
      } catch (e) {if (live.current) {setStatus(null); setStatusError(String(e));}}
      finally {pending = false;}
      if (document.hasFocus()) wake(60_000);
    };
    const focus = () => wake(5_000);
    void poll(); wake(0);
    const refresh = window.setInterval(() => void poll(), 5000);
    const clock = window.setInterval(() => setNow(Date.now()), 1000);
    window.addEventListener('focus', focus); document.addEventListener('visibilitychange', focus);
    return () => {
      stopped = true;
      window.clearInterval(refresh); window.clearInterval(clock);
      window.removeEventListener('focus', focus); document.removeEventListener('visibilitychange', focus);
    };
  }, [active]);
  const problem = error || statusError;
  const verdict = (entry: Entry) => entryVerdict(entry, report, status, now, problem);
  const current = fresh(report, status, now) && !problem;
  const shown = launches.map(verdict).filter(v => v !== 'not_installed');
  const overall = busy === 'repair' ? 'repairing' : shown.includes('blocked') ? 'blocked'
    : current && shown.length && shown.every(v => v === 'ready') ? 'ready' : checking || busy ? 'checking' : 'unknown';
  const join = (items: string[]) => items.map(item => t(item)).join(locale === 'zh' ? '、' : ', ');
  const problems = failing(report);
  const time = (at: number) => new Date(at).toLocaleTimeString(locale === 'zh' ? 'zh-CN' : 'en-US');
  const egressOk = current && !!report?.checks.some(check => check.id === 'fixed_egress' && check.state === 'ready');
  const guardFresh = !!status && now - status.observed_at <= 15_000 && now >= status.observed_at;
  const age = (at: number) => Math.max(0, Math.round((now - at) / 1000));
  const recovering = !!status?.guard.recovering;
  const stuck = recovering && recoveringSince.current !== null && now - recoveringSince.current > 120_000;
  const warn = alerts(report, status, now);
  const summary: [string, string, Record<string, string>?] = {
    ready: ['固定出口正常', '出口与指定 IP 一致，后台守护在运行。'],
    blocked: problems.length ? ['固定出口有问题，启动已暂停', '未通过：{items}', {items:join(problems)}] : ['固定出口有问题，启动已暂停', '展开下方检查项查看原因。'],
    repairing: ['正在修复 Proxy-v2…', '可能会重启 Clash 和相关应用，完成后自动重新检查。'],
    checking: ['正在检查固定出口…', '通常只需要几秒。'],
    unknown: recovering ? stuck ? ['后台守护长时间没有更新', '可能卡住了。重启电脑后再检查，或在 Proxy-v2 中运行检查。']
      : ['后台守护正在恢复', '刚从睡眠唤醒时常见，通常 30 秒内恢复；点「启动」会等它恢复后再检查。']
      : problem ? ['状态待确认', '检查没有完成。点“启动”或“重新检查”会再试一次。'] : report ? ['状态待确认', '上次检查 {time}。点“启动”时会自动重新检查。', {time:time(report.checked_at)}] : ['状态待确认', '还没有检查结果。'],
  }[overall] as [string, string, Record<string, string>?];
  const env = environment(exit, machine, browserView);
  const badge: Record<Consistency, [Verdict, string]> = {ok:['ready', '一致'], attention:['blocked', '不一致'], unknown:['unknown', '待确认']};
  const fact = (key: string, label: string, state: Consistency | null, value: string, detail = '', action: ReactNode = null) =>
    <div className={`proxy-entry${state === 'attention' ? ' proxy-attention' : ''}`} key={key}><div className="proxy-entry-main"><div><strong>{t(label)}</strong>{state && <span className={`proxy-badge proxy-${badge[state][0]}`}>{t(badge[state][1])}</span>}</div>
      <div className="proxy-workspace"><span>{value}</span>{detail && <small>{detail}</small>}</div></div>{action}</div>;
  const needsRepair = overall === 'blocked' || overall === 'repairing' || (current && shown.some(v => v !== 'ready'));
  return <section className="system-page proxy-page">
    <div className="cleanup-title"><div><h1>{t('使用 Claude')}</h1><p className="system-hint">{t('每次启动前都会确认走固定出口。')}</p></div><Button variant="secondary" size="small" disabled={checking || busy === 'repair'} loading={checking} onClick={() => {setNote(null); void check();}}>{t('重新检查')}</Button></div>
    <div className={`proxy-summary proxy-${overall}`} aria-live="polite" role="status"><span className="proxy-mark" aria-hidden="true">{overall === 'ready' ? '✓' : overall === 'blocked' ? '!' : '·'}</span><div><h2>{t(summary[0])}</h2><p>{t(summary[1], summary[2])}</p></div></div>
    {problem && <p role="alert" className="system-feedback error">{t(problem)}</p>}
    {note && <p role="status" className="system-feedback">{t(note.text, note.values)}</p>}
    {warn.running && <p role="alert" className="system-feedback error">{t('有正在运行的 Claude 程序连接没走固定出口（{items}）：关掉它，再从这里重新启动。', {items:join(warn.running.map(entry => labels[entry]))})}</p>}
    {warn.offchain && <p role="alert" className="system-feedback error">{t('守护发现有 Claude 程序的连接没走固定出口：关掉对应程序，再从这里重新启动。')}</p>}
    {warn.mode && <p role="status" className="system-feedback">{t('Clash 当前不在「规则」模式：普通浏览器里的 claude.ai 不走固定出口。网页版请从这里用指纹浏览器打开，或把 Clash 切回规则模式。')}</p>}
    <dl className="proxy-facts">
      <div><dt>{t('账号')}</dt><dd><strong>{who?.account || t(who ? '未登录' : '读取中…')}</strong></dd>{onIdentity && <Button variant="ghost" size="small" disabled={busy === 'repair'} onClick={onIdentity}>{t('切换')}</Button>}</div>
      <div><dt>{t('出口')}</dt><dd><strong>{current ? report?.observed_ips.join(' / ') || '—' : '—'}</strong><small>{egressOk ? exit?.label ? t('与指定出口一致 · {place}', {place:exit.label}) : t('与指定出口一致') : t('指定出口：{ip}', {ip:status?.expected_ip || '—'})}</small></dd></div>
      <div><dt>{t('最近检查')}</dt><dd><strong>{report ? time(report.checked_at) : '—'}</strong><small>{checking ? t('正在更新…') : current && report ? t('{n} 秒前', {n:String(age(report.checked_at))}) : report ? t('已过期，启动时会重新检查') : ' '}</small><small>{status?.guard.repair_active ? t('现有后端正在修复') : recovering ? t('后台守护正在恢复') : guardFresh && status!.guard.age_seconds !== null ? t('后台守护 {n} 秒前核对过出口', {n:String(Math.round(status!.guard.age_seconds))}) : t('后台守护状态待确认')}</small></dd></div>
    </dl>
    <div className="proxy-section-title"><h2>{t('环境一致性')}</h2><span>{t('电脑和指纹浏览器跟随固定出口')}</span></div>
    <div className="proxy-entries proxy-environment">
      {fact('exit', '出口地区', null, exit ? `${exit.label ?? exit.country} · ${exit.timezone}` : t('确认出口后显示'))}
      {fact('system', '系统时区', env.system, machine?.timezone ?? t('读取中…'), env.system === 'ok' ? t('与出口一致') : exit && env.system === 'attention' ? t('出口在 {zone}', {zone:exit.timezone}) : '',
        env.system === 'attention' && <Button variant="secondary" size="small" loading={adjusting === 'timezone'} disabled={!!adjusting} onClick={() => void adjust('timezone')}>{t('对齐时区')}</Button>)}
      {fact('browser', '指纹浏览器', env.browser, env.setting ? t('时区 {zone} · 语言 {language}', {zone:env.setting.timezone, language:env.setting.language}) : t('浏览器配置读取失败'),
        env.browser === 'ok' ? t('与出口一致') : env.browser === 'attention' ? t('下次打开网页版时自动对齐') : '')}
      {fact('location', '定位', env.location, t(machine?.location_enabled === false ? '定位已关闭' : machine?.location_enabled ? '定位已开启' : '定位状态未知'), '',
        machine?.location_enabled && <Button variant="secondary" size="small" loading={adjusting === 'location'} disabled={!!adjusting} onClick={() => void adjust('location')}>{t('关闭定位')}</Button>)}
      {fact('measured', '浏览器实测', env.measured, env.report && browserView?.report_received_at ? env.differences.length
        ? t('{time} 实测不一致：{items}', {time:time(browserView.report_received_at), items:join(env.differences)})
        : t('{time} 实测一致', {time:time(browserView.report_received_at)}) : t('打开网页版后自动实测'))}
    </div>
    <div className="proxy-section-title"><h2>{t('启动 Claude')}</h2></div>
    <div className="proxy-entries">{launches.map(entry => {
      const state = verdict(entry);
      return <div className="proxy-entry" key={entry}><div className="proxy-entry-main"><div><strong>{t(labels[entry])}</strong><span className={`proxy-badge proxy-${state}`}>{t(words[state])}</span></div>
        {entry === 'cli' && <div className="proxy-workspace"><span>{t('工作目录')}</span><code title={status?.workspace}>{status?.workspace || '—'}</code><Button variant="ghost" size="small" disabled={!!busy} onClick={() => void chooseWorkspace()}>{t('更改')}</Button></div>}
        {entry === 'browser' && <div className="proxy-workspace"><small>{t('在指纹浏览器中打开，代理固定走专用端口。')}</small></div>}
        {entry === 'desktop' && protection === 'needs_protect' && <div className="proxy-workspace proxy-attention"><small>{t('客户端还没有防火墙保护（常见于刚更新）。')}</small><Button variant="ghost" size="small" disabled={!!busy} loading={busy === 'protect'} onClick={() => setProtecting(true)}>{t('设置保护')}</Button></div>}
        {entry === 'desktop' && protection === 'firewall_off' && <div className="proxy-workspace proxy-attention"><small>{t('Windows 防火墙被关闭了：先在 Windows 安全中心打开防火墙。')}</small></div>}
        {entry === 'desktop' && protection === 'protected' && <div className="proxy-workspace"><small>{t('防火墙保护已生效：客户端只能经本机代理上网。')}</small></div>}</div>
        <Button variant="secondary" size="small" loading={busy === `launch:${entry}`} disabled={!!busy || !status || !canLaunch(state)} onClick={() => void run(`launch:${entry}`)}>{t('启动')}</Button></div>;
    })}</div>
    <p className="system-hint">{t('VS Code：{state}，从编辑器直接打开即可。', {state:t(words[verdict('vscode')])})}</p>
    <details className="proxy-details" key={overall === 'blocked' ? 'open' : 'closed'} open={overall === 'blocked'}><summary>{t('查看检查项')}</summary>{report?.checks.length ? report.checks.map(row => <div key={row.id}><span>{t(row.title)}{current && row.detail && <small>{t(row.detail)}</small>}</span><span>{t(words[current ? row.state : 'unknown'])}</span></div>) : <p>{t('还没有检查结果。')}</p>}</details>
    {needsRepair && <div className="proxy-footer"><div><strong>{t('需要修复现有配置？')}</strong><p>{t('先查看会改动什么，再决定是否运行 Proxy-v2 修复。')}</p></div><Button variant="ghost" size="small" loading={busy === 'plan'} disabled={!!busy || !status?.available} onClick={() => void run('plan')}>{t('查看修复计划')}</Button></div>}
    <AppDialog alert open={protecting} onOpenChange={setProtecting} title={t('设置客户端保护')} description={t('会弹出一次 Windows 管理员确认。')} footer={<><Button variant="secondary" data-dialog-cancel onClick={() => setProtecting(false)}>{t('取消')}</Button><Button variant="ink" onClick={() => {setProtecting(false); void run('protect');}}>{t('设置保护')}</Button></>}><ul><li>{t('给 Claude 客户端加防火墙规则：只能连本机代理，代理失效时直接断网。')}</li><li>{t('客户端每次更新后需要再设置一次。')}</li></ul></AppDialog>
    <AppDialog alert open={!!plan} onOpenChange={open => {if (!open) setPlan(null);}} title={t('修复现有 Proxy-v2')} description={t('这是一次真实修复，会改动现有网络配置。')} footer={<><Button variant="secondary" data-dialog-cancel onClick={() => setPlan(null)}>{t('取消')}</Button><Button variant="ink" onClick={() => {const token = plan?.token; setPlan(null); if (token) void run('repair', token);}}>{t('执行修复并复查')}</Button></>}>{current && problems.length > 0 && <p>{t('当前未通过：{items}', {items:join(problems)})}</p>}<ul>{plan?.effects.map(effect => <li key={effect}>{t(effect)}</li>)}</ul></AppDialog>
  </section>;
}
