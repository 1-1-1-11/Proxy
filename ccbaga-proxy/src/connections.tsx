// [INPUT]: Read-only connection snapshots from the native bridge (Proxy-v2's -Watch judgement), polled while visible.
// [OUTPUT]: Where Claude programs connected while the page was open, and which connections left the fixed exit.
// [POS]: Observation only; it never blocks, repairs or closes anything. Launch decisions stay on the home page.
import {useEffect, useRef, useState} from 'react';
import {invoke} from '@tauri-apps/api/core';
import {Button} from 'cromma-ui';
import {useI18n} from './i18n';
import {merge, offChain, type Seen, type Snapshot, type Source} from './connections-model';
import './proxy.css';

const sources: Record<Source, string> = {fixed_port:'专用端口', cli:'Claude CLI', vscode:'VS Code', desktop:'Claude 桌面客户端'};
const modes = {claude:'Claude 模式（虚拟网卡开）', domestic:'国内模式（虚拟网卡关）：客户端的连接可能不经过 Clash，这里看不到。', abnormal:'Clash 模式异常，请回首页检查。'} as const;

export function ConnectionsPanel({active = true}:{active?:boolean}) {
  const {t, locale} = useI18n();
  const [seen, setSeen] = useState<Seen[]>([]);
  const [latest, setLatest] = useState<Snapshot|null>(null), [error, setError] = useState('');
  const live = useRef(true);
  useEffect(() => { live.current = true; return () => { live.current = false; }; }, []);
  // Every 2 seconds while visible, like -Watch; short connections between looks can be missed.
  useEffect(() => {
    if (!active) return;
    let pending = false;
    const look = async () => {
      if (pending || document.visibilityState === 'hidden') return;
      pending = true;
      try {
        const next = await invoke<Snapshot>('proxy_connections');
        if (live.current) { setLatest(next); setSeen(old => merge(old, next)); setError(''); }
      } catch (e) { if (live.current) setError(String(e)); }
      finally { pending = false; }
    };
    void look();
    const timer = window.setInterval(() => void look(), 2000);
    return () => window.clearInterval(timer);
  }, [active]);
  const off = offChain(seen);
  const time = (at: number) => new Date(at).toLocaleTimeString(locale === 'zh' ? 'zh-CN' : 'en-US');
  return <section className="system-page proxy-page">
    <div className="cleanup-title"><div><h1>{t('连接监视')}</h1><p className="system-hint">{t('只读：每 2 秒看一次 Claude 程序经过 Clash 的连接，不会断开或修改任何东西。')}</p></div>
      <Button variant="secondary" size="small" disabled={!seen.length} onClick={() => setSeen([])}>{t('清空记录')}</Button></div>
    <div className={`proxy-summary proxy-${off ? 'blocked' : seen.length ? 'ready' : 'unknown'}`} role="status" aria-live="polite">
      <span className="proxy-mark" aria-hidden="true">{off ? '!' : seen.length ? '✓' : '·'}</span>
      <div><h2>{t(off ? '有 {n} 个连接没走固定出口' : seen.length ? '全部走固定出口' : '还没有看到 Claude 的连接', {n:String(off)})}</h2>
        <p>{t(seen.length ? '打开页面后共看到 {n} 个不同的目标。' : '空闲时正常；可以边用 Claude 边看。', {n:String(seen.length)})}</p></div></div>
    {error && <p role="alert" className="system-feedback error">{t(error)}</p>}
    {latest && !latest.readable && <p role="alert" className="system-feedback error">{t('读不到 Clash 的连接记录，正在重试…')}</p>}
    {latest?.mode && <p className="system-hint">{t(modes[latest.mode])}</p>}
    <div className="proxy-entries proxy-environment">{seen.map(row =>
      <div className={`proxy-entry${row.fixed ? '' : ' proxy-attention'}`} key={`${row.source}|${row.host}|${row.port}|${row.fixed}`}>
        <div className="proxy-entry-main"><div><strong>{row.host || '—'}{row.port ? `:${row.port}` : ''}</strong>
          <span className={`proxy-badge proxy-${row.fixed ? 'ready' : 'blocked'}`}>{t(row.fixed ? '固定出口' : '没走固定出口')}</span></div>
          <div className="proxy-workspace"><span>{t(sources[row.source])}</span><small>{row.fixed ? t('最近 {time}', {time:time(row.last)}) : t('路线：{route} · 最近 {time}', {route:row.route || '—', time:time(row.last)})}</small></div></div>
      </div>)}</div>
    <p className="system-hint">{t('只能看到经过 Clash 的连接；专用端口上的连接 Clash 不记录是哪个程序发起的，统一显示为「专用端口」。')}</p>
  </section>;
}
