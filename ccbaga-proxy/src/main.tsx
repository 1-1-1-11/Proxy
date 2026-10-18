/**
 * [INPUT]: A 品牌图、Laper 最新 Landing 壳/侧栏视觉参数、Cromma UI、共享 YAML 界面语言、身份页面、固定出口检查与受保护入口。
 * [OUTPUT]: CCBaga Proxy 品牌与极简侧栏：首页（使用 Claude）、连接监视与 Claude 身份管理；手动更新说明与语言切换在底部。
 * [POS]: 单窗口编排层；地区跟随固定出口、网页版与登录链接只用指纹浏览器，上游快捷设置/浏览器/电脑/网络页面源码保留但不在导航。修复或身份任务运行时锁定导航；首页常驻，切回时只在结果过期时静默复查。
 * [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
 */
import { Panel, NavButton, MotionRoot, TooltipProvider } from 'cromma-ui';
import { ShieldCheck as IdentityIcon, HomeDefault as HomeIcon, Globe as ConnectionsIcon } from 'cromma-ui/pika';
import { useEffect, useState } from 'react';
import {listen} from '@tauri-apps/api/event';
import {useI18n} from "./i18n";
import { createRoot } from 'react-dom/client';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { IdentityPanel } from './identities';
import { LanguageSwitch } from './language-switch';
import { ProxyPanel } from './proxy';
import { ConnectionsPanel } from './connections';
import appLogo from '../assets/cleaner-logo.jpg';
import './index.css';
import './style.css';
type Page = 'proxy' | 'connections' | 'cleaner';
const titles: Record<Page, string> = { proxy: '首页', connections: '连接监视', cleaner: 'Claude 身份管理' };
const icons: Record<Page, typeof HomeIcon> = { proxy: HomeIcon, connections: ConnectionsIcon, cleaner: IdentityIcon };
function App() {
    const {t}=useI18n();
    const [page, setPage] = useState<Page>('proxy'), [advancedBusy, setAdvancedBusy] = useState(false);
    const locked = advancedBusy;
    const [launchError, setLaunchError] = useState('');
    // Hidden in the tray the home page stops polling; showing the window resumes it.
    const [visible, setVisible] = useState(document.visibilityState !== 'hidden');
    useEffect(() => { void getCurrentWindow().isVisible().then(setVisible).catch(() => {}); const off = listen<boolean>('window-visible', event => setVisible(event.payload)); return () => {void off.then(stop => stop());}; }, []);
    useEffect(() => { const off = listen<string>('proxy-launch-blocked', event => {setLaunchError(event.payload); setPage('proxy');}); return () => {void off.then(stop => stop());}; }, []);
    return <><div className="drag-strip" onMouseDown={e => { if (e.button === 0)
        void getCurrentWindow().startDragging(); }}/><div className="app-shell"><aside className="app-sidebar">
    <div className="app-brand"><img src={appLogo} width={28} height={28} alt="" draggable={false} className="rounded-xl"/><strong>CCBaga Proxy</strong></div>
    <nav aria-label={t("主要页面")}>{(['proxy', 'connections', 'cleaner'] as const).map(p => { const Icon = icons[p]; return <NavButton key={p} className="workspace-nav" active={page === p} aria-current={page === p ? "page" : undefined} disabled={locked} icon={<Icon size={18} aria-hidden="true"/>} onClick={() => setPage(p)}>{t(titles[p])}</NavButton>; })}</nav>
    <div className="sidebar-bottom"><span className="proxy-edition">{t("本机整合版 · 手动更新")}</span><LanguageSwitch /></div>
  </aside><Panel frame className="workspace">{launchError && <div role="alert" className="proxy-launch-error" onClick={() => setLaunchError('')}>{t(launchError)}</div>}
    <div className={`cleaner-slot ${page !== 'proxy' ? 'page-hidden' : ''}`}><ProxyPanel active={page === 'proxy' && visible} onBusy={setAdvancedBusy} onIdentity={() => setPage('cleaner')}/></div>
    {page === 'connections' && <div className="cleaner-slot"><ConnectionsPanel active={visible}/></div>}
    {page === 'cleaner' && <div className="cleaner-slot"><IdentityPanel onBusy={setAdvancedBusy}/></div>}
  </Panel></div></>;
}
createRoot(document.getElementById('app')!).render(<MotionRoot><TooltipProvider delayDuration={600} skipDelayDuration={300}><App /></TooltipProvider></MotionRoot>);
