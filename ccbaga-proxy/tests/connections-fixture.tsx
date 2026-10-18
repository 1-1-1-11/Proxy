// Offline UI fixture for the connection monitor: in-memory snapshots, no native actions or network.
import {createRoot} from 'react-dom/client';
import {mockIPC} from '@tauri-apps/api/mocks';
import {MotionRoot, TooltipProvider} from 'cromma-ui';
import {ConnectionsPanel} from '../src/connections';
import {setLocale} from '../src/i18n';
import '../src/index.css';
import '../src/style.css';
type Mode = 'quiet'|'fixed'|'leak'|'unreadable'|'domestic';
let mode:Mode = 'quiet';
const commands:string[] = [];
const api = {source:'fixed_port', host:'api.anthropic.com', port:443, fixed:true, route:null};
const leak = {source:'desktop', host:'claude.ai', port:443, fixed:false, route:'DIRECT'};
mockIPC(async command => {
  commands.push(command);
  if (command !== 'proxy_connections') throw Error('Unexpected fixture command: '+command);
  return {schema:1, available:true, observed_at:Date.now(), readable:mode !== 'unreadable', mode:mode === 'domestic' ? 'domestic' : mode === 'unreadable' ? null : 'claude',
    connections:mode === 'quiet' || mode === 'unreadable' ? [] : mode === 'leak' ? [api, leak] : [api]};
});
const root = createRoot(document.getElementById('fixture')!);
const render = (active:boolean) => root.render(<MotionRoot><TooltipProvider><main className="app-shell"><div className="workspace cleaner-slot"><ConnectionsPanel active={active}/></div></main></TooltipProvider></MotionRoot>);
render(true);
Object.assign(window, {connectionsFixture:{commands, mode:(next:Mode) => {mode = next;}, active:render, language:setLocale}});
