// Uses the repository's pinned Chromium and IPC mocks. Blocks all external requests.
import {strict as assert} from 'node:assert';
import {resolve} from 'node:path';
import {mkdir} from 'node:fs/promises';
import {createServer} from 'vite';
import {chromium} from 'playwright-core';
const server=await createServer({server:{host:'127.0.0.1',port:0,strictPort:false,watch:{ignored:['**/src-tauri/**','**/browser-runtime/**','**/artifacts/**']}}, optimizeDeps:{include:['@tauri-apps/api/mocks']}});
await server.listen();
const base=`http://127.0.0.1:${(server.httpServer!.address() as {port:number}).port}`;
const browser=await chromium.launch({executablePath:resolve('browser-runtime/WindowsBrowser/chrome.exe'),headless:true});
const errors:string[]=[];
try {
  const context=await browser.newContext({viewport:{width:1040,height:820}});
  await context.route('**/*', route=>route.request().url().startsWith(base+'/') ? route.continue() : route.abort());
  const page=await context.newPage();
  page.on('pageerror',error=>errors.push(error.message));
  page.on('console',message=>{if (message.type()==='error') errors.push(message.text());});
  await page.goto(base+'/tests/proxy.html');
  assert.equal(await page.title(),'Proxy integration fixture');
  const fixture=(code:string)=>page.evaluate(code);
  const count=async(command:string)=>page.evaluate(command=>(window as any).proxyFixture.commands.filter((r:any)=>r.command===command).length,command);
  const launch=page.getByRole('button',{name:'启动',exact:true});
  const healthy=page.getByRole('heading',{name:'固定出口正常',exact:true});
  const mode=(name:string)=>fixture(`window.proxyFixture.mode(${JSON.stringify(name)})`);
  const recheck=async()=>{await page.getByRole('button',{name:'重新检查'}).click();await page.waitForFunction(()=>!document.querySelector('.proxy-page .cromma-button[data-loading="true"], .proxy-checking'));await page.waitForTimeout(500);};

  // Ready: three launch buttons, region of the fixed exit, no repair prompt while everything passes.
  await healthy.waitFor();
  assert.equal(await launch.count(),3);
  for (const button of await launch.all()) assert.equal(await button.isEnabled(),true);
  await page.getByText('与指定出口一致 · 美国 · 洛杉矶',{exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'查看修复计划'}).count(),0);

  // Who and where: account, an environment that follows the egress, and the web entry in the fingerprint browser.
  await page.getByText('person@example.invalid',{exact:true}).waitFor();
  const environment=page.locator('.proxy-environment');
  await environment.getByText('美国 · 洛杉矶 · America/Los_Angeles',{exact:true}).waitFor();
  await environment.getByText('出口在 America/Los_Angeles',{exact:true}).waitFor();
  await environment.getByText('时区 America/Los_Angeles · 语言 en-US',{exact:true}).waitFor();
  await environment.getByText(/实测不一致：系统时区$/).waitFor();
  await environment.getByText('定位已关闭',{exact:true}).waitFor();
  assert.equal(await environment.locator('.proxy-badge.proxy-blocked').count(),2);
  await page.getByRole('button',{name:'对齐时区'}).click();
  await page.getByText('时区已成功应用并核验。',{exact:true}).waitFor();
  await environment.getByText(/ 实测一致$/).waitFor();
  assert.equal(await environment.locator('.proxy-badge.proxy-blocked').count(),0);
  assert.equal(await page.getByRole('button',{name:'对齐时区'}).count(),0);
  await page.getByText('在指纹浏览器中打开，代理固定走专用端口。',{exact:true}).waitFor();
  assert.equal(await page.getByRole('combobox').count(),0);
  await page.getByRole('button',{name:'切换',exact:true}).click();
  assert.equal(await fixture('window.proxyFixture.identity.length'),1);
  await mkdir('artifacts',{recursive:true});
  await page.screenshot({path:'artifacts/proxy-ready.png'});

  // A recheck keeps the previous answer on screen instead of blanking it.
  await page.getByRole('button',{name:'重新检查'}).click();
  await page.getByText('正在更新…',{exact:true}).waitFor();
  assert.equal(await healthy.isVisible(),true);
  await page.getByText('正在更新…',{exact:true}).waitFor({state:'detached'});

  // CLI folder comes from the native picker and triggers a fresh check for that folder.
  const checks=await count('proxy_check');
  await page.getByRole('button',{name:'更改'}).click();
  await page.getByText('C:\\Projects\\demo',{exact:true}).waitFor();
  await page.waitForFunction(before=>(window as any).proxyFixture.commands.filter((r:any)=>r.command==='proxy_check').length>before,checks);

  // Launch: summary stays, navigation is not locked, the started entry is named.
  await launch.first().click();
  assert.equal(await healthy.isVisible(),true);
  await page.getByText('已打开 Claude CLI 控制台，在控制台中继续。',{exact:true}).waitFor();
  await page.getByRole('button',{name:'启动',exact:true}).nth(2).click();
  await page.getByText('已启动 网页版。',{exact:true}).waitFor();
  assert.deepEqual(await fixture("window.proxyFixture.commands.filter(r=>r.command==='proxy_launch').map(r=>r.args.entry)"),['cli','browser']);
  assert.deepEqual(await fixture('window.proxyFixture.busy.filter(Boolean).length'),0);
  await mode('launch-race');
  await launch.first().click();
  await page.getByText('启动前检查未通过，已停止启动。',{exact:true}).waitFor();

  // Desktop protection: shown from the check; protecting asks first, locks navigation while Windows asks, then rechecks.
  await mode('ready');
  await page.getByText('防火墙保护已生效：客户端只能经本机代理上网。',{exact:true}).waitFor();
  await fixture("window.proxyFixture.protection('needs_protect')");
  await recheck();
  await page.getByText('客户端还没有防火墙保护（常见于刚更新）。',{exact:true}).waitFor();
  await page.getByRole('button',{name:'设置保护'}).click();
  await page.getByRole('alertdialog').waitFor();
  assert.equal(await page.getByRole('button',{name:'取消',exact:true}).evaluate(node=>node===document.activeElement),true);
  await page.getByRole('button',{name:'取消',exact:true}).click();
  assert.equal(await count('proxy_protect'),0);
  await page.getByRole('button',{name:'设置保护'}).click();
  await page.getByRole('alertdialog').getByRole('button',{name:'设置保护'}).click();
  await page.getByText('客户端保护已设置并复查。',{exact:true}).waitFor();
  await page.getByText('防火墙保护已生效：客户端只能经本机代理上网。',{exact:true}).waitFor();
  assert.equal(await count('proxy_protect'),1);
  await fixture("window.proxyFixture.protection('firewall_off')");
  await recheck();
  await page.getByText('Windows 防火墙被关闭了：先在 Windows 安全中心打开防火墙。',{exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'设置保护'}).count(),0);
  await fixture("window.proxyFixture.protection('protected')");

  // Blocked: reasons in the summary, launch disabled, details open, repair offered with current failures.
  await mode('blocked');
  await recheck();
  await page.getByRole('heading',{name:'固定出口有问题，启动已暂停',exact:true}).waitFor();
  await page.getByText('未通过：固定出口 IP',{exact:true}).waitFor();
  for (const button of await launch.all()) assert.equal(await button.isEnabled(),false);
  assert.equal(await page.locator('details.proxy-details').evaluate(node=>(node as HTMLDetailsElement).open),true);
  await page.getByRole('button',{name:'查看修复计划'}).click();
  await page.getByRole('alertdialog').waitFor();
  await page.getByText('当前未通过：固定出口 IP',{exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'取消',exact:true}).evaluate(node=>node===document.activeElement),true);
  await page.getByRole('button',{name:'取消',exact:true}).click();
  assert.equal(await count('proxy_repair'),0);
  await page.getByRole('button',{name:'查看修复计划'}).click();
  await page.getByRole('button',{name:'执行修复并复查'}).click();
  await page.getByRole('heading',{name:'正在修复 Proxy-v2…',exact:true}).waitFor();
  await page.getByText('修复完成，已重新检查。',{exact:true}).waitFor();
  assert.equal(await count('proxy_repair'),1);
  assert.deepEqual(await fixture('window.proxyFixture.busy.filter(Boolean).length'),2); // protect and repair each lock navigation

  // Expired or failed checks only make the display neutral; a click will check again natively.
  for (const name of ['stale','error']) {
    await mode(name);
    await recheck();
    await page.getByRole('heading',{name:'状态待确认',exact:true}).waitFor();
    for (const button of await launch.all()) assert.equal(await button.isEnabled(),true);
  }
  await page.getByText('Error: fixture check failed',{exact:true}).waitFor();
  await page.setViewportSize({width:760,height:640});
  await page.screenshot({path:'artifacts/proxy-error-minimum.png'});
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);
  assert.equal(await page.locator('vite-error-overlay').count(),0);

  // A watchdog catching up after sleep is explained and stays launchable: the native side waits for it.
  await mode('recovering');
  await recheck();
  await page.getByRole('heading',{name:'后台守护正在恢复',exact:true}).waitFor();
  for (const button of await launch.all()) assert.equal(await button.isEnabled(),true);
  assert.equal(await page.getByRole('heading',{name:'固定出口有问题，启动已暂停',exact:true}).count(),0);

  // Running programs off the fixed exit and Clash outside Rule mode are shown, without blocking new launches.
  await mode('warnings');
  await recheck();
  await healthy.waitFor();
  await page.getByText('有正在运行的 Claude 程序连接没走固定出口（Claude CLI）：关掉它，再从这里重新启动。',{exact:true}).waitFor();
  await page.getByText('Clash 当前不在「规则」模式：普通浏览器里的 claude.ai 不走固定出口。网页版请从这里用指纹浏览器打开，或把 Clash 切回规则模式。',{exact:true}).waitFor();
  for (const button of await launch.all()) assert.equal(await button.isEnabled(),true);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth),false);

  // A broken login-link launcher does not decide the web entry: the fingerprint browser has its own gate.
  await mode('chrome-broken');
  await recheck();
  await healthy.waitFor();
  assert.equal(await launch.nth(2).isEnabled(),true);
  assert.equal(await page.getByRole('button',{name:'查看修复计划'}).count(),0);

  // Returning to the page rechecks only when the shown result has expired.
  await mode('ready');
  await recheck();
  await healthy.waitFor();
  let before=await count('proxy_check');
  await fixture('window.proxyFixture.active(false)'); await fixture('window.proxyFixture.active(true)');
  await page.waitForTimeout(300);
  assert.equal(await count('proxy_check'),before);
  await mode('stale');
  await recheck();
  before=await count('proxy_check');
  await fixture('window.proxyFixture.active(false)'); await fixture('window.proxyFixture.active(true)');
  await page.waitForFunction(before=>(window as any).proxyFixture.commands.filter((r:any)=>r.command==='proxy_check').length>before,before);

  // English and a broken heartbeat.
  await mode('ready');
  await recheck();
  await fixture('window.proxyFixture.language("en")');
  await page.getByRole('heading',{name:'Fixed egress is healthy',exact:true}).waitFor();
  await fixture('window.proxyFixture.language("zh")');
  await mode('heartbeat-error');
  await page.getByText('Error: fixture watchdog unavailable',{exact:true}).waitFor({timeout:8000});
  assert.equal(await launch.first().isEnabled(),false);

  // Hidden or unmounted panels stop polling.
  await fixture('window.proxyFixture.active(false)');
  before=await count('proxy_status');
  await page.waitForTimeout(5500);
  assert.equal(await count('proxy_status'),before);
  await fixture('window.proxyFixture.unmount()');

  // Connection monitor: read-only snapshots, each target once, off-chain on top and red, unreadable Clash kept apart.
  await page.goto(base+'/tests/connections.html');
  const monitor=(code:string)=>page.evaluate(code);
  await page.getByRole('heading',{name:'还没有看到 Claude 的连接',exact:true}).waitFor();
  await monitor("window.connectionsFixture.mode('fixed')");
  await page.getByRole('heading',{name:'全部走固定出口',exact:true}).waitFor();
  await page.getByText('Claude 模式（虚拟网卡开）',{exact:true}).waitFor();
  await monitor("window.connectionsFixture.mode('leak')");
  await page.getByRole('heading',{name:'有 1 个连接没走固定出口',exact:true}).waitFor();
  assert.equal(await page.locator('.proxy-entry').first().evaluate(node=>node.classList.contains('proxy-attention')),true);
  await page.getByText(/^路线：DIRECT · 最近 /).waitFor();
  assert.equal(await page.locator('.proxy-entry').count(),2);
  await monitor("window.connectionsFixture.mode('unreadable')");
  await page.getByText('读不到 Clash 的连接记录，正在重试…',{exact:true}).waitFor();
  assert.equal(await page.locator('.proxy-entry').count(),2);
  await monitor("window.connectionsFixture.mode('domestic')");
  await page.getByText('国内模式（虚拟网卡关）：客户端的连接可能不经过 Clash，这里看不到。',{exact:true}).waitFor();
  await page.getByRole('button',{name:'清空记录'}).click();
  await monitor("window.connectionsFixture.mode('quiet')");
  await page.getByRole('heading',{name:'还没有看到 Claude 的连接',exact:true}).waitFor();
  await monitor('window.connectionsFixture.language("en")');
  await page.getByRole('heading',{name:'No Claude connections seen yet',exact:true}).waitFor();
  await monitor('window.connectionsFixture.active(false)');
  const looks=await page.evaluate(()=>(window as any).connectionsFixture.commands.length);
  await page.waitForTimeout(2500);
  assert.equal(await page.evaluate(()=>(window as any).connectionsFixture.commands.length),looks);
  assert.deepEqual(errors,[]);
  console.log('PASS: ready, account, time zone alignment, silent recheck, CLI folder, environment consistency, desktop protection, launch without lock (web = fingerprint browser), native rejection, blocked reasons, repair, expired/error stay launchable, recovering watchdog, running/mode alerts, login-link launcher independent of web, return refresh, English, heartbeat, polling cleanup, connection monitor; no console errors.');
} finally {await browser.close();await server.close();}
