# CCBaga Proxy 本机整合版

Windows 本机版，2026-10-17 核对。定位：国内使用官方 Claude 账号的环境守护——Claude 只从固定 IP 出去，电脑和浏览器环境跟随这个 IP，多账号互不串。CCBaga 提供界面、托盘、指纹浏览器和身份管理；已安装的 Proxy-v2 负责固定出口判断、后台守护和修复。约束见根目录 `CLAUDE.md`。

## 打开

- **开机自动**：登录 Windows 后以托盘模式启动（`HKCU\Software\Microsoft\Windows\CurrentVersion\Run` 下的 `CCBaga Proxy` → `src-tauri\target\release\requirement-french.exe --tray`）；托盘菜单「开机后在托盘待命」可关闭。
- **托盘**：显示固定出口状态，故障和恢复各发一次 Windows 通知；菜单可打开主界面，启动 Claude CLI、桌面客户端和网页版（指纹浏览器），与首页走同一个原生门禁。
- **手动**：双击根目录 `启动整合版.cmd`（优先 release 版）。不要从 Claude Code / Codex 的终端启动：程序会继承会话环境变量并传给它启动的 CLI，CLI 会提示 `Transcript saving is off`。

## 怎么用

侧栏三页：首页、连接监视、Claude 身份管理。

1. **首页**：打开时做一次完整检查，之后每 5 秒读守护状态，完整结果 60 秒过期。
   - **启动 Claude**：CLI（工作目录可改）、桌面客户端、网页版。按钮状态不是许可，原生端每次重新检查。CLI 打开一个控制台，控制台里 Proxy-v2 还会再查一次。
   - **网页版**打开指纹浏览器（独立 Chromium，代理固定走专用端口、关 QUIC 和非代理 UDP）。它有自己的 `check-browser` 门禁，不受 Proxy-v2「登录链接入口」那一项影响。
   - **桌面客户端**一行显示防火墙保护：未保护（常见于客户端刚更新）时可点「设置保护」，先在应用里确认，再由 Windows 弹一次管理员确认，完成后自动复查；防火墙被关时只提示去 Windows 安全中心打开。
   - **环境一致性**：出口地区、系统时区（不一致可「对齐时区」）、指纹浏览器的时区和语言、定位（开启可「关闭定位」）、浏览器实测（指纹浏览器起始页回报，打开网页版几秒后刷新）。
   - 运行中的 Claude 程序有连接没走固定出口、Clash 不在规则模式，只做提醒，不参与启动判定。
   - **修复**：先「查看修复计划」，再「执行修复并复查」，调用 Proxy-v2 修复脚本，可能重启 Clash 和受保护应用；确认一次有效、2 分钟过期。
2. **连接监视**：只读，每 2 秒读一次 Clash 的连接记录（Proxy-v2 `-Watch` 的同一判定），每个目标只列一次，没走固定出口的标红置顶。只看得到经过 Clash 的连接；专用端口上的连接统一显示为「专用端口」。
3. **身份管理**：多个 Claude 账号的本地状态切换和加密归档。每个身份独占一份指纹浏览器资料和固定种子；切换时正常关闭浏览器，切换后重新过门禁再打开。`HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`、`NO_PROXY`、`BROWSER` 始终留在本机；网络复查失败或有未恢复事务时整合入口不放行。

**指纹浏览器跟随固定出口**：每次启动把时区设为出口时区、语言设为 en-US（旅居者组合）；出口地区读不到时保留原设置照常启动，差异会出现在核验页。核验页认可「目录地区的时区 + 英文」，不要求系统语言属于该地区；系统时区仍要与出口一致才算全部通过。选地区不改变 IP。

**CLI 登录链接**：Claude 设置里的 `BROWSER` 指向 Proxy-v2 的 `ClaudeBrowser.exe`；它先查一次固定出口，再把链接交给 CCBaga 的 `--browser` 入口，在当前身份的指纹浏览器里打开。CCBaga 每次启动把自身路径写进 `%APPDATA%\local.proxy.ccbaga\browser-entry.json`；没有这个登记时拒绝打开，不退回其他浏览器。

Proxy-v2 不可用时按原因提示：找不到安装、版本与整合版不匹配、缺少 Python 组件、策略文件无效；其他异常显示「桥接异常退出」。

## 依赖和范围

- 适配 `%USERPROFILE%\.codex\ClaudeNetwork` 与 `CodexNetworkGuard`。后端 `check.py` 的 `VERSION` 必须等于 `proxy-bridge/bridge.py` 的 `SUPPORTED_VERSION`（当前 `2026.10.17`）。两边一起改、一起构建、一起部署。
- 使用这台电脑的 `C:\Tools\Python\python.exe` 及其 psutil；不是面向任意电脑的通用安装器。
- 固定端口、预期 IP 来自已安装策略；项目里没有代理密码、controller secret 或 repair baseline。
- Proxy-v2 源码在私有仓库 `example-org/Proxy-v2`；出口判定、守护、修复和跳板顺序都在那里维护。
- 上游基线 CCBaga `612ddd9`，另挑了 `0a02de8`、`9851e0d`、`4cb4648`（身份归档重构、每身份独占浏览器资料、默认联动）；没有采用它们的文档改动和起始页身份工牌（依赖未挑的 `882564b`）。
- 原版傻瓜设置、VPS/网络、电脑环境、浏览器环境、自动更新页面及其原生命令已删除；macOS/Linux 平台代码保留未动。

## 已知限制

- 普通浏览器打开 claude.ai 只在 Clash 规则模式下走固定出口；首页会提醒，但不替你切换模式。网页版请用指纹浏览器。
- 启动前检查只代表那一刻；之后靠守护约每 30 秒核对一次，出口变化后最多约 30 秒才会阻断。
- 守护长时间不更新（进程在、状态不动）时，首页只能提示可能卡住。
- 连接监视每 2 秒看一次，很短的连接可能漏看。
- 桌面客户端慢启动时，桥接最多再等 30 秒核对新进程固定走专用端口；这段只经离线测试。

## 验证范围

2026-10-17 本机实测：

| 检查 | 结果 |
|---|---|
| `bun run build` | 类型检查与前端构建通过 |
| `bun test` | 25 项通过 |
| `bun run test:bridge` | 33 项通过 |
| `bun run test:proxy` | 通过：首页（含环境一致性、客户端保护、网页版=指纹浏览器）与连接监视的虚构 IPC 模拟，外网拦截，无控制台错误 |
| `bun run test:identities` | 19 项通过，含锁定引擎的两份资料 Cookie/本地存储隔离 |
| `cargo test` | 77 项通过，3 项按设计忽略；release 构建 0 警告 |
| Proxy-v2 离线测试 | 64 项通过 |
| Proxy-v2 部署 | `Deploy-Proxy.ps1 -Apply` 内置「代理没变」验证通过（24 个文件与 2 个 Clash 进程前后不变），守护重启 |
| 切换后随包桥接实调（只读） | 版本一致；cli/vscode/desktop/browser/web 五项 ready，12 项检查通过，守护 ready，客户端已保护；连接快照可读、全部走固定出口 |
| 实机界面 | 从首页启动 CLI 正常（以资源管理器环境启动后不再有会话环境提示） |

未覆盖：从界面打开网页版和登录链接的完整点击、真实账号的身份切换与浏览器重开、实际执行「设置保护」（会改防火墙）、真实修复、重启 Windows、休眠恢复、长时间断网、独立 DNS/WebRTC 泄漏测试。不把以上结果扩展成这些场景的保证。

## 构建、检查与切换

在项目根目录的 PowerShell 中运行检查：

```powershell
$env:PATH = "$env:USERPROFILE\.bun\bin;C:\Tools\Python;" + $env:PATH
bun install --frozen-lockfile
bun run build
bun test
bun run test:bridge
bun run test:proxy
bun run test:identities
cargo test --manifest-path src-tauri/Cargo.toml -- --test-threads=4
```

运行中的程序就在 `src-tauri\target\release`，所以 release 用独立目录构建，运行中的版本不受影响：

```powershell
$env:CARGO_TARGET_DIR = 'C:\Projects\ccbaga-build-target'
bun run build:windows
```

切换（两边版本绑定时必须一起做）：

1. 备份：`%APPDATA%\local.proxy.ccbaga`（含 `identity-vault`，权限用 `icacls ... /save` 另存）、旧的 `requirement-french.exe`、`browser-ui\`、`proxy-bridge\`。新版首次启动会升级身份保险库的表结构，旧版读不了升级后的库。
2. 从托盘「退出」（或结束 `requirement-french.exe`）。
3. 在 Proxy-v2 仓库运行 `.\Deploy-Proxy.ps1`（只看计划），确认后 `.\Deploy-Proxy.ps1 -Apply`。
4. 把新构建的 `requirement-french.exe`、`browser-ui\`、`proxy-bridge\` 拷进 `src-tauri\target\release`（引擎 `browser-runtime\` 版本不变时不必拷）。
5. 用资源管理器启动：`explorer.exe "C:\Projects\CCBaga-Proxy\src-tauri\target\release\requirement-french.exe"`，然后复查。

## 回退

1. 从托盘退出新版。
2. Proxy-v2：`.\Deploy-Proxy.ps1 -Rollback "<%USERPROFILE%\.codex\deploy-backups\ 下本次部署的目录>"`。
3. 把备份的旧程序文件拷回 `src-tauri\target\release`，把备份的 `identity-vault` 拷回 `%APPDATA%\local.proxy.ccbaga\`，再启动。
4. 回到 Proxy-v2 原来的托盘和桌面入口：把 `%APPDATA%\local.proxy.ccbaga\proxy-v2-shortcuts-backup\` 里的 `ClaudeStatus.lnk` 放回启动文件夹（`shell:startup`），其余快捷方式放回桌面，并取消「开机后在托盘待命」。

## 代码托管

私有仓库 `example-org/CCBaga-Proxy`（远程名 `private`，分支 `codex/proxy-integration`）；`origin` 指向上游公开仓库 `liseami/CCBaga`，不向它推送。原版 MIT 与第三方引擎许可保留。
