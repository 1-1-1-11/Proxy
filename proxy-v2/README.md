> **公开快照：** 后续开发在 [CC-Guard](https://github.com/1-1-1-11/CC-Guard)。本目录只作历史参考。用户名、安装路径、订阅节点名和 Clash 配置 UID 已换成示例，不能按原文部署回原来的电脑。

# Proxy v2：Claude 固定出口

让这台 Windows 电脑上的 Claude 只从固定公网 IP 访问。出口不对就断开，用之前能知道能不能用，出问题时知道怎么恢复；Claude 程序连了哪里，随时能看。

这是旧项目 `C:\Projects\Proxy` 的重写版，**代理本身不变**：Clash 规则、端口、固定出口链路、修复时写入的配置、守护的阻断都和旧版一致（证明方法见「验证代理没变」）。之后的有意改动：守护在本机自己断网时跳过自动重载；2026-10-14 起固定线路的跳板改为韩国优先（经「声明的改动」部署，出口 IP 不变）。按本机路径编写，不是通用安装包。

## 每天怎么用

> 本机自 2026-10-13 起由 CCBaga Proxy（`C:\Projects\CCBaga-Proxy`）的托盘和界面接管日常入口：下面的托盘图标开机启动和桌面快捷方式已移到 `%APPDATA%\local.proxy.ccbaga\proxy-v2-shortcuts-backup`，守护、检查、修复和保护仍是本项目。2026-10-17 起网页版和登录链接改用 CCBaga 的指纹浏览器，不再打开专用 Chrome。CCBaga 的桥接要求本项目 `check.py` 的 `VERSION` 与它一致（当前 `2026.10.17`），改版本时两边一起部署。恢复方法见 CCBaga Proxy 的 `docs/proxy-integration.md`「回退」。

**看右下角托盘图标**（开机自动显示）：

| 图标 | 含义 |
| --- | --- |
| 绿 C | Claude 模式（虚拟网卡开），全部入口可用 |
| 蓝「国」 | 国内模式（虚拟网卡关），CLI / VS Code / 指纹浏览器 / 客户端可用；普通浏览器不受保护 |
| 橙 … | 出口正在复查，或刚恢复、等第二次确认 |
| 红 ! | 出口连续两次检测失败、IP 不对已阻断、守护没运行、Clash 模式异常、**Claude 有连接没走固定出口**、**客户端没受保护已被关闭** |
| 灰 | 没有网络 |

**入口**：

| 入口 | 说明 |
| --- | --- |
| 终端里直接 `claude`、VS Code 插件 | 设置里已固定走专用端口，不用额外操作 |
| 桌面「Claude CLI 固定出口」 | 先花 1～2 秒检查出口，通过才启动 CLI |
| 登录链接（Claude 设置里的 `BROWSER` → `ClaudeBrowser.exe`） | 先检查出口，再把链接交给 CCBaga Proxy 的指纹浏览器（它打开前再查一次）；CCBaga 没登记入口时拒绝打开，不退回别的浏览器。网页版从 CCBaga 首页打开 |
| 桌面「Claude 客户端（固定出口）」、托盘右键同名菜单 | **客户端只从这里打开**：先检查出口，再让客户端固定走专用端口 17892 |
| 桌面「代理网络检查」 | 检查一遍；有问题时会问你要不要修复（输入 R） |
| 托盘右键「看看 Claude 连了哪里」 | 实时列出 Claude 程序连接的地址，以及是否走固定出口 |

**命令**：

```powershell
claude-proxy                 # 检查能不能用，几秒钟；只读
claude-proxy -Details        # 加上逐项证据
claude-proxy -Repair         # 修复受管理的代理配置，修完自动再检查（可能重启 Clash）
claude-proxy -Watch          # 观察 5 分钟内 Claude 连了哪里；-Minutes 10 改时长，Ctrl+C 提前结束
claude-proxy -Protect        # 给客户端加防火墙保护（弹一次管理员确认）；客户端每次更新后运行一次
```

输出示例：

```text
结论：可以使用 Claude
  CLI：可以使用
  VS Code：可以使用
  登录链接（指纹浏览器）：可以使用
  客户端（桌面端）：未安装
当前模式：Claude 模式（虚拟网卡开）
固定出口：203.0.113.10；两处检测 2/2 一致
用时 6.9 秒 · 退出码 0 · 逐项证据：claude-proxy -Details
```

不能用时，每条「原因」下面有一行「处理」。退出码：0 = 可以用，2 = 有明确问题，3 = 证据不足（不会把未知当成通过）。

## 客户端（桌面端）

- **固定走专用端口**：从「Claude 客户端（固定出口）」打开时，客户端带 `--proxy-server=http://127.0.0.1:17892` 启动，和 CLI 一样只走专用端口，与 Clash 的规则 / 全局 / 直连模式无关。
- **代理失效就断网**：Windows 防火墙只允许客户端连本机，禁止它直连外网。Clash 停止、固定出口失效或 IP 不对（守护把出口切为拒绝）时，它直接连不上网。
- **守护直接关闭客户端**（不只是提醒，约 30 秒一轮）：Windows 防火墙被关、防火墙没覆盖当前版本（多半是刚更新）、客户端不是从固定出口图标打开的（例如开始菜单、更新后自动重启）、Clash 记录到它有连接没走固定出口、或保护状态无法确认时，守护会关掉客户端并弹窗说明原因。
- **客户端更新后运行一次 `claude-proxy -Protect`**：防火墙规则按程序路径写，路径里带版本号。规则本身永久有效，不需要每次使用都重新配置；没覆盖新版本时，守护会关闭客户端，直到你运行 `-Protect`。
- Cowork 已按官方策略关闭；它的系统服务受应用包保护、不能禁用，所以用防火墙断了它的网（按服务名一条规则，不受版本影响）。规则不在或防火墙被关时，托盘变红并弹窗。扩展和本地 MCP 也已按官方策略关闭。策略位置：`HKLM\SOFTWARE\Policies\Claude`。
- 检查会逐条核对客户端此刻的连接是否都走固定出口；`claude-proxy -Watch` 能边用边看它连了哪里。
- **工具管不了本机信息。** 客户端是本机程序，能直接读到系统时区、区域和显示语言、用户名和电脑名，以及你授权给它的文件夹、剪贴板、屏幕。代理只决定网络出口，不能隐藏这些。要限制，只在客户端里授权需要的文件夹，不开不需要的扩展和电脑操控；想更彻底，就用一个单独的 Windows 账户运行客户端。
- 客户端启动的其他程序（例如 MCP 用的 node.exe）不叫 claude.exe，按普通规则上网，`-Watch` 结束时会列出它们的名字。

## 和旧版相比

| | 内容 |
| --- | --- |
| 删掉 | 网页版每次打开前的无头 Chrome WebRTC / DNS 审计和 playwright 依赖；`-Runtime` 逐进程核对；R/D/C/Q 修复菜单和 Chrome 策略写入；签名、git / npm、遥测检查；检查工具自身源码的检查；修复时重编浏览器启动器；修复后端没人用的 `--check-only`；守护里没人读的内核告警日志（占日志的 92%）和每 30 秒一行的同步日志 |
| 新增 | 客户端入口和核对；`-Watch`；`-Protect` 防火墙保护；守护在客户端失去保护时直接关闭它；Claude 连接没走固定出口时告警 |
| 修正 | 浏览器启动器编译时没指定 UTF-8，中文提示可能乱码；旧部署脚本漏了修复后端的 3 个依赖 |
| 规模 | 生产代码约 4,270 行 → 约 2,250 行；测试约 2,890 行 → 约 690 行（按 `wc -l`，不含 vendor） |

设置检查不再单独写一套规则：修复后端「需要改的文件」为空，设置就算正确。检查和修复用的是同一个标准。

## 怎么做到的

| 层 | 作用 | 文件 |
| --- | --- | --- |
| 数据面 | Clash 专用端口 17892 只连「Claude-固定出口」组，组里只有固定出口链路和 REJECT，没有直连兜底；规则把 Anthropic / Claude 域名和 claude.exe 导向同一组。固定线路的跳板按 `chainPreferred` 排序（韩国优先），日常线路按 `preferred`（日本优先）；所有固定线路的出口是同一个 IP | `routing-baseline.js`（`repair_proxy.py` 的 `CHAIN_FRONTS` 与之同序） |
| 客户端设置（不变） | Claude 和 VS Code 的代理指向 17892，打开链接用登录链接启动器 | 由 `repair_proxy.py` 维护 |
| 使用中守护 | 约每 30 秒核对出口；IP 不对就把受保护组切为 REJECT 并断开连接。日常线路连续 3 次失败时重载 Clash 配置（间隔至少 10 分钟）；线路失败时先经 DIRECT 访问国内站点，结果记为 `local_ok`，都不通说明本机自己断网，只记 `recovery_skipped`、不重载。另外只读地留意 Claude 连接和客户端模式 | `CodexNetworkGuard/` |
| 托盘图标 | 每 5 秒读守护的状态文件，不发网络请求 | `ClaudeStatus.cs` |
| 检查 / 观察 | 内核与端口、线路配置、两处出口检测（没回应的一处重试一次；任何一处看到别的 IP 就阻断，至少一处确认指定 IP 才通过，与守护同一标准）、实际路由、守护、设置、API 地址、专用浏览器、客户端模式、运行中的 Claude 连接 | `check.py`、`read_env.cjs` |
| CLI 启动器 | 检查通过后带专用端口环境启动 CLI；CLI 按 npm、原生安装、bun 的顺序查找，都没有时提示安装 | `claude-fixed.cmd` |
| 修复（不变） | 先在检查端口 17893 核对出口，对了才放开 Claude | `repair_proxy.py`、`repair_support.py`、`repair_jsonc.cjs` |
| 登录链接入口 | 检查通过才把链接交给 CCBaga Proxy 登记在 `%APPDATA%\local.proxy.ccbaga\browser-entry.json` 的程序（`--browser <链接>`）；检查项 `web` 只要求启动器存在且有这个登记 | `browser_entry.py`、`ClaudeBrowser.cs` |

## 维护

```powershell
py -m pip install -r requirements.txt
py -X utf8 -B -m unittest discover -s .\claude-network -p "test_*.py"     # 离线测试
powershell -NoProfile -ExecutionPolicy Bypass -File .\claude-network\Test-ClaudeStatus.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\CodexNetworkGuard\guard.ps1 -SelfTest
powershell -NoProfile -ExecutionPolicy Bypass -File .\Build-ClaudeBrowser.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\Build-ClaudeStatus.ps1
py -X utf8 -B .\verify_same_proxy.py                                        # 验证代理没变
.\Deploy-Proxy.ps1                                                          # 只看部署计划
.\Deploy-Proxy.ps1 -Apply                                                   # 部署
.\Deploy-Proxy.ps1 -Apply -ExpectFrontOrder                                 # 部署声明的改动：跳板顺序
.\Deploy-Proxy.ps1 -Rollback "<备份目录>"                                    # 回滚
claude-proxy -Repair                                                        # 改动代理后写入 Clash 并核对出口
```

- 测试需要 `claude-network\audit_policy.json`（从 `audit_policy.example.json` 复制后改成自己的固定 IP）。
- **验证代理没变**：`verify_same_proxy.py` 用旧版（已安装）和新版代码，对当前真实配置各生成一次 Clash 配置和设置写入结果，比较哈希；逐个比对会写代理的函数；再运行一次新版检查，确认代理相关文件和 Clash 进程前后没变。只在临时目录里放一份运行用的副本，结束即删。
- **声明的改动**：有意改变代理时必须点名。`--expect front-order`（部署时 `-ExpectFrontOrder`）只放行固定线路跳板顺序的变化：去掉顺序和线路名后的配置必须完全相同（出口节点、凭据、规则、日常顺序、设置都不变），且顺序确实变了；其余一律按「代理没变」检查。部署后运行 `claude-proxy -Repair` 写入 Clash，它先在检查端口核对出口再放行 Claude。
- **部署**：`-Apply` 先跑上面的验证，不通过就停；被替换和被淘汰的文件备份到 `%USERPROFILE%\.codex\deploy-backups\<时间>`；然后复制新文件，重启守护和仍在启动文件夹里的托盘图标（守护停几秒，期间不核对出口）。不碰 Clash、Clash 配置和 Claude / VS Code 设置。
- 安装位置不变：`%USERPROFILE%\.codex\ClaudeNetwork`、`%USERPROFILE%\.codex\CodexNetworkGuard`；部署不改桌面快捷方式和开机启动项。
- 旧项目 `C:\Projects\Proxy` 已归档（标签 `v1-final`），它的部署脚本已停用。
- 这份公开副本就是上面的源码。后续开发在 https://github.com/1-1-1-11/CC-Guard 。

## 仓库之外的系统设置

这些设置不在代码里，由部署之外的一次性操作写入；都可以撤回（撤回命令在管理员 PowerShell 中运行）。

| 设置 | 作用 | 撤回 |
| --- | --- | --- |
| 防火墙规则组 `Claude local policy` | 客户端和它的 Chrome 通信程序 `chrome-native-host.exe` 只能连本机；Cowork 服务断网 | `Remove-NetFirewallRule -Group 'Claude local policy'` |
| `HKLM\SOFTWARE\Policies\Claude` | 关闭 Cowork、扩展、扩展目录、本地 MCP | `Remove-Item 'HKLM:\SOFTWARE\Policies\Claude' -Recurse` |
| `HKCU\SOFTWARE\Policies\Google\Chrome\WebRtcIPHandling` = `disable_non_proxied_udp` | 原为旧专用 Chrome 设置（2026-10-17 起不再使用专用 Chrome，这项可以撤回）；影响你所有 Chrome 资料的 WebRTC 通话 | `Remove-ItemProperty 'HKCU:\SOFTWARE\Policies\Google\Chrome' -Name WebRtcIPHandling` |
| 全局 git：`http.https://github.com/.proxy` = 专用端口 | 所有仓库访问 GitHub 都走固定出口 | `git config --global --unset http.https://github.com/.proxy`（普通权限） |
| `gh` 外壳函数：`C:\Users\example\Documents\PowerShell\profile.ps1`、`C:\Users\example\Documents\WindowsPowerShell\profile.ps1`、`~/.bashrc` | gh 在 PowerShell 7 / 5.1 / Git Bash 里走固定出口，调用后恢复原环境变量 | 删掉文件里 `Claude fixed exit: GitHub CLI` 那一段（普通权限） |
| 桌面「Claude 客户端（固定出口）」 | 客户端固定走专用端口的入口（本机已移到上面「每天怎么用」所说的备份目录） | 删除快捷方式 |

## 迁移须知

公开快照里的路径、用户名、节点名和 Clash 配置 UID 都是示例，不是原来那台电脑上的值。

| 项目 | 本机约定 |
| --- | --- |
| Python | `C:\Tools\Python\python.exe` / `pythonw.exe` 写在命令入口、C# 启动器和 `guard.ps1` 里 |
| Clash | Clash Verge Rev（示例目录 `C:\Tools\ClashVerge`）及其 `verge-mihomo-production-*` 命名管道；公开快照里的配置 UID 是 `example-profile` / `example-script` / `example-prepend`，前置节点名是 `Example-JP-HY2` 这一组；端口 17892（专用）、17893（检查）、7892（日常） |
| 固定出口 | 预期 IP 写在 `audit_policy.json`；端口和组名在几个脚本里也写死了 |
| 用户与路径 | `C:\Users\example`、`C:\Users\example\Desktop`；互斥量名带 `example` |
| 恢复数据 | 安装目录里的 `repair-baseline.dpapi`（跟随 Windows 用户，不能跨机），不能删 |

## 边界

- 守护约每 30 秒核对一次，出口变化后最多约 30 秒才会阻断。
- 普通浏览器里的 Claude 只在 Claude 模式下受规则保护，其他情况只提醒、不阻断。
- 客户端不是从固定出口图标打开、或刚更新还没运行 `-Protect` 时，守护最多约 30 秒后关闭它；这段时间它经系统代理出去，规则模式下仍按程序名进入固定出口。
- 网页版和登录链接在 CCBaga Proxy 的指纹浏览器里（独立 Chromium 和独立资料目录）；客户端只在 Chrome / Edge 默认用户目录里找 Claude 扩展，碰不到它。旧专用 Chrome 的资料 `%LOCALAPPDATA%\ClaudeNetwork\ChromeData` 不再使用，未删除。Claude in Chrome 扩展能否在指纹浏览器里使用未验证；本地 MCP 保持关闭。
- gh 只在 PowerShell 7 / 5.1 / Git Bash 里经外壳函数走固定出口；cmd 里直接运行、或被其他程序直接调用的 `gh.exe` 仍按用户环境变量走日常线路。浏览器里的 github.com 不受影响。
- `-Watch` 每秒读一次 Clash 的连接记录，持续时间很短的连接可能漏看；只看得到经过 Clash 的连接。经专用端口的连接，Clash 不记录是哪个程序发起的，统一显示为「专用端口」。
- 不保证账号权益、地区资格或供应商永久静态 IP；不读取 Cookie，不登录，也不调用模型。
