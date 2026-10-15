# Proxy

Windows 上的 Claude 固定出口检查、专用启动入口和本机恢复工具。当前归档版本：`2026.10.07.1`，报告 schema 为 `4`。

![检查报告样例](assets/status.png)

上面是脱敏后的报告页样例（`assets/status.html`），用来对照结论、门禁状态和逐项结果。


**可以复用源码、回归测试和检查方法；当前版本不是换电脑后一键安装的通用工具。** 部分路径、端口、节点名和恢复逻辑针对原工作站编写。部署前需要核对下文的本机依赖。

## 检查什么

- 读取当前 Clash / Mihomo 进程、监听端口所属进程、实时控制器状态和固定出口候选链。
- 通过两处独立公网服务核对预期出口 IP；其中一处失败不会算完整通过。
- 可选 `-Runtime` 模式将运行中的 Claude CLI / VS Code 客户端 TCP 连接与 Mihomo 的实际请求和路由链对应；逐个实例判断。
- 核对 Claude、VS Code、项目设置、环境变量、第三方 API 覆盖及启动入口。
- 完整模式用临时未登录 Chrome 检查公网出口、原生 WebRTC 和 DNS。WebRTC 包含有效管理策略、STUN 正对照和实际连接观察；DNS 要求观察动态测试开始和结束。
- 专用浏览器启动前检查固定出口和 WebRTC 保护，并禁用 QUIC、非代理 WebRTC UDP 和 MediaRouter 投屏发现。

`claude-proxy` 和 `claude-proxy -Full` 用于使用前检查，不需要先打开 Claude；未运行或没有应用请求不会使预检失败。默认输出简短结论和下一步。默认检查通过表示 CLI 条件就绪；`-Full` 的必要项全部通过后，可以启动 CLI 和专用浏览器。

检查会产生探测流量，但不启动 Claude 或 Clash、不修复配置、不切节点，也不以旧报告代替当前证据。`-Full` 只另启临时未登录 Chrome。浏览器必要保护无法确认时仍返回 `INCOMPLETE`，并明确区分“CLI 可启动”和“专用浏览器暂不要启动”，不会把未知改成通过。

正常终端检查后提供菜单：`R` 查看修复方案、`D` 查看详情、`C` 重新检查、`Q` 结束。输入方案编号后先显示改动、影响、预期结果和恢复方式，只有再输入 `YES` 才执行；查看方案、取消或退出均不修改配置。脚本可用 `-NoPrompt` 禁用菜单，`-Json`、兼容参数 `-CheckOnly` 自动不交互。

目前提供两个具体方案：

| 方案 | 何时适用 | 改动与边界 |
| --- | --- | --- |
| 恢复本机代理配置 | 检查确认本地内核、入口或受管理配置有问题，且原恢复依赖齐全 | 调用原恢复后端，可能启动 / 重载 Clash 并恢复受管理分流；不承诺修复供应商、账号或物理网络。原后端保留 DPAPI 文件备份。 |
| 设置 Chrome WebRTC 保护 | 确认策略值或来源有问题、当前用户缺少期望值，且无机器级冲突或 URL 特例 | 先备份，再只写当前用户的一个 Chrome 策略值。影响该用户全部 Chrome 资料及 WebRTC 通话；不改 HKLM、不删 URL 特例、不自动关闭浏览器。执行结果提供单值回滚命令。 |

如果当前用户策略已经正确、但 Chrome 实际来源仍未确认，菜单会说明不能靠重复写入承诺修复，要求重新检查或进一步诊断。备份失败不会继续写策略；回滚也不会覆盖后续的其他修改。修复执行完会重新检查，命令执行成功不等于环境验收成功。

## 文件

| 路径 | 用途 |
| --- | --- |
| `claude-network/audit_proxy.py` | 统一检查入口、实时证据和退出状态 |
| `claude-network/audit_actions.py` | 显式确认后的修复方案、Chrome 单值备份和回滚 |
| `claude-network/audit_settings.py` | 配置和启动入口检查 |
| `claude-network/audit_browser.py`、`webrtc_probe.py`、`stun_probe.py` | 浏览器出口、WebRTC 和 DNS 检查 |
| `claude-network/browser_entry.py`、`ClaudeBrowser.cs` | 专用浏览器门禁和 Windows 启动器 |
| `claude-network/repair_proxy.py`、`repair_support.py`、`routing-baseline.js` | 原工作站的配置恢复逻辑 |
| `claude-network/test_*.py` | 离线回归测试及本地 PowerShell / Node 兼容性检查 |
| `claude-network/vendor/jsonc-parser/` | 随源码保存的 JSONC 解析器，附原 MIT 许可证 |
| `Build-ClaudeBrowser.ps1` | 仅编译启动器并生成本地 SHA-256 基线 |
| `Deploy-ClaudeAudit.ps1` | 原工作站已有安装的增量更新脚本 |
| `Validate-ClaudeAudit.ps1` | 对已安装命令执行检查，记录配置和进程是否保持不变 |

## 从仓库准备源码

本机验证环境为 Windows、Python `3.13.4`、Node.js `24.14.0`、Chrome `154.0.8037.93`、Windows PowerShell `5.1`、Clash Verge Rev `2.5.6`、Mihomo `1.19.31`。源码使用 `asyncio.timeout`，因此 Python 至少需要 `3.11`；其他版本组合尚未验证。

在仓库根目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 只在还没有本机策略文件时复制，避免覆盖已有配置。
if (-not (Test-Path .\claude-network\audit_policy.json)) {
    Copy-Item .\claude-network\audit_policy.example.json .\claude-network\audit_policy.json
}

.\.venv\Scripts\python.exe -X utf8 -B -m unittest discover -s .\claude-network -p 'test_*.py'
```

示例中的 `203.0.113.10` 是文档占位地址，必须改成自己的预期固定公网出口；测试通过不会替你建立代理。测试使用独立样本，不需要运行 Clash 或登录 Claude，部分测试会调用本机 PowerShell / Node。浏览器检查使用已安装的 Chrome，不要求额外执行 `playwright install`。

仓库不保存编译后的启动器。先核对 `ClaudeBrowser.cs` 中的 Python 路径，再执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Build-ClaudeBrowser.ps1
```

构建需要 Windows 自带的 .NET Framework C# 编译器，生成 `claude-network/ClaudeBrowser.exe` 和 `browser-build.json`。哈希仅用于检测本地构建漂移，不是供应商签名。构建脚本不会部署、启动浏览器或修改网络。

## 换电脑前要调整的内容

| 项目 | 当前约定和迁移要求 |
| --- | --- |
| Python | PowerShell / CMD 入口使用 `D:\Python\python.exe`，C# 使用 `D:\Python\pythonw.exe`；须改成实际安装路径。仅创建虚拟环境不会自动改这些入口。 |
| 安装与桌面路径 | 部分入口、部署和验证脚本仍含 `C:\Users\32299`、`D:\Desktop` 及原项目工作目录。安装目录约定为 `%USERPROFILE%\.codex\ClaudeNetwork`。 |
| 代理参数 | 示例策略集中保存出口 IP、端口和组名，但不是所有常量的唯一来源。`browser_entry.py`、`claude-fixed.cmd`、`route_verify.py`、`repair_proxy.py`、`routing-baseline.js` 和部分进程识别逻辑仍含固定端口或组名，迁移时须同步核对。 |
| Clash | 依赖 Clash Verge Rev 的数据目录和 `verge-mihomo-production-*` Windows 命名管道；不是任意 Mihomo 控制器的通用客户端。恢复后端还固定了 Clash 安装路径、订阅 / 脚本 UID 和前置节点名。 |
| Chrome | 正式浏览器路径为 `C:\Program Files\Google\Chrome\Application\chrome.exe`，专用资料约定为 `%LOCALAPPDATA%\ClaudeNetwork\ChromeData`。 |
| WebRTC 策略 | 当前门禁要求实际生效的 `WebRtcIPHandling=disable_non_proxied_udp` 来自 `managed`，且没有 URL 特例；仅有启动参数不够。工具不会自动建立或修改 Chrome 全局管理策略。 |
| Claude / VS Code | 需要已安装的官方客户端和指向专用入口的实际设置。登录状态、客户端及账号资料不随仓库分发。 |

`Deploy-ClaudeAudit.ps1` 要求原安装目录和四个桌面快捷方式已经存在。它是增量更新脚本，复制清单没有包含全部修复依赖；不能用作新机器安装器。其 `-RestoreOriginalShortcutWorkingDirectories` 参数另外依赖原机器的历史备份，不属于仓库恢复能力。

**不要把 `-Repair` 当作首次安装命令。** 它还需要本机 `repair-baseline.dpapi`、现存 Clash 配置及凭据，以及仓库之外的 `%USERPROFILE%\.codex\CodexNetworkGuard\health_monitor.py`。DPAPI 基线与 Windows 用户环境关联，不是跨机备份。恢复逻辑也涉及 Google、X、OpenAI 的分流；迁移前应核对整个 `routing-baseline.js`。普通只读检查不需要该 DPAPI 基线或外部守护模块。

## 已安装环境的使用方法

```powershell
claude-proxy                         # 使用前检查，不需要打开 Claude
claude-proxy -Full                   # 加查浏览器保护，通过后可启动专用浏览器
claude-proxy -Details                # 查看逐项检查和详细证据
claude-proxy -NoPrompt               # 禁用终端交互菜单
claude-proxy -Runtime                # 可选：自己启动并使用 Claude 后核验实际连接
claude-proxy -Runtime -Full -Details # 运行后核验，同时补测浏览器并显示详情
claude-proxy -LaunchCheck            # 桌面 CLI 启动入口使用的条件检查
claude-proxy -Workspace 'D:\MyProject'
claude-proxy -Full -Json -Output '.\proxy-audit.json'
claude-proxy -Repair                 # 仅在本机恢复依赖齐全时显式执行
```

`-Runtime` 是可选的启动后检查，不是预检前提，也不会启动应用。此模式要求每个运行中的 Claude 实例都有可关联的请求；未运行、空闲或证据不足时保留 `INCOMPLETE / 3`。它可以与 `-Full`、`-Details` 同用，不能与 `-LaunchCheck`、内部 `--preflight` 或 `-Repair` 混用。`-LaunchCheck` 也不能与 `-Full` 或 `-Repair` 混用。

`-Details` 只影响文字显示，不改变通过标准；`-Json` 始终包含完整结构化证据并自动关闭交互。需要稳定退出码的脚本调用应使用 `-NoPrompt` 或 `-Json`。

从源码直接调用审计器可以指定安装目录和实际项目，不依赖系统 PATH 中的旧命令：

```powershell
.\.venv\Scripts\python.exe -X utf8 -B .\claude-network\audit_proxy.py `
    --install-dir .\claude-network --workspace 'D:\MyProject' --full --no-prompt
```

| 状态 / 退出码 | 含义 |
| --- | --- |
| `ENVIRONMENT_READY / 0` | 使用前必要检查通过；默认模式可启动 CLI，`-Full` 还确认浏览器必要保护 |
| `CLAUDE_OBSERVED / 0` | 仅 `-Runtime`：必要检查通过，当前运行的 Claude 实例均已关联真实请求 |
| `LAUNCH_READY / 0` | 启动条件满足，不代表应用真实请求已验证 |
| `PROXY_READY / 0` | 内部网络预检通过，仅供门禁和兼容入口使用 |
| `NOT_READY / 2` | 存在明确错误 |
| `INCOMPLETE / 3` | 本模式必要证据不足；只有 `-Runtime` 要求应用真实请求证据，普通预检不因 Claude 未运行而进入此状态 |

关闭 Clash 窗口与停止 Mihomo 服务不同；界面消失但内核仍在运行时，代理可能仍正常。详情见 [使用说明](claude-network/使用说明.txt)。

## 本机验收记录

2026-10-06 对 `2026.10.06.6` 完成了 122 项回归检查，以及 CLI 实际模型请求、VS Code 新会话、专用浏览器真实出口 / WebRTC / 网站路由验证。另测试了有时限的代理入口故障和恢复，以及实际固定出口策略设为拒绝时，检查命令和启动门禁能否阻止继续使用。

当时最终完整检查仍为 `INCOMPLETE / 3`：网络、专用浏览器、WebRTC 和 DNS 项通过，但另一个既有空闲 VS Code 实例没有真实请求证据。这个状态没有被改写成全通过。

`2026.10.07.1` 将使用前环境检查与可选的 `-Runtime` 请求核验分开，默认命令不再要求先启动 Claude。2026-10-07 已在 Claude 和专用浏览器均关闭时，从 `C:\Users\32299` 实测正式 `claude-proxy -Full`：`ENVIRONMENT_READY / 0`，CLI 与浏览器启动条件均为 `READY`，配置、Clash 进程和 Chrome 策略保持不变。

本版共 167 项回归通过，包括交互取消 / 确认、修复后重检、中断、先备份再写入及受限回滚。修复写入行为使用隔离测试，本轮未为了验证菜单而改写实际网络或 Chrome 策略。这不等于重跑了上述历史模型请求验收。原始运行报告只保留在本机，仓库中的说明是当次验收摘要，不代表将来或其他电脑的运行状态。

这些短测不证明永久固定 IP、任意工具 / MCP / WSL / SSH 统一出口、所有未来请求、重启后的长期稳定或账号风控结果。

## 保存范围

仓库保存源码、测试、示例策略、构建和使用说明。`.gitignore` 排除真实策略 JSON、配置 YAML、DPAPI、浏览器资料、生成程序、快捷方式、部署备份、日志和运行报告；本机这些文件仍保留。

源码仍包含原工作站路径、节点名和部分历史目标地址，因此按私有仓库保存。这里没有代理密码、订阅链接、访问 token 或 Claude 登录资料，也不提供这些资料的恢复能力。不要用 `git add -f` 绕过排除规则上传本机配置。
