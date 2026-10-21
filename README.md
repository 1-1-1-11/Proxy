# Proxy

> **Development continues at [CC-Guard](https://github.com/1-1-1-11/CC-Guard).** This repository is the predecessor and is kept for reference.
>
> **后续开发在 [CC-Guard](https://github.com/1-1-1-11/CC-Guard)。** 本仓库停在 2026-10-18 前后的公开快照，只供查阅。不要在这里继续加功能，也不要按这里的路径部署到正在使用的电脑上。

一组 Windows 工作站上的历史工具：让官方 Claude 账号从固定出口出去；出口不对就断开；桌面程序负责浏览器和本机账号状态跟这个出口一致。

这不是通用安装包。公开树里的用户名、安装路径、订阅节点名和 Clash 配置 UID 都已换成示例。

## 仓库里有什么

| 路径 | 是什么 | 状态 |
| --- | --- | --- |
| [`ccbaga-proxy/`](ccbaga-proxy/) | 基于 [CCBaga](https://github.com/liseami/CCBaga)（MIT）改过的 Tauri 桌面程序。快照对应整合分支 `codex/proxy-integration` 的 `8d2d4bd`，不带上游提交历史。 | 历史快照 |
| [`proxy-v2/`](proxy-v2/) | 本机上的路由基线、只读检查、修复和后台守护。快照对应 `3f5f7be`。 | 历史快照 |
| [`v1/`](v1/) | 第一版检查和修复工具。2026-10-12 归档。标签 `v1-final` 是最后一次部署时的树。 | 已归档 |

三个目录各自保留 README、测试和许可证。相对链接只在该目录内有效。`ccbaga-proxy/.github/workflows/` 里的上游检查和发布流程不会在本仓库运行，GitHub 只读取仓库根目录的工作流。本仓库不另加发布流程。

## 各部分怎么接在一起

```text
Claude CLI、VS Code、桌面客户端
  -> Clash 监听 127.0.0.1:17892（钉在「Claude-固定出口」）
  -> 固定出口链：一个前置节点，再到同一条 SOCKS5 出口
     （组里只有这条链和 REJECT，没有直连兜底）

其他流量
  -> Clash TUN 和规则：国内站点 DIRECT，其余走日常代理组

Proxy v2 守护，大约每 30 秒
  -> 核对出口；IP 不对就把受保护组切到 REJECT，并断开它们的连接

CCBaga Proxy
  -> 桥接调用 Proxy v2 的检查和修复（白名单动作，版本锁定）
  -> 首页、托盘和指纹浏览器门禁展示并执行这个结果
```

- 路由基线在 `proxy-v2/claude-network/routing-baseline.js`。公开快照里的前置节点名是 `Example-JP-HY2`、`Example-KR-HY2`、`Example-SG-A`、`Example-US-A`。固定出口链把 `Example-KR-HY2` 排在前面。
- `proxy-v2/claude-network/check.py` 的 `VERSION` 必须等于 `ccbaga-proxy/proxy-bridge/bridge.py` 的 `SUPPORTED_VERSION`（快照里是 `2026.10.17`）。
- 网页会话和登录链接当时只从 CCBaga Proxy 的指纹浏览器打开。时区跟随固定出口，语言是 en-US。

更细的历史说明在 [`proxy-v2/README.md`](proxy-v2/README.md)、[`v1/README.md`](v1/README.md) 和 [`ccbaga-proxy/docs/proxy-integration.md`](ccbaga-proxy/docs/proxy-integration.md)。

## 环境

看代码和跑离线测试需要：

- Python 3.11 或更新版本。本仓库 CI 使用 3.13。
- `psutil` 和 `PyYAML`，版本见 [`proxy-v2/requirements.txt`](proxy-v2/requirements.txt)。v1 的 `requirements.txt` 还列了 playwright，离线测试不启动浏览器，所以 CI 不装它。
- `node` 在 PATH 上。路由基线测试会调用它。Windows 上若存在 `C:\Program Files\nodejs\node.exe`，修复脚本仍优先用那个路径。

原来那台工作站还假设这些条件。它们不是阅读本仓库的前提：

- Windows 10 或 11，Clash Verge Rev 开着服务模式和 TUN，订阅里有前置节点和一条 SOCKS5 出口。
- 构建桌面程序时的 Bun、Rust 和 Tauri。
- 示例路径，不是原电脑上的路径：Python `C:\Tools\Python\python.exe`，Clash `C:\Tools\ClashVerge\clash-verge.exe`，用户 `C:\Users\example`。
- 安装位置仍按设计写在 `%USERPROFILE%\.codex\ClaudeNetwork` 和 `%USERPROFILE%\.codex\CodexNetworkGuard`。

预期出口只放在本机的 `audit_policy.json`（从 `audit_policy.example.json` 复制）。该文件已被忽略，不要提交。示例地址是 `203.0.113.10`。

## 快速开始

下面两条是原工作站上的用法。公开快照不能直接装回去：

```powershell
claude-proxy            # 只读检查
claude-proxy -Repair    # 修复受管理的 Clash 配置后再检查；可能重启 Clash
```

离线测试不连外网，也不读本机 Clash：

```bash
python -m pip install -r proxy-v2/requirements.txt
cp proxy-v2/claude-network/audit_policy.example.json proxy-v2/claude-network/audit_policy.json
cp v1/claude-network/audit_policy.example.json v1/claude-network/audit_policy.json
python -m unittest discover -s proxy-v2/claude-network -p 'test_*.py'
python -m unittest discover -s v1/claude-network -p 'test_*.py'
python -m unittest discover -s ccbaga-proxy/proxy-bridge -p 'test_*.py'
python ccbaga-proxy/skills/ccbaga-network/scripts/test_network.py
```

桌面程序的 Bun / Cargo 检查写在 [`ccbaga-proxy/README.md`](ccbaga-proxy/README.md)。本仓库 CI 不跑它们。

## 安全

- 这些工具只决定网络出口。本机程序仍能读到时区、系统语言、用户名，以及你授权的文件夹。
- 守护大约每 30 秒核对一次。出口变了，最多大约 30 秒后才会切断。
- 普通浏览器里的 claude.ai 只在 Clash 规则模式下走固定出口。网页会话要用当时的指纹浏览器。
- 不要提交订阅链接、节点密码、`audit_policy.json`、`repair-baseline.dpapi`、私钥或本机 Clash 配置。
- 公开树已去掉工作站标识。Git 历史里还在，本次没有重写历史。见 [SECURITY.md](SECURITY.md)。

## 验证过什么，没验证过什么

下面是原作者机器上、脱敏之前记下的结果，不是这次 CI 重新跑出来的：

| 日期 | 检查 | 当时的结果 |
| --- | --- | --- |
| 2026-10-18 | Proxy v2 离线测试 | 67 项通过 |
| 2026-10-17 | `bun run build`、`bun test`、`bun run test:bridge`、`bun run test:identities` | 类型检查和构建通过；25、33、19 项通过 |
| 2026-10-17 | `cargo test` | 77 项通过，3 项按设计忽略 |

本仓库 CI 只在 Ubuntu 上做公开树检查、Python 语法检查，以及上一节的离线测试。不构建 Tauri，不签名，不发布。

没有验证过：网页和登录链接的实际点击、真实账号切换、防火墙保护的实际写入、在坏掉的环境上真的修复、重启、休眠恢复、长时间断网、独立的 DNS 和 WebRTC 泄漏测试。

不保证账号状态、地区资格，或供应商一直提供同一个静态 IP。

## 许可

Proxy v1、Proxy v2 和本仓库的维护文件以 MIT 许可发布，版权归徐俊毅（GitHub [1-1-1-11](https://github.com/1-1-1-11)），见 [LICENSE](LICENSE)。

`ccbaga-proxy/` 是 [liseami/CCBaga](https://github.com/liseami/CCBaga) 的修改副本，版权归 CCBaga contributors，全文在 [ccbaga-proxy/LICENSE](ccbaga-proxy/LICENSE)。第三方边界和尚未确认的许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 与 [ccbaga-proxy/NOTICE.md](ccbaga-proxy/NOTICE.md)。

## 参与

文档、许可和安全清理见 [CONTRIBUTING.md](CONTRIBUTING.md)。新功能请报到 [CC-Guard](https://github.com/1-1-1-11/CC-Guard)。
