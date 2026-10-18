## 本机固定出口适配

Windows 的代理来自已安装 Proxy-v2，所有启动路径（首页/托盘 `fixed_proxy::launch` → `open_gated`、`--browser` 入口 → `start_windows_companion`、`browser_launch`、切换身份后 `workspaces::transition` 重开）都先过独立 `check-browser` 门禁，把门禁给出的专用端口写入当前身份配置，并核对已运行资料进程的实际代理/UDP/QUIC 参数；危险开关的带值、前缀及大小写变体均拒绝。门禁不通过就不启动或不重开，原因写回界面。宿主启动不自动带起浏览器。

每次启动 `Config::follow_exit` 把时区设为固定出口时区、语言设为 en-US；出口读不到或本机不支持该时区时保留原设置。只剩读取（`browser_read`）与启动（`browser_launch`）两个命令；保存、换指纹、清缓存、对齐、默认浏览器等原版页面命令已删除，macOS/Linux 平台实现保留未动。`record_entry` 把宿主路径写入 `browser-entry.json` 供登录链接交接。下面的原版 macOS/Linux 默认代理与自动 companion 说明不用于本机整合版本。

# browser/
> L2 | 父级: ../CLAUDE.md
mod.rs: 浏览器读取/启动命令、单次变更锁与运行时状态、引擎发现、起始页会话（start.url）与 launch.args；`managed_config` 按当前身份资料目录读配置并强制写入固定代理。
launch.rs: 已持有浏览器互斥锁时的唯一启动核心，接收门禁给出的专用端口；身份联动与手动启动共用。
workspaces.rs: 以 SQLite 绑定解析当前身份的独占资料与配置、稳定种子；切换身份时正常退出、切换、重新过门禁后重开；恢复未完成时阻断启动；删除暂存身份时可单独确认删除其资料。
config.rs: 指纹配置、实际机器参数、代理/语言白名单、跟随出口规则与 Chromium 参数生成；明确启动 Default 资料。
profile.rs: 资料目录边界、进程占用检查、偏好窄范围写入；缓存清理只供测试使用。
network.rs: 平台与浏览器观测核验、出口服务备援、目标国家/语言/区域匹配（含旅居者目标，不要求系统语言属于该地区）。
server.rs: 随机令牌回环服务与打包静态资源（含图片 MIME 白名单）；上下文提供核验目标与绑定身份摘要。
windows.rs: Windows 引擎、`open_gated` 与 `--browser` 入口、浏览器入口登记。
tests.rs / workspace_tests.rs: 临时目录样本，验证代理/资料边界、缓存与 Cookie 隔离、种子稳定、恢复阻断与跟随出口规则；不触碰现有账号数据。
linux.rs: Linux 引擎与启动项（本机整合版未使用，保留未动）。
[PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
