# src/
> L2 | 父级: ../CLAUDE.md
界面只管理输入、状态和执行记录；本机权限交给原生层，每次启动/修复/保护都由原生端重新检查。两入口（主窗口、指纹浏览器起始页）复用 YAML 中英文文案，原始诊断保留到呈现时翻译；系统语言与界面语言独立。
main.tsx: 极简侧栏三页——首页（使用 Claude）、连接监视、Claude 身份管理；首页常驻，隐藏到托盘时停止轮询；修复、设置保护或身份事务运行时锁定导航；托盘被拦截的启动原因显示在顶部。
proxy.tsx: 首页。固定出口概要、账号与出口、环境一致性栏（出口地区、系统时区与「对齐时区」、指纹浏览器时区/语言、定位与「关闭定位」、浏览器实测）、启动 Claude（CLI 工作目录、桌面客户端防火墙保护与「设置保护」确认、网页版=指纹浏览器）、检查项与两步修复。状态每 5 秒读取，完整结果 60 秒过期；连接走偏和 Clash 非规则模式只提醒。
proxy-state.ts: 缓存结果只影响显示不授予许可；`browser` 是网页版自己的门禁结论，`web` 是 Proxy-v2 登录链接入口；环境一致性按固定出口判定，任一侧未知不显示一致。
proxy-state.test.ts: 过期、错误、策略变化、守护异常不保留可用；网页版不受登录链接入口影响；环境一致性的对齐、漂移与未知。
proxy.css: 首页与连接监视共用的细线行、徽章与提醒色。
connections.tsx: 连接监视页，可见时每 2 秒读一次只读快照；每个目标只列一次，没走固定出口的标红置顶，Clash 读不到时保留已见记录并提示。
connections-model.ts / connections-model.test.ts: 快照合并、去重与排序的纯函数及其回归。
browser-model.ts: 起始页的配置、目标（含旅居者「出口时区 + 英文」）、机器、出口服务目录与观测契约，不接入原生权限；三平台设备/CPU/版本核验共用。
browser-start.tsx: 指纹浏览器起始页：实际 navigator/Intl/Permissions 与 HTTPS 出口上报，已测项目全部匹配、回传成功且无错误时整页绿底大对勾；随机令牌回环服务隔离宿主命令。
browser-network.ts / browser-network.test.ts: 经浏览器当前路由检测出口，限流/故障切换服务；离线模拟回归。
identities.tsx: 空身份最左、当前账号其次的竖式工牌；浏览器联动开关、把现有资料关联给当前身份、删除暂存身份时可同时删其浏览器资料；切换/恢复/永久删除 Alert 警告默认聚焦取消；显示网络复查警告；凭据不进 UI。
identity-model.ts: 身份目录、浏览器联动、当前显示字段和保留策略契约。
claude-cli-panel.tsx: 身份页内的 CLI 卸载/重装。
cleaner-activity.tsx: 身份与 CLI 事务的进度通道和有界日志。
cleaner-model.ts / cleaner-model.test.ts: 路径父子去重与规模格式化，供身份页预览共用。
dialog.tsx: Radix Dialog/AlertDialog 受控模态，警告默认聚焦取消。
language-switch.tsx: 中英文切换，原子持久化成功后更新界面。
index.css / style.css: 黑白主题与 Laper 外框、侧栏、竖式工牌和起始页绿底；部分上游页面样式仍在 style.css 中未清理。
i18n.ts / i18n.test.ts: 文案格式化与动态原生结果模板匹配；双语键/插槽一致和全部界面源文案覆盖。
locales/: 双语 YAML 目录；见其 CLAUDE.md。部分已删除页面的文案键仍在，未清理。
[PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
