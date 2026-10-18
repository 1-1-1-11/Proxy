## 本机网络配置保护

`archive.rs` 保存完整 settings 时剥离网络字段；`store.rs` 清空/恢复都经过 `cleaner::identity::full_settings` 原子保留当前的 HTTP_PROXY、HTTPS_PROXY、ALL_PROXY、NO_PROXY、BROWSER（包含大小写变体）。旧归档中的这些字段无法覆盖当前值。部分认证键的原有合并方式不变。

`mod.rs` 的切换/恢复/删除当前身份经 `browser::identity_action` 联动浏览器（退出、切换、过门禁后重开），再调用 Proxy-v2 完整复查，失败明确说明身份操作与网络验证各自的状态。未恢复事务通过 `ensure_settled` 阻止整合入口启动。新版首次打开保险库会升级表结构，旧版程序读不了升级后的库。测试只使用临时 home 和虚构账号。

# identities/
> L2 | 父级: ../CLAUDE.md
mod.rs: 当前/空/已保存身份与切换/恢复/重命名/直接删除/停止进程/浏览器联动设置命令，复用 Cleaner 全局事务锁；UI 接收目录元数据及显式允许的本地账号显示字段；令牌不送 UI。
database.rs: SQLite 管理稳定账号槽位、不可变归档代次、浏览器资料绑定、HMAC 索引与持久恢复状态；旧版事务迁移，FULL 同步，凭据正文不入库。
store.rs: 先验收归档再切换工作区、失败回滚、独立恢复检查点与无新增备份删除。
archive.rs: tar/Zstd 新归档与旧 gzip 兼容验收，归档代次与稳定卡片编号分离；完整认证后才交目录事务。
catalog.rs: 以本机 HMAC 匹配账号与稳定槽位，未知账号不猜测合并。
compression.rs: Zstandard 流式压缩，读取侧按魔数兼容旧 gzip。
browser_link.rs: 身份到独占浏览器资料的绑定、稳定非零种子与绑定身份摘要；不读取 Cookie。
profile.rs: 只读默认 .claude.json 的用户名/邮箱/组织显示白名单；不读取钥匙串或 Cookie 正文。
credentials.rs: 默认 Code 凭据按用户策略合并身份与共享 MCP/插件秘密；正文只在原生内存流动。
codec.rs: ring AES-256-GCM 帧，独立归档密钥和认证结尾；拒绝篡改、截断与非法归档成员。
private.rs: POSIX 0700/0600 与 Windows 创建时指定当前用户所有者/独占 DACL、原子写入；拒绝所有者变化、链接和特殊文件。
tests.rs / optimization_tests.rs / browser_link_tests.rs: 临时账号样本的空身份、恢复、配置与网络字段保留、损坏与链接拒绝、连续切换、跨组织隔离、压缩兼容和浏览器绑定回归，不接触真实账号。
[PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
