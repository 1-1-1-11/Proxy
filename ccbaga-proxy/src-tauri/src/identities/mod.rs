// [INPUT]: SQLite 身份目录、加密压缩保险库、Cleaner 全局事务锁与 Tauri 进度通道。
// [OUTPUT]: 当前/空/已保存身份、有界账号显示信息、用户保留选项、浏览器联动确认及确认后的切换/恢复/重命名/直接删除命令。
// [POS]: GUI 身份管理的原生入口；不提供凭据读取、任意文件或网络接口。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
mod archive;
pub(crate) mod browser_link;
#[cfg(test)]
mod browser_link_tests;
mod catalog;
mod codec;
mod compression;
mod credentials;
pub(crate) mod database;
#[cfg(test)]
mod optimization_tests;
pub(crate) mod private;
mod profile;
mod store;
#[cfg(test)]
mod tests;
use crate::progress::{Progress, Reporter};
use serde::{Deserialize, Serialize};
use tauri::{ipc::Channel, Manager};
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub skills: bool,
    pub plugins: bool,
    pub mcp: bool,
    pub settings: bool,
    pub projects: bool,
    pub history: bool,
    pub cache: bool,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            skills: true,
            plugins: true,
            mcp: true,
            settings: true,
            projects: true,
            history: false,
            cache: false,
        }
    }
}
impl Policy {
    pub fn all() -> Self {
        Self {
            skills: false,
            plugins: false,
            mcp: false,
            settings: false,
            projects: false,
            history: false,
            cache: false,
        }
    }
    pub fn keeps(&self, category: &str) -> bool {
        match category {
            "skills" => self.skills,
            "plugins" => self.plugins,
            "mcp" => self.mcp,
            "settings" => self.settings,
            "history" => self.history,
            "cache" => self.cache,
            _ => false,
        }
    }
}
#[derive(Serialize)]
pub struct State {
    pub browser: browser_link::BrowserLink,
    pub browser_warning: Option<String>,
    pub records: Vec<database::Record>,
    pub active: String,
    pub recovery: Option<String>,
    pub running: bool,
    pub current: profile::Current,
    pub network_warning: Option<String>,
}
pub(crate) fn new_id() -> Result<String, String> {
    Ok(codec::random::<16>()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}
pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn name(value: &str) -> Result<String, String> {
    let n = value.trim();
    if n.is_empty() || n.chars().count() > 64 || n.chars().any(char::is_control) {
        Err("身份名称需要 1–64 个字符。".into())
    } else {
        Ok(n.into())
    }
}
fn vault(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|_| "身份保险库无法定位。")?
        .join("identity-vault"))
}
pub(crate) fn ensure_settled(app: &tauri::AppHandle) -> Result<(), String> {
    let path = vault(app)?;
    if path.exists() && database::Database::open(&path)?.get("recovery")?.is_some() {
        return Err("身份切换尚未恢复完成，请先到身份管理中恢复。".into());
    }
    Ok(())
}
/// 身份只影响 CLI 读取的设置；复查失败时操作本身仍算完成，以警告返回，启动入口自会再拦。
fn verify_after(app: &tauri::AppHandle, operation: Result<(), String>) -> Result<Option<String>, String> {
    let verification = crate::fixed_proxy::call(app, "check").and_then(|report| {
        match report["entries"]["cli"].as_str() {
            Some("ready") => Ok(()),
            _ => Err("固定出口检查未通过。".to_string()),
        }
    });
    match (operation, verification) {
        (Ok(()), Ok(())) => Ok(None),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(_)) => Ok(Some("网络复查未通过：Claude CLI 暂时不能启动，请到固定出口页查看原因。".into())),
        (Err(error), Err(_)) => Err(format!("{error} 网络复查也未通过，请到固定出口页面检查。")),
    }
}
/// Whitelisted email of the current Claude login, shown on the home page.
pub(crate) fn current_email() -> Option<String> {
    profile::read(&crate::cleaner::identity::root().ok()?).email
}
fn state(app: &tauri::AppHandle) -> Result<State, String> {
    let db = database::Database::open(&vault(app)?)?;
    Ok(State {
        browser: db.browser_link()?,
        browser_warning: app
            .state::<crate::browser::Browser>()
            .warning
            .lock()
            .unwrap()
            .clone(),
        records: db.records()?.into_iter().filter(|r| !r.empty).collect(),
        active: catalog::current_id(&vault(app)?, &crate::cleaner::identity::root()?, &db)?
            .unwrap_or_else(|| "current".into()),
        recovery: db.get("recovery")?,
        running: crate::cleaner::identity::processes_running()?,
        current: profile::read(&crate::cleaner::identity::root()?),
        network_warning: None,
    })
}
#[tauri::command]
pub async fn identities_read(app: tauri::AppHandle) -> Result<State, String> {
    tauri::async_runtime::spawn_blocking(move || state(&app))
        .await
        .map_err(|_| "身份列表读取被中断。".to_string())?
}
#[tauri::command]
pub async fn identities_stop(app: tauri::AppHandle) -> Result<(), String> {
    let cleaner = app.state::<crate::cleaner::Cleaner>();
    cleaner.enter()?;
    let result = tauri::async_runtime::spawn_blocking(crate::cleaner::stop_processes)
        .await
        .map_err(|_| "结束进程被中断，请刷新。".to_string())
        .and_then(|r| r)
        .map(|_| ());
    cleaner.leave();
    result
}
#[tauri::command]
pub async fn identities_switch(
    app: tauri::AppHandle,
    target_id: String,
    current_name: String,
    policy: Policy,
    recover: bool,
    on_progress: Channel<Progress>,
) -> Result<State, String> {
    let current_name = name(&current_name)?;
    if target_id != "empty" && !valid_id(&target_id) {
        return Err("身份编号无效。".into());
    }
    let cleaner = app.state::<crate::cleaner::Cleaner>();
    cleaner.enter()?;
    let worker = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let reporter = Reporter::channel(Some(on_progress));
        let changed = crate::browser::identity_action(&worker, &reporter, || {
            let mut store =
                store::Store::open(&vault(&worker)?, &crate::cleaner::identity::root()?)?;
            if recover {
                store.recover(&current_name, &reporter)
            } else {
                store.switch(&target_id, &current_name, &policy, &reporter)
            }
        });
        let result = verify_after(&worker, changed)
            .and_then(|warning| Ok(State { network_warning: warning, ..state(&worker)? }));
        if let Err(e) = &result {
            reporter.fail(e);
        }
        result
    })
    .await
    .map_err(|_| "身份切换中断；请使用恢复操作。".to_string())
    .and_then(|r| r);
    cleaner.leave();
    result
}
#[tauri::command]
pub async fn identities_rename(
    app: tauri::AppHandle,
    id: String,
    value: String,
) -> Result<State, String> {
    if !valid_id(&id) {
        return Err("身份编号无效。".into());
    }
    let value = name(&value)?;
    let cleaner = app.state::<crate::cleaner::Cleaner>();
    cleaner.enter()?;
    let worker = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let db = database::Database::open(&vault(&worker)?)?;
        if db.get("recovery")?.is_some() {
            return Err("请先恢复未完成的身份切换。".into());
        }
        db.rename(&id, &value)?;
        state(&worker)
    })
    .await
    .map_err(|_| "身份名称保存被中断。".to_string())
    .and_then(|r| r);
    cleaner.leave();
    result
}

#[tauri::command]
pub async fn identities_delete(
    app: tauri::AppHandle,
    id: String,
    policy: Policy,
    delete_browser: Option<bool>,
    on_progress: Channel<Progress>,
) -> Result<State, String> {
    if id != "current" && !valid_id(&id) {
        return Err("身份编号无效。".into());
    }
    let cleaner = app.state::<crate::cleaner::Cleaner>();
    cleaner.enter()?;
    let worker = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let reporter = Reporter::channel(Some(on_progress));
        let action = || {
            let mut store =
                store::Store::open(&vault(&worker)?, &crate::cleaner::identity::root()?)?;
            store.delete(&id, &policy, &reporter)?;
            Ok(())
        };
        let result = if id == "current" {
            verify_after(&worker, crate::browser::identity_action(&worker, &reporter, action))
        } else {
            crate::browser::delete_saved(&worker, &id, delete_browser.unwrap_or(false), action).map(|_| None)
        }
        .and_then(|warning| Ok(State { network_warning: warning, ..state(&worker)? }));
        if let Err(e) = &result {
            reporter.fail(e);
        }
        result
    })
    .await
    .map_err(|_| "直接删除中断；请刷新检查剩余数据。".to_string())
    .and_then(|r| r);
    cleaner.leave();
    result
}

#[tauri::command]
pub async fn identities_browser(
    app: tauri::AppHandle,
    enabled: bool,
    use_existing: bool,
) -> Result<State, String> {
    let cleaner = app.state::<crate::cleaner::Cleaner>();
    cleaner.enter()?;
    let worker = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        let reporter = Reporter::channel(None);
        crate::browser::configure_identity(&worker, &reporter, || {
            let mut db = database::Database::open(&vault(&worker)?)?;
            let current =
                catalog::current_id(&vault(&worker)?, &crate::cleaner::identity::root()?, &db)?;
            db.configure_browser(enabled, use_existing, current.as_deref())
        })?;
        state(&worker)
    })
    .await
    .map_err(|_| "浏览器联动设置被中断，请刷新。".to_string())
    .and_then(|r| r);
    cleaner.leave();
    result
}
