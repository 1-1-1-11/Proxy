// [INPUT]: 本机指纹引擎（优先 /Applications/CCBaga-B.app，回退 ~/Applications）、配置/资料边界、真实浏览器观测、宿主界面语言与共享操作日志。
// [OUTPUT]: 有界绑定身份上下文与浏览器设置/启动/清理和环境核验；宿主重启重新连接现有浏览器，回报时间明确标识通讯状态；上下文提供当前界面语言；launch.args 与 SQLite 当前身份共用独占资料/指纹参数，恢复期间阻断启动。
// [POS]: 独立浏览器模块的唯一编排入口；改变资料前必须退出浏览器；不自行改系统默认浏览器，只发起系统确认。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
pub(crate) mod config;
mod launch;
pub(crate) mod network;
mod profile;
mod workspaces;
use launch::launch_locked;
pub(crate) use workspaces::delete_saved;
pub(crate) use workspaces::identity_action;
pub(crate) fn configure_identity(
    app: &tauri::AppHandle,
    reporter: &Reporter,
    action: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    workspaces::transition(app, reporter, true, action)
}
#[cfg(target_os = "linux")]
include!("linux.rs");
#[cfg(target_os = "windows")]
include!("windows.rs");
pub(crate) mod server;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod workspace_tests;
#[cfg(target_os = "linux")]
use crate::linux::*;
#[cfg(not(target_os = "windows"))]
use crate::native::decode;
use crate::progress::{Progress, Reporter};
use config::{Config, Machine};
use network::{Check, Exit, Report};
#[cfg(not(target_os = "windows"))]
use serde::Deserialize;
use serde::Serialize;
#[cfg(target_os = "macos")]
use std::ffi::{c_char, CString};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
};
use tauri::{ipc::Channel, Manager};
#[cfg(target_os = "macos")]
extern "C" {
    fn rf_browser_register(path: *const c_char) -> *mut c_char;
    fn rf_browser_default_read(bundle: *const c_char) -> *mut c_char;
    fn rf_browser_set_default(bundle: *const c_char) -> *mut c_char;
    fn rf_system_region(language: *const c_char, locale: *const c_char) -> *mut c_char;
    fn rf_system_timezone(zone: *const c_char) -> *mut c_char;
    fn rf_system_location() -> *mut c_char;
}
#[derive(Default)]
pub struct Browser {
    gate: Mutex<()>,
    pub(crate) warning: Mutex<Option<String>>,
    session: Mutex<Option<Session>>,
    host: Mutex<Option<Exit>>,
}
struct Session {
    token: String,
    received_at: Option<u64>,
    report: Option<Report>,
}
#[derive(Clone, Serialize)]
pub struct Context {
    identity: crate::identities::browser_link::BrowserIdentity,
    ui_language: String,
    exit_services: &'static [&'static str],
    region: Option<crate::regions::Target>,
    config: Config,
    machine: Machine,
    engine_version: String,
}
#[derive(Serialize)]
pub struct Snapshot {
    ui_language: String,
    exit_services: &'static [&'static str],
    region: Option<crate::regions::Target>,
    config: Config,
    machine: Machine,
    engine_version: String,
    engine_ready: bool,
    running: bool,
    profile: String,
    identity_linked: bool,
    cache: Vec<profile::CacheItem>,
    cache_error: String,
    report: Option<Report>,
    report_received_at: Option<u64>,
    machine_exit: Option<Exit>,
    checks: Vec<Check>,
}
// The default-browser controls remain on macOS/Linux; Windows has no default-browser page.
#[cfg(not(target_os = "windows"))]
#[derive(Serialize, Deserialize)]
pub struct DefaultBrowser {
    is_default: bool,
    http: String,
    https: String,
    #[serde(default)]
    installed: bool,
    #[serde(default)]
    app: String,
}
fn identity_context(
    app: &tauri::AppHandle,
) -> Result<crate::identities::browser_link::BrowserIdentity, String> {
    let root = root(app)?;
    let vault = root
        .parent()
        .ok_or("应用目录不可用。")?
        .join("identity-vault");
    workspaces::database(&root)?.browser_identity(&vault, &crate::cleaner::identity::root()?)
}
fn root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app
        .path()
        .app_data_dir()
        .map_err(|_| "应用目录不可用。")?
        .join("browser"))
}
/// The current identity's browser config, always on the installed fixed proxy.
fn managed_config(app: &tauri::AppHandle, settings: &Path) -> Result<Config, String> {
    let mut config = config::load(settings)?;
    config.proxy = crate::fixed_proxy::endpoint(app)?;
    Ok(config)
}
#[cfg(target_os = "macos")]
pub const BROWSER_ID: &str = "ai.local.requirement-french.browser";
#[cfg(target_os = "macos")]
const BROWSER_APP: &str = "CCBaga-B.app";
#[cfg(target_os = "macos")]
const LSREGISTER: &str = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
/// install-apps.sh 安装的 CCBaga-B：优先 /Applications，回退 ~/Applications；存在时作为唯一引擎，避免同一包标识出现两份注册。
#[cfg(target_os = "macos")]
fn installed() -> Option<PathBuf> {
    let mut places = vec![PathBuf::from("/Applications")];
    if let Some(home) = std::env::var_os("HOME") {
        places.push(PathBuf::from(home).join("Applications"));
    }
    places
        .into_iter()
        .map(|dir| dir.join(BROWSER_APP))
        .find(|app| app.join("Contents/MacOS/Chromium").is_file())
}
#[cfg(target_os = "macos")]
fn register(engine: &Path) -> Result<(), String> {
    let path = CString::new(engine.to_string_lossy().as_bytes()).map_err(|_| "引擎路径无效。")?;
    let _: serde_json::Value = decode(unsafe { rf_browser_register(path.as_ptr()) })?;
    Ok(())
}
#[cfg(target_os = "macos")]
fn bundle_id() -> CString {
    CString::new(BROWSER_ID).unwrap()
}
/// CCBaga-B 入口（launcher/CCBrowser.c）读取的参数：与实测启动相同，只去掉起始页。
fn write_launch_args(
    root: &Path,
    config: &Config,
    machine: &Machine,
    profile: &Path,
    version: &str,
) -> Result<(), String> {
    let mut args = config::arguments(config, machine, profile, "", version);
    args.pop();
    crate::identities::private::directory(root)?;
    crate::identities::private::write(
        &root.join("launch.args"),
        (args.join("\n") + "\n").as_bytes(),
    )?;
    workspaces::unblock(root)
}
fn refresh_launch_args(app: &tauri::AppHandle) -> Result<(), String> {
    let root = root(app)?;
    workspaces::ensure(&root)?;
    let settings = workspaces::scope(&root)?;
    let profile = settings.join("profile");
    profile::check_path(&root, &profile)?;
    let config = managed_config(app, &workspaces::scope(&root)?)?;
    let machine = config::machine()?;
    config.validate(&machine)?;
    let engine = engine(app)?;
    write_launch_args(
        &root,
        &config,
        &machine,
        &profile,
        &packaged_version(app, &engine),
    )?;
    workspaces::unblock(&root)
}
/// 新建起始页会话：随机令牌回环服务 + 写入 browser/start.url（0600），供 CCBrowser 入口在每次全新启动时作为首个标签打开。
fn open_session(
    app: &tauri::AppHandle,
    config: &Config,
    machine: &Machine,
    engine_version: String,
) -> Result<String, String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let state = app.state::<Browser>();
    let listener = server::bind()?;
    let port = listener
        .local_addr()
        .map_err(|_| "本地端口不可用。")?
        .port();
    let token = server::nonce()?;
    let page = format!("http://127.0.0.1:{port}/{token}/browser.html");
    let context = Context {
        identity: identity_context(app)?,
        ui_language: crate::ui_language::ui_language_read(app.clone()),
        exit_services: &network::SERVICES,
        region: crate::regions::target(&config.language(machine), &config.timezone(machine)),
        config: config.clone(),
        machine: machine.clone(),
        engine_version,
    };
    let web = web(app)?;
    *state.session.lock().unwrap() = Some(Session {
        token: token.clone(),
        report: None,
        received_at: None,
    });
    server::start(app.clone(), listener, token, web, context);
    let root = root(app)?;
    fs::create_dir_all(&root).map_err(|_| "无法创建浏览器目录。")?;
    let temp = root.join("start.url.tmp");
    let mut options = fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temp).map_err(|_| "无法写入起始页地址。")?;
    file.write_all(format!("{page}\n").as_bytes())
        .map_err(|_| "无法写入起始页地址。")?;
    fs::rename(&temp, root.join("start.url")).map_err(|_| "无法写入起始页地址。")?;
    Ok(page)
}
/// 宿主退出时删除 start.url，避免 CCBrowser 入口读到失效令牌。
pub fn forget_start_url(app: &tauri::AppHandle) {
    if let Ok(root) = root(app) {
        let _ = fs::remove_file(root.join("start.url"));
    }
}
/// 宿主启动时建立起始页会话并带起 CCBaga-B（已在运行则不动），不抢焦点。
#[cfg(target_os = "macos")]
pub fn companion(app: tauri::AppHandle) {
    std::thread::spawn(move || {
        if let Err(error) = start_companion(&app) {
            eprintln!("CCBaga-B未随宿主启动：{error}");
        }
    });
}
#[cfg(target_os = "macos")]
fn start_companion(app: &tauri::AppHandle) -> Result<(), String> {
    let browser = installed().ok_or("未安装 /Applications/CCBaga-B.app。")?;
    let state = app.state::<Browser>();
    let _guard = state.gate.lock().unwrap();
    let root = root(app)?;
    workspaces::ensure(&root)?;
    let settings = workspaces::scope(&root)?;
    let profile = settings.join("profile");
    profile::check_path(&root, &profile)?;
    let config = managed_config(app, &workspaces::scope(&root)?)?;
    let machine = config::machine()?;
    config.validate(&machine)?;
    // 先刷新参数：浏览器已由 CCBaga-B 入口先行启动时，下一次启动也能沿用指纹参数。
    write_launch_args(&root, &config, &machine, &profile, &version(&browser))?;
    let page = open_session(app, &config, &machine, version(&browser))?;
    if profile::running(&profile)? {
        // 宿主重装/重启后端口与令牌变化：给运行中的浏览器打开新的实测页，避免旧标签失联。
        let mut child = Command::new(browser.join("Contents/MacOS/Chromium"))
            .arg(format!("--user-data-dir={}", profile.display()))
            .args(["--profile-directory=Default", &page])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "无法重新连接运行中的 CCBaga-B。")?;
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        return Ok(());
    }
    profile::preferences(&profile, &config, &machine)?;
    register(&browser)?;
    let status = Command::new("/usr/bin/open")
        .args(["-g", "-a"])
        .arg(&browser)
        .status()
        .map_err(|_| "无法打开 CCBaga-B。")?;
    if !status.success() {
        return Err("LaunchServices 拒绝打开 CCBaga-B。".into());
    }
    Ok(())
}
#[cfg(target_os = "macos")]
fn default_read() -> Result<DefaultBrowser, String> {
    let id = bundle_id();
    let mut value: DefaultBrowser = decode(unsafe { rf_browser_default_read(id.as_ptr()) })?;
    let browser = installed();
    value.installed = browser.is_some();
    value.app = browser
        .map(|x| x.to_string_lossy().into())
        .unwrap_or_default();
    Ok(value)
}
/// 一键设为默认浏览器：重新注册已安装的 CCBaga-B，注销应用数据中的旧引擎副本，再请求系统切换；macOS 会弹出确认框。
#[cfg(target_os = "macos")]
#[tauri::command]
pub async fn browser_set_default(app: tauri::AppHandle) -> Result<DefaultBrowser, String> {
    run(move || {
        let browser = installed()
            .ok_or("未找到 /Applications/CCBaga-B.app，请先运行 bun run install:apps。")?;
        let copy = root(&app)?.join("engine/Browser.app");
        if copy.exists() {
            let _ = Command::new(LSREGISTER).arg("-u").arg(&copy).status();
        }
        let _ = Command::new(LSREGISTER).arg("-f").arg(&browser).status();
        register(&browser)?;
        let id = bundle_id();
        let _: serde_json::Value = decode(unsafe { rf_browser_set_default(id.as_ptr()) })?;
        default_read()
    })
    .await
}
#[cfg(target_os = "macos")]
fn engine(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    if let Some(browser) = installed() {
        return Ok(browser);
    }
    let installed = root(app)?.join("engine/Browser.app");
    if installed.exists() {
        return Ok(installed);
    }
    if cfg!(debug_assertions) {
        return Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../browser-runtime/Browser.app"));
    }
    Ok(installed)
}
#[cfg(target_os = "macos")]
fn prepare_engine(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let engine = engine(app)?;
    if binary(&engine).is_file() {
        return Ok(engine);
    }
    let parent = engine.parent().ok_or("引擎目录无效。")?;
    profile::check_path(&root(app)?, parent)?;
    fs::create_dir_all(parent).map_err(|_| "无法安装内置引擎。")?;
    let archive = app
        .path()
        .resource_dir()
        .map_err(|_| "资源目录不可用。")?
        .join("browser-runtime/Browser.zip");
    let status = Command::new("/usr/bin/ditto")
        .args(["-x", "-k"])
        .arg(archive)
        .arg(parent)
        .status()
        .map_err(|_| "无法解压内置引擎。")?;
    if !status.success() || !binary(&engine).is_file() {
        return Err("内置引擎安装失败。".into());
    }
    Ok(engine)
}
fn packaged_version(app: &tauri::AppHandle, engine: &Path) -> String {
    if engine.exists() {
        return version(engine);
    }
    app.path()
        .resource_dir()
        .ok()
        .and_then(|p| fs::read_to_string(p.join("browser-runtime/version.txt")).ok())
        .unwrap_or_default()
        .trim()
        .into()
}
fn web(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let packaged = app
        .path()
        .resource_dir()
        .map_err(|_| "资源目录不可用。")?
        .join("browser-ui");
    if packaged.join("browser.html").exists() {
        return Ok(packaged);
    }
    if cfg!(debug_assertions) {
        return Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../dist"));
    }
    Err("浏览器起始页缺失。".into())
}
#[cfg(target_os = "macos")]
fn version(engine: &Path) -> String {
    let out = Command::new("/usr/bin/plutil")
        .args(["-extract", "CFBundleShortVersionString", "raw", "-o", "-"])
        .arg(engine.join("Contents/Info.plist"))
        .output();
    out.ok()
        .filter(|x| x.status.success())
        .map(|x| String::from_utf8_lossy(&x.stdout).trim().to_string())
        .unwrap_or_default()
}
fn snapshot(app: &tauri::AppHandle) -> Result<Snapshot, String> {
    let root = root(app)?;
    let settings = workspaces::scope(&root)?;
    let profile = settings.join("profile");
    profile::check_path(&root, &profile)?;
    let machine = config::machine()?;
    // 只读快照：桥接暂不可用时显示上次保存的固定代理，缓存等本地操作仍可用；启动仍走门禁。
    let config = managed_config(app, &settings).or_else(|_| config::load(&settings))?;
    config.validate(&machine)?;
    let engine = engine(app)?;
    let engine_version = packaged_version(app, &engine);
    let running = profile::running(&profile)?;
    let (report, report_received_at) = app
        .state::<Browser>()
        .session
        .lock()
        .unwrap()
        .as_ref()
        .filter(|_| running)
        .map(|x| (x.report.clone(), x.received_at))
        .unwrap_or((None, None));
    let host = app.state::<Browser>().host.lock().unwrap().clone();
    let checks = network::checks(
        &machine,
        &config,
        report.as_ref(),
        host.as_ref(),
        &engine_version,
    );
    let (cache, cache_error) = match profile::scan(&profile) {
        Ok(items) => (items, String::new()),
        Err(error) => (Vec::new(), error),
    };
    Ok(Snapshot {
        ui_language: crate::ui_language::ui_language_read(app.clone()),
        exit_services: &network::SERVICES,
        region: crate::regions::target(&config.language(&machine), &config.timezone(&machine)),
        config,
        machine,
        engine_ready: !engine_version.is_empty(),
        engine_version,
        running,
        profile: profile.to_string_lossy().into(),
        identity_linked: workspaces::database(&root)?.browser_link()?.enabled,
        cache,
        cache_error,
        report,
        report_received_at,
        machine_exit: host,
        checks,
    })
}
async fn run<T: Send + 'static>(
    action: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(action)
        .await
        .map_err(|_| "浏览器操作被中断。".to_string())?
}
#[tauri::command]
pub async fn browser_read(app: tauri::AppHandle) -> Result<Snapshot, String> {
    run(move || {
        let state = app.state::<Browser>();
        let _guard = state.gate.lock().unwrap();
        snapshot(&app)
    })
    .await
}
#[tauri::command]
pub async fn browser_launch(
    app: tauri::AppHandle,
    on_progress: Channel<Progress>,
) -> Result<Snapshot, String> {
    run(move || {
        let _operation = crate::fixed_proxy::exclusive(&app)?;
        let endpoint = crate::fixed_proxy::browser_gate(&app)?;
        let state = app.state::<Browser>();
        let _guard = state.gate.lock().unwrap();
        launch_locked(&app, endpoint, &Reporter::channel(Some(on_progress)))
    })
    .await
}


#[cfg(target_os = "macos")]
fn binary(engine: &Path) -> PathBuf {
    engine.join("Contents/MacOS/Chromium")
}
