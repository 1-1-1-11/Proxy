// [INPUT]: Windows Chromium 引擎、资源目录与共用资料/随机令牌会话。
// [OUTPUT]: 本地引擎发现与启动、用户主动设置默认浏览器。
// [POS]: browser 编排的 Windows 平台实现；只接收 URL/文件入口，不执行用户提供的 shell。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
fn register(_: &Path) -> Result<(), String> {
    Ok(())
}

fn binary(engine: &Path) -> PathBuf {
    engine.join("chrome.exe")
}

fn packaged_engine(resources: &Path) -> PathBuf {
    let legacy = resources.join("browser-runtime/WindowsBrowser");
    if binary(&legacy).is_file() {
        return legacy;
    }
    resources.join("WindowsBrowser")
}

fn engine(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let resources = app.path().resource_dir().map_err(|_| "资源目录不可用。")?;
    let packaged = packaged_engine(&resources);
    if binary(&packaged).is_file() || !cfg!(debug_assertions) {
        return Ok(packaged);
    }
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../browser-runtime/WindowsBrowser"))
}

fn prepare_engine(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let engine = engine(app)?;
    if !binary(&engine).is_file() {
        return Err(
            "Windows 指纹浏览器引擎缺失。请先运行 python scripts/fetch-browser.py 下载并准备引擎。"
                .into(),
        );
    }
    Ok(engine)
}

fn version(engine: &Path) -> String {
    fs::read_to_string(engine.join("version.txt"))
        .unwrap_or_default()
        .trim()
        .into()
}

pub fn open_urls(app: tauri::AppHandle, args: Vec<String>) {
    let urls = args
        .into_iter()
        .skip(1)
        .filter(|s| {
            s.starts_with("https://")
                || s.starts_with("http://")
                || s.starts_with("file://")
                || Path::new(s).is_absolute()
        })
        .collect::<Vec<_>>();
    std::thread::spawn(move || {
        if let Err(error) = start_windows_companion(&app, &urls) {
            use tauri::Emitter;
            crate::show(&app);
            let _ = app.emit("proxy-launch-blocked", error);
        }
    });
}

/// Records this program for Proxy-v2's login-link launcher, which hands URLs to `--browser`.
pub fn record_entry(app: &tauri::AppHandle) -> Result<(), String> {
    let folder = app.path().app_data_dir().map_err(|_| "应用目录不可用。")?;
    fs::create_dir_all(&folder).map_err(|_| "应用目录不可用。")?;
    let program = std::env::current_exe().map_err(|_| "无法定位 CCBaga Proxy。")?;
    let bytes = serde_json::to_vec(&serde_json::json!({"schema": 1, "program": program}))
        .map_err(|_| "浏览器入口编码失败。")?;
    crate::identities::private::write(&folder.join("browser-entry.json"), &bytes)
}

fn start_windows_companion(app: &tauri::AppHandle, urls: &[String]) -> Result<(), String> {
    let _operation = crate::fixed_proxy::exclusive_wait(app, std::time::Duration::from_secs(60))?;
    let endpoint = crate::fixed_proxy::browser_gate(app)?;
    open_gated(app, endpoint, urls)
}

/// Starts B, or a new window of the running B, on an endpoint that just passed the browser gate.
/// The caller holds the shared operation lock; a running profile must already use that endpoint.
pub fn open_gated(app: &tauri::AppHandle, endpoint: String, urls: &[String]) -> Result<(), String> {
    crate::startup_trace("companion entry");
    let state = app.state::<Browser>();
    let _guard = state.gate.lock().unwrap();
    let engine = prepare_engine(app)?;
    crate::startup_trace("engine ready");
    let root = root(app)?;
    let settings = workspaces::ensure(&root)?;
    let profile = settings.join("profile");
    profile::check_path(&root, &profile)?;
    let mut config = config::load(&settings)?;
    config.proxy = endpoint;
    crate::startup_trace("config ready");
    let machine = config::machine()?;
    crate::startup_trace("machine ready");
    config.follow_exit(crate::fixed_proxy::exit_timezone(app).ok().as_deref(), &machine);
    config.validate(&machine)?;
    crate::windows::browser_proxy_matches(&profile, &config.proxy)?;
    if !profile::running(&profile)? {
        config::save(&settings, &config)?;
        profile::preferences(&profile, &config, &machine)?;
    }
    write_launch_args(&root, &config, &machine, &profile, &version(&engine))?;
    workspaces::unblock(&root)?;
    crate::startup_trace("preferences ready");
    let page = open_session(app, &config, &machine, version(&engine))?;
    crate::startup_trace("session ready");
    let mut child = Command::new(binary(&engine))
        .args(config::arguments(
            &config,
            &machine,
            &profile,
            &page,
            &version(&engine),
        ))
        .args(urls)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "无法启动 Windows Chromium 浏览器。请检查引擎文件与依赖。".to_string())?;
    crate::startup_trace("companion spawned");
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
