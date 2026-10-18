// [INPUT]: macOS/Linux/Windows 平台边界、Tauri 生命周期、发布构建 custom-protocol 与清理、CLI 安装管理、浏览器、地区、系统、固定网络资源导航与独立界面语言命令及固定出口桥接/重启插件。
// [OUTPUT]: CCBaga Proxy 窗口（开机启动时留在托盘）、固定出口状态托盘、SQLite 本地身份暂存/恢复与无需全量扫描的身份进程停止和 CLI 卸载/重装、固定网络资源入口与随界面语言切换的托盘菜单，以及 CI 的固定启动阶段诊断。
// [POS]: 应用编排层；不注册翻译快捷键，不读取翻译设置或 API 密钥。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
// ----- 发布包必须内嵌前端资源，禁止依赖开发服务 -----
#[cfg(all(not(debug_assertions), not(feature = "custom-protocol")))]
compile_error!("发布构建需要 custom-protocol；使用 tauri build 或 cargo build --release --features custom-protocol。");
mod browser;
mod claude_cli;
mod cleaner;
mod identities;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;
mod native;
mod progress;
mod regions;
mod system;
mod ui_language;
#[cfg(test)]
mod updater_tests;
mod fixed_proxy;
mod tray;
use tauri::{Emitter, Manager};
fn show(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
        // The page polls only while it can be seen; the tray follows the guard in the background.
        let _ = window.emit("window-visible", true);
    }
}
pub(crate) fn startup_trace(stage: &str) {
    #[cfg(windows)]
    if std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true") {
        // CI 只记录固定启动阶段，不读取文件正文、参数或凭据。
        let path = std::env::temp_dir().join("ccbaga-ci-startup.log");
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            use std::io::Write;
            let _ = writeln!(file, "{stage}");
        }
    }
    let _ = stage;
}
fn main() {
    startup_trace("host entry");
    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_single_instance::init(|app, args, _| {
            #[cfg(target_os = "linux")]
            if args.iter().any(|arg| arg == "--browser") {
                browser::open_urls(app.clone(), args);
                return;
            }
            #[cfg(target_os = "windows")]
            if args.iter().any(|arg| arg == "--browser") {
                browser::open_urls(app.clone(), args);
                return;
            }
            // A sign-in start while already running must not pop the window.
            if args.iter().any(|arg| arg == "--tray") { return; }
            show(app)
        }))
        .setup(|app| {
            startup_trace("host setup");
            app.manage(ui_language::UiLanguage::load(app.handle()));
            app.manage(cleaner::Cleaner::default());
            app.manage(browser::Browser::default());
            app.manage(fixed_proxy::FixedProxy::default());
            #[cfg(target_os = "macos")]
            browser::companion(app.handle().clone());
            #[cfg(target_os = "linux")]
            browser::open_urls(app.handle().clone(), std::env::args().collect());
            #[cfg(target_os = "windows")]
            if std::env::args().any(|arg| arg == "--browser") {
                browser::open_urls(app.handle().clone(), std::env::args().collect());
            }
            // Login links from Claude reach the fingerprint browser through Proxy-v2's launcher.
            #[cfg(target_os = "windows")]
            if let Err(error) = browser::record_entry(app.handle()) {
                eprintln!("{error}");
            }
            tray::build(app.handle())?;
            tray::watch(app.handle().clone());
            // Started at sign-in: stay in the tray until the user opens the window.
            if !std::env::args().any(|arg| arg == "--tray") {
                show(app.handle());
            }
            startup_trace("host ready");
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
                let _ = window.emit("window-visible", false);
            }
        })
        .invoke_handler(tauri::generate_handler![
            fixed_proxy::proxy_status,
            fixed_proxy::proxy_check,
            fixed_proxy::proxy_launch,
            fixed_proxy::proxy_repair_plan,
            fixed_proxy::proxy_repair,
            fixed_proxy::proxy_workspace_choose,
            fixed_proxy::proxy_exit_region,
            fixed_proxy::proxy_account,
            fixed_proxy::proxy_connections,
            fixed_proxy::proxy_protect,
            ui_language::ui_language_read,
            ui_language::ui_language_write,
            cleaner::cleaner_stop,
            identities::identities_read,
            identities::identities_browser,
            identities::identities_stop,
            identities::identities_switch,
            identities::identities_rename,
            identities::identities_delete,
            claude_cli::claude_cli_read,
            claude_cli::claude_cli_manage,
            system::system_read,
            system::system_set_timezone,
            system::system_disable_location,
            browser::browser_read,
            browser::browser_launch,
        ])
        .build(tauri::generate_context!())
        .expect("无法启动 CCBaga-A")
        .run(|app, event| match event {
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { .. } => show(app),
            tauri::RunEvent::Exit => browser::forget_start_url(app),
            _ => {}
        });
}
