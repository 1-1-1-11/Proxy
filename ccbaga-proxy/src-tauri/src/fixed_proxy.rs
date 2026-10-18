// [INPUT]: Fixed bundled adapter, existing local Proxy-v2 installation and a natively chosen CLI folder.
// [OUTPUT]: Read-only status/audit, gated launches, one-use repair plans and the fixed exit's region.
// [POS]: Windows integration boundary; no arbitrary paths, commands or proxy secrets from IPC.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{io::Read, path::PathBuf, process::{Command, Stdio}, sync::Mutex, time::{Duration, Instant}};
use tauri::Manager;

#[derive(Default)]
pub struct FixedProxy {
    audit: Mutex<()>,
    plan: Mutex<Option<PendingRepair>>,
    exit: Mutex<Option<(std::net::IpAddr, ExitRegion)>>,
}
#[derive(Clone, Serialize)]
pub struct ExitRegion { country: String, timezone: String, region: Option<&'static str>, label: Option<&'static str> }
struct PendingRepair { token: String, fingerprint: String, created: Instant }
#[derive(Serialize)]
pub struct RepairPlan { token: String, effects: Vec<&'static str> }
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Entry { Cli, Desktop, Browser }

/// Shares the identity/CLI installer lock, including error and panic unwind paths.
pub struct Operation(tauri::AppHandle);
pub fn exclusive(app: &tauri::AppHandle) -> Result<Operation, String> {
    app.state::<crate::cleaner::Cleaner>().enter()?;
    Ok(Operation(app.clone()))
}
impl Drop for Operation {
    fn drop(&mut self) { self.0.state::<crate::cleaner::Cleaner>().leave(); }
}
/// Background entries (links opened from other apps) queue behind a running operation.
pub fn exclusive_wait(app: &tauri::AppHandle, limit: Duration) -> Result<Operation, String> {
    let started = Instant::now();
    loop {
        match exclusive(app) {
            Err(_) if started.elapsed() < limit => std::thread::sleep(Duration::from_millis(150)),
            result => return result,
        }
    }
}

// ----- CLI folder: chosen only through the native dialog, revalidated on every use -----
fn workspace_file(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    Ok(app.path().app_data_dir().map_err(|_| "应用目录不可用。")?.join("cli-workspace.json"))
}
fn usable(path: &std::path::Path) -> bool { path.is_absolute() && path.is_dir() }
pub fn workspace(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let saved = workspace_file(app).ok()
        .and_then(|file| std::fs::read(file).ok())
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value["path"].as_str().map(PathBuf::from))
        .filter(|path| usable(path));
    match saved {
        Some(path) => Ok(path),
        None => app.path().home_dir().map_err(|_| "无法定位用户主目录。".into()),
    }
}

fn adapter(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let path = app.path().resource_dir().map_err(|_| "无法定位本机桥接。")?.join("proxy-bridge/bridge.py");
    if path.is_file() { return Ok(path); }
    if cfg!(debug_assertions) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../proxy-bridge/bridge.py");
        if path.is_file() { return Ok(path); }
    }
    Err("本机桥接文件缺失，请重新构建整合版。".into())
}

// Launches and the browser gate first give a guard recovering from sleep up to 60 s.
fn duration(command: &str) -> Duration {
    Duration::from_secs(match command { "repair" => 260, "protect" => 330, "launch-desktop" => 210, "check-browser" | "launch-cli" => 150, "check" => 90, "connections" => 20, _ => 12 })
}

/// Known reasons the bridge gives for an unusable backend; anything else stays generic.
fn known_failure(bytes: &[u8]) -> Option<String> {
    let data: Value = serde_json::from_slice(bytes).ok()?;
    if data["schema"] != 1 || data["available"] != false { return None; }
    Some(match data["error"].as_str()? {
        "backend_missing" => "未找到已安装的 Proxy-v2（用户目录 .codex 下的 ClaudeNetwork）。".into(),
        "backend_version" => {
            let installed = data["installed"].as_str()
                .filter(|v| v.len() <= 16 && v.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())))
                .unwrap_or("未知");
            format!("已安装的 Proxy-v2 版本 {installed} 与整合版不匹配，需要先复核适配。")
        }
        "backend_dependency" => "Proxy-v2 需要的 Python 组件缺失（如 psutil、PyYAML），请检查本机 Python。".into(),
        "policy_invalid" => "Proxy-v2 的策略文件 audit_policy.json 缺失或无效。".into(),
        _ => return None,
    })
}

fn response(action: &str, success: bool, bytes: &[u8]) -> Result<Value, String> {
    if !success { return Err(known_failure(bytes).unwrap_or_else(|| "Proxy-v2 桥接异常退出，本次操作未完成。".into())); }
    let data: Value = serde_json::from_slice(bytes).map_err(|_| "检查结果格式不完整，不能确认可用。")?;
    let valid = |value: &Value| value.is_object() && value["schema"] == 1
        && value.get("error").is_none() && value["available"] != false;
    if !valid(&data) { return Err(known_failure(bytes).unwrap_or_else(|| "Proxy-v2 后端、策略或版本不可用。请检查现有安装。".into())); }
    let complete = match action {
        "policy" => validated_endpoint(&data).is_ok(),
        "status" | "check" | "check-browser" | "plan" => data["available"] == true,
        "connections" => data["available"] == true && data["connections"].is_array() && data["readable"].is_boolean(),
        "launch-cli" | "launch-desktop" | "repair" | "protect" => {
            let report = &data["report"];
            valid(report) && report["available"] == true && match action {
                "repair" => match data["action"].as_str() {
                    Some("repaired") => data["repair_exit"].as_i64() == Some(0),
                    Some("repair_failed") => data["repair_exit"].as_i64().is_some_and(|code| code != 0),
                    _ => false,
                },
                "protect" => matches!(data["action"].as_str(), Some("protected" | "protect_failed")),
                _ => matches!(data["action"].as_str(), Some("requested" | "blocked")),
            }
        }
        _ => false,
    };
    if !complete { return Err("检查结果格式不完整，不能确认可用。".into()); }
    Ok(data)
}

fn keeps_children(action: &str, data: &Value) -> bool {
    match action {
        "launch-cli" | "launch-desktop" => data["action"] == "requested",
        "repair" => data["action"] == "repaired" && data["repair_exit"] == 0,
        _ => false,
    }
}

#[cfg(windows)]
fn capture(mut command: Command, timeout: Duration, action: &str) -> Result<Value, String> {
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x08000000).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command.spawn().map_err(|_| "无法启动 Proxy-v2 桥接，请检查本机 Python。")?;
    let job = match crate::windows::ChildJob::attach(&child) {
        Ok(job) => job,
        Err(_) => { let _ = child.kill(); let _ = child.wait(); return Err("无法隔离本次检查进程。".into()); }
    };
    let result = (|| {
        let stdout = child.stdout.take().ok_or("检查输出不可用。")?;
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let result = stdout.take(512 * 1024 + 1).read_to_end(&mut bytes).map(|_| bytes);
            let _ = send.send(result);
        });
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() < timeout => std::thread::sleep(Duration::from_millis(50)),
                _ => return Err("检查或操作超时，不能确认可用；请重新检查。".into()),
            }
        };
        let bytes = receive.recv_timeout(Duration::from_secs(2)).map_err(|_| "检查输出读取超时。")?.map_err(|_| "检查输出读取失败。")?;
        if bytes.len() > 512 * 1024 { return Err("检查结果超过大小限制。".into()); }
        response(action, status.success(), &bytes)
    })();
    // Only a validated, successful action may leave applications running. Failed
    // repairs can leave grandchildren after Python's direct-child timeout.
    if let Ok(data) = &result {
        if keeps_children(action, data) {
            if let Err(error) = job.release() {
                job.stop_and_wait(Duration::from_secs(5))?;
                let _ = child.wait();
                return Err(error);
            }
            return result;
        }
    }
    job.stop_and_wait(Duration::from_secs(5))?;
    let _ = child.wait();
    result
}

pub fn call(app: &tauri::AppHandle, action: &'static str) -> Result<Value, String> {
    #[cfg(not(windows))]
    { let _ = (app, action); return Err("整合版本目前仅支持 Windows。".into()); }
    #[cfg(windows)]
    {
        let python = PathBuf::from(r"C:\Tools\Python\python.exe");
        if !python.is_file() { return Err("未找到 Proxy-v2 使用的 C:\\Tools\\Python\\python.exe。".into()); }
        let mut command = Command::new(python);
        command.args(["-I", "-X", "utf8", "-B"]).arg(adapter(app)?).arg(action).arg(workspace(app)?);
        capture(command, duration(action), action)
    }
}

pub fn endpoint(app: &tauri::AppHandle) -> Result<String, String> {
    let value = call(app, "policy")?;
    validated_endpoint(&value)
}
fn validated_endpoint(value: &Value) -> Result<String, String> {
    let endpoint = value["endpoint"].as_str().ok_or("固定代理地址缺失。")?;
    let port = endpoint.strip_prefix("http://127.0.0.1:").and_then(|port| port.parse::<u16>().ok());
    if port.is_none() || port == Some(0) { return Err("固定代理地址无效。".into()); }
    Ok(endpoint.into())
}

pub fn browser_gate(app: &tauri::AppHandle) -> Result<String, String> {
    crate::identities::ensure_settled(app)?;
    let report = call(app, "check-browser")?;
    browser_endpoint(&report, now()?)
}
fn now() -> Result<u64, String> {
    Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| "系统时间不可用。")?.as_millis() as u64)
}
fn browser_endpoint(report: &Value, now: u64) -> Result<String, String> {
    if report["entries"]["browser"] != "ready" || report["guard"]["state"] != "ready" {
        return Err("固定出口检查未通过。请回到固定出口页面查看原因。".into());
    }
    let checked = report["checked_at"].as_u64().ok_or("缺少检查时间。")?;
    if checked > now || now - checked > 60_000 { return Err("检查结果已过期，请重新检查。".into()); }
    validated_endpoint(&report)
}

#[tauri::command]
pub async fn proxy_status(app: tauri::AppHandle) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || call(&app, "status")).await.map_err(|_| "状态读取中断。")?
}
#[tauri::command]
pub async fn proxy_check(app: tauri::AppHandle) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<FixedProxy>();
        let _gate = state.audit.try_lock().map_err(|_| "已有检查正在进行。")?;
        call(&app, "check")
    }).await.map_err(|_| "检查中断。")?
}
/// The single gated launch path for the page and the tray. The web entry is the fingerprint
/// browser: it passes its own "check-browser" gate, then starts with the gate's fixed endpoint.
pub fn launch(app: &tauri::AppHandle, entry: Entry) -> Result<Value, String> {
    let _operation = exclusive(app)?;
    crate::identities::ensure_settled(app)?;
    match entry {
        Entry::Cli => call(app, "launch-cli"),
        Entry::Desktop => call(app, "launch-desktop"),
        Entry::Browser => {
            let report = call(app, "check-browser")?;
            let Ok(endpoint) = browser_endpoint(&report, now()?) else {
                return Ok(serde_json::json!({"schema": 1, "action": "blocked", "report": report}));
            };
            open_browser(app, endpoint)?;
            Ok(serde_json::json!({"schema": 1, "action": "requested", "report": report}))
        }
    }
}
#[cfg(windows)]
fn open_browser(app: &tauri::AppHandle, endpoint: String) -> Result<(), String> {
    crate::browser::open_gated(app, endpoint, &[])
}
#[cfg(not(windows))]
fn open_browser(_: &tauri::AppHandle, _: String) -> Result<(), String> {
    Err("整合版本目前仅支持 Windows。".into())
}
#[tauri::command]
pub async fn proxy_launch(app: tauri::AppHandle, entry: Entry) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || launch(&app, entry)).await.map_err(|_| "启动中断。")?
}
/// Proxy-v2's -Protect: firewall rules that keep the desktop app on the local proxy. Windows asks for
/// administrator consent itself; the result comes back with a fresh desktop check.
#[tauri::command]
pub async fn proxy_protect(app: tauri::AppHandle) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = exclusive(&app)?;
        call(&app, "protect")
    }).await.map_err(|_| "客户端保护设置中断，请重新检查。")?
}
/// One read-only snapshot of Claude's live connections through Clash, judged like Proxy-v2's -Watch.
#[tauri::command]
pub async fn proxy_connections(app: tauri::AppHandle) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || call(&app, "connections")).await.map_err(|_| "连接读取中断。")?
}
/// Whitelisted email of the current Claude login, shown on the home page.
#[tauri::command]
pub async fn proxy_account() -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(|| serde_json::json!({"account": crate::identities::current_email()}))
        .await.map_err(|_| "账号读取中断。".into())
}
#[tauri::command]
pub async fn proxy_repair_plan(app: tauri::AppHandle) -> Result<RepairPlan, String> {
    tauri::async_runtime::spawn_blocking(move || {
        use ring::rand::SecureRandom;
        let report = call(&app, "plan")?;
        let fingerprint = report["fingerprint"].as_str().ok_or("无法核对修复目标。")?.to_owned();
        let mut bytes = [0u8; 32];
        ring::rand::SystemRandom::new().fill(&mut bytes).map_err(|_| "无法生成修复确认。")?;
        let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        *app.state::<FixedProxy>().plan.lock().map_err(|_| "修复确认不可用。")? = Some(PendingRepair { token: token.clone(), fingerprint, created: Instant::now() });
        Ok(RepairPlan { token, effects: vec!["调用现有 Proxy-v2 修复脚本，可能重启 Clash 和受保护应用。", "修复固定代理与受管理的客户端设置；出口不符时保持阻断。", "修复完成后重新检查，失败不会自动更换出口。"] })
    }).await.map_err(|_| "修复计划读取中断。")?
}
#[tauri::command]
pub async fn proxy_repair(app: tauri::AppHandle, token: String) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let _operation = exclusive(&app)?;
        let pending = app.state::<FixedProxy>().plan.lock().map_err(|_| "修复确认不可用。")?.take().ok_or("请先查看修复计划。")?;
        if pending.token != token || pending.created.elapsed() > Duration::from_secs(120) { return Err("修复确认已失效，请重新查看计划。".into()); }
        let current = call(&app, "plan")?;
        if current["fingerprint"].as_str() != Some(&pending.fingerprint) { return Err("修复目标已变化，请重新查看计划。".into()); }
        call(&app, "repair")
    }).await.map_err(|_| "修复中断，请重新检查状态。")?
}

#[cfg(windows)]
fn pick_folder(owner: isize, start: PathBuf) -> Result<Option<PathBuf>, String> {
    use windows::core::{HSTRING, HRESULT};
    use windows::Win32::{Foundation::{ERROR_CANCELLED, HWND}, System::Com::*, UI::Shell::*};
    unsafe {
        let initialized = CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE).is_ok();
        let result = (|| -> windows::core::Result<Option<PathBuf>> {
            let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER)?;
            dialog.SetOptions(dialog.GetOptions()? | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOCHANGEDIR)?;
            if let Ok(item) = SHCreateItemFromParsingName::<_, _, IShellItem>(&HSTRING::from(start.as_os_str()), None) {
                let _ = dialog.SetFolder(&item);
            }
            if let Err(error) = dialog.Show(Some(HWND(owner as _))) {
                return if error.code() == HRESULT::from_win32(ERROR_CANCELLED.0) { Ok(None) } else { Err(error) };
            }
            let name = dialog.GetResult()?.GetDisplayName(SIGDN_FILESYSPATH)?;
            let path = name.to_string().map(PathBuf::from);
            CoTaskMemFree(Some(name.0 as _));
            Ok(path.ok())
        })();
        if initialized { CoUninitialize(); }
        result.map_err(|_| "无法打开文件夹选择窗口。".into())
    }
}

/// Opens the system folder picker; the WebView never supplies the path itself.
#[tauri::command]
pub async fn proxy_workspace_choose(app: tauri::AppHandle) -> Result<Option<String>, String> {
    #[cfg(not(windows))]
    { let _ = app; Err("整合版本目前仅支持 Windows。".into()) }
    #[cfg(windows)]
    {
        let owner = app.get_webview_window("main").and_then(|window| window.hwnd().ok()).map_or(0, |hwnd| hwnd.0 as isize);
        let start = workspace(&app)?;
        let (send, receive) = tokio::sync::oneshot::channel();
        // COM dialogs need their own single-threaded apartment.
        std::thread::spawn(move || { let _ = send.send(pick_folder(owner, start)); });
        let Some(chosen) = receive.await.map_err(|_| "文件夹选择中断。")?? else { return Ok(None) };
        let chosen = dunce::canonicalize(&chosen).map_err(|_| "所选文件夹不可用。")?;
        if !usable(&chosen) { return Err("所选文件夹不可用。".into()); }
        let file = workspace_file(&app)?;
        let bytes = serde_json::to_vec(&serde_json::json!({"path": chosen})).map_err(|_| "无法保存工作目录。")?;
        std::fs::create_dir_all(file.parent().ok_or("应用目录不可用。")?).map_err(|_| "无法保存工作目录。")?;
        std::fs::write(&file, bytes).map_err(|_| "无法保存工作目录。")?;
        Ok(Some(chosen.to_string_lossy().into_owned()))
    }
}

/// Region of the policy's fixed exit, probed once through the fixed proxy and cached per IP.
#[tauri::command]
pub async fn proxy_exit_region(app: tauri::AppHandle) -> Result<ExitRegion, String> {
    exit_region(&app).await
}
/// Time zone of the fixed exit for the fingerprint browser's synchronous launch paths.
pub fn exit_timezone(app: &tauri::AppHandle) -> Result<String, String> {
    tauri::async_runtime::block_on(exit_region(app)).map(|region| region.timezone)
}
async fn exit_region(app: &tauri::AppHandle) -> Result<ExitRegion, String> {
    let worker = app.clone();
    let policy = tauri::async_runtime::spawn_blocking(move || call(&worker, "policy")).await.map_err(|_| "出口地区读取中断。")??;
    let endpoint = validated_endpoint(&policy)?;
    let expected: std::net::IpAddr = policy["expected_ip"].as_str().and_then(|ip| ip.parse().ok()).ok_or("指定出口缺失。")?;
    let state = app.state::<FixedProxy>();
    if let Some((ip, region)) = state.exit.lock().map_err(|_| "出口地区不可用。")?.clone() {
        if ip == expected { return Ok(region); }
    }
    let exit = crate::browser::network::probe(&endpoint).await?;
    if exit.ip.parse::<std::net::IpAddr>().ok() != Some(expected) {
        return Err("实际出口与指定 IP 不一致，无法确认出口地区。".into());
    }
    let matched = crate::regions::for_exit(&exit.country, &exit.timezone);
    let region = ExitRegion { country: exit.country, timezone: exit.timezone, region: matched.map(|r| r.id), label: matched.map(|r| r.label) };
    *state.exit.lock().map_err(|_| "出口地区不可用。")? = Some((expected, region.clone()));
    Ok(region)
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("fixed_proxy_tests.rs");
    #[test]
    fn endpoint_requires_local_fixed_http_and_valid_port() {
        for invalid in ["http://evil:17892", "socks5://127.0.0.1:17892", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:17892/path"] {
            assert!(validated_endpoint(&serde_json::json!({"endpoint":invalid})).is_err());
        }
        assert_eq!(validated_endpoint(&serde_json::json!({"endpoint":"http://127.0.0.1:17892"})).unwrap(), "http://127.0.0.1:17892");
    }
    #[test]
    #[cfg(windows)]
    fn hanging_bridge_is_terminated() {
        let mut command = Command::new(r"C:\Tools\Python\python.exe");
        command.args(["-I", "-c", "import time; time.sleep(30)"]);
        let start = Instant::now();
        assert!(capture(command, Duration::from_millis(200), "check").is_err());
        assert!(start.elapsed() < Duration::from_secs(5));
    }
}
