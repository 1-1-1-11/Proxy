// Real, disposable Windows process trees. No installed backend or user settings.
#[cfg(windows)]
struct CaptureFixture(PathBuf);
#[cfg(windows)]
impl CaptureFixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("ccbaga-capture-{}", crate::identities::new_id().unwrap()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn child_handle(&self) -> Option<windows_sys::Win32::Foundation::HANDLE> {
        let pid = std::fs::read_to_string(self.0.join("child.pid")).ok()?.parse().ok()?;
        let handle = unsafe { windows_sys::Win32::System::Threading::OpenProcess(
            0x00100000 | windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION
                | windows_sys::Win32::System::Threading::PROCESS_TERMINATE, 0, pid) };
        if handle.is_null() { None } else { Some(handle) }
    }
    fn child_running(&self) -> bool {
        let Some(handle) = self.child_handle() else { return false; };
        let running = unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(handle, 0) } == 258;
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle); }
        running
    }
    fn command(&self, body: &str, code: i32) -> Command {
        let script = r#"import subprocess,sys
from pathlib import Path
child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(30)'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
(Path(sys.argv[1]) / 'child.pid').write_text(str(child.pid))
print(sys.argv[2], flush=True)
sys.exit(int(sys.argv[3]))
"#;
        let mut command = Command::new(r"C:\Tools\Python\python.exe");
        command.args(["-I", "-B", "-c", script]).arg(&self.0).arg(body).arg(code.to_string());
        command
    }
}
#[cfg(windows)]
impl Drop for CaptureFixture {
    fn drop(&mut self) {
        if let Some(handle) = self.child_handle() {
            unsafe {
                windows_sys::Win32::System::Threading::TerminateProcess(handle, 1);
                windows_sys::Win32::System::Threading::WaitForSingleObject(handle, 5000);
                windows_sys::Win32::Foundation::CloseHandle(handle);
            }
        }
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
#[cfg(windows)]
fn failed_bridge_responses_stop_descendants_before_returning() {
    let cases = [
        ("repair", 2, r#"{"schema":1,"available":false,"error":"backend_unavailable"}"#, true),
        ("repair", 0, "not json", true),
        ("repair", 0, r#"{"schema":99,"action":"repaired","repair_exit":0}"#, true),
        ("repair", 0, r#"{"schema":1,"action":"repaired","repair_exit":0}"#, true),
        ("repair", 0, r#"{"schema":1,"action":"repair_failed","repair_exit":1,"report":{"schema":1,"available":true}}"#, false),
        ("launch-cli", 0, r#"{"schema":1,"action":"blocked","report":{"schema":1,"available":true}}"#, false),
        ("check", 0, r#"{"schema":1,"available":true}"#, false),
    ];
    for (action, code, body, error) in cases {
        let fixture = CaptureFixture::new();
        let result = capture(fixture.command(body, code), Duration::from_secs(5), action);
        assert_eq!(result.is_err(), error, "{action}: {body}");
        assert!(fixture.0.join("child.pid").is_file(), "probe child must actually be spawned");
        assert!(!fixture.child_running(), "child survived {action}: {body}");
    }
}

#[test]
#[cfg(windows)]
fn successful_actions_keep_the_launched_application_alive() {
    for (action, body) in [
        ("launch-cli", r#"{"schema":1,"action":"requested","report":{"schema":1,"available":true}}"#),
        ("repair", r#"{"schema":1,"action":"repaired","repair_exit":0,"report":{"schema":1,"available":true}}"#),
    ] {
        let fixture = CaptureFixture::new();
        assert!(capture(fixture.command(body, 0), Duration::from_secs(5), action).is_ok());
        assert!(fixture.child_running(), "successful {action} killed its application");
    }
}

#[test]
#[cfg(windows)]
fn inner_python_repair_timeout_stops_the_grandchild() {
    let fixture = CaptureFixture::new();
    std::fs::write(fixture.0.join("repair_proxy.py"), r#"import subprocess,sys,time
from pathlib import Path
child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(30)'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
(Path(__file__).parent / 'child.pid').write_text(str(child.pid))
time.sleep(30)
"#).unwrap();
    let script = r#"import importlib.util,sys,types
from pathlib import Path
spec = importlib.util.spec_from_file_location('review_bridge', sys.argv[1])
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
bridge.load_backend = lambda: types.SimpleNamespace(HERE=Path(sys.argv[2]))
original_run = bridge.subprocess.run
def short_timeout(*args, **kwargs):
    assert kwargs['timeout'] == 180
    kwargs['timeout'] = 0.5
    return original_run(*args, **kwargs)
bridge.subprocess.run = short_timeout
sys.exit(bridge.main(['repair']))
"#;
    let mut command = Command::new(r"C:\Tools\Python\python.exe");
    command.args(["-I", "-B", "-c", script])
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../proxy-bridge/bridge.py"))
        .arg(&fixture.0);
    let result = capture(command, Duration::from_secs(10), "repair");
    assert!(result.unwrap_err().contains("异常退出"));
    assert!(fixture.0.join("child.pid").is_file());
    assert!(!fixture.child_running(), "repair grandchild survived the bridge failure");
}

#[test]
fn known_backend_failures_are_explained_and_unknown_ones_stay_generic() {
    let message = |body: &str| response("status", false, body.as_bytes()).unwrap_err();
    assert!(message(r#"{"schema":1,"available":false,"error":"backend_missing"}"#).contains("未找到已安装的 Proxy-v2"));
    assert_eq!(message(r#"{"schema":1,"available":false,"error":"backend_version","installed":"2026.10.20"}"#),
               "已安装的 Proxy-v2 版本 2026.10.20 与整合版不匹配，需要先复核适配。");
    for installed in [r#""<b>2026</b>""#, r#""2026..1""#, "7", r#""12345678901234567""#] {
        let body = format!(r#"{{"schema":1,"available":false,"error":"backend_version","installed":{installed}}}"#);
        assert!(message(&body).contains("版本 未知"), "{body}");
    }
    assert!(message(r#"{"schema":1,"available":false,"error":"backend_dependency"}"#).contains("psutil"));
    assert!(message(r#"{"schema":1,"available":false,"error":"policy_invalid"}"#).contains("audit_policy.json"));
    for body in [r#"{"schema":1,"available":false,"error":"backend_unavailable"}"#, "not json",
                 r#"{"schema":2,"available":false,"error":"policy_invalid"}"#] {
        assert!(message(body).contains("异常退出"), "{body}");
    }
    let invalid = response("status", true, br#"{"schema":1,"available":false,"error":"policy_invalid"}"#).unwrap_err();
    assert!(invalid.contains("audit_policy.json"));
}

#[test]
fn exit_lookup_can_block_inside_browser_launch_threads() {
    // exit_timezone blocks on a lookup that itself runs the bridge as a blocking task. Launches call it from
    // blocking tasks (page, identity switch) and from plain threads (tray, --browser handoff).
    let lookup = || tauri::async_runtime::block_on(async { tauri::async_runtime::spawn_blocking(|| 7).await.unwrap() });
    let from_task = tauri::async_runtime::block_on(tauri::async_runtime::spawn_blocking(lookup)).unwrap();
    let from_thread = std::thread::spawn(lookup).join().unwrap();
    assert_eq!((from_task, from_thread), (7, 7));
}

#[test]
fn web_entry_no_longer_accepts_the_dedicated_chrome_launch() {
    let body = br#"{"schema":1,"available":true,"action":"requested","report":{"schema":1,"available":true}}"#;
    assert!(response("launch-cli", true, body).is_ok());
    assert!(response("launch-web", true, body).is_err());
    assert!(!keeps_children("launch-web", &serde_json::json!({"action":"requested"})));
}

#[test]
fn fingerprint_browser_gate_uses_its_own_verdict_and_still_rejects_stale_networks() {
    let mut report = serde_json::json!({
        "schema":1, "available":true, "entries":{"browser":"ready","web":"blocked"},
        "guard":{"state":"ready"}, "checked_at":1000, "endpoint":"http://127.0.0.1:17892"
    });
    assert_eq!(browser_endpoint(&report, 1001).unwrap(), "http://127.0.0.1:17892");
    assert!(browser_endpoint(&report, 61_001).is_err());
    assert!(browser_endpoint(&report, 999).is_err());
    report["entries"]["browser"] = serde_json::json!("blocked");
    report["entries"]["web"] = serde_json::json!("ready");
    assert!(browser_endpoint(&report, 1001).is_err());
    report["entries"]["browser"] = serde_json::json!("ready");
    report["guard"]["state"] = serde_json::json!("unknown");
    assert!(browser_endpoint(&report, 1001).is_err());
}

#[test]
fn connection_snapshots_must_say_whether_clash_was_readable() {
    let ok = br#"{"schema":1,"available":true,"readable":true,"mode":"claude","connections":[]}"#;
    assert!(response("connections", true, ok).is_ok());
    for bad in [br#"{"schema":1,"available":true,"connections":[]}"#.as_slice(), br#"{"schema":1,"available":true,"readable":true}"#.as_slice()] {
        assert!(response("connections", true, bad).is_err());
    }
    assert!(!keeps_children("connections", &serde_json::json!({"action":"requested"})));
}

#[test]
fn protect_results_need_a_known_outcome_and_a_fresh_desktop_report() {
    let ok = br#"{"schema":1,"available":true,"action":"protected","report":{"schema":1,"available":true}}"#;
    let failed = br#"{"schema":1,"available":true,"action":"protect_failed","report":{"schema":1,"available":true}}"#;
    assert!(response("protect", true, ok).is_ok() && response("protect", true, failed).is_ok());
    for bad in [br#"{"schema":1,"available":true,"action":"requested","report":{"schema":1,"available":true}}"#.as_slice(),
                br#"{"schema":1,"available":true,"action":"protected"}"#.as_slice()] {
        assert!(response("protect", true, bad).is_err());
    }
    assert!(!keeps_children("protect", &serde_json::json!({"action":"protected"})));
    assert_eq!(duration("protect"), Duration::from_secs(330));
}
