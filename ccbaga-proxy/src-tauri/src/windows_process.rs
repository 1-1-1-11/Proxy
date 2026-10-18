// [INPUT]: Win32 Toolhelp/进程句柄、当前用户 SID、精确 CLI 入口与独立浏览器资料路径。
// [OUTPUT]: Claude 进程识别、创建时间/所有权复核后的结束，以及按完整资料参数正常关闭浏览器。
// [POS]: Windows 进程边界；参数仅用于原生判定，不返回 UI；不对其他用户或名称相似的程序执行终止。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
use super::{current_sid, input, process_sid, response};
use crate::cleaner::ClaudeProcess;
use serde_json::json;
use std::{ffi::c_char, path::Path};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, FILETIME, HANDLE, HWND, INVALID_HANDLE_VALUE, LPARAM},
    System::{
        Diagnostics::{
            Debug::ReadProcessMemory,
            ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
        },
        Threading::{
            GetProcessTimes, IsWow64Process, OpenProcess, QueryFullProcessImageNameW,
            TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
            PROCESS_VM_READ,
        },
    },
    UI::{
        Shell::CommandLineToArgvW,
        WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE},
    },
};
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
impl Handle {
    fn open(pid: u32, terminate: bool) -> Option<Self> {
        let flags = PROCESS_QUERY_LIMITED_INFORMATION
            | PROCESS_VM_READ
            | if terminate { PROCESS_TERMINATE } else { 0 };
        let handle = unsafe { OpenProcess(flags, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let handle = Self(handle);
        if unsafe { process_sid(handle.0) }.as_ref() != current_sid() || current_sid().is_none() {
            return None;
        }
        Some(handle)
    }
    fn image(&self) -> Option<String> {
        let mut buffer = vec![0u16; 32768];
        let mut size = buffer.len() as u32;
        if unsafe { QueryFullProcessImageNameW(self.0, 0, buffer.as_mut_ptr(), &mut size) } == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buffer[..size as usize]))
    }
    fn packaged_claude(&self) -> bool {
        let mut buffer = [0u16; 128];
        let mut size = buffer.len() as u32;
        let status = unsafe {
            windows_sys::Win32::Storage::Packaging::Appx::GetPackageFamilyName(
                self.0,
                &mut size,
                buffer.as_mut_ptr(),
            )
        };
        status == 0
            && String::from_utf16_lossy(&buffer[..size.saturating_sub(1) as usize])
                == "Claude_pzs8sxrjxfjjc"
    }
    fn created(&self) -> Option<u64> {
        let [mut created, mut exited, mut kernel, mut user] = [FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        }; 4];
        if unsafe { GetProcessTimes(self.0, &mut created, &mut exited, &mut kernel, &mut user) }
            == 0
        {
            return None;
        }
        Some((created.dwHighDateTime as u64) << 32 | created.dwLowDateTime as u64)
    }
}
#[repr(C)]
#[derive(Default, Copy, Clone)]
struct BasicInfo {
    status: i32,
    peb: usize,
    affinity: usize,
    priority: i32,
    pid: usize,
    parent: usize,
}
#[repr(C)]
#[derive(Default, Copy, Clone)]
struct Unicode {
    length: u16,
    maximum: u16,
    buffer: usize,
}
#[link(name = "ntdll")]
extern "system" {
    fn NtQueryInformationProcess(
        handle: HANDLE,
        class: u32,
        info: *mut std::ffi::c_void,
        size: u32,
        written: *mut u32,
    ) -> i32;
}
fn read<T: Default + Copy>(handle: HANDLE, address: usize) -> Option<T> {
    let mut value = T::default();
    let mut written = 0;
    let size = std::mem::size_of::<T>();
    if address == 0
        || unsafe {
            ReadProcessMemory(
                handle,
                address as _,
                (&mut value as *mut T).cast(),
                size,
                &mut written,
            )
        } == 0
        || written != size
    {
        return None;
    }
    Some(value)
}
fn arguments(handle: &Handle) -> Option<Vec<String>> {
    unsafe {
        let mut wow = 0;
        if IsWow64Process(handle.0, &mut wow) == 0 || wow != 0 {
            return None;
        }
        let mut basic = BasicInfo::default();
        let mut written = 0;
        if NtQueryInformationProcess(
            handle.0,
            0,
            (&mut basic as *mut BasicInfo).cast(),
            std::mem::size_of::<BasicInfo>() as u32,
            &mut written,
        ) != 0
        {
            return None;
        }
        let params: usize = read(handle.0, basic.peb.checked_add(0x20)?)?;
        let command: Unicode = read(handle.0, params.checked_add(0x70)?)?;
        if command.buffer == 0
            || command.length == 0
            || command.length > command.maximum
            || command.length % 2 != 0
        {
            return None;
        }
        let mut buffer = vec![0u16; command.length as usize / 2 + 1];
        let mut read_bytes = 0usize;
        if ReadProcessMemory(
            handle.0,
            command.buffer as _,
            buffer.as_mut_ptr().cast(),
            command.length as usize,
            &mut read_bytes,
        ) == 0
            || read_bytes != command.length as usize
        {
            return None;
        }
        // ----- 按 Windows 参数语法解析；完整参数判定，禁止子串命中 -----
        let mut count = 0;
        let args = CommandLineToArgvW(buffer.as_ptr(), &mut count);
        if args.is_null() {
            return None;
        }
        let values = std::slice::from_raw_parts(args, count as usize)
            .iter()
            .map(|p| {
                let mut size = 0;
                while *p.add(size) != 0 {
                    size += 1;
                }
                String::from_utf16_lossy(std::slice::from_raw_parts(*p, size))
            })
            .collect();
        LocalFree(args.cast());
        Some(values)
    }
}
fn normalized(path: &str) -> String {
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}
fn official_cli(args: &[String]) -> bool {
    let script = if args
        .first()
        .is_some_and(|a| normalized(a).ends_with("\\bun.exe"))
        && args.get(1).is_some_and(|a| a == "run")
    {
        2
    } else {
        1
    };
    args.get(script).is_some_and(|arg| {
        Path::new(arg).is_absolute()
            && normalized(arg).ends_with("\\node_modules\\@anthropic-ai\\claude-code\\cli.js")
    })
}
fn claude_kind(image: &str, args: &[String]) -> Option<&'static str> {
    let path = normalized(image);
    let name = path.rsplit('\\').next()?;
    if ["node.exe", "bun.exe"].contains(&name) && official_cli(args) {
        return Some("Claude Code");
    }
    let home = normalized(&std::env::var("USERPROFILE").ok()?);
    if path == format!("{home}\\.local\\bin\\claude.exe")
        || path == format!("{home}\\.bun\\bin\\claude.exe")
        || (Path::new(&path).parent()
            == Some(Path::new(&format!(
                "{home}\\.local\\share\\claude\\versions"
            )))
            && version_name(name))
    {
        return Some("Claude Code");
    }
    if name != "claude.exe" {
        return None;
    }
    let local = normalized(&std::env::var("LOCALAPPDATA").ok()?);
    if path == format!("{local}\\microsoft\\winget\\packages\\anthropic.claudecode_microsoft.winget.source_8wekyb3d8bbwe\\claude.exe") { return Some("Claude Code"); }
    if path.starts_with(&format!("{local}\\anthropicclaude\\"))
        || path.starts_with(&format!("{local}\\programs\\claude\\"))
    {
        return Some("Claude Desktop");
    }
    None
}
fn version_name(name: &str) -> bool {
    let name = name.strip_suffix(".exe").unwrap_or(name);
    let parts: Vec<_> = name.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}
fn processes(terminate: bool) -> Result<Vec<(u32, Handle)>, String> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err("无法检查 Windows 进程。".into());
    }
    let snapshot = Handle(snapshot);
    let mut entry = unsafe { std::mem::zeroed::<PROCESSENTRY32W>() };
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut result = vec![];
    let mut has = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    while has != 0 {
        let name = String::from_utf16_lossy(&entry.szExeFile)
            .trim_end_matches('\0')
            .to_lowercase();
        if (["claude.exe", "node.exe", "bun.exe", "chrome.exe"].contains(&name.as_str())
            || version_name(&name))
            && entry.th32ProcessID > 1
        {
            if let Some(handle) = Handle::open(entry.th32ProcessID, terminate) {
                result.push((entry.th32ProcessID, handle));
            }
        }
        has = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    Ok(result)
}
pub fn claude_processes() -> Result<Vec<ClaudeProcess>, String> {
    let mut found = vec![];
    for (pid, handle) in processes(false)? {
        let Some(image) = handle.image() else { continue; };
        let args = arguments(&handle).unwrap_or_default();
        let kind = if handle.packaged_claude() {
            Some("Claude Desktop")
        } else {
            claude_kind(&image, &args)
        };
        if let (Some(kind), Some(created)) = (kind, handle.created()) {
            found.push(ClaudeProcess {
                pid: pid as i32,
                name: kind.into(),
                executable: image,
                created,
            });
        }
    }
    Ok(found)
}
pub fn kill_process(target: &ClaudeProcess) -> Result<(), String> {
    let Some(handle) = Handle::open(target.pid as u32, true) else { return Ok(()); };
    if handle.created() != Some(target.created)
        || handle.image().as_deref() != Some(target.executable.as_str())
    {
        return Ok(());
    }
    if !handle.packaged_claude()
        && claude_kind(&target.executable, &arguments(&handle).unwrap_or_default()).is_none()
    {
        return Ok(());
    }
    if unsafe { TerminateProcess(handle.0, 1) } == 0 {
        return Err("无法终止已核验的 Claude 进程。".into());
    }
    Ok(())
}
fn profile_matches(args: &[String], profile: &str) -> bool {
    args.iter().enumerate().any(|(index, arg)| {
        let value = arg.strip_prefix("--user-data-dir=").or_else(|| {
            if arg == "--user-data-dir" {
                args.get(index + 1).map(String::as_str)
            } else {
                None
            }
        });
        value.is_some_and(|value| normalized(value) == normalized(profile))
    })
}
fn protected_arguments(args: &[String], endpoint: &str) -> bool {
    let (mut proxy, mut bypass, mut webrtc) = (None, None, None);
    let mut disable_quic = false;
    for argument in args {
        let arg = argument.trim();
        if arg == "--" { break; }
        let Some(switch) = arg.strip_prefix("--").or_else(|| arg.strip_prefix('-')).or_else(|| arg.strip_prefix('/')) else { continue; };
        let (name, value) = switch.split_once('=').unwrap_or((switch, ""));
        let key = name.to_ascii_lowercase();
        match key.as_str() {
            // Chromium tests presence for these switches, even when the value is "false".
            "no-proxy-server" | "proxy-pac-url" | "proxy-auto-detect" | "enable-quic"
            // This Windows shell form reparses the raw command line; do not infer its switches.
            | "single-argument" => return false,
            "proxy-server" | "proxy-bypass-list" | "force-webrtc-ip-handling-policy" | "disable-quic" => {},
            _ => continue,
        }
        // Only trust the canonical spelling generated by this application. Recognize
        // Windows aliases/case/whitespace above so they cannot conceal an override.
        if arg != argument || !arg.starts_with("--") || name != key { return false; }
        // Chromium keeps the last value of duplicate switches.
        match key.as_str() {
            "proxy-server" => proxy = Some(value),
            "proxy-bypass-list" => bypass = Some(value),
            "force-webrtc-ip-handling-policy" => webrtc = Some(value),
            "disable-quic" => disable_quic = true,
            _ => unreachable!(),
        }
    }
    proxy == Some(endpoint) && disable_quic
        && webrtc == Some("disable_non_proxied_udp")
        && bypass == Some("localhost;127.0.0.1;[::1]")
}
pub(crate) fn browser_proxy_matches(profile: &Path, endpoint: &str) -> Result<(), String> {
    for (_, handle) in processes(false)? {
        let Some(args) = arguments(&handle) else { continue; };
        if handle.image().is_some_and(|image| normalized(&image).ends_with("\\chrome.exe"))
            && profile_matches(&args, &profile.to_string_lossy())
            && !args.iter().any(|a| a.starts_with("--type="))
            && !protected_arguments(&args, endpoint) {
            return Err("已运行的指纹浏览器没有绑定当前固定代理。请正常退出后重新启动。".into());
        }
    }
    Ok(())
}
unsafe extern "system" fn close_window(window: HWND, pid: LPARAM) -> i32 {
    let mut owner = 0;
    GetWindowThreadProcessId(window, &mut owner);
    if owner == pid as u32 {
        PostMessageW(window, WM_CLOSE, 0, 0);
    }
    1
}
fn browser(profile: &str, close: bool) -> Result<bool, String> {
    if !Path::new(profile).is_absolute() {
        return Err("资料路径无效。".into());
    }
    let mut found = false;
    for (pid, handle) in processes(false)? {
        if handle
            .image()
            .is_some_and(|image| normalized(&image).ends_with("\\chrome.exe"))
            && arguments(&handle).is_some_and(|args| profile_matches(&args, profile))
        {
            found = true;
            if close {
                unsafe {
                    EnumWindows(Some(close_window), pid as LPARAM);
                }
            }
        }
    }
    Ok(found)
}
pub unsafe fn rf_browser_running(profile: *const c_char) -> *mut c_char {
    response(browser(input(profile), false).map(|running| json!({"running":running})))
}
pub unsafe fn rf_browser_quit(profile: *const c_char) -> *mut c_char {
    response(browser(input(profile), true).map(|_| json!({"ok":true})))
}
// ----- 本次安装子进程树：超时和宿主退出都不会留下后台安装器 -----
pub(crate) struct ChildJob(Handle);
impl ChildJob {
    pub(crate) fn attach(child: &std::process::Child) -> Result<Self, String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::JobObjects::*;
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err("无法隔离 Windows 安装子进程。".into());
        }
        let job = Self(Handle(raw));
        let mut limit = unsafe { std::mem::zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
        limit.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                raw,
                JobObjectExtendedLimitInformation,
                (&limit as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limit) as u32,
            )
        } == 0
            || unsafe { AssignProcessToJobObject(raw, child.as_raw_handle()) } == 0
        {
            return Err("无法隔离 Windows 安装子进程。".into());
        }
        Ok(job)
    }
    pub(crate) fn stop(&self) {
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.0 .0, 1);
        }
    }
    pub(crate) fn stop_and_wait(&self, timeout: std::time::Duration) -> Result<(), String> {
        use windows_sys::Win32::Foundation::{GetLastError, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA, WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::JobObjects::*;
        use windows_sys::Win32::System::Threading::{PROCESS_SYNCHRONIZE, WaitForSingleObject};
        let started = std::time::Instant::now();
        // Job accounting can reach zero before process handles become signaled.
        // Retain live process objects before termination; a PID alone can be reused.
        let mut capacity = 16usize;
        let handles = loop {
            let mut buffer = vec![0usize; capacity + 2];
            let bytes = (buffer.len() * std::mem::size_of::<usize>()) as u32;
            let result = unsafe { QueryInformationJobObject(self.0 .0, JobObjectBasicProcessIdList,
                buffer.as_mut_ptr().cast(), bytes, std::ptr::null_mut()) };
            let list = unsafe { &*buffer.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() };
            if result == 0 {
                if unsafe { GetLastError() } != ERROR_MORE_DATA {
                    return Err("无法读取本次操作的子进程树。".into());
                }
                capacity = capacity.saturating_mul(2).max(list.NumberOfAssignedProcesses as usize);
                if capacity > 65_536 || started.elapsed() >= timeout {
                    return Err("读取本次操作的子进程树超时或超过限制。".into());
                }
                continue;
            }
            let count = list.NumberOfProcessIdsInList as usize;
            let offset = std::mem::offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList);
            if count > (bytes as usize - offset) / std::mem::size_of::<usize>() {
                return Err("本次操作的子进程列表不完整。".into());
            }
            let pids = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>().add(offset).cast::<usize>(), count) };
            let mut handles = Vec::with_capacity(count);
            for &pid in pids {
                let pid = u32::try_from(pid).map_err(|_| "本次操作的进程标识无效。")?;
                let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
                if raw.is_null() {
                    // The process may have exited and disappeared since the snapshot.
                    if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER { continue; }
                    return Err("无法等待本次操作的子进程退出。".into());
                }
                let handle = Handle(raw);
                let mut in_job = 0;
                if unsafe { IsProcessInJob(handle.0, self.0 .0, &mut in_job) } == 0 {
                    return Err("无法核验本次操作的子进程归属。".into());
                }
                if in_job != 0 { handles.push(handle); }
            }
            break handles;
        };
        if unsafe { TerminateJobObject(self.0 .0, 1) } == 0 {
            return Err("无法终止本次操作的子进程树。".into());
        }
        for handle in &handles {
            let remaining = timeout.saturating_sub(started.elapsed()).as_millis().min(u32::MAX as u128 - 1) as u32;
            match unsafe { WaitForSingleObject(handle.0, remaining) } {
                WAIT_OBJECT_0 => {},
                WAIT_TIMEOUT => return Err("等待本次操作的子进程退出超时。".into()),
                _ => return Err("无法核验本次操作的子进程已退出。".into()),
            }
        }
        let mut accounting = unsafe { std::mem::zeroed::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() };
        if unsafe { QueryInformationJobObject(self.0 .0, JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            std::mem::size_of_val(&accounting) as u32, std::ptr::null_mut()) } == 0 {
            return Err("无法核验本次操作的子进程树已停止。".into());
        }
        if accounting.ActiveProcesses != 0 {
            return Err("本次操作仍有未退出的子进程。".into());
        }
        Ok(())
    }
    pub(crate) fn release(&self) -> Result<(), String> {
        use windows_sys::Win32::System::JobObjects::*;
        let limit = unsafe { std::mem::zeroed::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() };
        if unsafe { SetInformationJobObject(self.0 .0, JobObjectExtendedLimitInformation,
            (&limit as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(), std::mem::size_of_val(&limit) as u32) } == 0 {
            return Err("无法释放已完成操作的进程。".into());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn conflicting_or_missing_browser_switches_are_rejected() {
        let endpoint = "http://127.0.0.1:17892";
        let args = vec![format!("--proxy-server={endpoint}"), "--disable-quic".into(),
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp".into(), "--proxy-bypass-list=localhost;127.0.0.1;[::1]".into()];
        assert!(protected_arguments(&args, endpoint));
        for name in ["no-proxy-server", "proxy-auto-detect", "proxy-pac-url", "enable-quic", "single-argument"] {
            for prefix in ["--", "-", "/"] {
                for suffix in ["", "=", "=false", "=true", "=http://example.invalid/pac"] {
                    for key in [name.to_string(), name.to_ascii_uppercase()] {
                        let flag = format!("{prefix}{key}{suffix}");
                        let mut invalid = args.clone(); invalid.push(flag.clone());
                        assert!(!protected_arguments(&invalid, endpoint), "accepted {flag}");
                    }
                }
            }
        }
        for flag in ["--proxy-server=http://127.0.0.1:7892", "--proxy-server", "--proxy-server=", "--proxy-bypass-list=*",
            "--force-webrtc-ip-handling-policy=default", " --no-proxy-server=false ", "--PROXY-SERVER=http://127.0.0.1:7892",
            "-proxy-server=http://127.0.0.1:7892", "/proxy-server=http://127.0.0.1:7892"] {
            let mut invalid = args.clone(); invalid.push(flag.into());
            assert!(!protected_arguments(&invalid, endpoint), "accepted {flag}");
        }
        for index in 0..args.len() {
            let mut missing = args.clone(); missing.remove(index);
            assert!(!protected_arguments(&missing, endpoint));
            for alias in [args[index].replacen("--", "-", 1), args[index].replacen("--", "/", 1), args[index].to_ascii_uppercase(), format!(" {} ", args[index])] {
                let mut unusual = args.clone(); unusual[index] = alias;
                assert!(!protected_arguments(&unusual, endpoint));
            }
        }
        let mut corrected = vec!["--proxy-server=http://127.0.0.1:7892".into()];
        corrected.extend(args.clone());
        assert!(protected_arguments(&corrected, endpoint));
        let mut after_terminator = vec!["--".into()]; after_terminator.extend(args.clone());
        assert!(!protected_arguments(&after_terminator, endpoint));
        let mut url_arguments = args.clone(); url_arguments.extend(["--".into(), "--no-proxy-server=false".into()]);
        assert!(protected_arguments(&url_arguments, endpoint));
        let mut url = args.clone(); url.push("https://example.invalid/?--no-proxy-server=false".into());
        assert!(protected_arguments(&url, endpoint));
        assert!(!protected_arguments(&[], endpoint));
    }
    #[test]
    fn exact_arguments_reject_substrings_and_unrelated_scripts() {
        assert!(official_cli(&[
            "node.exe".into(),
            "C:\\test\\node_modules\\@anthropic-ai\\claude-code\\cli.js".into()
        ]));
        assert!(!official_cli(&[
            "node.exe".into(),
            "C:\\other.js".into(),
            "C:\\test\\node_modules\\@anthropic-ai\\claude-code\\cli.js".into()
        ]));
        assert!(!profile_matches(
            &["--user-data-dir=C:\\profile-other".into()],
            "C:\\profile"
        ));
        assert!(profile_matches(
            &["--user-data-dir=C:\\空 格\\profile".into()],
            "C:\\空 格\\profile"
        ));
        let home = std::env::var("USERPROFILE").unwrap();
        assert_eq!(
            claude_kind(&format!(r"{home}\.bun\bin\claude.exe"), &[]),
            Some("Claude Code")
        );
        assert!(current_sid().is_some());
        assert!(Handle::open(std::process::id(), false).is_some());
    }
}
