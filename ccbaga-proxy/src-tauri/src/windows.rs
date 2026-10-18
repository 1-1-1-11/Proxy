// [INPUT]: Windows 当前用户 SID、时区、注册表状态、系统工具与受限进程接口。
// [OUTPUT]: Windows 平台 JSON 桥；支持时区/语言/区域/定位状态、Win32 剪贴板、当前用户文件所有权和安全进程接口。
// [POS]: 仅原生识别与用户触发的系统操作；不含网络客户端，不向 UI 输出进程参数或代理秘密。
// [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
use serde_json::{json, Value};
use std::os::windows::process::CommandExt;
use std::{
    ffi::{c_char, CStr, CString},
    process::{Command, Stdio},
};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
#[path = "windows_process.rs"]
mod processes;
pub(crate) use processes::ChildJob;
pub(crate) use processes::browser_proxy_matches;
pub use processes::{claude_processes, kill_process, rf_browser_quit, rf_browser_running};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

#[cfg(test)]
pub unsafe fn rf_credentials_remove(_: *const c_char) -> *mut c_char {
    response(Err("Windows 凭据管理器不支持自动删除。".into()))
}

fn response(value: Result<Value, String>) -> *mut c_char {
    let value = value.unwrap_or_else(|error| json!({"error": error}));
    CString::new(value.to_string())
        .expect("JSON escapes NUL")
        .into_raw()
}

unsafe fn input<'a>(value: *const c_char) -> &'a str {
    CStr::from_ptr(value).to_str().unwrap_or("")
}

pub unsafe fn rf_free(value: *mut c_char) {
    if !value.is_null() {
        drop(CString::from_raw(value));
    }
}

fn output(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .creation_flags(0x08000000)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|_| format!("Windows: {program} 无法执行。"))?;
    if !out.status.success() {
        let err_msg = String::from_utf8_lossy(&out.stderr);
        return Err(format!("Windows: {program} 执行失败: {err_msg}"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

pub fn open_external_url(url: &str) -> Result<(), String> {
    let verb: Vec<u16> = "open".encode_utf16().chain(Some(0)).collect();
    let file: Vec<u16> = url.encode_utf16().chain(Some(0)).collect();
    unsafe {
        let inst = ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
        if (inst as usize) > 32 {
            Ok(())
        } else {
            Err("无法打开目标地址。".into())
        }
    }
}


pub unsafe fn rf_credentials_list() -> *mut c_char {
    response(Err(
        "Windows 凭据管理器不自动读取；文件登录记录可在清理预览中选择。".into(),
    ))
}

// ----- 所有权：只比较 SID，不收集账户名称或凭据正文 -----
pub(super) unsafe fn process_sid(process: HANDLE) -> Option<Vec<u8>> {
    let mut token = std::ptr::null_mut();
    if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
        return None;
    }
    let mut size = 0;
    GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size);
    let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    let ok = size > 0
        && GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        ) != 0;
    let sid = if ok {
        let user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
        Some(
            std::slice::from_raw_parts(
                user.User.Sid.cast::<u8>(),
                GetLengthSid(user.User.Sid) as usize,
            )
            .to_vec(),
        )
    } else {
        None
    };
    CloseHandle(token);
    sid
}
pub(super) fn current_sid() -> Option<&'static Vec<u8>> {
    static SID: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();
    SID.get_or_init(|| unsafe { process_sid(GetCurrentProcess()) })
        .as_ref()
}
pub fn owned(path: &std::path::Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe {
        let mut owner = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        let status = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        );
        let matches = status == 0
            && !owner.is_null()
            && current_sid().is_some_and(|sid| {
                sid.as_slice()
                    == std::slice::from_raw_parts(owner.cast::<u8>(), GetLengthSid(owner) as usize)
            });
        if !descriptor.is_null() {
            LocalFree(descriptor.cast());
        }
        matches
    }
}
#[cfg(test)]
pub(crate) fn fixture_owner(path: &std::path::Path) {
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner = current_sid().expect("test user SID").clone();
    assert_eq!(
        unsafe {
            windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                owner.as_mut_ptr().cast(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        0
    );
}
pub fn preserve_file_permissions(
    source: &std::path::Path,
    target: &std::path::Path,
) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let wide = |path: &std::path::Path| {
        path.as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<u16>>()
    };
    let source = wide(source);
    let target = wide(target);
    unsafe {
        let mut owner = std::ptr::null_mut();
        let mut acl = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        let read = GetNamedSecurityInfoW(
            source.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut descriptor,
        );
        let status = if read == 0 && !owner.is_null() && !acl.is_null() {
            SetNamedSecurityInfoW(
                target.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                std::ptr::null_mut(),
                acl,
                std::ptr::null(),
            )
        } else {
            1
        };
        if !descriptor.is_null() {
            LocalFree(descriptor.cast());
        }
        if status != 0 {
            return Err("无法保留 Windows 配置权限，未写入内容。".into());
        }
    }
    Ok(())
}
pub fn linked(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & 0x400 != 0
}


pub fn open_settings(pane: &str) -> Result<Value, String> {
    let uri = match pane {
        "timezone" => "ms-settings:dateandtime",
        "language" => "ms-settings:regionformatting",
        "location" => "ms-settings:privacy-location",
        _ => return Err("无效的系统设置入口。".into()),
    };
    open_external_url(uri)?;
    Ok(json!({"ok": true}))
}

#[path = "windows_timezones.rs"]
mod zones;
use zones::TZ_MAP;

pub fn iana_to_windows_tz(iana: &str) -> Option<&'static str> {
    TZ_MAP.iter().find(|(i, _)| *i == iana).map(|(_, w)| *w)
}

pub fn windows_to_iana_tz(win: &str) -> Option<&'static str> {
    let win_clean = win.trim();
    TZ_MAP
        .iter()
        .find(|(_, w)| w.eq_ignore_ascii_case(win_clean))
        .map(|(i, _)| *i)
}

pub fn timezone() -> String {
    let out = raw_windows_timezone();
    crate::regions::get_regions()
        .iter()
        .find(|region| {
            region.locale == locale() && iana_to_windows_tz(region.timezone) == Some(out.as_str())
        })
        .map(|region| region.timezone)
        .or_else(|| windows_to_iana_tz(&out))
        .unwrap_or(&out)
        .to_string()
}

pub fn raw_windows_timezone() -> String {
    use windows_sys::Win32::System::Time::{
        GetDynamicTimeZoneInformation, DYNAMIC_TIME_ZONE_INFORMATION,
    };
    let mut information = unsafe { std::mem::zeroed::<DYNAMIC_TIME_ZONE_INFORMATION>() };
    if unsafe { GetDynamicTimeZoneInformation(&mut information) } == u32::MAX {
        return String::new();
    }
    let key = information
        .TimeZoneKeyName
        .split(|c| *c == 0)
        .next()
        .unwrap_or_default();
    String::from_utf16_lossy(key)
}

pub fn timezones() -> Vec<String> {
    let mut list = Vec::new();
    for (iana, _) in TZ_MAP {
        list.push((*iana).to_string());
    }
    list.sort();
    list.dedup();
    list
}

fn locale() -> String {
    use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
    let mut value = [0u16; 85];
    let count = unsafe { GetUserDefaultLocaleName(value.as_mut_ptr(), value.len() as i32) };
    if count <= 1 {
        return String::new();
    }
    String::from_utf16_lossy(&value[..count as usize - 1]).replace('-', "_")
}
fn session_language() -> String {
    use windows_sys::Win32::Globalization::{GetUserPreferredUILanguages, MUI_LANGUAGE_NAME};
    let mut count = 0;
    let mut size = 0;
    unsafe {
        GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME,
            &mut count,
            std::ptr::null_mut(),
            &mut size,
        );
    }
    let mut buffer = vec![0u16; size as usize];
    if size == 0
        || unsafe {
            GetUserPreferredUILanguages(
                MUI_LANGUAGE_NAME,
                &mut count,
                buffer.as_mut_ptr(),
                &mut size,
            )
        } == 0
    {
        return String::new();
    }
    let first = buffer.split(|c| *c == 0).next().unwrap_or_default();
    let language = String::from_utf16_lossy(first);
    match language.as_str() {
        "zh-CN" | "zh-SG" => "zh-Hans".into(),
        "zh-TW" | "zh-HK" => "zh-Hant".into(),
        _ => language,
    }
}
pub(super) fn registry_string(
    root: windows_sys::Win32::System::Registry::HKEY,
    key: &str,
    name: &str,
) -> Option<String> {
    use windows_sys::Win32::System::Registry::{RegGetValueW, RRF_RT_REG_SZ};
    let key: Vec<u16> = key.encode_utf16().chain(Some(0)).collect();
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut value = [0u16; 2048];
    let mut bytes = std::mem::size_of_val(&value) as u32;
    let status = unsafe {
        RegGetValueW(
            root,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            value.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status != 0 {
        return None;
    }
    Some(
        String::from_utf16_lossy(&value[..bytes as usize / 2])
            .trim_end_matches('\0')
            .into(),
    )
}
fn location_enabled() -> Option<bool> {
    use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    match registry_string(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
        "Value",
    )?
    .as_str()
    {
        "Allow" => Some(true),
        "Deny" => Some(false),
        _ => None,
    }
}

fn snapshot() -> Value {
    json!({
        "platform": "windows",
        "timezone": timezone(),
        "timezones": timezones(),
        "automatic_timezone": null,
        "languages": [session_language()],
        "location_enabled": location_enabled(),
        "accessibility": false
    })
}

pub unsafe fn rf_browser_machine() -> *mut c_char {
    let mut state = snapshot();
    state["platform"] = json!("windows");
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    state["version"] = json!(VERSION.get_or_init(|| output(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[System.Environment]::OSVersion.Version.ToString()"
        ]
    )
    .unwrap_or_default()));
    state["cores"] = json!(std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1));
    state["locale"] = json!(locale());
    let proxy = [
        "ALL_PROXY",
        "all_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ]
    .iter()
    .find_map(|k| std::env::var(k).ok())
    .unwrap_or_default();
    state["system_proxy"] = json!(proxy);
    response(Ok(state))
}

pub unsafe fn rf_system_read() -> *mut c_char {
    response(Ok(snapshot()))
}


pub unsafe fn rf_system_timezone(zone: *const c_char) -> *mut c_char {
    response((|| {
        let requested = input(zone).trim();
        let target_win_tz = iana_to_windows_tz(requested).ok_or("无效的时区。")?;
        if output("tzutil", &["/s", target_win_tz]).is_err() {
            open_settings("timezone")?;
            return Err("Windows 未允许修改时区；请在系统设置中完成授权后重试。".into());
        }
        let current_raw = raw_windows_timezone();
        if current_raw.to_lowercase() != target_win_tz.to_lowercase() {
            return Err("时区修改未通过核验。".into());
        }
        Ok(json!({
            "state": snapshot(),
            "message": "时区已成功应用并核验。"
        }))
    })())
}


pub unsafe fn rf_system_location() -> *mut c_char {
    response((|| {
        if location_enabled() == Some(false) {
            Ok(json!({
                "state": snapshot(),
                "message": "Windows 定位权限已成功禁用并核验。"
            }))
        } else {
            open_settings("location")?;
            Err("请在打开的 Windows 设置窗口中手动关闭定位权限。".into())
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ci_timezone_write_is_verified_and_restored() {
        for region in crate::regions::get_regions() {
            assert!(iana_to_windows_tz(region.timezone).is_some());
        }
        if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
            return;
        }
        struct Restore(String);
        impl Drop for Restore {
            fn drop(&mut self) {
                output("tzutil", &["/s", &self.0]).expect("restore CI timezone");
            }
        }
        let before = Restore(raw_windows_timezone());
        assert!(!before.0.is_empty());
        let requested = CString::new("Asia/Tokyo").unwrap();
        let state: Value =
            crate::native::decode(unsafe { rf_system_timezone(requested.as_ptr()) }).unwrap();
        assert!(state["state"].is_object());
        assert_eq!(raw_windows_timezone(), "Tokyo Standard Time");
        let invalid = CString::new("Asia/Tokyo; malicious").unwrap();
        assert!(
            crate::native::decode::<Value>(unsafe { rf_system_timezone(invalid.as_ptr()) })
                .is_err()
        );
        assert_eq!(raw_windows_timezone(), "Tokyo Standard Time");
    }
}
