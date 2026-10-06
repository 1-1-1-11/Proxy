"""Read-only, secret-safe Claude configuration checks.

No Claude process, repair operation, credential file, browser profile or network
probe is invoked here.  ``evidence`` contains projections, never raw settings.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import urlsplit


_PROXY_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
_AUTH_KEYS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN")
_PROVIDER_KEYS = ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY")
_FLAG_KEYS = (*_PROVIDER_KEYS, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
              "DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING", "NODE_TLS_REJECT_UNAUTHORIZED")
_ENV_KEYS = (*_PROXY_KEYS, *(k.lower() for k in _PROXY_KEYS), "NO_PROXY", "no_proxy",
             "BROWSER", "ANTHROPIC_BASE_URL", *_AUTH_KEYS, *_FLAG_KEYS)
_LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _item(ident, status, title, detail, evidence=None, required=False):
    return {"id": ident, "category": "configuration", "status": status,
            "required": required, "title": title, "detail": detail,
            "evidence": evidence or {}}


def _run(args, **kwargs):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=kwargs.pop("timeout", 20),
                          creationflags=0x08000000 if os.name == "nt" else 0, **kwargs)


def _safe_url(value):
    """Keep only an endpoint; URL userinfo, path, query and fragment never leave."""
    if not isinstance(value, str):
        return {"valid": False, "type": type(value).__name__}
    try:
        p = urlsplit(value)
        valid = p.scheme in {"http", "https", "socks", "socks4", "socks5", "socks5h"} and bool(p.hostname)
        return {"valid": valid, "scheme": p.scheme if valid else None,
                "host": p.hostname if valid else None, "port": p.port if valid else None,
                "has_credentials": p.username is not None or p.password is not None,
                "has_path": p.path not in {"", "/"}, "has_query": bool(p.query),
                "has_fragment": bool(p.fragment)}
    except (ValueError, TypeError):
        return {"valid": False, "type": "str"}


def _safe_no_proxy(value):
    if not isinstance(value, str):
        return {"valid": False, "invalid_entries": 1, "loopback": []}
    entries = [s.strip().lower() for s in value.split(",") if s.strip()]
    invalid = sum(e not in _LOOPBACK for e in entries)
    return {"valid": bool(entries) and not invalid, "invalid_entries": invalid,
            "loopback": sorted(set(e for e in entries if e in _LOOPBACK))}


def _flag(value):
    if value in (True, 1, "1", "true", "yes", "on"):
        return {"enabled": True, "valid": True}
    if value in (False, 0, "0", "false", "no", "off", ""):
        return {"enabled": False, "valid": True}
    return {"enabled": None, "valid": False}


def _safe_env(raw, browser):
    """Used for Windows environment and tests; file projection happens in Node."""
    if not isinstance(raw, dict):
        return {"_invalid": True}
    result = {}
    for key in _ENV_KEYS:
        if key not in raw:
            continue
        value = raw[key]
        if key.upper() in _PROXY_KEYS or key == "ANTHROPIC_BASE_URL":
            result[key] = _safe_url(value)
        elif key.upper() == "NO_PROXY":
            result[key] = _safe_no_proxy(value)
        elif key in _AUTH_KEYS:
            result[key] = {"present": True}
        elif key == "BROWSER":
            result[key] = {"matches_expected": isinstance(value, str) and
                           value.replace("\\", "/").lower() == str(browser).replace("\\", "/").lower()}
        elif key in _FLAG_KEYS:
            result[key] = _flag(value)
    return result


def _env_evidence(projected):
    """Keep case-distinct names as values for case-insensitive JSON readers.

    ``projected`` already contains only the secret-safe fields used by the
    checks. Keep their dictionary shape internally so precedence checks retain
    both variants; only the report representation changes.
    """
    return [{"name": name, "value": value} for name, value in projected.items()]


# JSONC is parsed once in a child process. Only the projected fields cross its
# stdout pipe. In particular, an auth value is replaced before JSON.stringify.
_JSONC_READER = r"""
const fs=require('fs');
const req=JSON.parse(fs.readFileSync(0,'utf8'));
const parser=require(req.parser);
const proxyKeys=new Set(['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY']);
const authKeys=new Set(req.authKeys), flagKeys=new Set(req.flagKeys);
const known=new Set(req.keys), loopback=new Set(['localhost','127.0.0.1','::1','[::1]']);
const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
function url(v){
 if(typeof v!=='string') return {valid:false,type:typeof v};
 try {const u=new URL(v);const scheme=u.protocol.slice(0,-1);
  const valid=['http','https','socks','socks4','socks5','socks5h'].includes(scheme)&&!!u.hostname;
  return {valid,scheme:valid?scheme:null,host:valid?u.hostname.replace(/^\[|\]$/g,''):null,
   port:valid?(u.port?Number(u.port):scheme==='http'?80:scheme==='https'?443:null):null,
   has_credentials:!!(u.username||u.password),has_path:!['','/'].includes(u.pathname),
   has_query:!!u.search,has_fragment:!!u.hash};
 }catch{return {valid:false,type:'str'};}
}
function flag(v){
 if([true,1,'1','true','yes','on'].includes(v))return {enabled:true,valid:true};
 if([false,0,'0','false','no','off',''].includes(v))return {enabled:false,valid:true};
 return {enabled:null,valid:false};
}
function env(e){
 if(!e||typeof e!=='object'||Array.isArray(e))return {_invalid:true};
 const out={};
 for(const [k,v] of Object.entries(e)){
  if(!known.has(k))continue;
  if(proxyKeys.has(k.toUpperCase())||k==='ANTHROPIC_BASE_URL')out[k]=url(v);
  else if(k.toUpperCase()==='NO_PROXY'){
   const a=typeof v==='string'?v.split(',').map(x=>x.trim().toLowerCase()).filter(Boolean):[];
   const invalid=typeof v==='string'?a.filter(x=>!loopback.has(x)).length:1;
   out[k]={valid:!!a.length&&!invalid,invalid_entries:invalid,loopback:[...new Set(a.filter(x=>loopback.has(x)))].sort()};
  }else if(authKeys.has(k))out[k]={present:true};
  else if(k==='BROWSER')out[k]={matches_expected:typeof v==='string'&&v.replace(/\\/g,'/').toLowerCase()===req.browser.replace(/\\/g,'/').toLowerCase()};
  else if(flagKeys.has(k))out[k]=flag(v);
 }
 return out;
}
const result=[];
for(const file of req.files){
 try {
  const errors=[],data=parser.parse(fs.readFileSync(file.path,'utf8').replace(/^\uFEFF/,''),errors,{allowTrailingComma:true});
  if(errors.length||!data||typeof data!=='object'||Array.isArray(data)){
   result.push({path:file.path,error:'invalid_jsonc',errors:errors.map(e=>({code:e.error,offset:e.offset,length:e.length}))});continue;
  }
  let projected;
  if(file.kind==='vscode'){
   const list=data['claudeCode.environmentVariables'];
   let e={},invalid=false,duplicates=[];
   if(list!==undefined){
    if(!Array.isArray(list))invalid=true;
    else for(const a of list){
     if(!a||typeof a!=='object'||typeof a.name!=='string'||!own(a,'value')){invalid=true;continue;}
     if(known.has(a.name)&&own(e,a.name))duplicates.push(a.name);
     e[a.name]=a.value;
    }
   }
   projected={env:invalid?{_invalid:true}:env(e),duplicate_keys:duplicates,
    externalBrowser:own(data,'workbench.externalBrowser')?{matches_expected:typeof data['workbench.externalBrowser']==='string'&&data['workbench.externalBrowser'].replace(/\\/g,'/').toLowerCase()===req.browser.replace(/\\/g,'/').toLowerCase()}:null,
    vscodeHttpProxy:own(data,'http.proxy')?url(data['http.proxy']):null,
    terminalEnv:own(data,'terminal.integrated.env.windows')?env(data['terminal.integrated.env.windows']):null};
  }else projected={env:own(data,'env')?env(data.env):{},apiKeyHelper:own(data,'apiKeyHelper')};
  result.push({path:file.path,data:projected});
 }catch{result.push({path:file.path,error:'read_or_parse_failed'});}
}
process.stdout.write(JSON.stringify(result));
"""


def _read_settings_batch(install_dir, files):
    parser = install_dir / "vendor/jsonc-parser/lib/main.js"
    node = shutil.which("node")
    if not node or not parser.is_file():
        return {}, "JSONC 解析器或 Node 不可用"
    request = {"parser": str(parser.resolve()), "files": files,
               "browser": str(install_dir / "ClaudeBrowser.exe"),
               "authKeys": _AUTH_KEYS, "flagKeys": _FLAG_KEYS, "keys": _ENV_KEYS}
    try:
        result = _run([node, "-e", _JSONC_READER], input=json.dumps(request), timeout=20)
        if result.returncode:
            return {}, "JSONC 解析进程失败"
        rows = json.loads(result.stdout)
        if not isinstance(rows, list):
            raise ValueError()
        return {r["path"]: r for r in rows}, None
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        return {}, "JSONC 解析未完成"


def _correct_proxy(value, port):
    return bool(value.get("valid") and value.get("scheme") == "http" and
                value.get("host") == "127.0.0.1" and value.get("port") == port and
                not any(value.get(k) for k in ("has_credentials", "has_path", "has_query", "has_fragment")))


def _audit_projected_env(env, ident, title, port, complete=False, external_browser=None,
                         require_external=False, duplicate_keys=()):
    problems = []
    if env.get("_invalid"):
        problems.append("环境变量结构无效")
    if complete:
        # Both case variants are deliberate: clients differ in precedence and
        # a lower-case stale value must never be masked by an upper-case check.
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "NO_PROXY", "no_proxy", "BROWSER"):
            if key not in env:
                problems.append("缺少 " + key)
    for key, value in env.items():
        if key.upper() in _PROXY_KEYS and not _correct_proxy(value, port):
            problems.append(key + " 未指向无凭据的专用 HTTP 入口")
        elif key.upper() == "NO_PROXY" and not value.get("valid"):
            problems.append(key + " 不是仅含本机地址的非空列表")
        elif key == "BROWSER" and not value.get("matches_expected"):
            problems.append("BROWSER 未指向专用启动器")
    if duplicate_keys:
        problems.append("VS Code 环境变量列表存在重复键")
    if (require_external and external_browser is None) or (external_browser is not None and not external_browser.get("matches_expected")):
        problems.append("VS Code 外部浏览器未指向专用启动器")
    evidence = {"env": _env_evidence(env), "problems": problems}
    if external_browser is not None:
        evidence["external_browser"] = external_browser
    return _item(ident, "fail" if problems else "pass", title,
                 "；".join(problems) if problems else ("必要代理及浏览器字段正确。" if complete else "存在的设置未覆盖为其他入口。"),
                 evidence, required=True)


def _audit_identity(env, ident, helper=False):
    auth = [k for k in _AUTH_KEYS if env.get(k, {}).get("present")]
    providers = [k for k in _PROVIDER_KEYS if env.get(k, {}).get("enabled") is not False and k in env]
    base = env.get("ANTHROPIC_BASE_URL")
    bad_base = base is not None and not (base.get("valid") and base.get("scheme") == "https" and base.get("host") == "api.anthropic.com" and not base.get("has_credentials"))
    evidence = {"auth_override_keys_present": auth, "provider_switches_present": providers,
                "api_key_helper_present": bool(helper)}
    if base is not None:
        evidence["base_url_host"] = base.get("host")
        evidence["base_url_valid"] = base.get("valid")
    if bad_base:
        return _item(ident, "fail", "官方 API 与认证覆盖", "检测到非官方或无法确认的 API 地址覆盖；未读取或显示认证值。", evidence, True)
    if auth or providers or helper:
        return _item(ident, "warn", "官方 API 与认证覆盖", "存在认证、供应商或 apiKeyHelper 覆盖，需要核对是否符合官方订阅登录用途；未读取凭据文件。", evidence, True)
    return _item(ident, "pass", "官方 API 与认证覆盖", "未发现第三方地址、认证环境变量或供应商切换覆盖；此项不证明当前登录身份。", evidence)


def _audit_safety_switches(env, ident):
    output = []
    if env.get("NODE_TLS_REJECT_UNAUTHORIZED", {}).get("enabled") is False:
        output.append(_item(ident + "-tls", "fail", "TLS 校验覆盖", "检测到 NODE_TLS_REJECT_UNAUTHORIZED 禁用 TLS 证书校验。", required=True))
    switches = {k: env[k] for k in ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING") if k in env}
    if any(v.get("enabled") is not True for v in switches.values()):
        output.append(_item(ident + "-telemetry", "warn", "非必要流量开关覆盖", "存在未启用或无效的禁用开关；需结合该作用域的优先级核对最终行为。", switches))
    return output


def _collect_files(workspace):
    user = Path.home()
    code = Path(os.environ.get("APPDATA", str(user / "AppData/Roaming"))) / "Code/User"
    specs = [dict(path=str(user / ".claude/settings.json"), kind="claude", complete=True, label="Claude 用户设置"),
             dict(path=str(code / "settings.json"), kind="vscode", complete=True, label="VS Code 用户设置")]
    optional = [(user / ".claude/settings.local.json", "claude", "Claude 用户 local 设置")]
    optional += [(p, "vscode", "VS Code profile 设置") for p in code.glob("profiles/*/settings.json")]
    for base in [workspace, *workspace.parents]:
        optional += [(base / ".claude/settings.json", "claude", "项目或祖先设置"),
                     (base / ".claude/settings.local.json", "claude", "项目或祖先 local 设置"),
                     (base / ".vscode/settings.json", "vscode", "项目或祖先 VS Code 设置")]
    optional += [(Path(os.environ.get("ProgramData", "C:/ProgramData")) / "ClaudeCode/managed-settings.json", "claude", "系统管理设置"),
                 (Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "ClaudeCode/managed-settings.json", "claude", "系统管理设置")]
    seen = {str(Path(s["path"]).resolve()).lower() for s in specs}
    for path, kind, label in optional:
        canonical = str(path.resolve()).lower()
        if path.is_file() and canonical not in seen:
            specs.append(dict(path=str(path), kind=kind, complete=False, label=label))
            seen.add(canonical)
    return specs


def _windows_environment():
    raw = {k: ("present" if k in _AUTH_KEYS else os.environ[k]) for k in _ENV_KEYS if k in os.environ}
    scopes = {"Process": raw}
    failures = []
    if os.name != "nt":
        return scopes, ["User", "Machine"]
    try:
        import winreg
        for scope, root, path in (("User", winreg.HKEY_CURRENT_USER, "Environment"),
                                  ("Machine", winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")):
            values = {}
            try:
                with winreg.OpenKey(root, path) as key:
                    for name in _ENV_KEYS:
                        try:
                            value, _ = winreg.QueryValueEx(key, name)
                            values[name] = "present" if name in _AUTH_KEYS else value
                        except FileNotFoundError:
                            pass
                scopes[scope] = values
            except FileNotFoundError:
                scopes[scope] = {}
            except OSError:
                failures.append(scope)
    except (ImportError, OSError):
        failures.extend(["User", "Machine"])
    return scopes, failures


def _client_signatures():
    user = Path.home()
    cli = [user / "AppData/Roaming/npm/node_modules/@anthropic-ai/claude-code/bin/claude.exe", user / ".local/bin/claude.exe"]
    extensions = list((user / ".vscode/extensions").glob("anthropic.claude-code-*/resources/native-binary/claude.exe"))
    paths = [p for p in cli + extensions if p.is_file()]
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if not shell or not paths:
        return [_item("client-signatures", "unknown", "Claude 客户端官方签名", "未找到可检查的官方客户端或 PowerShell；未启动 Claude。", required=True)]
    script = r'''[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$ErrorActionPreference='Stop'
$paths=([Console]::In.ReadToEnd()|ConvertFrom-Json)
$out=@(foreach($p in $paths){try{$i=Get-Item -LiteralPath $p;$s=Get-AuthenticodeSignature -LiteralPath $p
@{path=$p;version=$i.VersionInfo.ProductVersion;status=[string]$s.Status;anthropic=([string]$s.SignerCertificate.Subject -match 'O="?Anthropic, PBC"?(?:,|$)')}
}catch{@{path=$p;status='Unknown';anthropic=$false}}})
ConvertTo-Json -InputObject $out -Depth 4 -Compress'''
    try:
        result = _run([shell, "-NoProfile", "-NonInteractive", "-Command", script], input=json.dumps([str(p) for p in paths]), timeout=35)
        if result.returncode:
            raise ValueError()
        rows = json.loads(result.stdout.lstrip("\ufeff"))
        if not isinstance(rows, list) or len(rows) != len(paths):
            raise ValueError()
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return [_item("client-signatures", "unknown", "Claude 客户端官方签名", "签名查询未完成；没有据此认定客户端可信。", required=True)]
    output = []
    for label, candidates in (("cli", cli), ("vscode", extensions)):
        group = [r for r in rows if r.get("path") in {str(p) for p in candidates}]
        bad = any(r.get("status") not in {"Valid", "Unknown", "UnknownError"} or (r.get("status") == "Valid" and not r.get("anthropic")) for r in group)
        good = bool(group) and all(r.get("status") == "Valid" and r.get("anthropic") for r in group)
        output.append(_item("client-signature-" + label, "pass" if good else "fail" if bad else "unknown",
                            "CLI 官方签名" if label == "cli" else "VS Code Claude 官方签名",
                            "发现的客户端均有有效 Anthropic 签名；未启动客户端，不等于当前进程身份。" if good else "缺少客户端或无法确认有效的 Anthropic 签名。",
                            {"files": group}, required=True))
    return output


def _launcher(install_dir, expected_ip, entry_port):
    checks = []
    try:
        flags = None
        tree = ast.parse((install_dir / "browser_entry.py").read_text(encoding="utf-8-sig"))
        for statement in tree.body:
            if isinstance(statement, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "FLAGS" for t in statement.targets):
                flags = ast.literal_eval(statement.value)
        wanted = {f"--proxy-server=http://127.0.0.1:{entry_port}", "--proxy-bypass-list=localhost;127.0.0.1;[::1]",
                  "--webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-quic",
                  "--disable-features=MediaRouter"}
        good = isinstance(flags, list) and set(flags) == wanted
        checks.append(_item("browser-source-flags", "pass" if good else "fail", "专用浏览器启动参数",
                            "源码声明了专用代理、本机绕过、QUIC 与 MediaRouter 禁用和 WebRTC 策略参数；参数存在不证明策略生效或实际 UDP 受限。" if good else "浏览器源码的代理参数不符合预期或存在额外参数。",
                            {"flags_match": good}, True))
    except (OSError, SyntaxError, ValueError, TypeError):
        checks.append(_item("browser-source-flags", "unknown", "专用浏览器启动参数", "无法静态核对浏览器源码。", required=True))
    try:
        meta = json.loads((install_dir / "browser-build.json").read_text(encoding="utf-8-sig"))
        matches = {name: hashlib.sha256((install_dir / name).read_bytes()).hexdigest() == meta.get(name)
                   for name in ("ClaudeBrowser.cs", "ClaudeBrowser.exe")}
        good = all(matches.values())
        checks.append(_item("browser-build-baseline", "pass" if good else "fail", "专用浏览器构建基线",
                            "源码和程序与本机保存的哈希一致；这不是供应商签名认证。" if good else "源码或程序与保存的构建哈希不一致。", matches, True))
    except (OSError, ValueError, AttributeError):
        checks.append(_item("browser-build-baseline", "unknown", "专用浏览器构建基线", "启动器、源码或构建哈希不可读取。", required=True))
    try:
        policy = json.loads((install_dir / "audit_policy.json").read_text(encoding="utf-8-sig"))
        tree = ast.parse((install_dir / "network_check.py").read_text(encoding="utf-8-sig"))
        assignments = {name: [s.value for s in tree.body if isinstance(s, ast.Assign)
                              and any(isinstance(t, ast.Name) and t.id == name for t in s.targets)]
                       for name in ("_POLICY", "EXPECTED_IP")}
        policy_reference = len(assignments["_POLICY"]) == 1 and any(
            isinstance(n, ast.Constant) and n.value == "audit_policy.json" for n in ast.walk(assignments["_POLICY"][0]))
        values = assignments["EXPECTED_IP"]
        ip_reference = len(values) == 1 and isinstance(values[0], ast.Subscript) and isinstance(values[0].value, ast.Name) and values[0].value.id == "_POLICY" and isinstance(values[0].slice, ast.Constant) and values[0].slice.value == "expected_ip"
        functions = {s.name: s for s in tree.body if isinstance(s, ast.FunctionDef)}
        fixed = functions.get("fixed_ready")
        imports_preflight = any(isinstance(n, ast.ImportFrom) and n.module == "audit_proxy" and any(a.name == "preflight" and a.asname in {None, "preflight"} for a in n.names) for n in ast.walk(tree))
        calls_preflight = fixed is not None and any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "preflight" for n in ast.walk(fixed))
        guards_preserved = "checked" in functions and "probe" in functions
        policy_matches = isinstance(policy, dict) and policy.get("expected_ip") == expected_ip and policy.get("entry_port") == entry_port
        good = all((policy_reference, ip_reference, imports_preflight, calls_preflight, guards_preserved, policy_matches))
        checks.append(_item("launcher-expected-ip", "pass" if good else "fail", "启动前检查的预期出口",
                            "旧入口引用统一策略和 audit_proxy.preflight，且保留 guard 所需的 probe/checked 函数；此项为静态检查。" if good else "旧入口没有完整引用统一策略及预检，或 guard 接口、出口策略不一致。",
                            {"policy_matches": policy_matches, "reads_policy_file": policy_reference,
                             "expected_ip_from_policy": ip_reference, "imports_preflight": imports_preflight,
                             "fixed_ready_calls_preflight": calls_preflight, "guard_interfaces_present": guards_preserved}, True))
    except (OSError, SyntaxError, ValueError, TypeError, AttributeError):
        checks.append(_item("launcher-expected-ip", "unknown", "启动前检查的预期出口", "无法读取旧入口的预期出口配置。", required=True))
    return checks


def _tool_proxies(workspace, entry_port):
    result = []
    git = shutil.which("git")
    if not git:
        result.append(_item("git-proxy", "not_tested", "Git 独立代理覆盖", "本机未找到 Git。"))
    else:
        try:
            run = _run([git, "-C", workspace, "config", "--get-regexp", r"^(http(\..*)?\.proxy|https\.proxy|remote\..*\.proxy)$"], timeout=10)
            if run.returncode not in (0, 1):
                raise ValueError()
            values = [_safe_url(line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else "") for line in run.stdout.splitlines()]
            bad = any(not _correct_proxy(v, entry_port) for v in values)
            result.append(_item("git-proxy", "warn" if bad else "pass", "Git 独立代理覆盖",
                                "存在不符合专用入口的 Git 代理覆盖，相关子进程路径需单独确认。" if bad else "当前 Git 配置没有其他代理覆盖；未发起 Git 网络请求。",
                                {"proxy_values": values}))
        except (OSError, ValueError, subprocess.TimeoutExpired):
            result.append(_item("git-proxy", "unknown", "Git 独立代理覆盖", "Git 配置查询失败。"))
    npm_paths = [Path.home() / ".npmrc", workspace / ".npmrc",
                 Path(os.environ.get("APPDATA", str(Path.home() / "AppData/Roaming"))) / "npm/etc/npmrc",
                 Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "nodejs/etc/npmrc"]
    for key in ("NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG", "npm_config_userconfig", "npm_config_globalconfig"):
        if os.environ.get(key):
            npm_paths.append(Path(os.environ[key]))
    rows, errors, seen = [], [], set()
    for path in npm_paths:
        if str(path).lower() in seen:
            continue
        seen.add(str(path).lower())
        if not path.is_file():
            continue
        try:
            for line in path.read_text(encoding="utf-8-sig").splitlines():
                if not line.strip() or line.lstrip().startswith(("#", ";")) or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip().lower()
                if key in {"proxy", "https-proxy"}:
                    rows.append({"source": str(path), "key": key, "proxy": _safe_url(value.strip())})
                elif key in {"noproxy", "no-proxy"}:
                    rows.append({"source": str(path), "key": key, "bypass": _safe_no_proxy(value.strip())})
        except (OSError, UnicodeError):
            errors.append(str(path))
    for key in ("npm_config_proxy", "npm_config_https_proxy", "npm_config_noproxy"):
        value = os.environ.get(key) or os.environ.get(key.upper())
        if value is not None:
            rows.append({"source": "Process", "key": key,
                         "bypass" if key.endswith("noproxy") else "proxy": _safe_no_proxy(value) if key.endswith("noproxy") else _safe_url(value)})
    bad = any(("proxy" in r and not _correct_proxy(r["proxy"], entry_port)) or ("bypass" in r and not r["bypass"].get("valid")) for r in rows)
    result.append(_item("npm-proxy", "unknown" if errors else "warn" if bad else "pass", "npm 独立代理覆盖",
                        "已检查常见及显式指定的 npm 配置文件和进程代理变量；未读取或显示认证字段，未发起 npm 网络请求。",
                        {"overrides": rows, "read_errors": errors}))
    return result


def audit_settings(install_dir: Path, workspace: Path, expected_ip: str = "103.249.185.229", entry_port: int = 17892) -> list[dict]:
    """Return safe check records. Required failures remain failures in all modes."""
    install_dir, workspace = Path(install_dir).resolve(), Path(workspace).resolve()
    results = []
    specs = _collect_files(workspace)
    existing = [s for s in specs if Path(s["path"]).is_file()]
    parsed, parse_error = _read_settings_batch(install_dir, existing)
    user_env = {}
    for index, spec in enumerate(specs):
        ident = "settings-" + str(index)
        path = spec["path"]
        if not Path(path).is_file():
            results.append(_item(ident, "fail", spec["label"], "必要的用户配置文件不存在。", {"path": path}, True))
            continue
        row = parsed.get(path, {})
        if parse_error or row.get("error") or "data" not in row:
            results.append(_item(ident, "unknown", spec["label"], parse_error or "设置文件不能完整解析，未使用局部解析结果。",
                                 {"path": path, "error": row.get("error", "parser_unavailable")}, True))
            continue
        data = row["data"]
        check = _audit_projected_env(data["env"], ident, spec["label"], entry_port, spec["complete"],
                                     data.get("externalBrowser"), spec["complete"] and spec["kind"] == "vscode", data.get("duplicate_keys", ()))
        check["evidence"]["path"] = path
        results.append(check)
        identity = _audit_identity(data["env"], ident + "-identity", data.get("apiKeyHelper", False))
        identity["evidence"]["path"] = path
        results.append(identity)
        results.extend(_audit_safety_switches(data["env"], ident))
        if index == 0:
            user_env = data["env"]
        extra = {}
        if data.get("vscodeHttpProxy") is not None:
            extra["http.proxy"] = data["vscodeHttpProxy"]
        if data.get("terminalEnv") is not None:
            extra["terminal.integrated.env.windows"] = _env_evidence(data["terminalEnv"])
            results.append(_audit_identity(data["terminalEnv"], ident + "-terminal-identity"))
        if extra:
            results.append(_item(ident + "-other-tools", "warn", "VS Code 通用网络设置", "发现通用 HTTP 或终端环境覆盖；不据此推断 Claude 扩展的真实连接路径。", extra))
    telemetry = user_env.get("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", {})
    individual = all(user_env.get(k, {}).get("enabled") is True for k in ("DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING"))
    off = telemetry.get("enabled") is True or individual
    results.append(_item("telemetry-policy", "pass" if off else "warn", "非必要遥测配置",
                         "用户设置已禁用非必要流量或分别禁用遥测和错误报告；此项不证明零网络请求。" if off else "未确认用户设置中的非必要流量禁用开关。",
                         {"nonessential_traffic_disabled": telemetry.get("enabled") is True, "individual_switches_disabled": individual}))
    scopes, failures = _windows_environment()
    for scope, raw in scopes.items():
        env = _safe_env(raw, install_dir / "ClaudeBrowser.exe")
        results.append(_item("environment-" + scope.lower(), "pass", scope + " 通用环境变量",
                             "已只读采样；通用代理允许指向日常入口 7892，不能据此替代 Claude 进程连接证据。",
                             {"env": _env_evidence(env)}))
        results.append(_audit_identity(env, "environment-" + scope.lower() + "-identity"))
        results.extend(_audit_safety_switches(env, "environment-" + scope.lower()))
    if failures:
        results.append(_item("environment-unreadable", "unknown", "Windows 持久环境变量", "部分环境作用域无法读取。", {"scopes": failures}, True))
    results.append(_item("managed-registry", "not_tested", "注册表管理策略", "本模块核对管理设置文件，尚未核对注册表策略；不据此声称不存在管理覆盖。"))
    results.extend(_client_signatures())
    results.extend(_launcher(install_dir, expected_ip, entry_port))
    results.extend(_tool_proxies(workspace, entry_port))
    return results
