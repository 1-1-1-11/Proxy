"""Narrow local adapter for the installed Proxy-v2; stdout contains no raw reports.

This file never copies policy credentials and never installs or starts a watchdog.
Only the explicit repair/launch commands mutate state. Tests inject a fake backend.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import site
import subprocess
import sys
import time

SCHEMA = 1
SUPPORTED_VERSION = "2026.10.17"
ENTRIES = ("cli", "vscode", "web", "desktop")
BASE = {"clash_core", "fixed_policy", "fixed_egress", "route", "guard"}
REQUIRED = {
    "cli": BASE | {"settings", "api_override"},
    "vscode": BASE | {"settings", "api_override"},
    "web": BASE | {"web"},
    "desktop": BASE | {"desktop_protection"},
}
TITLES = {
    "policy": "本机策略文件", "clash_core": "代理进程与端口",
    "fixed_policy": "固定线路规则", "fixed_egress": "固定出口 IP",
    "route": "实际路由", "guard": "使用中守护", "settings": "代理与浏览器设置",
    "api_override": "Claude API 地址", "web": "登录链接入口",
    "desktop_protection": "桌面客户端保护", "cowork": "Cowork 服务断网",
    "traffic": "运行中的 Claude 连接", "traffic_cli": "CLI 连接",
    "traffic_vscode": "VS Code 连接", "traffic_desktop": "桌面客户端连接",
}
REASONS = {
    "policy": "本机策略文件缺失或无效，需要恢复现有安装。",
    "clash_core": "代理进程或专用端口未通过检查，请检查 Clash 是否正常运行。",
    "fixed_policy": "固定线路规则未通过检查，可先查看修复计划。",
    "fixed_egress": "探测到的出口与指定 IP 不一致，已阻止启动。",
    "route": "实际路由没有通过固定线路检查，请查看现有 Proxy-v2 诊断。",
    "guard": "后台守护不可用、状态过期或已阻断出口。",
    "settings": "客户端代理或专用浏览器设置不符合当前策略，可先查看修复计划。",
    "api_override": "配置中发现不符合策略的 API 地址，请检查 Claude 的 API 设置。",
    "web": "登录链接启动器缺失，或 CCBaga Proxy 还没有登记指纹浏览器入口。",
    "desktop_protection": "桌面客户端的代理或防火墙保护未通过检查。",
    "cowork": "Cowork 服务的断网保护未通过检查。",
}


def timestamp():
    return int(time.time() * 1000)


def state(ok):
    return "ready" if ok is True else "blocked" if ok is False else "unknown"


RECOVERING = "后台守护正在恢复（常见于刚从睡眠唤醒），通常 30 秒内更新；启动会等它恢复。"
MODES = ("rule", "global", "direct")


class Failure(Exception):
    """A known reason the installed backend cannot be used; only the code and safe fields leave."""
    def __init__(self, code, **fields):
        super().__init__(code)
        self.code, self.fields = code, fields


def release(value):
    """A backend version that may be shown: digits and dots only."""
    return value if isinstance(value, str) and 0 < len(value) <= 16 and all(p.isdigit() for p in value.split(".")) else None


def guard_recovering(row):
    """Alive and not blocking, only silent past its limit: usual right after sleep, never a pass."""
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
    return (row.get("ok") is False and evidence.get("alive") is True
            and evidence.get("fixed_exit_blocked") is not True and evidence.get("repair_active") is not True)


def summarize(item, known):
    """State and plain reason of one backend check; backend details and labels never leave."""
    if item["id"] == "guard" and guard_recovering(item):
        return "unknown", RECOVERING
    # An unknown check keeps its failure under a neutral label; it can never pass silently.
    verdict = state(item.get("ok")) if known or item.get("ok") is False else "unknown"
    if verdict == "ready":
        return verdict, ""
    if not known:
        return verdict, "网络检查没有得到可确认的通过结果。"
    if verdict == "unknown":
        return verdict, "这项检查没有得到确定结果，请重新检查。"
    return verdict, REASONS.get(item["id"], "运行中的连接没有全部通过固定线路检查。")


def browser_row(key, related):
    """A backend check the fingerprint browser's gate uses: the shared fixed-exit checks and anything
    tied to the web entry, except Proxy-v2's login-link launcher itself."""
    return key != "web" and (key in BASE | {"policy"} or "web" in related)


def browser_verdict(rows, guard):
    """One rule for the browser gate and for the home page's view of it."""
    present = {row["id"] for row in rows}
    if any(row["state"] == "blocked" for row in rows):
        verdict = "blocked"
    elif not BASE.issubset(present) or any(row["state"] != "ready" for row in rows):
        verdict = "unknown"
    else:
        verdict = "ready"
    if guard["state"] == "blocked" or guard["blocked"]:
        return "blocked"
    if guard["state"] != "ready" or guard["repair_active"]:
        return "unknown" if verdict != "blocked" else verdict
    return verdict


def protection_state(raw_checks):
    """Whether Proxy-v2's -Protect would help the desktop app, from the evidence its check already read."""
    row = next((c for c in raw_checks if isinstance(c, dict) and c.get("id") == "desktop_protection"), None)
    evidence = row.get("evidence") if row and isinstance(row.get("evidence"), dict) else None
    if not evidence or not isinstance(evidence.get("paths"), list) or not isinstance(evidence.get("missing"), list):
        return "unknown"
    if evidence.get("firewall_on") is not True:
        return "firewall_off" if evidence.get("firewall_on") is False else "unknown"
    if not evidence["paths"]:
        return "not_installed"
    if evidence["missing"] or (evidence.get("cowork_installed") is True and evidence.get("cowork_blocked") is not True):
        return "needs_protect"
    return "protected"


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def load_backend():
    location = Path.home() / ".codex" / "ClaudeNetwork" / "check.py"
    if os.name != "nt" or not location.is_file():
        raise Failure("backend_missing")
    # -I excludes the caller's directory and PYTHONPATH. Only the fixed installation
    # is added to resolve check.py's own helpers.
    sys.path.insert(0, str(location.parent))
    # Proxy-v2's psutil is installed in this user's Python runtime. Add that known
    # dependency directory without executing user .pth files or importing the cwd.
    user_packages = Path(site.getusersitepackages())
    if (user_packages / "psutil/__init__.py").is_file():
        sys.path.append(str(user_packages))
    spec = importlib.util.spec_from_file_location("check", location)
    backend = importlib.util.module_from_spec(spec)
    sys.modules["check"] = backend
    try:
        spec.loader.exec_module(backend)
    except ImportError:
        # A package Proxy-v2 imports (psutil, PyYAML) is missing from this Python.
        raise Failure("backend_dependency") from None
    if getattr(backend, "VERSION", None) != SUPPORTED_VERSION:
        raise Failure("backend_version", installed=release(getattr(backend, "VERSION", None)))
    return backend


def parse(argv):
    """Return (command, workspace). The optional workspace is the native-chosen CLI folder."""
    if len(argv) not in (1, 2):
        raise ValueError("arguments")
    workspace = None
    if len(argv) == 2:
        workspace = Path(argv[1])
        if not workspace.is_absolute() or not workspace.is_dir():
            raise ValueError("workspace")
    return argv[0], workspace


class Bridge:
    def __init__(self, backend, workspace=None):
        self.backend = backend
        self.workspace = workspace or Path.home()

    def policy(self):
        try:
            policy = self.backend.load_policy()
            port, expected = policy["entry_port"], valid_ip(policy["expected_ip"])
        except Exception:
            raise Failure("policy_invalid") from None
        if type(port) is not int or not 1 <= port <= 65535 or expected is None:
            raise Failure("policy_invalid")
        return {"endpoint": f"http://127.0.0.1:{port}", "expected_ip": expected}

    def guard(self):
        row = self.backend.guard_check()
        evidence = row.get("evidence", {})
        age = evidence.get("age_seconds")
        recovering = guard_recovering(row)
        return {"state": "unknown" if recovering else state(row.get("ok")),
                "age_seconds": age if type(age) in (int, float) and age >= 0 else None,
                "blocked": evidence.get("fixed_exit_blocked") is True,
                "repair_active": evidence.get("repair_active") is True,
                "recovering": recovering, **self.observed()}

    def observed(self):
        """What the guard last saw (read-only): Claude connections off the fixed exit and Clash's mode."""
        try:
            data = json.loads((Path(self.backend.GUARD_DIR) / "network-state.json").read_text(encoding="utf-8"))
        except (AttributeError, TypeError, OSError, ValueError):
            data = {}
        data = data if isinstance(data, dict) else {}
        count, mode, tun = data.get("claude_offchain"), data.get("mode"), data.get("tun")
        return {"offchain": count if type(count) is int and count >= 0 else None,
                "mode": mode if mode in MODES else None, "tun": tun if type(tun) is bool else None}

    def settle_guard(self, limit=60):
        """A launch gives a recovering guard one round (about 30 s) to report before it checks."""
        deadline = time.monotonic() + limit
        while self.guard()["recovering"] and time.monotonic() < deadline:
            time.sleep(3)

    def status(self):
        return {"schema": SCHEMA, "available": True, "observed_at": timestamp(),
                "version": self.backend.VERSION, "workspace": str(self.workspace),
                "guard": self.guard(), **self.policy()}

    def audit(self, mode="all"):
        started = timestamp()
        raw = self.backend.run(mode, self.workspace)
        if not isinstance(raw, dict) or not isinstance(raw.get("checks"), list):
            raise ValueError("invalid_report")
        checks = []
        browser_rows = []
        observed_ips = []
        for item in raw["checks"]:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                continue
            known = item["id"] in TITLES
            verdict, detail = summarize(item, known)
            related = item.get("entries") if isinstance(item.get("entries"), list) else []
            checks.append({"id": item["id"] if known else "network_check",
                           "title": TITLES[item["id"]] if known else "其他网络检查",
                           "state": verdict, "detail": detail, "entries": [e for e in ENTRIES if e in related]})
            if browser_row(item["id"], related):
                browser_rows.append(checks[-1])
            if item["id"] == "fixed_egress":
                for probe in item.get("evidence", {}).get("probes", []):
                    ip = valid_ip(probe.get("ip"))
                    if ip and ip not in observed_ips:
                        observed_ips.append(ip)
        cowork = any(isinstance(c, dict) and c.get("id") == "desktop_protection"
                     and c.get("evidence", {}).get("cowork_installed") is True for c in raw["checks"])
        # Connections of programs already running are reported apart: launches use the same
        # checks without them, so the page and the tray reach one verdict.
        running = [c for c in checks if c["id"].startswith("traffic")]
        entries = {}
        for entry, verdict in raw.get("entries", {}).items():
            if entry not in ENTRIES:
                continue
            related = [c for c in checks if entry in c["entries"]]
            gate = [c for c in related if not c["id"].startswith("traffic")]
            required = set(REQUIRED[entry]) | ({"cowork"} if entry == "desktop" and cowork else set())
            if verdict == "NOT_INSTALLED" and entry == "desktop":
                entries[entry] = "not_installed"
            elif any(c["state"] == "blocked" for c in gate):
                entries[entry] = "blocked"
            elif not required.issubset({c["id"] for c in gate}) or any(c["state"] != "ready" for c in gate):
                # Backend can omit a failed worker; missing evidence must never pass.
                entries[entry] = "unknown"
            elif verdict != "READY" and all(c["state"] == "ready" for c in related):
                # The backend saw a problem that none of its rows explain: never pass on that.
                entries[entry] = "unknown"
            else:
                entries[entry] = "ready"
        result = self.status()
        if result["guard"]["state"] != "ready":
            entries = {e: s if s == "not_installed" else result["guard"]["state"] for e, s in entries.items()}
        if mode == "all":
            # The web entry is the fingerprint browser: shown by the same rule its launch gate applies.
            entries["browser"] = browser_verdict(browser_rows, result["guard"])
        if mode in ("all", "desktop"):
            result["desktop_protection"] = protection_state(raw["checks"])
        worst =("blocked" if any(c["state"] == "blocked" for c in running) else
                 "unknown" if any(c["state"] != "ready" for c in running) else "ready")
        result.update(checked_at=started, entries=entries, checks=checks, observed_ips=observed_ips,
                      running={"state": worst, "entries": [e for e in ENTRIES if any(
                          c["state"] == "blocked" and e in c["entries"] for c in running)]} if running else None)
        return result

    def browser_audit(self):
        """Check the shared network without requiring Proxy-v2's login-link launcher."""
        self.settle_guard()
        started = timestamp()
        raw = self.backend.run("web", self.workspace)
        if not isinstance(raw, dict) or not isinstance(raw.get("checks"), list):
            raise ValueError("invalid_report")
        checks = []
        observed_ips = []
        for item in raw["checks"]:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                raise ValueError("invalid_check")
            key = item["id"]
            related = item.get("entries", [])
            if not isinstance(related, list):
                raise ValueError("invalid_check_entries")
            if not browser_row(key, related):
                continue
            # A new network check cannot silently disappear from this gate. Keep
            # its failure, but do not expose arbitrary backend labels or details.
            known = key in TITLES
            verdict, detail = summarize(item, known)
            checks.append({"id": key if known else "network_check",
                           "title": TITLES[key] if known else "其他网络检查",
                           "state": verdict, "detail": detail, "entries": ["browser"]})
            if key == "fixed_egress":
                for probe in item.get("evidence", {}).get("probes", []):
                    ip = valid_ip(probe.get("ip"))
                    if ip and ip not in observed_ips:
                        observed_ips.append(ip)
        result = self.status()
        result.update(checked_at=started, entries={"browser": browser_verdict(checks, result["guard"])},
                      checks=checks, observed_ips=observed_ips)
        return result

    def fingerprint(self):
        digest = hashlib.sha256()
        for name in ("audit_policy.json", "check.py", "repair_proxy.py", "claude-fixed.cmd", "browser_entry.py"):
            digest.update(name.encode())
            digest.update((self.backend.HERE / name).read_bytes())
        return digest.hexdigest()

    def launch(self, entry):
        # The web entry is the fingerprint browser, started natively after "check-browser".
        modes = {"cli": "launch", "desktop": "desktop"}
        if entry not in modes:
            raise ValueError("unsupported_entry")
        self.settle_guard()
        report = self.audit(modes[entry])
        if report["entries"].get(entry) != "ready" or timestamp() - report["checked_at"] > 60000:
            return {"schema": SCHEMA, "action": "blocked", "report": report}
        if entry == "cli":
            launcher = self.backend.HERE / "claude-fixed.cmd"
            if not launcher.is_file():
                raise RuntimeError("launcher_missing")
            shell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
            spawned = {"cwd": self.workspace, "env": os.environ | {"CCBAGA_FIXED_CLI": str(launcher)}}
            if os.name == "nt":
                spawned["creationflags"] = subprocess.CREATE_NEW_CONSOLE
            subprocess.Popen([str(shell), "-NoLogo", "-NoProfile", "-NoExit", "-Command", "& $env:CCBAGA_FIXED_CLI"], **spawned)
        else:
            before = set(self.desktops())
            if self.backend.open_desktop(self.workspace) != 0 and not self.started_pinned(before):
                return {"schema": SCHEMA, "action": "blocked", "report": self.audit("desktop")}
        return {"schema": SCHEMA, "action": "requested", "report": report}

    def desktops(self):
        return {pid: row for pid, row in self.backend.claude_processes().items() if row["kind"] == "desktop"}

    def started_pinned(self, before, limit=30):
        """Proxy-v2 confirms a new desktop app within 10 s. A slower start still counts once its
        new process is up and pinned to the dedicated port; an unpinned one never does."""
        port = self.backend.load_policy()["entry_port"]
        deadline = time.monotonic() + limit
        while True:
            new = [row for pid, row in self.desktops().items() if pid not in before]
            if new:
                return not self.backend.desktop_protection(new, port)["unpinned"]
            if time.monotonic() >= deadline:
                return False
            time.sleep(1)

    def connections(self):
        """One read-only look at Claude's live connections through Clash, as Proxy-v2's -Watch judges them.
        Only addresses, ports, the entry kind and whether the fixed chain was used leave; never policy fields."""
        policy = self.backend.load_policy()
        try:
            records = self.backend.api("/connections").get("connections", [])
        except Exception:
            return {"schema": SCHEMA, "available": True, "observed_at": timestamp(), "readable": False,
                    "mode": None, "connections": []}
        try:
            mode = (self.backend.routing_mode(self.backend.read_clash()) or {}).get("profile")
        except Exception:
            mode = None
        rows, seen = [], set()
        for row in records if isinstance(records, list) else []:
            if not isinstance(row, dict):
                continue
            meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            # Clash records no program on the dedicated port; everything there is pinned to the fixed exit.
            if meta.get("inboundName") == "claude-fixed-http":
                source = "fixed_port"
            elif str(meta.get("process") or "").lower() == "claude.exe":
                source = self.backend.client_kind(meta.get("processPath"))
            else:
                continue
            target = self.backend.describe(row)
            fixed = self.backend.valid_chain(row.get("chains", []), policy) is True
            host = target.get("host") if isinstance(target.get("host"), str) else ""
            port = target.get("port")
            port = int(port) if str(port).isdigit() and 0 < int(port) < 65536 else None
            key = (source, host[:253], port, fixed)
            if key in seen:
                continue
            seen.add(key)
            route = target.get("route") if isinstance(target.get("route"), str) else ""
            rows.append({"source": source, "host": host[:253], "port": port, "fixed": fixed,
                         "route": None if fixed else route[:200]})
        mode = mode if mode in ("claude", "domestic", "abnormal") else None
        return {"schema": SCHEMA, "available": True, "observed_at": timestamp(), "readable": True,
                "mode": mode, "connections": rows[:300]}

    def protect(self):
        """Proxy-v2's -Protect: firewall the installed desktop app to the local proxy (one administrator prompt)."""
        with contextlib.redirect_stdout(io.StringIO()):
            code = self.backend.protect()
        return {"schema": SCHEMA, "action": "protected" if code == 0 else "protect_failed", "report": self.audit("desktop")}

    def repair(self):
        # Same fixed repair entry used by check.repair. Suppress child output: it is
        # not a UI protocol and must never leak local configuration into the view.
        result = subprocess.run([sys.executable, "-X", "utf8", "-B", str(self.backend.HERE / "repair_proxy.py"),
                                 "--workspace", str(self.workspace)], timeout=180,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return {"schema": SCHEMA, "action": "repaired" if result.returncode == 0 else "repair_failed",
                "repair_exit": result.returncode, "report": self.audit()}

    def dispatch(self, command):
        if command == "status":
            return self.status()
        if command == "check":
            return self.audit()
        if command == "check-browser":
            return self.browser_audit()
        if command == "policy":
            return {"schema": SCHEMA, **self.policy()}
        if command == "protect":
            return self.protect()
        if command == "connections":
            return self.connections()
        if command == "plan":
            return {**self.status(), "fingerprint": self.fingerprint()}
        if command == "repair":
            return self.repair()
        if command in ("launch-cli", "launch-desktop"):
            return self.launch(command[7:])
        raise ValueError("unsupported_command")


def main(argv):
    try:
        command, workspace = parse(argv)
        # Trusted backend diagnostics are not part of the protocol. Its raw report
        # (settings, paths, controller payloads) is never printed or persisted.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = Bridge(load_backend(), workspace).dispatch(command)
        print(json.dumps(result, ensure_ascii=False, allow_nan=False))
        return 0
    except Failure as failure:
        print(json.dumps({"schema": SCHEMA, "available": False, "error": failure.code, **failure.fields}))
        return 2
    except Exception:
        print(json.dumps({"schema": SCHEMA, "available": False, "error": "backend_unavailable"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
