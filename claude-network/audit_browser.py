"""Bounded browser observations in a new, unsigned-in Chrome profile.

Only this module's browser is closed. Existing windows, browser profiles and
production proxy settings are never read or changed. Page bodies stay in memory;
returned evidence contains only the selected network observations.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
from pathlib import Path
import re
import shutil
import tempfile
import time


_SCOPE = "temporary_matching_flags"
_DNS_COMPLETION_SOURCE = "browserleaks_dns_loading_transition_v1"
_TITLES = {
    "browser_fixed_exit": "临时浏览器公网出口",
    "browser_webrtc": "临时浏览器 WebRTC 泄漏测试",
    "browser_dns": "临时浏览器 DNS 解析观察",
}


def _result(identifier: str, status: str, detail: str, **evidence) -> dict:
    return {
        "id": identifier,
        "category": "browser_test",
        "status": status,
        "required": identifier != "browser_dns",
        "title": _TITLES[identifier],
        "detail": detail,
        "evidence": {"scope": _SCOPE, **evidence},
    }


def _unavailable(detail: str) -> list[dict]:
    return [_result(identifier, "unknown", detail) for identifier in _TITLES]


def _ip(value: object) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip().strip("[]")))
    except ValueError:
        return None


def _candidate_ips(value: object) -> list[str]:
    # Accept complete IP tokens, not arbitrary substrings of labels or hostnames.
    return sorted({ip for token in re.split(r"[\s,;]+", str(value)) if (ip := _ip(token))})


def _parse_trace(text: str, expected_ip: str) -> dict:
    fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    observed = _ip(fields.get("ip", ""))
    if observed is None:
        return _result("browser_fixed_exit", "unknown", "页面没有返回可解析的公网 IP，不能用 HTTP 成功代替出口验收。")
    matched = observed == expected_ip
    return _result(
        "browser_fixed_exit", "pass" if matched else "fail",
        "临时浏览器返回预期固定出口；仅证明本次匹配启动参数的测试。" if matched
        else "临时浏览器返回的公网 IP 与预期固定出口不同。",
        observed_ip=observed, expected_ip=expected_ip,
    )


def _parse_dns(snapshot: dict, stable: bool = False) -> dict:
    summary = str(snapshot.get("summary", ""))
    match = re.search(r"Found\s+(\d+)\s+Servers?\s*,\s*(\d+)\s+ISP(?:s)?\s*,\s*(\d+)\s+Locations?", summary, re.I)
    resolvers: dict[str, tuple[str, str, str]] = {}
    for row in snapshot.get("rows", []):
        if not isinstance(row, list) or len(row) < 3:
            continue
        address = _ip(row[0])
        if address is None:
            continue
        isp = str(row[1]).strip()
        location = str(row[2]).strip()
        country = location.split(",", 1)[0].strip()
        # Location text is reduced to a country, never returned as full page text.
        if not isp or not country or len(country) > 80 or not re.fullmatch(r"[\w .()'’-]+", country):
            continue
        resolvers[address] = (isp, country, location)
    countries = sorted({row[1] for row in resolvers.values()})
    isp_count = len({row[0] for row in resolvers.values()})
    declared = int(match.group(1)) if match else None
    completed = (snapshot.get("completed") is True
                 and snapshot.get("completion_source") == _DNS_COMPLETION_SOURCE
                 and snapshot.get("structure_valid") is True
                 and snapshot.get("started_observed") is True
                 and snapshot.get("loading") is False)
    evidence = {
        "resolver_count": len(resolvers), "reported_resolver_count": declared,
        "countries": countries, "isp_count": isp_count,
        "observation_stable": stable, "completion_confirmed": completed,
        "completion_source": _DNS_COMPLETION_SOURCE,
        "started_observed": snapshot.get("started_observed") is True,
        "loading": snapshot.get("loading") if isinstance(snapshot.get("loading"), bool) else None,
    }
    if any(country.casefold() in {"china", "cn", "mainland china", "people's republic of china", "中国", "中国大陆"}
           for country in countries):
        return _result("browser_dns", "warn", "观察到位于中国大陆的 DNS 服务器；这是地域观察，未改动配置，也不据此判断账号风险。", **evidence)
    if not match or not resolvers:
        return _result("browser_dns", "unknown", "尚未取得非空 DNS 服务器表及对应结果摘要，不能判定测试通过。", **evidence)
    locations_count = len({row[2] for row in resolvers.values()})
    if declared != len(resolvers) or int(match.group(2)) != isp_count or int(match.group(3)) != locations_count:
        return _result("browser_dns", "unknown", "DNS 结果摘要与已解析服务器表尚不一致，仅记录本次观察。", **evidence)
    if not completed:
        return _result("browser_dns", "unknown", "已观察到 DNS 服务器结果，但尚未确认本次测试从加载到结束的完整变化；服务器数量不代表测试域名数量。", **evidence)
    if not stable:
        return _result("browser_dns", "unknown", "页面报告测试完成，但结果尚未在观察间隔内稳定。", **evidence)
    return _result("browser_dns", "pass", "已观察到本次 DNS 测试加载标志开始并移除，非空结果表与摘要一致；服务器地域仅作路径观察，不证明不存在其他 DNS 路径。", **evidence)


# BrowserLeaks /js/dns.js creates 50 tasks, drains them with 15 fetch workers,
# and removes #dns-test.load-td only in Promise.all(workers).then(...).
# Observe the start in Python too: a missing class on an unstarted/error page
# alone is not completion. Only the exact result cell and result table are read.
_SNAPSHOT_JS = r"""(kind) => {
    const tests = [...document.querySelectorAll('#dns-test')];
    const lists = [...document.querySelectorAll('#dns-list')];
    const visible = el => !!el && el.getClientRects().length > 0;
    const valid = tests.length === 1 && visible(tests[0]) && lists.length <= 1;
    const text = valid ? (tests[0].innerText || '').trim() : '';
    const summary = /^Found\s+\d+\s+Servers?\s*,\s*\d+\s+ISPs?\s*,\s*\d+\s+Locations?$/i.test(text) ? text : '';
    const cellText = (row, selector) => (row.querySelector(selector)?.innerText || '').replace(/\s+/g, ' ').trim();
    const rows = lists.length === 1 && visible(lists[0]) ? [...lists[0].querySelectorAll(':scope > tr')]
        .filter(visible).map(row => [cellText(row, '.dns-col-ip'), cellText(row, '.dns-col-isp'),
            cellText(row, '.dns-td:not(.dns-col-ip):not(.dns-col-isp)')]) : [];
    return {summary, rows, structure_valid: valid,
        completion_source: 'browserleaks_dns_loading_transition_v1',
        loading: valid ? tests[0].classList.contains('load-td') : null};
}"""


async def _probe_trace(context, expected_ip: str) -> dict:
    page = await context.new_page()
    try:
        await page.goto("https://www.cloudflare.com/cdn-cgi/trace", wait_until="domcontentloaded", timeout=20000)
        return _parse_trace(await page.locator("body").inner_text(timeout=2000), expected_ip)
    except Exception:
        return _result("browser_fixed_exit", "unknown", "在限定时间内未取得浏览器出口结果；未保存页面或异常中的网址。")
    finally:
        await _close(page)


async def _probe_dynamic(context, kind: str, expected_ip: str) -> dict:
    if kind != "dns":
        raise ValueError("Only DNS uses dynamic page parsing")
    page = await context.new_page()
    identifier = "browser_" + kind
    deadline = time.monotonic() + 55
    snapshot: dict = {}
    stable_since: float | None = None
    previous = None
    stable = False
    saw_loading = False
    try:
        await page.goto("https://browserleaks.com/" + kind, wait_until="domcontentloaded", timeout=20000)
        while time.monotonic() < deadline:
            snapshot = await page.evaluate(_SNAPSHOT_JS, kind)
            trusted = (snapshot.get("completion_source") == _DNS_COMPLETION_SOURCE
                       and snapshot.get("structure_valid") is True)
            if trusted and snapshot.get("loading") is True:
                saw_loading = True
            snapshot["started_observed"] = saw_loading
            snapshot["completed"] = bool(trusted and saw_loading and snapshot.get("loading") is False)
            if snapshot == previous:
                stable_since = stable_since or time.monotonic()
            else:
                previous = snapshot
                stable_since = time.monotonic()
            stable = time.monotonic() - stable_since >= 6
            result = _parse_dns(snapshot, stable)
            if kind == "dns" and stable and snapshot.get("completed") is True:
                return result
            await asyncio.sleep(min(0.75, max(0.01, deadline - time.monotonic())))
        return _parse_dns(snapshot, stable)
    except Exception:
        # Keep useful partial DNS evidence if the dynamic page stalls or closes.
        if snapshot:
            return _parse_dns(snapshot, stable)
        return _result(identifier, "unknown", "页面未在限定时间内产生可解析的实际测试结果。")
    finally:
        await _close(page)


async def _close(obj, method: str = "close") -> bool:
    if obj is not None:
        try:
            await asyncio.wait_for(getattr(obj, method)(), timeout=2)
        except Exception:
            return False
    return True


def _chrome_path() -> Path | None:
    candidates = [
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", r"C:\Users\Default\AppData\Local")) / "Google/Chrome/Application/chrome.exe",
    ]
    return next((path for path in candidates if path.is_file()), None)


async def _browser_audit_async(chrome: Path, entry_port: int, expected_ip: str, include_dns: bool = True) -> list[dict]:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return _unavailable("当前 Python 缺少 Playwright；未安装依赖，未执行浏览器测试。")
    playwright = browser = context = None
    profile_path = None
    profile_removed = False
    results: list[dict] = []
    try:
        # All navigation and dynamic waiting share this wall-clock budget. Cleanup
        # gets at most four additional seconds; three pages run concurrently.
        async with asyncio.timeout(80):
            playwright = await async_playwright().start()
            temp_root = Path(tempfile.gettempdir()).resolve()
            profile_path = Path(tempfile.mkdtemp(prefix='claude-audit-', dir=temp_root)).resolve()
            if profile_path.parent != temp_root or not profile_path.name.startswith('claude-audit-'):
                raise RuntimeError('Unexpected temporary profile')
            # chrome://prefs-internals needs a regular profile, not an incognito
            # context. This regular profile is newly created and never signed in.
            context = await playwright.chromium.launch_persistent_context(
                user_data_dir=str(profile_path),
                executable_path=str(chrome), headless=True, timeout=10000,
                args=[
                    f"--proxy-server=http://127.0.0.1:{entry_port}",
                    "--proxy-bypass-list=localhost;127.0.0.1;[::1]",
                    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
                    "--disable-quic",
                    "--disable-features=MediaRouter",
                ],
            )
            browser = context.browser

            async def collect(coro):
                result = await coro
                results.append(result)

            from webrtc_probe import native_check
            async def webrtc():
                status, detail, evidence = await native_check(context, expected_ip)
                evidence.pop('scope', None)
                return _result('browser_webrtc', status, detail, **evidence)
            tasks = [collect(_probe_trace(context, expected_ip)), collect(webrtc())]
            if include_dns:
                tasks.append(collect(_probe_dynamic(context, 'dns', expected_ip)))
            await asyncio.gather(*tasks)
    except Exception:
        pass
    finally:
        browser_closed = await _close(context if context is not None else browser)
        driver_stopped = await _close(playwright, "stop")
        if profile_path is not None:
            try:
                if profile_path.parent != Path(tempfile.gettempdir()).resolve() or not profile_path.name.startswith('claude-audit-'):
                    raise RuntimeError('Temporary cleanup boundary mismatch')
                shutil.rmtree(profile_path)
                profile_removed = True
            except (OSError, RuntimeError):
                pass
        else:
            profile_removed = True
    found = {result["id"]: result for result in results}
    ordered = [found.get(identifier, _result(identifier, "unknown", "浏览器测试未完成或超过总时限；没有把缺失结果记为通过。"))
               for identifier in _TITLES if include_dns or identifier != "browser_dns"]
    for result in ordered:
        result["evidence"]["temporary_browser_cleanup_confirmed"] = browser_closed and driver_stopped and profile_removed
        if not (browser_closed and driver_stopped and profile_removed):
            result["detail"] += " 自创建浏览器的关闭操作未获完整确认。"
            if result["status"] == "pass":
                result["status"] = "unknown"
    return ordered


def browser_audit(entry_port: int = 17892, expected_ip: str = "203.0.113.10", include_dns: bool = True) -> list[dict]:
    """Observe HTTP exit, native ICE/effective policy, and optional DNS results.

    This is supplemental evidence from a temporary unsigned-in profile, never a
    statement about an existing Claude browser or its authenticated session.
    Call from synchronous code (or via asyncio.to_thread from an async caller).
    """
    if isinstance(entry_port, bool) or not isinstance(entry_port, int) or not 1 <= entry_port <= 65535 or _ip(expected_ip) is None:
        return _unavailable("入口端口或预期 IP 无效，未启动浏览器。")
    chrome = _chrome_path()
    if chrome is None:
        return _unavailable("未找到已安装的 Google Chrome；未安装软件，未执行浏览器测试。")
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_browser_audit_async(chrome, entry_port, str(ipaddress.ip_address(expected_ip)), include_dns))
    return _unavailable("同步浏览器检测接口需要在线程或无活动事件循环的调用端执行；本次未启动浏览器。")
