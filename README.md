<!--
[INPUT]: Proxy v1 (archived), Proxy v2 and CCBaga Proxy as they stood on 2026-10-18, with the checks recorded on 2026-10-17 and 2026-10-18.
[OUTPUT]: English entry for the repository: what each directory is, how the parts fit together, how to check and build them, and what has not been verified.
[POS]: Public entry of the repository. Each project keeps its own README and contracts; this file only connects them.
[PROTOCOL]: Update this header when the layout or a recorded result changes, then check ccbaga-proxy/CLAUDE.md.
-->
# Proxy

**A fixed exit IP for an official Claude account on one Windows workstation: checks that say whether it holds, a guard that cuts Claude off when it does not, and a desktop app that keeps the browser and the account state consistent with that exit.**

中文简介：在国内使用官方 Claude 账号的环境守护。Claude 只从固定 IP 出去，出口不对就断开；电脑和指纹浏览器环境跟随这个出口，多个账号互不串。这是为一台 Windows 工作站定制的工具，不是通用安装包。

## What is in this repository

| Path | What it is | Status |
| --- | --- | --- |
| [`ccbaga-proxy/`](ccbaga-proxy/) | **CCBaga Proxy**: a Tauri desktop app (Rust, React, TypeScript) with a tray, a home page showing the fixed-exit state, a connection monitor, Claude identity management and a fingerprint browser that only starts after the same check passes. Built on upstream [CCBaga](https://github.com/liseami/CCBaga) (MIT). | Current. Copy of branch `codex/proxy-integration` at `8d2d4bd`. |
| [`proxy-v2/`](proxy-v2/) | **Proxy v2**: the part that does the work on the machine. Routing baseline for Clash Verge, a read-only check, a repair command and a background guard. | Current. Copy of `main` at `3f5f7be`. |
| [`v1/`](v1/) | **Proxy v1**: the first audit, launcher and repair toolset. | Archived on 2026-10-12 and replaced by Proxy v2. Tag `v1-final` marks its last deployed state. |

The two current projects are copied here without their commit history; the commits above identify the exact trees. Each directory keeps its own README, tests and licence files, and its relative links only resolve inside it.

## How the parts fit together

```text
Claude CLI, VS Code, desktop client
  -> Clash listener 127.0.0.1:17892 (pinned to the "Claude-固定出口" group)
  -> fixed-exit chain: a front node, then one SOCKS5 exit with a single public IP
     (the group holds only that chain and REJECT: there is no direct fallback)

Everything else
  -> Clash TUN and rules: domestic sites DIRECT, the rest through the daily proxy group

Proxy v2 guard, about every 30 seconds
  -> checks the exit IP; a wrong IP switches the protected groups to REJECT and closes their connections

CCBaga Proxy
  -> a bridge calls Proxy v2 for the check and the repair (whitelisted actions, version-locked)
  -> the home page, the tray and the fingerprint-browser gate show and enforce that result
```

- **Routing baseline** (`proxy-v2/claude-network/routing-baseline.js`). Anthropic and Claude domains plus `claude.exe` go to the fixed exit, as do Google and X; OpenAI and Codex use the daily group. Every front node reaches the same exit IP, and the fronts are ordered by measured stability.
- **Domestic sites.** Since 2026-10-18 the baseline puts `GEOSITE,CN` and GlobalSign's OCSP/CRL hosts on DIRECT, right before the subscription's `GEOIP,CN` and `MATCH` tail. Before that, domestic sites missing from the subscription's short DIRECT list were resolved through the daily proxy, came back with foreign CDN addresses and were dropped by the HY2 front nodes. On the author's machine 13 of 17 sampled domestic sites failed the same `curl.exe` command before the change; afterwards all 17 answered through both the system proxy and the TUN path in 441 of 442 requests (the one failure was not diagnosed).
- **Version lock.** The `VERSION` in `proxy-v2/claude-network/check.py` must equal `SUPPORTED_VERSION` in `ccbaga-proxy/proxy-bridge/bridge.py` (currently `2026.10.17`). When it changes, both sides are built and deployed together.
- **Browser gate.** Web sessions and login links open only in CCBaga Proxy's fingerprint browser, which runs its own check first. Its time zone follows the fixed exit and its language is en-US.

## Installation

Windows 10 or 11 only, and tied to the original workstation: paths, ports, node names and the recovery logic are hard-coded. Read the migration notes (迁移须知) in [`proxy-v2/README.md`](proxy-v2/README.md) and the integration guide [`ccbaga-proxy/docs/proxy-integration.md`](ccbaga-proxy/docs/proxy-integration.md) before reusing any of it. Both are written in Chinese. What they assume:

- Clash Verge Rev with its service mode and TUN enabled, and a subscription that contains the front nodes and a SOCKS5 exit.
- Python 3.13 with `psutil` and `PyYAML` (see `proxy-v2/requirements.txt`) and Node.js.
- Proxy v2 installed under `%USERPROFILE%\.codex\ClaudeNetwork` and `%USERPROFILE%\.codex\CodexNetworkGuard` with `Deploy-Proxy.ps1`; CCBaga Proxy built from `ccbaga-proxy/` with Bun, Rust and the Tauri toolchain.

## Quick start

```powershell
claude-proxy            # read-only check: can Claude be used right now, and through which exit
claude-proxy -Repair    # repair the managed Clash configuration, then check again (may restart Clash)
```

CCBaga Proxy starts in the tray after Windows login. Launch it from Explorer or the startup entry, not from an AI coding terminal, which would hand its environment variables to the CLI it starts. Its three pages are Home, Connection monitor and Claude identities.

## Checks

```powershell
# Proxy v2, from proxy-v2/
py -X utf8 -B -m unittest discover -s .\claude-network -p "test_*.py"

# CCBaga Proxy, from ccbaga-proxy/
bun install --frozen-lockfile
bun run build
bun test
bun run test:bridge
bun run test:proxy
bun run test:identities
cargo test --manifest-path src-tauri/Cargo.toml -- --test-threads=4
```

Recorded results, all on the author's machine:

| Date | Check | Result |
| --- | --- | --- |
| 2026-10-18 | Proxy v2 offline tests | 67 passed |
| 2026-10-17 | `bun run build`, `bun test`, `bun run test:bridge`, `bun run test:identities` | type check and build passed; 25, 33 and 19 tests passed |
| 2026-10-17 | `cargo test` | 77 passed, 3 ignored by design |

## Boundaries

- The checks describe one moment. The guard re-checks about every 30 seconds, so a changed exit is blocked after at most about 30 seconds.
- An ordinary browser opening claude.ai goes through the fixed exit only while Clash is in rule mode. Use the fingerprint browser for the web app.
- The tools decide the network exit. A local client can still read the time zone, system language, user name and the folders you grant it.
- Not verified: clicking through the web app and login links, identity switching with real accounts, the firewall protection step, a real repair on a broken setup, rebooting, resuming from sleep, long outages, and independent DNS and WebRTC leak tests.
- No promise about account standing, regional eligibility or a permanent static IP from the supplier.

## License and credits

`ccbaga-proxy/` is MIT-licensed (copyright CCBaga contributors, see `ccbaga-proxy/LICENSE`); third-party terms are in `ccbaga-proxy/NOTICE.md`. It builds on [liseami/CCBaga](https://github.com/liseami/CCBaga). `proxy-v2/` and `v1/` ship without a licence file.
