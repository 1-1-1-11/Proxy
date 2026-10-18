---
name: ccbaga-network
license: MIT
compatibility: Requires a local coding agent with file and terminal access, Python 3.10+ (3.12+ on Windows), OpenSSH and curl; remote deployment targets authorized Debian 12/13 hosts.
metadata:
  author: liseami
  opencode/slash: "true"
description: Collect user-supplied files and connection details, then handle DMIT VPS and Webshare static ISP purchases, matching PEM/PPK/PUB SSH keys, local checks, authorized Debian deployment, residential SOCKS5 egress, subscription delivery and verified TUN setup. Use for CCBaga network setup; installation alone does not authorize purchases or server changes.
---
<!--
[INPUT]: 用户直接提供的服务器地址、密钥附件/文件包与家宽连接资料；AI 负责整理本机私密配置。
[OUTPUT]: 可验证的购买引导、SSH/出口预检、明确确认后的部署、私密订阅与 TUN 开关流程。
[POS]: 独立于应用 UI 的 AI 操作协议；执行复用 scripts/network.py 与 setup-vps.sh。
[PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
-->
# CCBaga network

Act as a patient network engineer. Respond in the user's language, including English when the installation prompt is English. Use the bundled scripts; do not rewrite the deployment from memory. Resolve all script paths relative to this skill's directory, not the current project. Read [README.md](README.md) for installation and CLI commands before starting.

## Interaction contract

- Start with **one plain-language checklist**, not a technical questionnaire: “Send me your VPS address, the three PEM/PPK/PUB files or downloaded key bundle, and the residential proxy address, port, username and password. You can attach files or paste the supplier's connection details. I will handle the rest. If anything is missing, I will show you where to get it.” Use the user's language. Accept all available information at once; ask only for missing items. Skip purchases already completed.
- **The AI operates the terminal. The user does not.** Never ask the user to open a terminal, type commands, find file paths, edit JSON, run `configure`, or return “ready”. Locate only the attachments/files the user supplied, parse their connection details, prepare the private configuration, run checks, and handle authorized deployment yourself. Do not display an agent-facing CLI command as a user task.
- Installing this skill authorizes local installation and offline tests only. Purchases are performed by the user on the supplier website. Before deployment, summarize the actual host and proposed changes, and obtain explicit authorization. Never interpret a pasted installation prompt as permission to pay or deploy.
- Accept user-provided key attachments and proxy credentials in their chosen local coding-agent conversation. Explain briefly that these are sensitive setup details, not website login passwords. Do not claim that an AI chat is a secret vault: its provider may process/store supplied information. Prefer file attachments over pasted key text, but do not force the user to enter paths or use a terminal. Save setup material outside Git and the installed skill; create private files with POSIX 0600 permissions or current-user-only Windows NTFS ACLs. Do not echo credentials, print raw configuration/deployment output, put secrets in argv, or publish them in logs/issues/commits. Never ask for DMIT/Webshare account passwords.
- Never reuse credentials from screenshots, past chats or other projects. Never add telemetry, collect browser history or upload configuration to a third-party converter. Keep generated files outside the repository.
- A VPS hosts the relay; the residential SOCKS5 proxy supplies the exit IP. Buying a VPS does not turn its IP into a residential IP. A static ISP proxy is not proof of a physical household line. Do not promise platform acceptance, anonymity or absence of leaks.

## Native Windows

Detect the local OS before running commands. On Windows use Python 3.12+ (`python` or `py -3`), Microsoft's native OpenSSH Client under System32/OpenSSH, and native `curl.exe`. No WSL or local Bash is required for operations; the server script runs through SSH on Debian. The AI locates/install-checks these tools itself. If OpenSSH Client is absent, explain the optional Windows capability installation and administrator prompt, obtain authorization for that prerequisite, and handle it; do not ask the user to type a terminal command. Avoid Store Python aliases that are not an installed interpreter.

Use the bundled Windows helper for current-user NTFS owner/DACL protection instead of `chmod`. Files must be on a local NTFS volume with a single user-only protected ACL; reject junction/symlink parents and do not place keys in shared/synced/project folders. Never weaken permissions to make a check pass. The helper confines timeout cleanup to its own child-process Job Object. Resolve drive-letter/Unicode/space-containing attachment paths with the agent's subprocess API, never shell interpolation. Copy the whole Skill including `windows.py`.

Windows TUN clients may require a service installation and administrator approval. Explain the exact helper/service change, obtain approval and let the AI operate it or guide the user through the application's permission dialog. Keep System Proxy off; preserve existing adapters/profiles and do not disable Defender, SmartScreen, firewall or corporate policy. Verify the actual system exit and browser observation separately. A generated subscription is not proof that a Windows tunnel is active.

## 1. Choose a region, then guide the VPS purchase

Ask which exit country the user needs and whether this is a fresh server. Explain monthly budget, bandwidth and billing/renewal choices before the user pays. Use `python3 scripts/network.py links` to obtain the two exact supplier links from `providers.json`; keep every query parameter intact. Open the DMIT link first when the VPS is missing.

On DMIT: select a location reasonably close to the intended exit, a plan adequate for the user's bandwidth, **Debian 12 or 13**, a public IPv4 address, **root key login on SSH port 22**, and **Generate SSH Key after order**. The user's reference was LAX.AN4.Pro.MINI; verify current inventory/specifications rather than promising that name, price or capacity is still available. Do not silently buy a different plan. Public IPv6/hostnames are supported by the helper, but explain provider/client compatibility before deviating from the IPv4 baseline.

After payment, ask the user to confirm the instance is running and supply its public IP/hostname. Three key files cannot tell you the VPS address. See [DMIT's key guide](https://docs.dmit.io/guide/sshkeys/ssh-keys).

## 2. Collect and validate the three files

Ask the user to attach `id_rsa.pem`, `id_rsa.ppk` and `id_rsa.pub`, or attach the downloaded key ZIP (names may differ; extensions must match). Alternatively accept their selected local files. Resolve supplied attachment paths yourself; never ask the user to type paths. For an archive, list entries first, accept only the required three key files, reject traversal/absolute paths, symlinks and oversized entries, and extract them to a private directory outside Git with 0600 files. Do not read unrelated archives or directories. Ask for a missing file only when it is actually missing. Do not request website passwords or SSH Agent access.

Run `python3 scripts/network.py keys --pem '<path>' --ppk '<path>' --pub '<path>'` with correctly quoted paths. The helper compares PPK/PUB public data, derives the PEM public key with `ssh-keygen`, rejects encrypted/unpaired keys, and uses a temporary 0600 copy without changing originals. A PPK is a PuTTY private-key format; OpenSSH connects with the PEM. All three belong to the same key, not three separate authentication factors. If they do not match, stop and request a new complete bundle; never disable pairing checks or print key material.

## 3. Guide the residential exit purchase

Use the Webshare link from `network.py links`. Ask for **Static Residential / ISP**, a fixed exit in the selected country, **Direct Connection** and **Username/Password** authentication, with SOCKS5 support. Do not substitute rotating residential or datacenter proxies. If the intended use needs exclusivity, ask the user to evaluate a dedicated option and its price before purchase. Do not claim that all static ISP plans are exclusive.

After purchase, ask the user to copy the connection details or attach their current proxy-list screenshot. Extract Proxy Address, actual Port, Username and Password yourself; ask only for unreadable/missing values. Do not assume port 1080; the user's reference used another port. Require the expected fixed exit IP; for a hostname, obtain it from the supplier rather than guessing from the hostname. [Webshare's connection guide](https://help.webshare.io/en/articles/8375305-understanding-proxy-connection-types-direct-rotating-and-backbone) documents direct/static connections and HTTP/SOCKS5 support.

## 4. Local private configuration and first SSH identity

First run `python3 scripts/test_network.py` locally. Distinguish this offline regression from a real network test; never claim a real VPS was deployed by passing fixtures.

The AI prepares configuration; the user supplies information, not terminal input. Populate these fields from the supplied material: `vps`, `pem`, `ppk`, `pub`, `home_host`, integer `home_port`, `home_user`, `home_pass`, and `expected_ip`. The three key fields are paths resolved by the AI; when the proxy host is an IP, use that as the expected exit unless the supplier specifies a different fixed exit. For a hostname, obtain the actual expected IP from the supplier information.

Invoke `network.py configure` yourself with the JSON on **standard input**, not command arguments. Use the agent's subprocess/file capability, with stdin and captured output; never shell-trace, echo, or put credential values in command history. This validates all fields before creating `~/.config/ccbaga-network/connection.json` with private permissions (0600 on POSIX, a verified current-user-only ACL on Windows), rejects Git/skill destinations, and prints no credentials. No interactive terminal or `getpass` is required. Existing files are not overwritten; select a fresh private `--config` path for a new setup and preserve the earlier configuration. Tell the user only which prerequisites passed or what is missing.

Run `identity --config '<private-path>'`. This sends no proxy secrets; it verifies root login and prints the SSH host-key fingerprint. First contact uses trust-on-first-use (`accept-new`), not a claim that the network supplied an authenticated fingerprint. Ask the user to compare it with the DMIT console/provider record; if necessary the console command is `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. Subsequent operations use strict host-key checking. A changed fingerprint must stop the workflow; never automatically delete known_hosts or set StrictHostKeyChecking=no.

## 5. Validate before modifying the VPS

Run `check --config '<private-path>'`. Validate locally installed Python 3, OpenSSH and curl; paired keys; root login; Debian 12/13; authorized_keys; and SOCKS5 access from the VPS. The helper also attempts a local SOCKS probe. A blocked local direct route can be reported as **unverified** while the VPS-to-SOCKS route passes; do not call the local probe successful. Unexpected VPS exit IP or failed authentication stops deployment.

The fresh server must already have curl and Python 3 for read-only checks. If absent, ask permission for the specific package installation and repeat the check; do not hide installation inside a supposedly read-only check. Inspect occupied TCP 443/8443, existing Xray/sub services and `/etc/xray-setup.env` without printing secret contents. Stop if unrelated services would be overwritten. Prefer a new server.

## 6. Review and deploy

Show only the VPS address, root:22 identity, matched exit IP and proposed changes: Debian updates, packages, BBR/sysctl tuning, key-only SSH, fail2ban, firewall ports 22/443/8443, Xray/Reality, a static subscription service, and root/service-group-readable credential state. Explain that failures can leave partial remote changes, and a provider console/session must remain available during SSH hardening. Confirm that the user owns/is authorized to modify this server, then obtain approval for these specific changes.

Only after approval run `deploy --config '<private-path>' --confirm`. It repeats preflight, sends configuration and the bundled script through encrypted SSH standard input, suppresses raw output, and returns a subscription only on successful self-checks. It then verifies services through a **new SSH session** and retrieves a local import file over SSH. Never put credentials in command arguments, shell history or uploaded logs.

Routing knowledge: client → VLESS/Reality/Vision TCP 443 → VPS → authenticated residential SOCKS5. The helper disables the legacy Stripe server direct exception by default; proxy-bound TCP has no direct fallback. UDP, private-network destinations and BitTorrent are blocked. The subscription intentionally sends listed Chinese domains and bootstrap DNS directly on the client; therefore not every destination uses the residential IP. AI and default proxy groups offer node/REJECT, not DIRECT. Do not add a direct fallback to make a failing test look green.

## 7. Deliver the subscription privately

The helper creates 0600 `subscription-*.json` and `clash-*.yaml` files alongside the private config; provide a clickable link to the private local YAML and, where the local client supports it, open/import it for the user. Do not make the user inspect JSON or run a terminal command. Tell the user to import the local YAML file into a compatible Mihomo-based client. The generated subscription URL is in the private receipt and contains access credentials. Its legacy server endpoint is **plain HTTP** on 8443: the random token is not transport encryption. Prefer the SSH-retrieved local file; do not submit the URL to online conversion sites or public issues/logs.

If a client requires URL import, explain transport exposure before use; a localhost SSH tunnel can retrieve it without exposing the URL over public HTTP. If the user explicitly requests the subscription link, retrieve it from the private receipt and give it directly in their private conversation, with the HTTP transport limitation stated; never instruct them to open a terminal to find it. Do not publish it or use an online converter. Never claim the HTTP link is encrypted. `fetch` rechecks services in a new SSH session and downloads a fresh private YAML file without redeploying.

## 8. TUN setup and real verification

Ask which client/OS the user has. Use that client's current official instructions rather than inventing labels. A compatible example is [Clash Verge Rev](https://www.clashverge.dev/guide/quickstart.html); install through its official release/source and review OS permissions with the user.

1. Import the private YAML; select the new profile and node. Keep Rule mode unless the user intentionally changes routing.
2. Install/enable the client's required service/admin helper when prompted. Explain the specific permission before granting it.
3. Turn **TUN ON** and **System Proxy OFF**. CCBaga-B's explicit browser proxy must remain empty. Close conflicting VPN/TUN clients with the user's agreement.
4. Run `tun-check --config '<private-path>'`; its curl probe ignores proxy environment variables and must report the fixed residential exit through the actual system route. This verifies the CLI route, not browser or all DNS traffic.
5. In CCBaga-B, refresh the environment page and compare its measured exit/country/timezone with the target. A stale/unavailable exit is not a pass. Verify browser DNS/WebRTC separately before claiming leak results; the built-in green page does not independently test them. Do not fabricate location/country or force green.
6. Ask the user to verify normal browsing and the intended applications. If they fail, inspect service status, authentication, client logs with credentials redacted, Reality compatibility, route conflicts and DNS. Never change the public exit expectations or introduce DIRECT merely to clear an error.
7. To disconnect: switch **TUN OFF** first, keep System Proxy OFF, then quit the client/tunnel. Confirm ordinary connectivity is restored. Remove persistent tunnel/helper services only with separate user authorization; do not delete the VPS or proxy subscription.

## Failure and recovery

- Wrong host/key: verify public IP, key binding, root:22 and console; do not fall back to passwords or disable host checks.
- SOCKS auth/exit failure: confirm exact panel port, Username/Password, fixed plan and provider availability. A rotating IP is incompatible with the fixed expected-IP gate.
- Deployment interrupted: inspect server status and timestamped backups before rerun. State in `/etc/xray-setup.env` preserves node identity on reruns; never display or discard it casually. System/package/firewall changes are not atomically reversible.
- Preserve an established SSH session and console during hardening. Validate `sshd -t` and a fresh key login before closing the old session. SSH port 22 is opened before enabling ufw.
- System route works but browser differs: check another proxy, browser explicit proxy, stale session, client routing groups and Rule-mode direct exceptions. Do not spoof the browser result.

Mark each phase verified, failed or not exercised. Stop at the first unresolved prerequisite. The completed outcome requires server checks **and actual client TUN/browser observations**, not merely a generated URL.
