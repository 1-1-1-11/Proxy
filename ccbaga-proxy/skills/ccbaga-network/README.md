<!--
[INPUT]: Agent Skills 规范、npm skills 通用安装器、五项 AI 工具和完整自包含资源。
[OUTPUT]: 跨平台 npm/npx 安装与更新、隐私边界和分阶段命令索引。
[POS]: 网络页 Skill 按钮的公开落点；安装与远端部署分开授权。
[PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
-->
# CCBaga Network Skill

Give your AI the files and connection details. It handles the commands: VPS → static residential/ISP exit → matching SSH keys → local validation → approved deployment → private subscription → verified TUN.

## Installation

**Easiest:** In CCBaga-A, open **Network**, select **General**, **Codex**, **Cursor**, **OpenCode** or **Copilot**, and click **Copy prompt**. Paste it into that tool's local coding-agent chat. The short prompt installs the complete skill and then invokes it; the skill itself handles the workflow. Switching CCBaga to English also switches the copied prompt to English.

No CCBaga app is required. This directory follows the [Agent Skills specification](https://agentskills.io/specification) and includes its MIT license, execution scripts and provider configuration.

### npm / npx

Use the standard [skills installer](https://github.com/vercel-labs/skills), available from npm. Node.js 22.20+ and npm are installation prerequisites; the AI can handle them. The skill's network scripts require Python and the native tools described below.

```sh
# macOS / Linux — let the AI run this for you
DO_NOT_TRACK=1 npx --yes skills add liseami/CCBaga --skill ccbaga-network --global --agent codex --copy --yes
```

```powershell
# Windows PowerShell — no WSL required
$env:DO_NOT_TRACK='1'
npx --yes skills add liseami/CCBaga --skill ccbaga-network --global --agent codex --copy --yes
```

Choose `--agent codex`, `cursor`, `opencode` or `github-copilot`. For another tool, the AI selects its supported agent identifier. `--global` keeps the installation outside the current project; `--copy` avoids Windows symlink privilege requirements. `DO_NOT_TRACK=1` disables the installer's telemetry and remote audit requests. The command downloads skill files; it does not execute a VPS deployment.

You can also install the npm CLI once with `npm install --global skills`, then use `skills add` with the same options and environment. To update this skill, keep tracking disabled and run `npx --yes skills update ccbaga-network --global`.

Ask your agent to install it and then invoke `ccbaga-network` in your language. Review any existing installation before replacing it; private connection configuration stays outside the skill directory.

| Tool | Personal installation directory | Invoke |
| --- | --- | --- |
| General | Your current coding agent chooses its supported skill directory | Ask it to use `ccbaga-network` |
| Codex | `~/.agents/skills/ccbaga-network` | `$ccbaga-network` |
| Cursor | `~/.cursor/skills/ccbaga-network` | `/ccbaga-network` |
| OpenCode | `~/.config/opencode/skills/ccbaga-network` | `/ccbaga-network` (included slash metadata) |
| Copilot CLI | `~/.copilot/skills/ccbaga-network` | `/ccbaga-network` |

The npm installer uses the shared `~/.agents/skills/ccbaga-network` directory supported by these clients. The table lists their compatible manual directories.

Copy **the whole directory**, including `providers.json` and `scripts/`. Restart/reload the agent if it does not discover the new skill. A local agent with terminal/file access is required; a plain web chat or cloud session without access to your local keys cannot complete SSH deployment.

For manual installation from an existing checkout (example: Codex):

```sh
mkdir -p "$HOME/.agents/skills"
test ! -e "$HOME/.agents/skills/ccbaga-network" && \
  cp -R skills/ccbaga-network "$HOME/.agents/skills/ccbaga-network"
python3 "$HOME/.agents/skills/ccbaga-network/scripts/test_network.py"
```

The guard preserves an existing installation. Compare/review before replacing existing skill code. Private configuration lives separately under `~/.config/ccbaga-network`; it must never be copied into a Git checkout or skill directory.

[Codex documentation](https://developers.openai.com/codex/skills) · [Cursor documentation](https://cursor.com/docs/skills) · [OpenCode documentation](https://opencode.ai/docs/skills/) · [Copilot documentation](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills)

## What the AI asks for

Send what you already have in one message:

- The VPS public IP/address.
- The `.pem`, `.ppk` and `.pub` files, or the downloaded key bundle.
- The residential proxy address, actual port, username and password. Pasted supplier connection details or a current proxy-list screenshot also work.

The AI resolves file paths, prepares private configuration, runs terminal commands and checks the connection. It asks only for missing information and handles deployment after you approve the actual server changes. You never need to type commands or edit JSON. If you have not bought the resources, it guides you through the two supplier websites first. You perform checkout yourself.

Use a local coding agent that you trust with these sensitive setup details; information supplied in its chat may be processed/stored by its provider. Do not supply your supplier account passwords. Subscription files and connection configuration stay outside the source repository.

The provider entrance configuration is centralized in [providers.json](providers.json). `network.py links` produces the original two purchase addresses, also used by the application's buttons. Plan inventory/prices must be checked before paying.

## Agent command reference

**These commands are for the AI, not tasks for the user.** Use Python 3.10+, OpenSSH and curl on macOS/Linux. On native Windows use Python 3.12+, Microsoft OpenSSH Client and curl.exe; invoke the same scripts with `python` or `py -3`. The AI handles prerequisites, paths and commands. Private files use verified current-user-only NTFS ACLs; no WSL is required. Windows TUN service installation may need administrator approval. Run commands relative to the installed skill directory (or use absolute paths):

```sh
python3 scripts/test_network.py            # offline; no VPS or real credentials
python3 scripts/network.py links           # purchase entrances
python3 scripts/network.py keys --pem '/path/id_rsa.pem' --ppk '/path/id_rsa.ppk' --pub '/path/id_rsa.pub'
python3 scripts/network.py configure       # AI sends validated connection JSON on stdin; no terminal prompts
python3 scripts/network.py identity        # first SSH identity, no proxy secrets sent
python3 scripts/network.py check           # local + read-only VPS/exit validation
python3 scripts/network.py deploy --confirm # ONLY after specific server-change approval
python3 scripts/network.py fetch           # fresh SSH session, private local YAML
python3 scripts/network.py tun-check       # actual system exit, bypass proxy env
```

`configure` accepts all nine fields on standard input: `vps`, `pem`, `ppk`, `pub`, `home_host`, integer `home_port`, `home_user`, `home_pass`, `expected_ip`. It validates before writing, refuses overwrites and Git/skill destinations, and never prints credentials. `--config /absolute/private/connection.json` selects another private config. SSH is root:22 with the matching PEM; password and Agent authentication are disabled. First identity uses TOFU; compare the provider fingerprint before continuing. Later commands reject unknown/changed host keys.

Deployment targets an authorized Debian 12/13 server. It changes system packages, SSH/firewall and Xray services; failures may leave partial changes. The bundled server script keeps root-owned identity state and timestamped backups. It is not a universal installer for existing production servers.

## Subscription and TUN

Successful deployment saves a private receipt containing the subscription URL and retrieves a private YAML file over SSH. Import that file into a compatible Mihomo client, enable **TUN**, disable **System Proxy**, and leave CCBaga-B's explicit proxy empty. Verify system and browser exits against the fixed expected IP. UDP forwarding is blocked; listed domestic domains/bootstrap DNS remain direct in Rule mode. DNS/WebRTC require separate checks.

The subscription URL uses plain HTTP on port 8443 and contains access credentials. Prefer the local file retrieved over SSH; the token does not encrypt HTTP. Do not publish private receipts, passwords or key contents in issues, logs or online subscription converters. The AI can provide the private local import file directly; you do not need to inspect the receipt in a terminal.

## Verification boundary

Offline tests validate key pairing/permissions, shell-input transport, destination checks, failure/timeout handling and secret-safe configuration. They do **not** establish that a real VPS, SOCKS account, client TUN or privileged operation works. The skill must report target-environment checks separately and stop on failures.
