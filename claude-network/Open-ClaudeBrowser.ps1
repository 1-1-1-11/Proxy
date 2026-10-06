param([switch]$FromClipboard, [switch]$CheckOnly, [string]$Url = 'https://claude.ai/login')
$ErrorActionPreference = 'Stop'
if ($CheckOnly) {
    & 'C:\Tools\Python\python.exe' -X utf8 -B (Join-Path $PSScriptRoot 'browser_entry.py') --check-only
    exit $LASTEXITCODE
}
if ($FromClipboard) { $Url = ([string](Get-Clipboard -Raw)).Trim() }
$launcher = Join-Path $PSScriptRoot 'ClaudeBrowser.exe'
if (-not (Test-Path -LiteralPath $launcher)) { throw '专用浏览器启动器缺失。请运行 claude-proxy -Repair 修复。' }
# Direct executable invocation: URL is one literal argument, never shell code.
& $launcher $Url
