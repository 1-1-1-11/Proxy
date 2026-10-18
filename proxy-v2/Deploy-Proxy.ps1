# Deploy this rewrite over the installed tools. Without -Apply it only prints the plan.
# -Apply: runs verify_same_proxy.py first and stops if the proxy would differ, backs up every
#         replaced or retired file, copies the new files, then restarts the tray and the guard.
# -ExpectFrontOrder: with -Apply, accepts exactly one named proxy change (the fixed chains'
#         first-hop order, see verify_same_proxy.py --expect); repair_proxy.py then applies it.
# -ExpectDomesticRules: with -Apply, accepts exactly one named proxy change (the GEOSITE,CN and
#         globalsign.com direct rules before the GEOIP,CN tail); repair_proxy.py then applies it.
# -Rollback <folder>: puts every file from that backup back and restarts the tray and the guard.
# Clash, its configuration and the Claude / VS Code settings are never touched here.
param([switch]$Apply, [string]$Rollback, [switch]$ExpectFrontOrder, [switch]$ExpectDomesticRules)
$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot 'claude-network'
$install = Join-Path $env:USERPROFILE '.codex\ClaudeNetwork'
$guard = Join-Path $env:USERPROFILE '.codex\CodexNetworkGuard'
$npmShim = Join-Path $env:APPDATA 'npm\claude-proxy.cmd'
$backupRoot = Join-Path $env:USERPROFILE '.codex\deploy-backups'
$python = 'C:\Tools\Python\python.exe'
$installFiles = @('check.py','browser_entry.py','network_check.py','repair_proxy.py','repair_support.py','repair_jsonc.cjs',
    'read_env.cjs','routing-baseline.js','ClaudeBrowser.cs','ClaudeBrowser.exe','ClaudeStatus.cs','ClaudeStatus.exe',
    'Open-ClaudeBrowser.ps1','Open-ClaudeDesktop.cmd','Repair-ClaudeProxy.ps1','claude-fixed.cmd','Network-Check.cmd')
$guardFiles = @('health_monitor.py','guard.ps1','run-hidden.vbs')
$retired = @('audit_proxy.py','audit_settings.py','audit_browser.py','audit_actions.py','webrtc_probe.py','stun_probe.py',
    'route_verify.py','browser-build.json')

function Stop-Tools {
    Get-Process ClaudeStatus -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='powershell.exe'" |
        Where-Object { $_.CommandLine -match 'CodexNetworkGuard\\(health_monitor\.py|guard\.ps1)' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Start-Sleep -Seconds 2
}
function Start-Tools {
    # Same path as login: Explorer opens the startup shortcuts, so both outlive this console.
    $startup = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
    foreach ($name in @('ClaudeStatus.lnk','CodexNetworkGuard.lnk')) {
        # A tray replaced by another app has no startup shortcut; Explorer would only show an error.
        $shortcut = Join-Path $startup $name
        if (Test-Path -LiteralPath $shortcut) {
            Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList ('"' + $shortcut + '"')
        }
    }
    for ($i = 0; $i -lt 45; $i++) {
        $existing = $null
        if ([Threading.Mutex]::TryOpenExisting('Local\ClashNetworkHealth-example', [ref]$existing)) { $existing.Dispose(); return 'guard running' }
        Start-Sleep -Seconds 2
    }
    return 'guard NOT confirmed within 90 seconds: run claude-proxy to check'
}

if ($Rollback) {
    $manifest = Get-Content -LiteralPath (Join-Path $Rollback 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Stop-Tools
    foreach ($entry in $manifest) {
        if ($entry.backup) { Copy-Item -LiteralPath $entry.backup -Destination $entry.target -Force }
        elseif (Test-Path -LiteralPath $entry.target) { Remove-Item -LiteralPath $entry.target }
    }
    [pscustomobject]@{restored=@($manifest).Count; from=$Rollback; tools=(Start-Tools)} | ConvertTo-Json
    exit 0
}

$plan = @()
foreach ($name in $installFiles) { $plan += [pscustomobject]@{source=(Join-Path $source $name); target=(Join-Path $install $name); action='copy'} }
foreach ($name in $guardFiles) { $plan += [pscustomobject]@{source=(Join-Path (Join-Path $PSScriptRoot 'CodexNetworkGuard') $name); target=(Join-Path $guard $name); action='copy'} }
$plan += [pscustomobject]@{source=(Join-Path $source 'claude-proxy.cmd'); target=$npmShim; action='copy'}
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $source 'vendor') -Recurse -File) {
    $plan += [pscustomobject]@{source=$file.FullName; target=(Join-Path $install $file.FullName.Substring($source.Length + 1)); action='copy'}
}
foreach ($name in $retired) {
    $target = Join-Path $install $name
    if (Test-Path -LiteralPath $target) { $plan += [pscustomobject]@{source=$null; target=$target; action='retire'} }
}
# The old usage notes (.txt / .md) describe removed commands; README.md in the repository replaces them.
foreach ($doc in Get-ChildItem -LiteralPath $install -File | Where-Object { $_.Extension -in '.txt','.md' }) {
    $plan += [pscustomobject]@{source=$null; target=$doc.FullName; action='retire'}
}
foreach ($entry in $plan) {
    if ($entry.source -and -not (Test-Path -LiteralPath $entry.source -PathType Leaf)) { throw ('Missing source (build the exe files first): ' + $entry.source) }
}
$changed = @($plan | Where-Object { $_.action -eq 'retire' -or -not (Test-Path -LiteralPath $_.target) -or
    (Get-FileHash -LiteralPath $_.source).Hash -ne (Get-FileHash -LiteralPath $_.target).Hash })
if (-not $Apply) {
    $changed | ForEach-Object { '{0,-7} {1}' -f $_.action, $_.target }
    "Plan only: $($changed.Count) of $($plan.Count) files would change. Run with -Apply to deploy."
    exit 0
}

if ($ExpectFrontOrder -and $ExpectDomesticRules) { throw 'Name one proxy change at a time: -ExpectFrontOrder or -ExpectDomesticRules.' }
$verifyArgs = @()
if ($ExpectFrontOrder) { $verifyArgs += @('--expect', 'front-order') }
if ($ExpectDomesticRules) { $verifyArgs += @('--expect', 'domestic-rules') }
& $python -X utf8 -B (Join-Path $PSScriptRoot 'verify_same_proxy.py') @verifyArgs
if ($LASTEXITCODE -ne 0) { throw 'verify_same_proxy.py did not confirm the proxy change; nothing was deployed.' }
$backup = Join-Path $backupRoot (Get-Date -Format 'yyyyMMdd-HHmmss')
New-Item -ItemType Directory -Path $backup | Out-Null
$manifest = @()
$index = 0
foreach ($entry in $changed) {
    $saved = $null
    if (Test-Path -LiteralPath $entry.target) {
        $saved = Join-Path $backup ('{0:D3}-{1}' -f $index, (Split-Path $entry.target -Leaf))
        Copy-Item -LiteralPath $entry.target -Destination $saved
    }
    $manifest += [pscustomobject]@{target=$entry.target; backup=$saved; action=$entry.action}
    $index++
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $backup 'manifest.json') -Encoding UTF8
Stop-Tools
foreach ($entry in $changed) {
    if ($entry.action -eq 'retire') { Remove-Item -LiteralPath $entry.target; continue }
    New-Item -ItemType Directory -Path (Split-Path $entry.target) -Force | Out-Null
    Copy-Item -LiteralPath $entry.source -Destination $entry.target -Force
    if ((Get-FileHash -LiteralPath $entry.source).Hash -ne (Get-FileHash -LiteralPath $entry.target).Hash) { throw ('Copy mismatch: ' + $entry.target) }
}
[pscustomobject]@{deployed=$changed.Count; backup=$backup; rollback=('Deploy-Proxy.ps1 -Rollback "' + $backup + '"'); tools=(Start-Tools)} | ConvertTo-Json
