param([switch]$RestoreOriginalShortcutWorkingDirectories)
$ErrorActionPreference = 'Stop'
$sourceRoot = Join-Path $PSScriptRoot 'claude-network'
$installRoot = 'C:\Users\example\.codex\ClaudeNetwork'
$npmTarget = 'C:\Users\example\AppData\Roaming\npm\claude-proxy.cmd'
$desktopRoot = 'C:\Users\example\Desktop'
$backupRoot = Join-Path $PSScriptRoot ('deployment-backup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$files = @('stun_probe.py','webrtc_probe.py','audit_policy.json','audit_proxy.py','audit_settings.py','audit_browser.py',
    'network_check.py','browser_entry.py','route_verify.py','repair_proxy.py',
    'ClaudeBrowser.cs','ClaudeBrowser.exe','browser-build.json',
    'Open-ClaudeBrowser.ps1','Repair-ClaudeProxy.ps1','claude-fixed.cmd','Network-Check.cmd','使用说明.txt')
$shortcuts = @('Claude 专用浏览器.lnk','Claude 打开授权链接.lnk','Claude CLI 固定出口.lnk','代理网络检查.lnk')
$plan = @()
foreach ($name in $files) {
    $plan += [pscustomobject]@{source=(Join-Path $sourceRoot $name);target=(Join-Path $installRoot $name);kind='file';key=('install-' + $name)}
}
$plan += [pscustomobject]@{source=(Join-Path $sourceRoot '使用说明.txt');target=(Join-Path $installRoot '代理修复命令说明.md');kind='file';key='install-代理修复命令说明.md'}
$plan += [pscustomobject]@{source=(Join-Path $sourceRoot 'claude-proxy.cmd');target=$npmTarget;kind='file';key='npm-claude-proxy.cmd'}
foreach ($name in $shortcuts) {
    $plan += [pscustomobject]@{source=$null;target=(Join-Path $desktopRoot $name);kind='shortcut';key=$name}
}
foreach ($entry in $plan) {
    $absolute = [IO.Path]::GetFullPath($entry.target)
    $expectedParent = if ($entry.kind -eq 'shortcut') {$desktopRoot} elseif ($entry.target -eq $npmTarget) {[IO.Path]::GetDirectoryName($npmTarget)} else {$installRoot}
    if ([IO.Path]::GetDirectoryName($absolute) -ne $expectedParent) {throw 'Unexpected deployment target.'}
    if ($entry.source -and -not (Test-Path -LiteralPath $entry.source -PathType Leaf)) {throw ('Missing source: ' + $entry.key)}
    if ($entry.kind -eq 'shortcut' -and -not (Test-Path -LiteralPath $entry.target -PathType Leaf)) {throw ('Missing shortcut: ' + $entry.key)}
}
New-Item -ItemType Directory -Path $backupRoot | Out-Null
$manifest = @()
foreach ($entry in $plan) {
    $existed = Test-Path -LiteralPath $entry.target -PathType Leaf
    $saved = Join-Path $backupRoot $entry.key
    $beforeHash = $null
    if ($existed) {
        Copy-Item -LiteralPath $entry.target -Destination $saved
        $beforeHash = (Get-FileHash -LiteralPath $entry.target -Algorithm SHA256).Hash
    }
    $manifest += [pscustomobject]@{target=$entry.target;existed=$existed;backup=$(if($existed){$saved}else{$null});before_sha256=$beforeHash;after_sha256=$null;applied=$false}
}
$manifestPath = Join-Path $backupRoot 'manifest.json'
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8
$shell = New-Object -ComObject WScript.Shell
try {
    for ($index = 0; $index -lt $plan.Count; $index++) {
        $entry = $plan[$index]
        if ($entry.kind -eq 'file') {
            Copy-Item -LiteralPath $entry.source -Destination $entry.target -Force
            if ((Get-FileHash -LiteralPath $entry.target -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $entry.source -Algorithm SHA256).Hash) {throw ('Deployment hash mismatch: ' + $entry.key)}
        } else {
            $shortcut = $shell.CreateShortcut($entry.target)
            if ($RestoreOriginalShortcutWorkingDirectories) {
                $originalPath = Join-Path (Join-Path $PSScriptRoot 'deployment-backup-20261006-100840') $entry.key
                if (-not (Test-Path -LiteralPath $originalPath -PathType Leaf)) {throw ('Missing original shortcut: ' + $entry.key)}
                $original = $shell.CreateShortcut($originalPath)
                $shortcut.WorkingDirectory = $original.WorkingDirectory
            }
            switch ($entry.key) {
                'Claude 专用浏览器.lnk' {$shortcut.Description = '先检查固定出口及实际 WebRTC 保护，证据不足即停止。'}
                'Claude 打开授权链接.lnk' {$shortcut.Description = '固定出口及实际 WebRTC 保护通过后，在专用浏览器打开剪贴板授权链接。'}
                'Claude CLI 固定出口.lnk' {$shortcut.Description = '先检查项目设置、真实内核和双出口，再启动官方 Claude CLI。'}
                '代理网络检查.lnk' {$shortcut.Description = '完整只读检查：实际进程、端口、策略、双出口、配置、WebRTC 和 DNS；不自动修复。'}
            }
            $shortcut.Save()
        }
        $manifest[$index].after_sha256 = (Get-FileHash -LiteralPath $entry.target -Algorithm SHA256).Hash
        $manifest[$index].applied = $true
        $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8
    }
} finally {
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell) | Out-Null
}
[pscustomobject]@{installed=$manifest.Count;backup=$backupRoot;manifest=$manifestPath;network_configuration_changed=$false;processes_restarted=$false} | ConvertTo-Json
