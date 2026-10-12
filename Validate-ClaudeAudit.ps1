param([switch]$Full, [ValidatePattern('^[a-zA-Z0-9-]+$')][string]$Label = 'v4')
throw 'Archived: this v1 script is disabled. Use C:\Projects\Proxy-v2 (Deploy-Proxy.ps1).'
$ErrorActionPreference = 'Stop'
function Get-AuditState {
    $names = @('C:\Users\example\.claude\settings.json','C:\Users\example\.claude\settings.local.json',
        'C:\Users\example\AppData\Roaming\Code\User\settings.json',
        'C:\Users\example\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\clash-verge.yaml',
        'C:\Users\example\AppData\Roaming\io.github.clash-verge-rev.clash-verge-rev\profiles.yaml',
        'C:\Users\example\.codex\ClaudeNetwork\repair-last-result.json')
    $hashes = @($names | ForEach-Object {
        [ordered]@{path=$_;sha256=$(if(Test-Path -LiteralPath $_ -PathType Leaf){(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash}else{$null})}
    })
    $running = @(Get-CimInstance Win32_Process -Filter "Name='clash-verge.exe' OR Name='verge-mihomo.exe'" | Sort-Object ProcessId | ForEach-Object {
        [ordered]@{name=$_.Name;pid=[int]$_.ProcessId;created=$_.CreationDate.ToString('o')}
    })
    $webrtcPolicy = (Get-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Policies\Google\Chrome' -Name WebRtcIPHandling -ErrorAction SilentlyContinue).WebRtcIPHandling
    [ordered]@{files=$hashes;processes=$running;chrome_webrtc_policy=$webrtcPolicy}
}
$mode = if($Full){'full'}else{'normal'}
$reportPath = Join-Path $PSScriptRoot ('validation-' + $Label + '-' + $mode + '.json')
$before = Get-AuditState
$command = (Get-Command claude-proxy.cmd -ErrorAction Stop).Source
$arguments = @('-Json','-Output',$reportPath)
if ($Full) {$arguments += '-Full'}
$stdout = & $command @arguments
$actualExit = $LASTEXITCODE
$after = Get-AuditState
$proof = [ordered]@{command=$command;exit_code=$actualExit;files_unchanged=(($before.files|ConvertTo-Json -Depth 5 -Compress) -eq ($after.files|ConvertTo-Json -Depth 5 -Compress));clash_processes_unchanged=(($before.processes|ConvertTo-Json -Depth 5 -Compress) -eq ($after.processes|ConvertTo-Json -Depth 5 -Compress));before=$before;after=$after}
$proof.chrome_policy_unchanged = $before.chrome_webrtc_policy -eq $after.chrome_webrtc_policy
$proof | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $PSScriptRoot ('validation-' + $Label + '-' + $mode + '-readonly.json')) -Encoding utf8
if (-not (Test-Path -LiteralPath $reportPath)) {Write-Output $stdout; throw 'Checker did not write the explicitly requested report.'}
$report = Get-Content -LiteralPath $reportPath -Raw -Encoding utf8 | ConvertFrom-Json
[ordered]@{state=$report.state;exit_code=$actualExit;duration=$report.duration_seconds;files_unchanged=$proof.files_unchanged;clash_processes_unchanged=$proof.clash_processes_unchanged;counts=@($report.checks | Group-Object status | Select-Object Name,Count);nonpass=@($report.checks | Where-Object status -ne 'pass' | Select-Object id,title,status,detail,required,evidence);runtime=@($report.checks | Where-Object id -in @('fixed_egress','claude_runtime','browser_runtime') | Select-Object id,status,evidence);report=$reportPath} | ConvertTo-Json -Depth 12
exit $actualExit
