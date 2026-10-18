param([switch]$Once, [switch]$SelfTest, [ValidateRange(10,300)][int]$IntervalSeconds = 30)
$ErrorActionPreference = 'Stop'
$configPath = Join-Path $env:USERPROFILE '.codex\config.toml'
$logPath = Join-Path $PSScriptRoot 'guard.log'
$noProxy = 'localhost,127.0.0.1,::1'
$proxyKeys = @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')
$allKeys = $proxyKeys + @('NO_PROXY','no_proxy')

function Write-Log([string]$message) {
    if ((Test-Path -LiteralPath $logPath) -and (Get-Item -LiteralPath $logPath).Length -gt 262144) {
        Move-Item -LiteralPath $logPath -Destination "$logPath.old" -Force
    }
    Add-Content -LiteralPath $logPath -Encoding UTF8 -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $message"
}

# One fixed local entry. Unavailability must never select another proxy.
$codexProxy = 'http://127.0.0.1:7892'

function Update-ConfigText([string]$text, [string]$proxy) {
    $section = [regex]::Match($text, '(?m)^\[shell_environment_policy\.set\][ \t]*\r?$')
    if ($section.Success) {
        $start = $section.Index + $section.Length
        $next = [regex]::Match($text.Substring($start), '(?m)^\s*\[')
        $end = if ($next.Success) { $start + $next.Index } else { $text.Length }
        $body = $text.Substring($start, $end - $start)
        foreach ($key in $allKeys) {
            $value = if ($proxyKeys -ccontains $key) { $proxy } else { $noProxy }
            $pattern = '(?m)^[ \t]*' + [regex]::Escape($key) + '[ \t]*=[^\r\n]*'
            $matchesForKey = [regex]::Matches($body, $pattern)
            if ($matchesForKey.Count -gt 1) { throw "Duplicate proxy key: $key" }
            $line = "$key = `"$value`""
            if ($matchesForKey.Count -eq 1) {
                $body = [regex]::Replace($body, $pattern, $line)
            } else { $body = $body.TrimEnd("`r","`n") + "`r`n$line`r`n" }
        }
        return $text.Substring(0, $start) + $body + $text.Substring($end)
    }
    $text = $text.TrimEnd("`r","`n") + "`r`n`r`n[shell_environment_policy.set]`r`n"
    foreach ($key in $allKeys) {
        $value = if ($proxyKeys -ccontains $key) { $proxy } else { $noProxy }
        $text += "$key = `"$value`"`r`n"
    }
    return $text
}

function Invoke-Check {
    $proxy = $codexProxy
    if (-not (Test-Path -LiteralPath $configPath)) { throw 'Codex config.toml is missing; existing settings preserved.' }
    $before = [IO.File]::ReadAllText($configPath)
    $after = Update-ConfigText $before $proxy
    if ($before -cne $after) {
        $temporary = "$configPath.network-guard.tmp"
        try {
            [IO.File]::WriteAllText($temporary, $after, (New-Object Text.UTF8Encoding($false)))
            if ([IO.File]::ReadAllText($configPath) -cne $before) { throw 'Config changed concurrently; retry next cycle.' }
            [IO.File]::Replace($temporary, $configPath, "$configPath.network-guard.bak")
        } finally {
            if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
        }
        Write-Log 'Updated proxy keys in Codex config (atomic replacement, previous file backed up).'
    }
    foreach ($key in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY')) {
        $value = if ($key -eq 'NO_PROXY') { $noProxy } else { $proxy }
        if ([Environment]::GetEnvironmentVariable($key,'User') -cne $value) {
            [Environment]::SetEnvironmentVariable($key,$value,'User')
            Write-Log "SYNC: user environment $key set to the fixed local entry."
        }
    }
}

if ($SelfTest) {
    $sample = "[other]`nHTTPS_PROXY = `"keep`"`n[shell_environment_policy.set]`nHTTP_PROXY = `"old`"`nextra = `"preserve`"`n[next]`nx = 1`n"
    $updated = Update-ConfigText $sample 'http://127.0.0.1:1234'
    if (-not $updated.Contains("[other]`nHTTPS_PROXY = `"keep`"")) { throw 'Unrelated section changed' }
    if (-not $updated.Contains('extra = "preserve"') -or -not $updated.Contains("[next]`nx = 1")) { throw 'Unrelated content changed' }
    if ((Update-ConfigText $updated 'http://127.0.0.1:1234') -cne $updated) { throw 'Update is not idempotent' }
    foreach ($key in $allKeys) {
        if ([regex]::Matches($updated, '(?m)^' + $key + ' = "http://127\.0\.0\.1:1234"').Count -ne 1 -and $key -cnotin @('NO_PROXY','no_proxy')) { throw "Missing key: $key" }
    }
    $newSection = Update-ConfigText "[other]`nx = 1`n" 'http://127.0.0.1:1234'
    if ((Update-ConfigText $newSection 'http://127.0.0.1:1234') -cne $newSection) { throw 'New section is not idempotent' }
    $duplicateRejected = $false
    try { $null = Update-ConfigText "[shell_environment_policy.set]`nHTTP_PROXY='a'`nHTTP_PROXY='b'" 'http://127.0.0.1:1234' } catch { $duplicateRejected = $true }
    if (-not $duplicateRejected) { throw 'Duplicate key was accepted' }
    Write-Output 'PASS: section isolation, preservation, both key cases, idempotence, missing section, duplicate rejection.'
    exit 0
}

$created = $false
$mutex = New-Object Threading.Mutex($true, 'Local\CodexNetworkGuard-example', [ref]$created)
if (-not $created) { $mutex.Dispose(); exit 0 }
try {
    Write-Log "START: PID=$PID; interval=$IntervalSeconds; once=$Once"
    $healthScript = Join-Path $PSScriptRoot 'health_monitor.py'
    do {
        # The monitor blocks Claude when the exit changes; restart it whenever its mutex is gone.
        $existing = $null
        if ([Threading.Mutex]::TryOpenExisting('Local\ClashNetworkHealth-example', [ref]$existing)) {
            $existing.Dispose()
        } elseif (Test-Path -LiteralPath $healthScript) {
            Start-Process -FilePath 'C:\Tools\Python\pythonw.exe' -ArgumentList @('-B', ('"' + $healthScript + '"')) -WindowStyle Hidden
            Write-Log 'Network health monitor was not running; start requested (single-instance mutex).'
        }
        try { Invoke-Check } catch { Write-Log "ERROR: $($_.Exception.Message)"; if ($Once) { throw } }
        if ($Once) { break }
        Start-Sleep -Seconds $IntervalSeconds
    } while ($true)
} finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
