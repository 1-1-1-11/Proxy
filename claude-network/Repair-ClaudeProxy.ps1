param(
    [switch]$CheckOnly,
    [switch]$Repair,
    [switch]$Full,
    [switch]$LaunchCheck,
    [switch]$Runtime,
    [switch]$Details,
    [switch]$NoPrompt,
    [switch]$Json,
    [string]$Output,
    [string]$Workspace = (Get-Location).Path
)
$ErrorActionPreference = 'Stop'
if ($CheckOnly -and $Repair) { throw '-CheckOnly and -Repair cannot be used together.' }
if ($LaunchCheck -and ($Full -or $Repair)) { throw '-LaunchCheck cannot be combined with -Full or -Repair.' }
if ($Runtime -and ($LaunchCheck -or $Repair)) { throw '-Runtime cannot be combined with -LaunchCheck or -Repair.' }
$pythonExe = 'D:\Python\python.exe'
if (-not (Test-Path -LiteralPath $pythonExe)) {throw 'Required local Python is missing: D:\Python\python.exe'}
$arguments = @('-X','utf8','-B',(Join-Path $PSScriptRoot 'audit_proxy.py'),'--workspace',$Workspace)
if ($Repair) {$arguments += '--repair'}
if ($Full) {$arguments += '--full'}
if ($LaunchCheck) {$arguments += '--launch-check'}
if ($Runtime) {$arguments += '--runtime'}
if ($Details) {$arguments += '--details'}
if ($NoPrompt -or $CheckOnly) {$arguments += '--no-prompt'}
if ($Json) {$arguments += '--json'}
if ($Output) {$arguments += @('--output',$Output)}
& $pythonExe @arguments
exit $LASTEXITCODE
