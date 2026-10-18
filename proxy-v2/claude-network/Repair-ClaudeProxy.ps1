param(
    [switch]$Repair,
    [switch]$Details,
    [switch]$Json,
    [switch]$Watch,
    [ValidateRange(1,120)][int]$Minutes = 5,
    [switch]$LaunchCheck,
    [switch]$OfferRepair,
    [switch]$Protect,
    # Accepted for old habits; the browser audit it used to start no longer exists.
    [switch]$Full,
    [string]$Workspace = (Get-Location).Path
)
$ErrorActionPreference = 'Stop'
$pythonExe = 'C:\Tools\Python\python.exe'
if (-not (Test-Path -LiteralPath $pythonExe)) { throw 'Required local Python is missing: C:\Tools\Python\python.exe' }
$arguments = @('-X','utf8','-B',(Join-Path $PSScriptRoot 'check.py'),'--workspace',$Workspace)
if ($Watch) { $arguments += @('--watch',$Minutes) }
if ($Repair) { $arguments += '--repair' }
if ($Details) { $arguments += '--details' }
if ($Json) { $arguments += '--json' }
if ($LaunchCheck) { $arguments += '--launch' }
if ($OfferRepair) { $arguments += '--offer-repair' }
if ($Protect) { $arguments += '--protect' }
& $pythonExe @arguments
exit $LASTEXITCODE
