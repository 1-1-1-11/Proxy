$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
# Optimized GUI build first; the debug build is a console program, so its console stays hidden.
$release = Join-Path $projectRoot 'src-tauri\target\release\requirement-french.exe'
$debug = Join-Path $projectRoot 'src-tauri\target\debug\requirement-french.exe'
if (Test-Path -LiteralPath $release -PathType Leaf) {
    Start-Process -FilePath $release -WorkingDirectory $projectRoot
} elseif (Test-Path -LiteralPath $debug -PathType Leaf) {
    Start-Process -FilePath $debug -WorkingDirectory $projectRoot -WindowStyle Hidden
} else {
    throw '整合版尚未构建，请先按 docs\proxy-integration.md 构建。'
}
