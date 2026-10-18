param([string]$SourceDirectory = (Join-Path $PSScriptRoot 'claude-network'))
$ErrorActionPreference = 'Stop'
$sourceRoot = (Resolve-Path -LiteralPath $SourceDirectory -ErrorAction Stop).Path
$source = Join-Path $sourceRoot 'ClaudeStatus.cs'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'ClaudeStatus.cs is missing.' }
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'The Windows .NET Framework C# compiler is missing.' }
$temporary = Join-Path $sourceRoot ('ClaudeStatus.build-' + [Guid]::NewGuid().ToString('N') + '.exe')
try {
    & $compiler '/nologo' '/target:winexe' '/codepage:65001' '/reference:System.Windows.Forms.dll' '/reference:System.Drawing.dll' '/reference:System.Web.Extensions.dll' ('/out:' + $temporary) $source
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $temporary -PathType Leaf)) {
        throw 'C# compilation failed; the existing status icon was not replaced.'
    }
    Move-Item -LiteralPath $temporary -Destination (Join-Path $sourceRoot 'ClaudeStatus.exe') -Force
    Write-Output ('Built status icon in: ' + $sourceRoot)
} finally {
    if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary }
}
