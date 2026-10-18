param([string]$SourceDirectory = (Join-Path $PSScriptRoot 'claude-network'))
$ErrorActionPreference = 'Stop'
$sourceRoot = (Resolve-Path -LiteralPath $SourceDirectory -ErrorAction Stop).Path
$source = Join-Path $sourceRoot 'ClaudeBrowser.cs'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'ClaudeBrowser.cs is missing.' }
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'The Windows .NET Framework C# compiler is missing.' }
$temporary = Join-Path $sourceRoot ('ClaudeBrowser.build-' + [Guid]::NewGuid().ToString('N') + '.exe')
try {
    # The source is UTF-8 without BOM; without /codepage the Chinese message box text is garbled.
    & $compiler '/nologo' '/target:winexe' '/codepage:65001' '/reference:System.Windows.Forms.dll' ('/out:' + $temporary) $source
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $temporary -PathType Leaf)) {
        throw 'C# compilation failed; the existing launcher was not replaced.'
    }
    Move-Item -LiteralPath $temporary -Destination (Join-Path $sourceRoot 'ClaudeBrowser.exe') -Force
    Write-Output ('Built launcher in: ' + $sourceRoot)
} finally {
    if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary }
}
