param([string]$SourceDirectory = (Join-Path $PSScriptRoot 'claude-network'))
$ErrorActionPreference = 'Stop'
$sourceRoot = (Resolve-Path -LiteralPath $SourceDirectory -ErrorAction Stop).Path
$source = Join-Path $sourceRoot 'ClaudeBrowser.cs'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw 'ClaudeBrowser.cs is missing.' }
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'The Windows .NET Framework C# compiler is missing.' }
$temporary = Join-Path $sourceRoot ('ClaudeBrowser.build-' + [Guid]::NewGuid().ToString('N') + '.exe')
$target = Join-Path $sourceRoot 'ClaudeBrowser.exe'
try {
    & $compiler '/nologo' '/target:winexe' '/reference:System.Windows.Forms.dll' ('/out:' + $temporary) $source
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $temporary -PathType Leaf)) {
        throw 'C# compilation failed; the existing launcher was not replaced.'
    }
    Move-Item -LiteralPath $temporary -Destination $target -Force
    $hashes = [ordered]@{}
    foreach ($name in @('ClaudeBrowser.cs', 'ClaudeBrowser.exe')) {
        $hashes[$name] = (Get-FileHash -LiteralPath (Join-Path $sourceRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $hashes | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $sourceRoot 'browser-build.json') -Encoding UTF8
    Write-Output ('Built launcher and SHA-256 baseline in: ' + $sourceRoot)
} finally {
    if (Test-Path -LiteralPath $temporary -PathType Leaf) { Remove-Item -LiteralPath $temporary }
}
