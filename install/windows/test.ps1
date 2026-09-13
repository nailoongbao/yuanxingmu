[CmdletBinding()]
param([string]$Python = 'python', [string]$OutputDirectory, [switch]$CheckWslListing)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $OutputDirectory) { $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) ('yuanxingmu-windows-tests-' + [Guid]::NewGuid().ToString('N')) }
$testOutput = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $testOutput) { throw 'Choose a new test output directory.' }
New-Item -ItemType Directory -Path $testOutput -ErrorAction Stop | Out-Null
$compiler = Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'The Windows x64 .NET Framework compiler is unavailable.' }
$testExecutable = Join-Path $testOutput 'LauncherOfflineTests.exe'
& $compiler /nologo /utf8output /codepage:65001 /target:exe /platform:x64 ('/out:' + $testExecutable) /reference:System.dll /reference:System.Core.dll /reference:System.Web.Extensions.dll (Join-Path $PSScriptRoot 'LauncherCore.cs') (Join-Path $PSScriptRoot 'tests/OfflineTests.cs')
if ($LASTEXITCODE -ne 0) { throw 'Offline C# test compilation failed.' }
& $testExecutable
if ($LASTEXITCODE -ne 0) { throw 'Offline C# tests failed.' }
if ($CheckWslListing) {
    & $testExecutable check-wsl-list
    if ($LASTEXITCODE -ne 0) { throw 'The actual read-only WSL distribution listing failed.' }
}
& $Python -I -B (Join-Path $PSScriptRoot 'tests/test_bridge.py')
if ($LASTEXITCODE -ne 0) { throw 'Offline Python bridge tests failed.' }
Write-Output ('Offline test binaries: ' + $testOutput)
