[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [switch]$Release,
    [string]$SourceCommit
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputRoot) { throw 'Choose a new output directory; previous artifacts are preserved.' }
if ($outputRoot.StartsWith($repoRoot + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Build artifacts must use a new directory outside this checkout.'
}
$compiler = Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'The Windows x64 .NET Framework compiler is unavailable.' }
$sourceNames = @('.gitattributes', 'LauncherCore.cs', 'Program.cs', 'bridge.py', 'build.ps1', 'test.ps1',
                 'tests/OfflineTests.cs', 'tests/test_bridge.py', 'README.md')
$head = (& git -C $repoRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$') { throw 'Cannot identify the source checkout.' }
if ($Release) {
    if ($SourceCommit -notmatch '^[0-9a-f]{40}$' -or $head -cne $SourceCommit) { throw 'Release requires -SourceCommit matching the full checked-out commit.' }
    & git -C $repoRoot diff --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Release requires clean tracked source files.' }
    & git -C $repoRoot diff --cached --quiet
    if ($LASTEXITCODE -ne 0) { throw 'Release requires a clean index.' }
    $localChanges = @(& git -C $repoRoot status --porcelain --untracked-files=all -- install/windows)
    if ($localChanges.Count -ne 0) { throw 'Release requires all Windows launcher inputs to be committed and clean.' }
} elseif ($SourceCommit) { throw '-SourceCommit is only used with -Release.' }

$sources = [ordered]@{}
foreach ($name in $sourceNames) {
    $path = Join-Path $PSScriptRoot $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing source input: $name" }
    $info = Get-Item -LiteralPath $path
    if ($info.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Source input must not be a link: $name" }
    if ($Release) {
        $blob = (& git -C $repoRoot rev-parse ($SourceCommit + ':install/windows/' + $name)).Trim()
        if ($LASTEXITCODE -ne 0) { throw "Source is not present in the fixed commit: $name" }
        $workingBlob = (& git -C $repoRoot hash-object --no-filters -- $path).Trim()
        if ($LASTEXITCODE -ne 0 -or $blob -cne $workingBlob) { throw "Source bytes differ from the fixed commit: $name" }
    }
    $sources['install/windows/' + $name] = [ordered]@{ bytes = $info.Length; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
}

$version = '0.1.0a1'
$suffix = if ($Release) { '' } else { '-dev' }
$binaryName = 'Yuanxingmu-Windows-' + $version + $suffix + '.exe'
$binary = Join-Path $outputRoot $binaryName
New-Item -ItemType Directory -Path $outputRoot -ErrorAction Stop | Out-Null
$compilerArguments = @('/nologo', '/utf8output', '/codepage:65001', '/optimize+', '/target:winexe', '/platform:x64',
    ('/out:' + $binary), '/reference:System.dll', '/reference:System.Core.dll', '/reference:System.Drawing.dll',
    '/reference:System.Windows.Forms.dll', ('/resource:' + (Join-Path $PSScriptRoot 'bridge.py') + ',Yuanxingmu.Windows.Bridge'),
    (Join-Path $PSScriptRoot 'LauncherCore.cs'), (Join-Path $PSScriptRoot 'Program.cs'))
if (-not $Release) { $compilerArguments = @('/define:DEV_BUILD') + $compilerArguments }
& $compiler @compilerArguments
if ($LASTEXITCODE -ne 0) { throw 'Windows launcher compilation failed.' }

foreach ($name in $sourceNames) {
    $actual = (Get-FileHash -LiteralPath (Join-Path $PSScriptRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $sources['install/windows/' + $name].sha256) { throw "Source changed during compilation: $name" }
}
if ((& git -C $repoRoot rev-parse HEAD).Trim() -cne $head) { throw 'Checked-out commit changed during compilation.' }
$binaryHash = (Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = [ordered]@{
    schema_version = 1; product = 'yuanxingmu-windows-launcher'; version = $version
    publishable = [bool]$Release; source_commit = $(if ($Release) { $head } else { $null })
    development_checkout_head = $(if ($Release) { $null } else { $head })
    platform = 'windows-x64'; compiler = [ordered]@{ file_version = (Get-Item -LiteralPath $compiler).VersionInfo.FileVersion; sha256 = (Get-FileHash -LiteralPath $compiler -Algorithm SHA256).Hash.ToLowerInvariant() }
    supported_installer = '0.4.0a2'; supported_runtime = '0.7.0a2'; authenticode_signed = $false
    binary = [ordered]@{ name = $binaryName; bytes = (Get-Item -LiteralPath $binary).Length; sha256 = $binaryHash }
    sources = $sources
}
$utf8 = New-Object System.Text.UTF8Encoding($false)
$manifestPath = Join-Path $outputRoot 'launcher-manifest.json'
[IO.File]::WriteAllText($manifestPath, (($manifest | ConvertTo-Json -Depth 8) + "`n"), $utf8)
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
[IO.File]::WriteAllText((Join-Path $outputRoot 'SHA256SUMS'), ($binaryHash + '  ' + $binaryName + "`n" + $manifestHash + '  launcher-manifest.json' + "`n"), $utf8)
Write-Output ($manifest | ConvertTo-Json -Depth 8)
