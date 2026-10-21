# Builds sora-core for Windows 7 SP1+ with the patched XTLS/go-win7 SDK.
#
# This is the local twin of the control-windows job in
# .github/workflows/legacy.yml: same SDK archive, same SHA-256, same
# VERSION check against core/go.mod, same build flags. A core binary
# built with stock Go has a Windows 10 floor and does not start on
# Windows 7/8.1 (stock Go 1.21+ dropped them); only this SDK produces
# the NT 6.1-baseline binary. Building with a plain `go build` and
# calling the result a Windows 7 build is exactly the mistake this
# script exists to prevent.
#
# Requires: stock Go of the version named in core/go.mod (bootstrap
# for the SDK build), Windows PowerShell 5.1+ or PowerShell 7+.
# Output: legacy\artifacts\sora-legacy-core-x86.exe and -x64.exe,
# the same names the CI job uploads.

[CmdletBinding()]
param(
    [ValidateSet('386', 'amd64', 'both')]
    [string]$Arch = 'both',
    [string]$WorkDir = (Join-Path $env:TEMP 'sora-go-win7'),
    [string]$OutputDir = (Join-Path $PSScriptRoot '..\artifacts')
)

$ErrorActionPreference = 'Stop'

$SdkArchiveUrl = 'https://github.com/XTLS/go-win7/releases/download/current/go-win7-win6-1.26.zip'
$SdkArchiveSha256 = '4a8ea74640bcdf608fbe351b3eaa5715685b18ec0b0d27e8d59608ade86c8397'

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$coreDir = Join-Path $repoRoot 'core'

# The SDK VERSION must equal the toolchain core/go.mod asks for; CI
# pins the same pair (this archive carries go1.26.9, go.mod says so).
$goModVersion = $null
foreach ($line in Get-Content (Join-Path $coreDir 'go.mod')) {
    if ($line -match '^go\s+(\d+\.\d+\.\d+)\s*$') { $goModVersion = $Matches[1]; break }
}
if (-not $goModVersion) { throw 'Cannot read the go version from core/go.mod' }
$expectedSdkVersion = "go$goModVersion"

$stockGo = Get-Command go -ErrorAction SilentlyContinue
if (-not $stockGo) { throw 'Stock Go (bootstrap for the SDK build) not found in PATH' }
$stockGoVersion = & go version
if ($stockGoVersion -notmatch [regex]::Escape($expectedSdkVersion)) {
    throw "Bootstrap Go must be $expectedSdkVersion (core/go.mod), found: $stockGoVersion"
}
$bootstrapRoot = & go env GOROOT

New-Item -ItemType Directory -Force $WorkDir | Out-Null
$archive = Join-Path $WorkDir 'go-win7.zip'
if (-not (Test-Path $archive)) {
    Invoke-WebRequest $SdkArchiveUrl -OutFile $archive
}
if ((Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $SdkArchiveSha256) {
    throw 'Unverified Go SDK source: SHA-256 mismatch'
}

$sdk = Join-Path $WorkDir "go-win7-$goModVersion"
Expand-Archive $archive $sdk -Force
if ((Get-Content (Join-Path $sdk 'VERSION') -First 1) -ne $expectedSdkVersion) {
    throw 'Unexpected Go SDK version'
}
if (-not (Test-Path (Join-Path $sdk 'bin\go.exe'))) {
    $env:GOROOT_BOOTSTRAP = $bootstrapRoot
    $env:CGO_ENABLED = '0'
    $env:GOTOOLCHAIN = 'local'
    Push-Location (Join-Path $sdk 'src')
    try {
        cmd /c make.bat
        if ($LASTEXITCODE -ne 0) { throw 'Windows 7 SDK build failed' }
    }
    finally { Pop-Location }
}

New-Item -ItemType Directory -Force $OutputDir | Out-Null
$targets = @($Arch)
if ($Arch -eq 'both') { $targets = @('386', 'amd64') }
foreach ($target in $targets) {
    $platform = 'x64'
    if ($target -eq '386') { $platform = 'x86' }
    $out = Join-Path $OutputDir "sora-legacy-core-$platform.exe"
    $env:GOOS = 'windows'
    $env:GOARCH = $target
    $env:CGO_ENABLED = '0'
    $env:GOTOOLCHAIN = 'local'
    $env:GOROOT = $sdk
    Push-Location $coreDir
    try {
        & (Join-Path $sdk 'bin\go.exe') build -trimpath -ldflags '-s -w -X main.buildVersion=legacy-dev' -o $out ./cmd/sora-core
        if ($LASTEXITCODE -ne 0) { throw "Core build failed for GOARCH=$target" }
    }
    finally { Pop-Location }
    Write-Host "Built $out (Windows 7 SP1+ baseline, GOARCH=$target)"
}
