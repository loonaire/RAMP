<#
.SYNOPSIS
    Build RAMP in release mode and ship ramp.exe out of cargo's build folder.

.DESCRIPTION
    ramp.exe installs Apache, MariaDB, PHP and phpMyAdmin into the folder it is
    started from. Started from cargo's target folder, a `cargo clean` would wipe
    all of that, databases included (the panel refuses to install there). This
    script builds once and packages ramp.exe on its own:

        dist\RAMP-<version>-win64.zip          RAMP-<version>\ramp.exe
        dist\RAMP-<version>-win64.zip.sha256   its SHA256

    With -InstallDir, ramp.exe is also copied into that folder (created when
    missing). Start it there: the first launch installs the servers next to it.
    An existing installation is kept as it is, only ramp.exe is replaced.

    The GitHub workflow .github/workflows/release.yml runs this script on every
    pushed v* tag, with -Tag: it then also hands the package paths to the next
    workflow steps (GITHUB_OUTPUT).

.PARAMETER InstallDir
    Folder to install or update ramp.exe in. Never inside cargo's target folder
    or inside this repository.

.PARAMETER NoBuild
    Package the ramp.exe already built instead of running cargo build first.

.PARAMETER Tag
    Release tag being built (v0.5, v0.5.1...). The script stops when it does not
    name the version in Cargo.toml, so a package never carries a wrong number.

.EXAMPLE
    .\release.ps1

.EXAMPLE
    .\release.ps1 -InstallDir C:\RAMP

.EXAMPLE
    .\release.ps1 -Tag v0.5
#>
[CmdletBinding()]
param(
    [string]$InstallDir,
    [switch]$NoBuild,
    [string]$Tag
)

$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$meta = cargo metadata --format-version 1 --no-deps | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
$version = ($meta.packages | Where-Object name -eq 'ramp').version
$target = [IO.Path]::GetFullPath($meta.target_directory)

if ($Tag) {
    # Tags are short (v0.5 for 0.5.0); a pre-release tag must match exactly.
    $want = $Tag -replace '^v', ''
    if ($want -match '^\d+\.\d+$') { $want = "$want.0" }
    if ($version -ne $want) {
        throw "tag $Tag does not match version $version in Cargo.toml: bump the version or fix the tag"
    }
}

if (-not $NoBuild) {
    # --locked: the package is built from Cargo.lock as committed, never re-resolved.
    cargo build --release --locked
    if ($LASTEXITCODE -ne 0) { throw 'cargo build --release failed' }
}
$exe = Join-Path $target 'release\ramp.exe'
if (-not (Test-Path $exe)) { throw "$exe not found: run without -NoBuild" }

# ---------------------------------------------------------------- package
$name = "RAMP-$version"
$dist = Join-Path $PSScriptRoot 'dist'
$stage = Join-Path ([IO.Path]::GetTempPath()) "ramp-dist-$PID"
New-Item -ItemType Directory -Force (Join-Path $stage $name) | Out-Null
try {
    Copy-Item $exe (Join-Path $stage "$name\ramp.exe")
    New-Item -ItemType Directory -Force $dist | Out-Null
    $zip = Join-Path $dist "$name-win64.zip"
    Compress-Archive -Path (Join-Path $stage $name) -DestinationPath $zip -Force
}
finally {
    Remove-Item -Recurse -Force $stage
}
$hash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
[IO.File]::WriteAllText("$zip.sha256", "$hash  $(Split-Path $zip -Leaf)`n")
Write-Host "Package : $zip"
Write-Host "SHA256  : $hash"
if ($env:GITHUB_OUTPUT) {
    Add-Content -Path $env:GITHUB_OUTPUT -Encoding utf8 -Value @(
        "version=$version"
        "zip=$zip"
        "sha256=$zip.sha256"
    )
}

# ---------------------------------------------------------------- install
if (-not $InstallDir) { return }

$dest = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InstallDir))
function Test-Inside([string]$path, [string]$root) {
    $p = $path.TrimEnd('\') + '\'
    $r = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
    return $p.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)
}
if (Test-Inside $dest $target) {
    throw "$dest is inside cargo's target folder ($target): cargo clean would wipe the installation"
}
if (Test-Inside $dest $PSScriptRoot) {
    throw "$dest is inside the repository: pick a folder of its own (for example C:\RAMP)"
}

$destExe = Join-Path $dest 'ramp.exe'
$running = Get-Process ramp -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and ($_.Path -ieq $destExe) }
if ($running) { throw "$destExe is running: quit the panel first" }

$existing = Test-Path (Join-Path $dest 'apache')
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item $exe $destExe -Force
if ($existing) {
    Write-Host "Updated : $destExe (the installation next to it is kept)"
}
else {
    Write-Host "Installed: $destExe"
    Write-Host 'Start it: the first launch downloads and installs Apache, MariaDB, PHP and phpMyAdmin there.'
}
