<#
.SYNOPSIS
    Publishes a WPF app and packages it with Velopack.

.DESCRIPTION
    Velopack produces a per-user installer that writes to %LOCALAPPDATA%, so it needs
    NO elevation and NO registry writes for OAuth to work.

    That last point is worth stating plainly, because it is a common misconception:
    the loopback redirect (http://127.0.0.1:{port}/callback) requires nothing to be
    registered anywhere. HttpListener binds a high port on the loopback adapter as the
    interactive user, which needs no URL ACL and no admin rights. README §4.3 chose
    loopback over a custom URI scheme (appa://) precisely to avoid registry writes and
    the machine-global namespace that any other installed application can hijack.

    What Velopack DOES set up:
      - Start Menu shortcut
      - Add/Remove Programs entry (this is the only registry it touches, under
        HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall — standard per-user
        install bookkeeping, nothing to do with OAuth)
      - Update/rollback machinery via VelopackApp.Build().Run() in App.xaml.cs

    If you later decide you DO want a custom URI scheme (README §4.3 explains the
    trade-off), see build/register-uri-scheme.ps1.

.EXAMPLE
    ./build/publish.ps1 -App AppA -Version 1.0.0
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('AppA', 'AppB')]
    [string]$App,

    [Parameter(Mandatory)]
    [string]$Version,

    [string]$Runtime = 'win-x64',

    [switch]$UseTelerik,

    [string]$ReleaseDir = "$PSScriptRoot/../artifacts/$App"
)

$ErrorActionPreference = 'Stop'

$repoRoot   = Resolve-Path "$PSScriptRoot/.."
$projectDir = Join-Path $repoRoot "src/$App"
$publishDir = Join-Path $repoRoot "artifacts/publish/$App"

Write-Host "==> Publishing $App $Version ($Runtime)" -ForegroundColor Cyan

if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }

# Self-contained so target machines need no .NET runtime install. Velopack handles
# the resulting size well via delta packages.
$publishArgs = @(
    'publish', (Join-Path $projectDir "$App.csproj")
    '-c', 'Release'
    '-r', $Runtime
    '--self-contained', 'true'
    '-o', $publishDir
    "-p:Version=$Version"
    '-p:PublishSingleFile=false'   # Velopack manages the file layout itself
)

if ($UseTelerik) { $publishArgs += '-p:UseTelerik=true' }

& dotnet @publishArgs
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed with exit code $LASTEXITCODE" }

# ── Velopack CLI ─────────────────────────────────────────────────────────────
if (-not (Get-Command vpk -ErrorAction SilentlyContinue)) {
    Write-Host "==> Installing the Velopack CLI (vpk)" -ForegroundColor Yellow
    & dotnet tool install -g vpk
    if ($LASTEXITCODE -ne 0) { throw 'Could not install the Velopack CLI.' }

    Write-Host "    Installed. If 'vpk' is not found, restart your shell or add" -ForegroundColor Yellow
    Write-Host "    $env:USERPROFILE\.dotnet\tools to PATH." -ForegroundColor Yellow
}

Write-Host "==> Packaging with Velopack" -ForegroundColor Cyan

& vpk pack `
    --packId    "Corp.$App" `
    --packVersion $Version `
    --packDir   $publishDir `
    --mainExe   "$App.exe" `
    --packTitle "$App" `
    --packAuthors "Corp" `
    --outputDir $ReleaseDir

if ($LASTEXITCODE -ne 0) { throw "vpk pack failed with exit code $LASTEXITCODE" }

Write-Host ""
Write-Host "==> Done. Installer and release files are in:" -ForegroundColor Green
Write-Host "    $(Resolve-Path $ReleaseDir)" -ForegroundColor Green
Write-Host ""
Write-Host "    Corp.$App-win-Setup.exe   per-user installer, no elevation" -ForegroundColor Gray
Write-Host "    RELEASES                  update feed manifest" -ForegroundColor Gray
Write-Host ""
Write-Host "    Reminder: the loopback ports in appsettings.json must be registered" -ForegroundColor Yellow
Write-Host "    as redirect URIs in Okta, or sign-in fails (README §6.5)." -ForegroundColor Yellow
