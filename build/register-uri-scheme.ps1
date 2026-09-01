<#
.SYNOPSIS
    OPTIONAL: registers a custom URI scheme (appa://) for this application.

.DESCRIPTION
    ⚠️ THIS IS NOT REQUIRED FOR SSO TO WORK, AND IS NOT USED BY THE DEMO.

    The demo uses a loopback redirect (http://127.0.0.1:{port}/callback), which needs
    no registry writes at all. README §4.3 chose it deliberately over a custom scheme:

      - No registry writes, so no installer elevation.
      - A custom scheme is a MACHINE-GLOBAL NAMESPACE. Any other installed application
        can register the same 'appa://' and silently hijack your OAuth callback, and
        Windows gives you no way to detect or prevent it. Loopback + PKCE + state is
        strictly stronger.
      - Loopback is debuggable: the redirect is an ordinary HTTP request.

    This script exists for two legitimate cases:
      1. You want deep links (appa://orders/12345) as a product feature, independent
         of authentication.
      2. Your environment blocks loopback binds (rare, but present in some hardened
         SOE images), leaving no alternative.

    If you use it for OAuth, register the scheme as an ADDITIONAL redirect URI in Okta
    and keep loopback as the primary. PKCE still protects the code either way — the
    scheme is a weaker delivery channel, not a weaker grant.

.NOTES
    Writes to HKCU (per-user), so no elevation is needed. Call it from a Velopack
    install hook, or run it manually.

.EXAMPLE
    ./build/register-uri-scheme.ps1 -Scheme appa -ExePath "$env:LOCALAPPDATA\Corp.AppA\current\AppA.exe"
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$Scheme,
    [Parameter(Mandatory)][string]$ExePath,
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'

# HKCU, not HKCR: per-user registration needs no administrator rights.
$root = "HKCU:\Software\Classes\$Scheme"

if ($Unregister) {
    if (Test-Path $root) {
        if ($PSCmdlet.ShouldProcess($root, 'Remove URI scheme registration')) {
            Remove-Item $root -Recurse -Force
            Write-Host "Unregistered $Scheme://" -ForegroundColor Green
        }
    }
    return
}

if (-not (Test-Path $ExePath)) { throw "Executable not found: $ExePath" }

if (-not $PSCmdlet.ShouldProcess($root, "Register $Scheme:// -> $ExePath")) { return }

New-Item -Path $root -Force | Out-Null
Set-ItemProperty -Path $root -Name '(Default)' -Value "URL:$Scheme Protocol"

# This empty value is what tells Windows the key is a protocol handler.
Set-ItemProperty -Path $root -Name 'URL Protocol' -Value ''

New-Item -Path "$root\DefaultIcon" -Force | Out-Null
Set-ItemProperty -Path "$root\DefaultIcon" -Name '(Default)' -Value "`"$ExePath`",0"

New-Item -Path "$root\shell\open\command" -Force | Out-Null
Set-ItemProperty -Path "$root\shell\open\command" -Name '(Default)' -Value "`"$ExePath`" `"%1`""

Write-Host "Registered $Scheme:// -> $ExePath" -ForegroundColor Green
Write-Host ""
Write-Host "If you are using this for OAuth, add this to the Okta app integration's" -ForegroundColor Yellow
Write-Host "Sign-in redirect URIs as well:  $Scheme`://callback" -ForegroundColor Yellow
Write-Host "Keep the loopback URIs registered too — see README §4.3." -ForegroundColor Yellow
