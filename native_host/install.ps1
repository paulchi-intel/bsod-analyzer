<#
    BSOD Analyzer - Native Messaging Host installer

    Registers `com.bsod.copilot` as a Chrome / Edge native messaging host for
    the current user, pointing at bsod_host.py in this folder.

    Usage:
        # 1. Load the extension (chrome_ext/bsod-analyzer/) unpacked in Chrome,
        #    copy its ID from chrome://extensions.
        # 2. Run from PowerShell (no admin needed):
        powershell -ExecutionPolicy Bypass -File install.ps1 -ExtensionId <EXT_ID>

    Optional:
        -PythonExe  : path to python.exe (default: auto-detect via `where python`)
        -Browsers   : Chrome, Edge, or Both (default: Both)
        -Uninstall  : remove registry entries

    Notes:
        - Writes into HKCU only; no admin required.
        - Regenerates `com.bsod.copilot.json` and `bsod_host.bat` in this folder.
#>

param(
    [Parameter(Mandatory=$false)] [string] $ExtensionId,
    [string] $PythonExe,
    [ValidateSet('Chrome','Edge','Both')] [string] $Browsers = 'Both',
    [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'

$HostName   = 'com.bsod.copilot'
$Here       = Split-Path -Parent $MyInvocation.MyCommand.Path
$HostScript = Join-Path $Here 'bsod_host.py'
$Launcher   = Join-Path $Here 'bsod_host.bat'
$Manifest   = Join-Path $Here "$HostName.json"

$RegPaths = @()
if ($Browsers -eq 'Chrome' -or $Browsers -eq 'Both') {
    $RegPaths += "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
}
if ($Browsers -eq 'Edge' -or $Browsers -eq 'Both') {
    $RegPaths += "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HostName"
}

# ---------- Uninstall ----------
if ($Uninstall) {
    foreach ($rp in $RegPaths) {
        if (Test-Path $rp) {
            Remove-Item $rp -Recurse -Force
            Write-Host "Removed $rp" -ForegroundColor Yellow
        }
    }
    Write-Host "Uninstalled native host registrations." -ForegroundColor Green
    return
}

# ---------- Install ----------
if (-not $ExtensionId) {
    Write-Error "Missing -ExtensionId. Load the extension in chrome://extensions first, copy its ID, then rerun."
}
if ($ExtensionId -notmatch '^[a-p]{32}$') {
    Write-Warning "ExtensionId '$ExtensionId' doesn't look like a typical 32-char Chrome ID; continuing anyway."
}

if (-not (Test-Path $HostScript)) {
    Write-Error "bsod_host.py not found at $HostScript"
}

# Resolve python.exe
if (-not $PythonExe) {
    $py = Get-Command python.exe -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command py.exe -ErrorAction SilentlyContinue }
    if (-not $py) { Write-Error "python.exe not found on PATH. Pass -PythonExe <path> or install Python 3." }
    $PythonExe = $py.Source
}
if (-not (Test-Path $PythonExe)) {
    Write-Error "PythonExe not found: $PythonExe"
}

# Write launcher .bat (Chrome requires .exe or .bat)
@"
@echo off
"$PythonExe" "$HostScript" %*
"@ | Set-Content -Encoding Ascii -Path $Launcher

# Write host manifest
$manifestObj = [ordered]@{
    name            = $HostName
    description     = 'BSOD Analyzer native host (runs kd.exe locally for the BSOD Analyzer Chrome extension).'
    path            = $Launcher
    type            = 'stdio'
    allowed_origins = @("chrome-extension://$ExtensionId/")
}
$manifestObj | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 -Path $Manifest

# Register in HKCU
foreach ($rp in $RegPaths) {
    New-Item -Path $rp -Force | Out-Null
    Set-ItemProperty -Path $rp -Name '(Default)' -Value $Manifest
    Write-Host "Registered $rp -> $Manifest" -ForegroundColor Green
}

Write-Host ''
Write-Host "[OK] BSOD Analyzer native host installed." -ForegroundColor Green
Write-Host "     Host name   : $HostName"
Write-Host "     Launcher    : $Launcher"
Write-Host "     Manifest    : $Manifest"
Write-Host "     Python      : $PythonExe"
Write-Host "     Extension   : $ExtensionId"
Write-Host ''
Write-Host "Reload the extension in chrome://extensions if it was already loaded."
