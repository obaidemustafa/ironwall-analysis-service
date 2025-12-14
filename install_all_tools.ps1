<#
install_all_tools.ps1
Consolidated installer -> installs Chocolatey (if missing), core system packages
and required Python packages for the binary preprocessing module.

USAGE (run as Administrator):
  Open an elevated PowerShell, then:
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\install_all_tools.ps1

This script attempts to run the common install commands non-interactively.
It is written to be idempotent and to continue where possible if a step fails.
#>

# Ensure running elevated
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!" -ForegroundColor Red
    Write-Host "Open PowerShell (Admin) and run:`n  Set-ExecutionPolicy Bypass -Scope Process -Force`n  .\install_all_tools.ps1"
    exit 1
}

function Run-Command($cmd) {
    Write-Host "\n> $cmd" -ForegroundColor Cyan
    try {
        iex $cmd
    } catch {
        Write-Host "Command failed: $cmd" -ForegroundColor Yellow
        Write-Host $_.Exception.Message -ForegroundColor Yellow
    }
}

Write-Host "Starting consolidated installer for Binary Preprocessing dependencies..." -ForegroundColor Green

# 1) Install Chocolatey if missing
if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Host "Chocolatey not found — installing Chocolatey..." -ForegroundColor Green
    Run-Command "Set-ExecutionPolicy Bypass -Scope Process -Force"
    Run-Command "iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
    # refreshenv may be available after choco install
    try { RefreshEnv } catch { }
} else {
    Write-Host "Chocolatey is already installed." -ForegroundColor Green
}

# 2) Install common system packages via Chocolatey
$packages = @("git","python","7zip","llvm","openjdk11","clamav")
$pkgList = $packages -join ' '
Write-Host "Installing system packages: $($packages -join ', ')" -ForegroundColor Green
Run-Command "choco install $pkgList -y"

# 3) Upgrade pip and install required Python packages
Write-Host "Installing Python packages (pip)..." -ForegroundColor Green
Run-Command "python -m pip install --upgrade pip setuptools wheel"
$pyPkgs = @("capstone","lief","pefile","pyelftools","networkx","ghidra-bridge","rich","loguru")
Run-Command "python -m pip install $($pyPkgs -join ' ')"

# 4) Optional: binwalk and other analysis tools (may be limited on native Windows)
Write-Host "Installing optional analysis tools (binwalk). If you prefer WSL, install there instead." -ForegroundColor Green
Run-Command "choco install binwalk -y"  # best-effort; may not exist on all systems
Run-Command "python -m pip install binwalk"

# 5) Update ClamAV DB (if freshclam available)
Write-Host "Attempting to update ClamAV database (if installed)..." -ForegroundColor Green
try { Run-Command "freshclam" } catch { Write-Host "freshclam not available or update failed." -ForegroundColor Yellow }

Write-Host "\nInstallation script finished."
Write-Host "Next steps: Open a NEW PowerShell (Admin) or run `refreshenv` then run:`n  python verify_all.py`" -ForegroundColor Cyan

Write-Host "If any step failed, re-run this script or follow the manual steps in INSTALLATION_GUIDE.md" -ForegroundColor Yellow
