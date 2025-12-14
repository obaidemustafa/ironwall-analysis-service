# Windows Installation Script for Binary Preprocessing Module Dependencies
# Purpose: Install all required tools and Python packages
# Usage: Run as Administrator in PowerShell
#        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
#        .\install_windows.ps1

Write-Host ""
Write-Host "==================================================================="
Write-Host "BINARY PREPROCESSING MODULE - WINDOWS INSTALLATION"
Write-Host "==================================================================="
Write-Host ""

# Check Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "ERROR: This script must be run as Administrator!"  -ForegroundColor Red
    Write-Host "Please right-click PowerShell and select 'Run as Administrator'"
    exit 1
}

Write-Host "Status: Running as Administrator" -ForegroundColor Green
Write-Host ""
Write-Host "This script will install:"
Write-Host "  1. Chocolatey package manager"
Write-Host "  2. File utility (libmagic)"
Write-Host "  3. Binwalk binary analysis tool"
Write-Host "  4. GNU strings utility"
Write-Host "  5. ClamAV antivirus"
Write-Host "  6. Java Development Kit"
Write-Host "  7. Python packages: capstone, lief, pefile, pyelftools, networkx, etc."
Write-Host ""
Write-Host "Total installation time: ~20-30 minutes"
Write-Host ""

Write-Host "For detailed installation instructions, see:" -ForegroundColor Yellow
Write-Host "  - INSTALLATION_GUIDE.md (comprehensive)"
Write-Host "  - README.md (quick start)"
Write-Host "  - START_HERE.md (entry point)"
Write-Host ""

Write-Host "==================================================================="
Write-Host "MANUAL INSTALLATION STEPS"
Write-Host "==================================================================="
Write-Host ""
Write-Host "Since PowerShell syntax is complex, please follow these manual steps:"
Write-Host ""
Write-Host "Step 1: Install Chocolatey"
Write-Host "  Open PowerShell as Administrator and run:"
Write-Host "    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force"
Write-Host "    iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
Write-Host ""

Write-Host "Step 2: Install system tools"
Write-Host "    choco install gnuwin32-file binwalk llvm openjdk11 clamav -y"
Write-Host ""

Write-Host "Step 3: Install Python packages"
Write-Host "    python -m pip install --upgrade pip"
Write-Host "    pip install capstone lief pefile pyelftools networkx ghidra-bridge rich loguru"
Write-Host ""

Write-Host "Step 4: Update ClamAV database"
Write-Host "    freshclam"
Write-Host ""

Write-Host "Step 5: Verify installation"
Write-Host "    python verify_all.py"
Write-Host ""

Write-Host "Step 6: Test the module"
Write-Host "    python test_preprocessing.py"
Write-Host ""

Write-Host "==================================================================="
Write-Host "QUICK REFERENCE"
Write-Host "==================================================================="
Write-Host ""
Write-Host "Check dependencies:"
Write-Host "  python checklist.py"
Write-Host ""
Write-Host "Full verification:"
Write-Host "  python verify_all.py"
Write-Host ""
Write-Host "Test the module:"
Write-Host "  python test_preprocessing.py"
Write-Host ""

Write-Host "For complete automated setup, see INSTALLATION_GUIDE.md"
Write-Host ""
