# Complete Binary Preprocessing Module Setup Guide

## Overview

This guide will walk you through installing all dependencies needed for the `binary_preprocessing.py` module to perform complete binary analysis. The setup is split into three parts:

1. **System Tools** (file, binwalk, strings, clamscan)
2. **Python Libraries** (capstone, lief, pefile, pyelftools, networkx, etc.)
3. **Optional: Ghidra + Java** (for advanced disassembly)

---

## Part 1: System Tools Installation

### Windows (PowerShell with Administrator Privileges)

#### Step 1.1: Install Chocolatey (if not already installed)

Chocolatey is a package manager for Windows that makes installing tools easy.

```powershell
# Run PowerShell as Administrator, then:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
Invoke-Expression ((New-Object System.Net.ServicePointManager).SecurityProtocol = 'Tls12'; (Invoke-WebRequest -UseBasicParsing -Uri "https://community.chocolatey.org/install.ps1").Content) | Out-String | Invoke-Expression
```

Verify Chocolatey installation:
```powershell
choco --version
```

Expected output: `Chocolatey v2.x.x` or similar.

#### Step 1.2: Install File (libmagic) for Windows

```powershell
# Using GnuWin32 (easiest option for Windows)
choco install gnuwin32-file -y
```

Alternative (if Chocolatey fails):
```powershell
# Download from: https://gnuwin32.sourceforge.net/packages/file.htm
# Extract to C:\Program Files\GnuWin32\
# Add C:\Program Files\GnuWin32\bin to PATH
```

Verify:
```powershell
file --version
file C:\Windows\System32\notepad.exe
```

Expected: Should show something like `PE 32-bit executable` or similar magic string.

#### Step 1.3: Install Binwalk

```powershell
# Using Python package (easiest on Windows)
pip install binwalk
```

Verify:
```powershell
binwalk --version
```

Expected: `Binwalk v2.x.x`

#### Step 1.4: Install Strings Utility

```powershell
# Strings is part of LLVM/Clang tools or can be found in GnuWin32
choco install llvm -y
# OR get from GnuWin32
choco install gnuwin32-grep -y
```

Alternative: Use Python's built-in string extraction (module already has fallback).

Verify:
```powershell
strings --version
```

#### Step 1.5: Install ClamAV (clamscan)

```powershell
# Download Windows installer from:
# https://www.clamav.net/downloads/production/clamav-1.0.7.win.x86_64.msi

# Or via Chocolatey:
choco install clamav -y

# After installation, update virus definitions:
freshclam
```

Verify:
```powershell
clamscan --version
```

Expected: `ClamAV 1.0.x`

Then update virus database (required):
```powershell
freshclam
# This may take 5-10 minutes on first run
```

---

### Linux (Ubuntu/Debian or RHEL/CentOS)

#### Step 1.1: Update Package Manager

```bash
# Debian/Ubuntu
sudo apt-get update

# RHEL/CentOS
sudo yum update
```

#### Step 1.2: Install File (libmagic)

```bash
# Debian/Ubuntu
sudo apt-get install -y file libmagic-dev

# RHEL/CentOS
sudo yum install -y file file-devel file-libs
```

Verify:
```bash
file --version
file /bin/bash
```

#### Step 1.3: Install Binwalk

```bash
# Debian/Ubuntu
sudo apt-get install -y binwalk

# RHEL/CentOS
sudo yum install -y binwalk
```

Or via Python pip (more reliable):
```bash
pip install binwalk
```

Verify:
```bash
binwalk --version
```

#### Step 1.4: Install GNU Core Utils (includes strings)

```bash
# Debian/Ubuntu
sudo apt-get install -y binutils

# RHEL/CentOS
sudo yum install -y binutils
```

Verify:
```bash
strings --version
strings /bin/bash | head -10
```

#### Step 1.5: Install ClamAV

```bash
# Debian/Ubuntu
sudo apt-get install -y clamav clamav-daemon

# RHEL/CentOS
sudo yum install -y clamav clamd

# Update virus definitions
sudo freshclam

# Start the daemon
sudo systemctl start clamav-daemon
sudo systemctl enable clamav-daemon
```

Verify:
```bash
clamscan --version
```

---

## Part 2: Python Libraries Installation

### Step 2.1: Install Core Python Packages

Ensure Python 3.10+ is installed:

```powershell
# Windows
python --version

# Linux
python3 --version
```

Install all required Python packages:

```powershell
# Windows (in PowerShell as Administrator)
pip install --upgrade pip setuptools wheel

# Install all required packages in one command
pip install capstone lief pefile pyelftools networkx ghidra-bridge rich loguru
```

For **Linux**:
```bash
# Linux (may need sudo or use virtualenv)
sudo pip install --upgrade pip setuptools wheel
sudo pip install capstone lief pefile pyelftools networkx ghidra-bridge rich loguru
```

### Step 2.2: Verify Each Python Library

Create a verification script. Save as `verify_imports.py`:

```python
import sys

packages = {
    'capstone': 'Capstone (disassembly)',
    'lief': 'LIEF (binary parsing)',
    'pefile': 'PE File parsing',
    'elftools': 'ELF file parsing',
    'networkx': 'NetworkX (graph analysis)',
    'ghidra_bridge': 'Ghidra Bridge (optional)',
    'rich': 'Rich (logging)',
    'loguru': 'Loguru (logging)',
}

failed = []
for pkg, desc in packages.items():
    try:
        __import__(pkg.replace('-', '_'))
        print(f"✓ {desc:40} installed")
    except ImportError:
        print(f"✗ {desc:40} MISSING")
        failed.append(pkg)

if failed:
    print(f"\nFailed packages: {', '.join(failed)}")
    print(f"Install with: pip install {' '.join(failed)}")
    sys.exit(1)
else:
    print("\n✓ All required packages installed!")
    sys.exit(0)
```

Run verification:
```powershell
# Windows
python verify_imports.py

# Linux
python3 verify_imports.py
```

Expected output:
```
✓ Capstone (disassembly)               installed
✓ LIEF (binary parsing)                installed
✓ PE File parsing                      installed
✓ ELF file parsing                     installed
✓ NetworkX (graph analysis)            installed
✓ Ghidra Bridge (optional)             installed
✓ Rich (logging)                       installed
✓ Loguru (logging)                     installed

✓ All required packages installed!
```

---

## Part 3: Optional - Ghidra Setup (Advanced)

### Note on Ghidra

Ghidra is optional because the module has **fallback mechanisms**. However, for best results:
- Install it if you want **function recovery**, **CFG analysis**, and **deeper disassembly**.
- Without it, Capstone disassembly will be used (still effective, but less sophisticated).

### Step 3.1: Install Java Development Kit (JDK)

Ghidra requires Java. Install JDK 11 or higher:

**Windows:**
```powershell
# Option 1: Using Chocolatey
choco install openjdk11 -y

# Option 2: Download from Oracle/Eclipse Adoptium
# https://adoptium.net/
# Download JDK 17 LTS installer and run it
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install -y openjdk-17-jdk-headless
```

**Linux (RHEL/CentOS):**
```bash
sudo yum install -y java-17-openjdk-devel
```

Verify Java installation:
```powershell
# Windows & Linux
java -version
javac -version
```

Expected:
```
openjdk version "17.0.x" ...
javac 17.0.x
```

### Step 3.2: Set JAVA_HOME Environment Variable

**Windows (PowerShell as Administrator):**
```powershell
# Find Java installation path
$javaPath = (Get-Command java).Source | Split-Path -Parent | Split-Path -Parent
$javaPath  # Should show C:\Program Files\Eclipse Adoptium\jdk-17.0.x or similar

# Set JAVA_HOME permanently
[System.Environment]::SetEnvironmentVariable('JAVA_HOME', $javaPath, [System.EnvironmentVariableTarget]::Machine)

# Verify
$env:JAVA_HOME
```

**Linux:**
```bash
# Find Java path
sudo update-alternatives --display java  # Check if alternatives are set

# Or manually find it:
which java
# Typical path: /usr/lib/jvm/java-17-openjdk-amd64

# Add to ~/.bashrc or ~/.bash_profile
echo 'export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64' >> ~/.bashrc
source ~/.bashrc

# Verify
echo $JAVA_HOME
```

### Step 3.3: Download and Install Ghidra

**Option A: Download Pre-built Binary**

1. Visit: https://ghidra-sre.org/
2. Click "Downloads"
3. Download **Ghidra 11.0.3** (or latest stable) for your OS
4. Extract to a convenient location:
   - Windows: `C:\tools\ghidra\`
   - Linux: `/opt/ghidra/` or `~/tools/ghidra/`

**Option B: Chocolatey (Windows)**
```powershell
choco install ghidra -y
```

Verify Ghidra installation:
```powershell
# Windows
C:\tools\ghidra\ghidra_11.0.3\ghidraRun.bat --version

# Linux
/opt/ghidra/ghidra_11.0.3/ghidraRun --version
```

### Step 3.4: Configure Ghidra-Bridge (Python Connection)

The Python `ghidra_bridge` package allows Python to control Ghidra.

**Install or Verify:**
```powershell
pip install ghidra-bridge
```

**Configure Ghidra Server (Complex - Skip if Not Needed):**

If you want bidirectional communication (Ghidra analyzing Python requests), you need to:

1. Install Ghidra
2. Start Ghidra in server mode
3. Connect from Python

For basic use, the module will work with just Capstone fallback.

### Step 3.5: Test Ghidra Installation

Create `test_ghidra.py`:

```python
import shutil
import subprocess
import os

# Test 1: Check if ghidra executable exists
ghidra_paths = [
    r"C:\tools\ghidra\ghidra_11.0.3\bin\ghidraRun.bat",  # Windows
    "/opt/ghidra/ghidra_11.0.3/bin/ghidraRun",           # Linux
    "/usr/bin/ghidra",                                    # If installed via package manager
]

ghidra_found = False
for path in ghidra_paths:
    if os.path.exists(path):
        print(f"✓ Ghidra found at: {path}")
        ghidra_found = True
        break

if not ghidra_found:
    print("✗ Ghidra not found in standard locations")
    print("  You can still use Capstone-based analysis")
else:
    # Test 2: Check JAVA_HOME
    java_home = os.environ.get('JAVA_HOME', '')
    print(f"✓ JAVA_HOME: {java_home if java_home else 'Not set (will use default)'}")
    
    # Test 3: Try importing ghidra_bridge
    try:
        import ghidra_bridge
        print("✓ ghidra_bridge Python package installed")
    except ImportError:
        print("⚠ ghidra_bridge not installed, but Ghidra binary can still be used")

print("\n✓ Ghidra setup ready!")
```

Run test:
```powershell
python test_ghidra.py
```

---

## Part 4: Master Verification Script

This script verifies **everything** is installed and working.

Save as `verify_all.py`:

```python
#!/usr/bin/env python
"""
Master verification script for binary preprocessing module.
Checks all system tools, Python packages, and optional components.
"""

import os
import shutil
import subprocess
import sys
import json
from datetime import datetime

class Verifier:
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "system_tools": {},
            "python_packages": {},
            "optional_components": {},
            "summary": {}
        }
        self.on_windows = sys.platform.startswith('win')
        
    def check_command(self, cmd, args=None, name=None):
        """Check if a command exists and returns version."""
        if args is None:
            args = ['--version']
        if name is None:
            name = cmd
            
        try:
            result = subprocess.run(
                [cmd] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False
            )
            output = result.stdout.decode(errors='ignore').strip()
            if result.returncode == 0 and output:
                return True, output.split('\n')[0][:100]
            return True, "Found (no version output)"
        except FileNotFoundError:
            return False, "Not found in PATH"
        except Exception as e:
            return False, str(e)
        
    def check_python_package(self, package_name, import_name=None):
        """Check if a Python package is installed."""
        if import_name is None:
            import_name = package_name.replace('-', '_')
            
        try:
            __import__(import_name)
            return True, "Installed"
        except ImportError as e:
            return False, f"Not installed: {e}"
        except Exception as e:
            return False, str(e)
    
    def verify_system_tools(self):
        """Verify all system tools."""
        tools = {
            'file': (['file', '--version'], 'libmagic/file utility'),
            'binwalk': (['binwalk', '--version'], 'binwalk binary analysis'),
            'strings': (['strings', '--version'], 'GNU strings utility'),
            'clamscan': (['clamscan', '--version'], 'ClamAV antivirus'),
        }
        
        print("\n[1/3] SYSTEM TOOLS")
        print("=" * 70)
        
        for tool, (cmd, desc) in tools.items():
            found, output = self.check_command(cmd[0], cmd[1:], tool)
            self.results['system_tools'][tool] = {
                'found': found,
                'description': desc,
                'output': output
            }
            
            status = "✓" if found else "✗"
            print(f"{status} {tool:20} {desc:30} {output}")
    
    def verify_python_packages(self):
        """Verify all Python packages."""
        packages = {
            'capstone': 'Disassembly engine',
            'lief': 'Binary parsing (PE/ELF/Mach-O)',
            'pefile': 'PE file parsing',
            'elftools': 'ELF file parsing',
            'networkx': 'Graph/CFG analysis',
        }
        
        print("\n[2/3] PYTHON PACKAGES (Required)")
        print("=" * 70)
        
        for pkg, desc in packages.items():
            found, output = self.check_python_package(pkg)
            self.results['python_packages'][pkg] = {
                'found': found,
                'description': desc,
                'output': output
            }
            
            status = "✓" if found else "✗"
            print(f"{status} {pkg:20} {desc:35} {output}")
    
    def verify_optional_components(self):
        """Verify optional components."""
        print("\n[3/3] OPTIONAL COMPONENTS")
        print("=" * 70)
        
        # Check Ghidra
        ghidra_paths = [
            (r'C:\tools\ghidra', 'Windows'),
            ('/opt/ghidra', 'Linux'),
            (os.path.expanduser('~/ghidra'), 'Home dir'),
        ]
        
        ghidra_found = False
        for path, location in ghidra_paths:
            if os.path.exists(path):
                self.results['optional_components']['ghidra'] = {
                    'found': True,
                    'path': path,
                    'location': location
                }
                print(f"✓ {'Ghidra':20} Advanced disassembler        Found at {path}")
                ghidra_found = True
                break
        
        if not ghidra_found:
            self.results['optional_components']['ghidra'] = {
                'found': False,
                'note': 'Fallback to Capstone will be used'
            }
            print(f"⊘ {'Ghidra':20} Advanced disassembler        Not found (optional)")
        
        # Check Java
        found, output = self.check_command('java', ['-version'], 'java')
        self.results['optional_components']['java'] = {
            'found': found,
            'output': output
        }
        status = "✓" if found else "⊘"
        print(f"{status} {'Java/JDK':20} Required for Ghidra           {output}")
        
        # Check ghidra_bridge Python package
        found, output = self.check_python_package('ghidra-bridge', 'ghidra_bridge')
        self.results['optional_components']['ghidra_bridge'] = {
            'found': found,
            'output': output
        }
        status = "✓" if found else "⊘"
        print(f"{status} {'ghidra_bridge':20} Ghidra-Python bridge         {output}")
    
    def generate_summary(self):
        """Generate a summary and action items."""
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        
        # Count missing items
        missing_tools = [k for k, v in self.results['system_tools'].items() if not v['found']]
        missing_packages = [k for k, v in self.results['python_packages'].items() if not v['found']]
        
        self.results['summary'] = {
            'missing_system_tools': missing_tools,
            'missing_python_packages': missing_packages,
            'status': 'READY' if not (missing_tools or missing_packages) else 'INCOMPLETE'
        }
        
        if missing_tools or missing_packages:
            print("\n⚠ MISSING COMPONENTS:\n")
            if missing_tools:
                print(f"  System Tools: {', '.join(missing_tools)}")
            if missing_packages:
                print(f"  Python Packages: {', '.join(missing_packages)}")
            print("\nRECOMMENDED ACTIONS:")
            if missing_tools:
                if self.on_windows:
                    print("\n  Windows - Install missing tools via Chocolatey:")
                    for tool in missing_tools:
                        print(f"    choco install {tool} -y")
                else:
                    print("\n  Linux - Install missing tools:")
                    for tool in missing_tools:
                        if tool in ['file', 'strings']:
                            print(f"    sudo apt-get install {tool}")
                        else:
                            print(f"    sudo apt-get install {tool}")
            
            if missing_packages:
                print(f"\n  Python - Install missing packages:")
                print(f"    pip install {' '.join(missing_packages)}")
        else:
            print("\n✓ ALL REQUIRED COMPONENTS ARE INSTALLED!")
            print("\nThe binary_preprocessing.py module is ready for full analysis:")
            print("  • File type detection (magic, format, arch)")
            print("  • Binary disassembly (Capstone)")
            print("  • Function recovery")
            print("  • CFG (Control Flow Graph) extraction")
            print("  • Data flow and taint analysis")
            print("  • String extraction")
            print("  • Binwalk embedded content scanning")
            print("  • ClamAV antivirus scanning")
            if self.results['optional_components']['ghidra']['found']:
                print("  • Ghidra-based advanced analysis (AVAILABLE)")
    
    def save_report(self, filename='verification_report.json'):
        """Save detailed report to JSON."""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nDetailed report saved to: {filename}")
    
    def run_all(self):
        """Run all verifications."""
        print("\nBinary Preprocessing Module - Dependency Verification")
        print("=" * 70)
        
        self.verify_system_tools()
        self.verify_python_packages()
        self.verify_optional_components()
        self.generate_summary()
        self.save_report()
        
        return 0 if self.results['summary']['status'] == 'READY' else 1

if __name__ == '__main__':
    verifier = Verifier()
    sys.exit(verifier.run_all())
```

Run the master verification:
```powershell
# Windows
python verify_all.py

# Linux
python3 verify_all.py
```

This will generate `verification_report.json` with all details.

---

## Part 5: Quick Test - Run the Preprocessing Module

Once all installations are complete, test the module:

```python
# test_preprocessing.py
from binary_preprocessing import BinaryPreprocessor
import json

# Test with a system binary
bp = BinaryPreprocessor()
result = bp.analyze('C:\\Windows\\System32\\notepad.exe')  # Windows
# OR
# result = bp.analyze('/bin/bash')  # Linux

print("Analysis Results:")
print(f"  Artifact ID:   {result['artifact_id']}")
print(f"  File Size:     {result['metadata']['file_size']}")
print(f"  SHA256:        {result['metadata']['sha256']}")
print(f"  Format:        {result['metadata']['format']}")
print(f"  Architecture:  {result['metadata']['arch']}")
print(f"  Magic:         {result['metadata']['magic']}")
print(f"\n  Functions Detected:     {len(result['ghidra_analysis']['functions'])}")
print(f"  CFG Nodes:              {len(result['cfg']['nodes'])}")
print(f"  Data Flow Sources:      {len(result['df']['sources'])}")
print(f"  Data Flow Sinks:        {len(result['df']['sinks'])}")
print(f"  Taint Flows Detected:   {result['taint']['flows_detected']}")
print(f"  Binwalk Findings:       {len(result['binwalk']['findings'])}")
print(f"  String Artifacts:       {len(result['strings'])}")
print(f"  ClamAV Installed:       {result['clamav']['installed']}")
print(f"  Warnings:               {len(result['warnings'])}")

if result['warnings']:
    print(f"\n⚠ Warnings:")
    for w in result['warnings']:
        print(f"  - {w}")

# Optionally print full JSON
print("\n\nFull JSON output:")
print(json.dumps(result, indent=2))
```

Run test:
```powershell
python test_preprocessing.py
```

---

## Troubleshooting

### "file" utility not found (Windows)

**Solution:**
```powershell
# Method 1: Using GnuWin32
$url = "https://gnuwin32.sourceforge.net/downlinks/file-bin-zip.php"
# Download and extract to C:\Program Files\GnuWin32\

# Method 2: Add to system PATH
# Manual download: https://gnuwin32.sourceforge.net/packages/file.htm
# Add extracted directory to PATH

# Verify
file --version
```

### "clamscan" returns no results

**Solution:**
```powershell
# Update virus database
freshclam

# May take 5-10 minutes
# Verify database was updated
clamscan --version
```

### ghidra_bridge connection error

**Solution:**
If Ghidra-Bridge fails to connect:
1. It's optional - the module will use Capstone fallback
2. To fix: Ensure JAVA_HOME is set and Ghidra is properly installed
3. You can continue without it - Capstone provides adequate disassembly

### Python package installation fails

**Solution:**
```powershell
# Use a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1  # Windows
source venv/bin/activate      # Linux

# Then install
pip install --upgrade pip
pip install capstone lief pefile pyelftools networkx
```

---

## Summary Checklist

After following this guide, verify:

- [ ] `file --version` works
- [ ] `binwalk --version` works
- [ ] `strings --version` works or fallback works
- [ ] `clamscan --version` works and database is updated
- [ ] `python -c "import capstone"` succeeds
- [ ] `python -c "import lief"` succeeds
- [ ] `python -c "import pefile"` succeeds
- [ ] `python -c "import elftools"` succeeds
- [ ] `python -c "import networkx"` succeeds
- [ ] `python verify_all.py` shows no ✗ marks for required items
- [ ] `python test_preprocessing.py` runs without errors
- [ ] `result['metadata']['format']` is not null
- [ ] `result['cfg']['nodes']` is not empty
- [ ] `result['clamav']['installed']` is True

---

## Next Steps

1. **Run the verification script** to identify what's missing
2. **Follow the installation steps** for your OS (Windows or Linux)
3. **Verify each component** using the provided test scripts
4. **Test the preprocessing module** with a sample binary
5. **Integrate into your security pipeline** with confidence

Good luck with your binary analysis setup!
