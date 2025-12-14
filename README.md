# Binary Preprocessing Module - Quick Start Guide

## 📋 Overview

This directory contains a complete binary analysis preprocessing module that extracts:
- ✓ File metadata and type detection
- ✓ Binary architecture and format
- ✓ Functions and basic blocks (disassembly)
- ✓ Control Flow Graphs (CFG)
- ✓ Data flow and taint analysis
- ✓ String extraction and classification
- ✓ Embedded content detection (Binwalk)
- ✓ Antivirus scanning (ClamAV)

## 🚀 Quick Start (5 minutes)

### Step 1: Run Automatic Installation

**Windows (PowerShell as Administrator):**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\install_windows.ps1
```

**Linux (Bash):**
```bash
chmod +x install_linux.sh
./install_linux.sh
```

### Step 2: Verify Installation

```bash
# Check all dependencies
python verify_all.py
```

Expected output: ✓ All required components installed

### Step 3: Test the Module

```bash
# Test with a system binary
python test_preprocessing.py

# Or test a specific binary
python test_preprocessing.py /path/to/binary

# Get JSON output
python test_preprocessing.py --json
```

---

## 📚 Documentation

| File | Purpose |
|------|---------|
| [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md) | **Comprehensive setup guide** with detailed explanations |
| [install_windows.ps1](install_windows.ps1) | Automated Windows installation script |
| [install_linux.sh](install_linux.sh) | Automated Linux installation script |
| [verify_all.py](verify_all.py) | Dependency verification tool |
| [test_preprocessing.py](test_preprocessing.py) | Module testing and validation |
| [binary_preprocessing.py](binary_preprocessing.py) | Main preprocessing module |

---

## 🔧 What Gets Installed

### System Tools
- `file` - File type detection (libmagic)
- `binwalk` - Firmware/binary analysis
- `strings` - String extraction (binutils)
- `clamscan` - Antivirus scanning
- `java` - Required for Ghidra (optional)

### Python Libraries
- `capstone` - Disassembly engine
- `lief` - Binary parsing (PE/ELF/Mach-O)
- `pefile` - PE file analysis
- `pyelftools` - ELF file analysis
- `networkx` - Graph analysis for CFG
- `ghidra-bridge` - Ghidra integration (optional)
- `rich` & `loguru` - Logging utilities

---

## 📊 Module Usage

### Basic Usage

```python
from binary_preprocessing import BinaryPreprocessor

bp = BinaryPreprocessor()
result = bp.analyze('sample.exe')

# Access components
print(result['metadata'])        # File info
print(result['ghidra_analysis'])  # Functions
print(result['cfg'])            # Control flow
print(result['strings'])        # Extracted strings
print(result['binwalk'])        # Embedded content
print(result['clamav'])         # Antivirus results
```

### Command Line

```bash
python binary_preprocessing.py sample.exe
python binary_preprocessing.py sample.exe --json
```

---

## 🔍 Troubleshooting

### "Command not found" errors

**Windows:**
```powershell
choco install gnuwin32-file binwalk -y
refreshenv  # Refresh PATH
```

**Linux:**
```bash
sudo apt-get install file binutils binwalk clamav
```

### Python package import errors

```bash
# Upgrade pip first
pip install --upgrade pip

# Install missing packages
pip install capstone lief pefile pyelftools networkx
```

### ClamAV not finding signatures

```bash
# Update virus database
freshclam  # Windows
sudo freshclam  # Linux
```

### Ghidra not found (optional)

This is optional. The module will use Capstone disassembly as fallback.

To install Ghidra:
1. Download from: https://ghidra-sre.org/
2. Extract to: `C:\tools\ghidra\` (Windows) or `/opt/ghidra` (Linux)
3. Ensure Java 11+ is installed

---

## ✅ Verification Checklist

After installation, verify everything works:

- [ ] `python verify_all.py` shows all green checkmarks
- [ ] `python test_preprocessing.py` completes without errors
- [ ] `file` utility works: `file --version`
- [ ] `binwalk` works: `binwalk --version`
- [ ] `clamscan` works: `clamscan --version`
- [ ] Python imports work: `python -c "import capstone"`

---

## 📈 Output Structure

The analysis returns a comprehensive JSON structure:

```json
{
  "artifact_id": "uuid-here",
  "metadata": {
    "file_size": 1000000,
    "sha256": "...",
    "magic": "PE32 executable",
    "format": "PE",
    "arch": "x64",
    "imports": ["kernel32.dll", ...]
  },
  "ghidra_analysis": {
    "functions": [...],
    "num_basic_blocks": 150,
    "suspicious_functions": [...],
    "xrefs": {...}
  },
  "cfg": {
    "nodes": [...],
    "edges": [...],
    "basic_blocks": [...]
  },
  "df": {
    "sources": [...],
    "sinks": [...],
    "flows": [...],
    "taint_summary": {...}
  },
  "taint": {
    "sources": [...],
    "flows_detected": 5,
    "details": [...]
  },
  "binwalk": {
    "findings": [...]
  },
  "strings": [
    {"string": "example.com", "kind": "url"},
    ...
  ],
  "clamav": {
    "installed": true,
    "infected": false,
    "raw": "..."
  },
  "warnings": [],
  "errors": []
}
```

---

## 🎯 Next Steps

1. **Install dependencies** → Run the installation script
2. **Verify installation** → Run `verify_all.py`
3. **Test the module** → Run `test_preprocessing.py`
4. **Integrate** → Use in your security pipeline
5. **Read full guide** → See [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)

---

## 📖 Full Documentation

For detailed information about each component, installation options, and troubleshooting:

👉 **Read [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)**

---

## ⚠️ Important Notes

- **Windows**: Run PowerShell as Administrator for installation
- **Linux**: Some tools require `sudo` for system-wide installation
- **Java/Ghidra**: Optional but recommended for advanced analysis
- **ClamAV**: Requires database update (`freshclam`) before first use
- **First Run**: May take 1-2 minutes for virus database download

---

## 🆘 Getting Help

If you encounter issues:

1. Run `python verify_all.py --install-help` to see installation commands
2. Check [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md) for detailed steps
3. Review the Troubleshooting section above
4. Check `verification_report.json` for detailed diagnostics

---

## 📝 Module API

```python
from binary_preprocessing import BinaryPreprocessor

bp = BinaryPreprocessor(top_n_strings=200)  # Limit extracted strings
result = bp.analyze('/path/to/binary')

# All fields
artifact_id, metadata, ghidra_analysis, cfg, df, taint
binwalk, strings, clamav, warnings, errors
```

---

**Last Updated:** December 2025  
**Status:** Production Ready
