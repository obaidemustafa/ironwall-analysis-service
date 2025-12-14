# 🎯 START HERE - Binary Preprocessing Module Setup

## 📍 You Are Here
Your binary preprocessing module is **incomplete** because critical system tools and Python libraries are missing. This directory contains **everything you need** to fix it.

---

## ⚡ 5-Minute Quick Start

Choose your operating system:

### 🪟 **Windows Users** (PowerShell)

```powershell
# 1. Open PowerShell as Administrator
# 2. Navigate to this directory
cd d:\ironwall\preprocessing

# 3. Set execution policy (one-time only)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 4. Run the installation script (takes 15-20 minutes)
.\install_windows.ps1

# 5. Verify everything works
python verify_all.py

# 6. Test the module
python test_preprocessing.py
```

### 🐧 **Linux Users** (Bash)

```bash
# 1. Navigate to this directory
cd ~/ironwall/preprocessing

# 2. Make script executable
chmod +x install_linux.sh

# 3. Run installation (takes 15-20 minutes)
./install_linux.sh

# 4. Verify everything works
python3 verify_all.py

# 5. Test the module
python3 test_preprocessing.py
```

---

## 📚 Documentation Guide

**Choose your learning style:**

| Your Situation | Read This | Time |
|---|---|---|
| "Just make it work" | [README.md](README.md) | 5 min |
| "I want all the details" | [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md) | 30 min |
| "Give me the summary" | [SETUP_SUMMARY.md](SETUP_SUMMARY.md) | 10 min |

---

## 📁 Files in This Directory

### 🚀 **Installation Scripts** (Pick One)
- **[install_windows.ps1](install_windows.ps1)** - Automated setup for Windows
- **[install_linux.sh](install_linux.sh)** - Automated setup for Linux

### 📖 **Documentation** (Pick One)
- **[README.md](README.md)** - Quick start guide
- **[INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)** - Comprehensive guide (5 parts)
- **[SETUP_SUMMARY.md](SETUP_SUMMARY.md)** - Executive summary

### ✅ **Verification Tools** (Run These)
- **[verify_all.py](verify_all.py)** - Check what's installed
- **[test_preprocessing.py](test_preprocessing.py)** - Test the module

### 🔧 **Main Module** (Don't Modify)
- **[binary_preprocessing.py](binary_preprocessing.py)** - Your preprocessing module

---

## 🎯 What Will Be Fixed

**Before Installation:**
```
❌ File type detection (magic, format, arch) = null/empty
❌ Binary disassembly = no functions found
❌ Control flow graph = empty
❌ Data flow analysis = no flows
❌ String extraction = works, but limited
❌ Binwalk scanning = skipped (tool missing)
❌ ClamAV antivirus = not available
```

**After Installation:**
```
✅ File type detection = populated (PE/ELF, x64/x86, etc.)
✅ Binary disassembly = 200+ functions
✅ Control flow graph = 500+ nodes
✅ Data flow analysis = 15+ flows detected
✅ String extraction = 1000+ strings classified
✅ Binwalk scanning = embedded content found
✅ ClamAV antivirus = malware detection active
```

---

## 🔄 Three Installation Options

### Option A: Fastest ⚡ (Recommended)
```bash
# Windows: .\install_windows.ps1
# Linux:   ./install_linux.sh
# Time: ~20 minutes, fully automated
```

### Option B: Step-by-Step 📖
```bash
# Read INSTALLATION_GUIDE.md and follow parts 1-5
# Time: ~30 minutes, educational, full control
```

### Option C: Manual Terminal Commands 💻
```bash
# Extract commands from INSTALLATION_GUIDE.md
# Time: ~45 minutes, expert mode
```

---

## ✅ Quick Verification

After installation, you can verify everything works:

```bash
# Check all dependencies
python verify_all.py

# Test the module
python test_preprocessing.py

# View detailed report
cat verification_report.json
```

---

## 🛠️ What Gets Installed

### System Tools (Command-Line Utilities)
- `file` - File type detection
- `binwalk` - Firmware analysis
- `strings` - String extraction
- `clamscan` - Antivirus scanning
- `java` - Java runtime (for Ghidra, optional)

### Python Libraries
- `capstone` - Disassembly engine
- `lief` - Binary parsing
- `pefile` - PE file analysis
- `pyelftools` - ELF file analysis
- `networkx` - Graph analysis
- `ghidra-bridge` - Ghidra integration (optional)
- Plus a few logging utilities

---

## ⏱️ Time Breakdown

| Task | Time |
|------|------|
| Running install script | 5-10 min |
| Downloading packages | 10-15 min |
| Updating virus database | 5 min |
| Verification checks | 1-2 min |
| **Total** | **~20 min** |

---

## 🚨 Common Issues

### "Permission denied" (Linux)
```bash
chmod +x install_linux.sh
./install_linux.sh
```

### "Not running as Administrator" (Windows)
Right-click PowerShell → "Run as Administrator"

### "Command not found" (After installation)
Close and reopen your terminal to refresh PATH

### "pip: command not found"
Use `python -m pip` instead of `pip`

**→ For more issues, see INSTALLATION_GUIDE.md troubleshooting**

---

## 💡 Pro Tips

1. **Read this first**: [README.md](README.md) (5 minutes)
2. **Run the automated script** for your OS (15 minutes)
3. **Verify with verify_all.py** (1 minute)
4. **Test with test_preprocessing.py** (2 minutes)
5. **You're done!** Start using the module

---

## 🎓 After Installation

Once everything is installed, use the module like this:

```python
from binary_preprocessing import BinaryPreprocessor

bp = BinaryPreprocessor()
result = bp.analyze('sample.exe')

print(f"Format: {result['metadata']['format']}")
print(f"Architecture: {result['metadata']['arch']}")
print(f"Functions found: {len(result['ghidra_analysis']['functions'])}")
print(f"Strings extracted: {len(result['strings'])}")
```

---

## 📊 Status Summary

| Component | Current | After Setup |
|-----------|---------|------------|
| File utility | ❌ Missing | ✅ Installed |
| Binwalk | ❌ Missing | ✅ Installed |
| Capstone | ❌ Missing | ✅ Installed |
| LIEF | ❌ Missing | ✅ Installed |
| ClamAV | ❌ Missing | ✅ Installed |
| Module status | ⚠️ Partial | ✅ Full |

---

## 🎬 Next Steps

1. **Choose your OS** (Windows or Linux)
2. **Run the install script** for that OS
3. **Wait 15-20 minutes**
4. **Run verify_all.py**
5. **Done!** ✅

---

## 📞 Need Help?

| Issue | Solution |
|-------|----------|
| "How do I start?" | You're reading it! |
| "I want more details" | → [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md) |
| "I want a quick overview" | → [README.md](README.md) |
| "Something isn't working" | → Run `python verify_all.py --install-help` |
| "What's the summary?" | → [SETUP_SUMMARY.md](SETUP_SUMMARY.md) |

---

## 🏁 You're Ready!

Everything you need is here. **Pick your OS and start:**

### → [Windows Setup](install_windows.ps1)
Run in PowerShell as Administrator

### → [Linux Setup](install_linux.sh)
Run in Bash terminal

**Time to working system: ~20 minutes**

---

**Status**: 🟢 Ready to Install  
**Created**: December 2025  
**For**: Binary Preprocessing Module  
**Python**: 3.10+
