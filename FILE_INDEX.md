# 📑 Complete File Index & Quick Reference

**Last Updated**: December 2025  
**Status**: ✅ Complete Setup Package Ready

---

## 📁 Directory Structure

```
preprocessing/
│
├── 🎯 START HERE
│   ├── START_HERE.md                    [5 min read] Where to begin
│   ├── README.md                        [10 min read] Quick overview
│   └── checklist.py                     Quick dependency checker
│
├── 📖 DETAILED DOCUMENTATION
│   ├── INSTALLATION_GUIDE.md            [30 min read] Complete 5-part guide
│   └── SETUP_SUMMARY.md                 [15 min read] Executive summary
│
├── 🚀 INSTALLATION SCRIPTS
│   ├── install_windows.ps1              Automated Windows setup
│   └── install_linux.sh                 Automated Linux setup
│
├── ✅ VERIFICATION & TESTING
│   ├── verify_all.py                    Master verification tool
│   ├── test_preprocessing.py            Module testing tool
│   └── checklist.py                     Dependency checker
│
├── 🔧 MAIN MODULE
│   ├── binary_preprocessing.py          Main analysis module
│   └── preprocessing.py                 Related module
│
└── 📊 GENERATED OUTPUTS (After Running)
    ├── verification_report.json         Status report
    └── dependency_checklist.json        Dependency status
```

---

## 🎯 Which File to Read First?

### I have 5 minutes
👉 **Read**: [START_HERE.md](START_HERE.md)  
Contents: Quick overview, decide Windows or Linux, run one script

### I have 10 minutes  
👉 **Read**: [README.md](README.md)  
Contents: Overview, features, quick commands, usage examples

### I have 15 minutes
👉 **Read**: [SETUP_SUMMARY.md](SETUP_SUMMARY.md)  
Contents: Full summary with before/after comparison, all tools listed

### I have 30+ minutes
👉 **Read**: [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)  
Contents: Everything - 5 detailed parts with explanations

---

## 🚀 Which Script to Run?

### I'm on Windows
```powershell
.\install_windows.ps1
```
**Contains**: Chocolatey setup, all system tools, Python packages, Java, ClamAV config

### I'm on Linux  
```bash
./install_linux.sh
```
**Contains**: Package manager updates, all system tools, Python packages, Java, ClamAV config

### I just want to check what's missing
```bash
python checklist.py
# OR
python verify_all.py
```
**Shows**: What's installed, what's missing, installation help

---

## 🔍 File-by-File Guide

### Entry Points (Read First)

**[START_HERE.md](START_HERE.md)** (5 min)
- Purpose: Where to begin
- Contains: Quick start for Windows/Linux, time estimates
- Decision point: Tells you what to read/run next
- Run after: Never, just read

**[README.md](README.md)** (10 min)
- Purpose: Feature overview and quick start
- Contains: What gets installed, how to use module, troubleshooting
- Decision point: Covers both automated and manual setup
- Run after: Reading this file, before installation

### Comprehensive Guides (Read Second)

**[SETUP_SUMMARY.md](SETUP_SUMMARY.md)** (15 min)
- Purpose: Complete executive summary
- Contains: Before/after comparison, all tools listed, architecture diagram
- Details: Installation flow, verification checklist, next steps
- Read when: Want full picture without minute-by-minute details

**[INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)** (30 min)
- Purpose: Exhaustive step-by-step guide
- Contains: 5 parts: System tools, Python libs, Ghidra, verification, troubleshooting
- Details: Every command explained, every tool documented
- Read when: Want to understand every step in detail

### Automated Installation Scripts (Run These)

**[install_windows.ps1](install_windows.ps1)** (~20 min)
- Purpose: Automated Windows setup
- Platform: Windows (PowerShell as Administrator)
- Does: Installs Chocolatey, all tools, all packages, Java, configures everything
- Run: After reading START_HERE.md or README.md
- Next: Run verify_all.py

**[install_linux.sh](install_linux.sh)** (~20 min)
- Purpose: Automated Linux setup
- Platform: Linux (Bash)
- Does: Detects distro, installs all tools, all packages, Java, updates ClamAV
- Run: After reading START_HERE.md or README.md
- Next: Run python3 verify_all.py

### Verification Tools (Run After Installation)

**[verify_all.py](verify_all.py)** (1-2 min)
- Purpose: Comprehensive dependency verification
- Usage: `python verify_all.py`
- Options: 
  - `--json` for JSON output
  - `--install-help` for installation commands
- Output: verification_report.json
- Check: Everything is installed correctly
- Run: After running install script

**[checklist.py](checklist.py)** (30 sec)
- Purpose: Quick interactive dependency checklist
- Usage: `python checklist.py`
- Options:
  - `--auto` for automated output
  - `--save` to save JSON
- Output: dependency_checklist.json
- Check: What's installed vs what's missing
- Run: Before OR after installation

**[test_preprocessing.py](test_preprocessing.py)** (2-5 min)
- Purpose: Test the module on system binaries
- Usage: `python test_preprocessing.py`
- Options:
  - `--list` to see available test binaries
  - `--json` for JSON output
  - `<path>` to test specific binary
- Check: Module works correctly with all components
- Run: After verify_all.py succeeds

### Main Module (Don't Edit)

**[binary_preprocessing.py](binary_preprocessing.py)** (Your module)
- Purpose: Main preprocessing module
- Contains: All analysis code (metadata, disassembly, CFG, strings, etc.)
- Usage: `from binary_preprocessing import BinaryPreprocessor`
- Status: Ready to use after dependencies installed
- Modify: Only if adding features

---

## 📊 Quick Decision Tree

```
START
  │
  ├─→ "Give me 5 minutes" → READ START_HERE.md
  │                        ↓
  │                  Pick Windows/Linux
  │                        ↓
  │                  Run install script
  │
  ├─→ "Give me 10 minutes" → READ README.md
  │                         ↓
  │                    Pick Windows/Linux
  │                         ↓
  │                    Run install script
  │
  ├─→ "Give me details" → READ INSTALLATION_GUIDE.md
  │                      ↓
  │                 Follow all 5 parts
  │
  └─→ "Just check status" → RUN checklist.py
                            ↓
                      See what's missing
                            ↓
                      Run install script
```

---

## ⏱️ Time Guide by Activity

| Activity | Time | Files |
|----------|------|-------|
| Understand what's happening | 5 min | START_HERE.md |
| Learn overview | 10 min | README.md |
| Get full summary | 15 min | SETUP_SUMMARY.md |
| Read all details | 30 min | INSTALLATION_GUIDE.md |
| Check dependencies (before) | 1 min | checklist.py |
| Run installation | 20 min | install_windows.ps1 or install_linux.sh |
| Verify installation | 2 min | verify_all.py |
| Test module | 3 min | test_preprocessing.py |
| **Total (fastest path)** | **~40 min** | START_HERE.md + install script + verify |
| **Total (detailed path)** | **~70 min** | All docs + manual setup |

---

## 🔄 Recommended Workflow

### First Time (Complete Setup)
```
1. Read START_HERE.md (5 min)
   ↓
2. Run checklist.py (1 min) - See what's missing
   ↓
3. Run install script (20 min)
   ├─ install_windows.ps1 (Windows)
   └─ install_linux.sh (Linux)
   ↓
4. Run verify_all.py (2 min) - Confirm success
   ↓
5. Run test_preprocessing.py (3 min) - Test module
   ↓
6. ✅ READY!
```

### Detailed/Learning (Educational Setup)
```
1. Read START_HERE.md (5 min)
   ↓
2. Read README.md (10 min)
   ↓
3. Read INSTALLATION_GUIDE.md (30 min)
   ↓
4. Decide: Automated or Manual
   ├─ Automated: Run install script (20 min)
   └─ Manual: Follow guide commands (45 min)
   ↓
5. Run verify_all.py (2 min)
   ↓
6. Read SETUP_SUMMARY.md (15 min) - Review architecture
   ↓
7. Run test_preprocessing.py (3 min)
   ↓
8. ✅ READY! + Fully understood
```

### Troubleshooting (Something Wrong)
```
1. Run checklist.py (1 min) - What's missing?
   ↓
2. Run verify_all.py --install-help - See commands
   ↓
3. Check INSTALLATION_GUIDE.md Troubleshooting
   ↓
4. Install missing component
   ├─ Windows: choco install <tool>
   └─ Linux: apt-get install <tool>
   ↓
5. Run verify_all.py again
   ↓
6. ✅ FIXED!
```

---

## 🎯 Success Indicators

You'll know you're on the right track when:

- [ ] You've read START_HERE.md
- [ ] You ran checklist.py and saw what's missing
- [ ] You ran the install script for your OS
- [ ] verify_all.py shows ✓ for all required items
- [ ] test_preprocessing.py completes successfully
- [ ] verification_report.json shows "status": "READY"

---

## 📞 Help Resources by Topic

| Topic | File | Section |
|-------|------|---------|
| How do I start? | START_HERE.md | All of it |
| What gets installed? | README.md | 🔧 What Gets Installed |
| Windows setup | install_windows.ps1 | All (run it) |
| Linux setup | install_linux.sh | All (run it) |
| Detailed steps | INSTALLATION_GUIDE.md | Part 1-5 |
| File utilities | INSTALLATION_GUIDE.md | Part 1: System Tools |
| Python libraries | INSTALLATION_GUIDE.md | Part 2: Python |
| Java/Ghidra | INSTALLATION_GUIDE.md | Part 3: Ghidra |
| Verification | INSTALLATION_GUIDE.md | Part 4 |
| Troubleshooting | INSTALLATION_GUIDE.md | Part 5 |
| Check status | checklist.py | Run it |
| Test module | test_preprocessing.py | Run it |
| Common issues | README.md | 🛠️ Troubleshooting |
| Summary | SETUP_SUMMARY.md | All |

---

## 🚀 Fastest Path to Working System

**Total Time: ~40 minutes**

```bash
# 1. Read this (5 min)
START_HERE.md

# 2. Run this (20 min)
# Windows:
.\install_windows.ps1

# Linux:
./install_linux.sh

# 3. Verify this (2 min)
python verify_all.py

# 4. Test this (3 min)
python test_preprocessing.py

# 5. You're done! ✅
```

---

## 📋 File Manifest

**Total files created/modified**: 7  
**Documentation files**: 4 (START_HERE.md, README.md, SETUP_SUMMARY.md, INSTALLATION_GUIDE.md)  
**Automation files**: 2 (install_windows.ps1, install_linux.sh)  
**Utility files**: 3 (verify_all.py, test_preprocessing.py, checklist.py)  
**Original module**: 1 (binary_preprocessing.py - no changes needed)

---

## ✅ File Checklist

After installation, you should have:

- [ ] START_HERE.md - Quick start guide
- [ ] README.md - Feature overview
- [ ] INSTALLATION_GUIDE.md - Comprehensive guide
- [ ] SETUP_SUMMARY.md - Executive summary
- [ ] install_windows.ps1 - Windows automation
- [ ] install_linux.sh - Linux automation
- [ ] verify_all.py - Verification tool
- [ ] test_preprocessing.py - Testing tool
- [ ] checklist.py - Dependency checker
- [ ] binary_preprocessing.py - Main module
- [ ] verification_report.json - Generated after verification
- [ ] dependency_checklist.json - Generated after checklist

---

## 🎓 Learning Path

### Beginner
```
START_HERE.md → Run install script → verify_all.py → DONE
```

### Intermediate
```
README.md → Run install script → verify_all.py → test_preprocessing.py → DONE
```

### Advanced
```
INSTALLATION_GUIDE.md → Manual setup → checklist.py → verify_all.py → test_preprocessing.py → DONE
```

---

**🎯 You're ready! Choose your path and get started.**

**→ [START_HERE.md](START_HERE.md)** for quick start  
**→ [README.md](README.md)** for overview  
**→ [INSTALLATION_GUIDE.md](INSTALLATION_GUIDE.md)** for details
