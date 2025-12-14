#!/usr/bin/env python
"""
Interactive dependency checklist for binary preprocessing module setup.

Run this BEFORE installation to see what's missing.
Run this AFTER installation to verify everything is complete.

Usage:
    python checklist.py              # Interactive checklist
    python checklist.py --auto       # Auto-check and report
    python checklist.py --save       # Save checklist to file
"""

import os
import sys
import json
import shutil
import subprocess
from datetime import datetime

class DependencyChecklist:
    def __init__(self):
        self.items = {
            "System Tools": {
                "file": {"cmd": "file", "args": ["--version"], "critical": True, "reason": "File type detection (libmagic)"},
                "binwalk": {"cmd": "binwalk", "args": ["--version"], "critical": True, "reason": "Firmware/binary analysis"},
                "strings": {"cmd": "strings", "args": ["--version"], "critical": True, "reason": "String extraction"},
                "clamscan": {"cmd": "clamscan", "args": ["--version"], "critical": True, "reason": "Antivirus scanning"},
                "java": {"cmd": "java", "args": ["-version"], "critical": False, "reason": "Ghidra support (optional)"},
            },
            "Python Packages": {
                "capstone": {"import": "capstone", "critical": True, "reason": "Disassembly engine"},
                "lief": {"import": "lief", "critical": True, "reason": "Binary parsing (PE/ELF/Mach-O)"},
                "pefile": {"import": "pefile", "critical": True, "reason": "PE file parsing"},
                "elftools": {"import": "elftools", "critical": True, "reason": "ELF file parsing"},
                "networkx": {"import": "networkx", "critical": True, "reason": "CFG/graph analysis"},
                "ghidra_bridge": {"import": "ghidra_bridge", "critical": False, "reason": "Ghidra integration (optional)"},
                "rich": {"import": "rich", "critical": False, "reason": "Output formatting (optional)"},
                "loguru": {"import": "loguru", "critical": False, "reason": "Logging (optional)"},
            }
        }
        self.results = {}
        self.on_windows = sys.platform.startswith('win')
    
    def check_command(self, cmd, args):
        """Check if a command exists and is runnable."""
        try:
            result = subprocess.run(
                [cmd] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False
            )
            return True, "Found"
        except FileNotFoundError:
            return False, "Not in PATH"
        except Exception as e:
            return False, str(e)
    
    def check_python_package(self, package):
        """Check if a Python package is importable."""
        try:
            __import__(package)
            return True, "Installed"
        except ImportError:
            return False, "Not installed"
        except Exception as e:
            return False, str(e)
    
    def run_checks(self):
        """Run all dependency checks."""
        # Check system tools
        for tool, info in self.items["System Tools"].items():
            found, msg = self.check_command(info["cmd"], info["args"])
            self.results[tool] = {
                "category": "System Tools",
                "found": found,
                "message": msg,
                "critical": info["critical"],
                "reason": info["reason"]
            }
        
        # Check Python packages
        for pkg, info in self.items["Python Packages"].items():
            found, msg = self.check_python_package(info["import"])
            self.results[pkg] = {
                "category": "Python Packages",
                "found": found,
                "message": msg,
                "critical": info["critical"],
                "reason": info["reason"]
            }
    
    def print_checklist(self):
        """Print interactive checklist."""
        print("\n" + "=" * 80)
        print("BINARY PREPROCESSING MODULE - DEPENDENCY CHECKLIST")
        print("=" * 80)
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Platform:  {'Windows' if self.on_windows else 'Linux/Unix'}")
        print("=" * 80 + "\n")
        
        # Group by category
        current_category = None
        
        for name, result in sorted(self.results.items()):
            if result["category"] != current_category:
                current_category = result["category"]
                print(f"\n{current_category}")
                print("-" * 80)
            
            status = "✓" if result["found"] else "✗"
            critical = "REQUIRED" if result["critical"] else "optional"
            
            print(f"{status} [{critical:8}] {name:20} {result['message']:25} {result['reason']}")
        
        # Summary
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        
        missing_critical = [
            name for name, result in self.results.items()
            if not result["found"] and result["critical"]
        ]
        missing_optional = [
            name for name, result in self.results.items()
            if not result["found"] and not result["critical"]
        ]
        
        if not missing_critical:
            print("✅ ALL REQUIRED COMPONENTS INSTALLED!")
            if missing_optional:
                print(f"\n⚠ {len(missing_optional)} optional components missing:")
                for item in missing_optional:
                    print(f"  • {item}")
                print("\n→ Module will still work, but with reduced functionality")
        else:
            print(f"❌ {len(missing_critical)} REQUIRED components missing:")
            for item in missing_critical:
                result = self.results[item]
                print(f"  • {item}")
            
            print(f"\n→ Install these before using the preprocessing module")
            
            if self.on_windows:
                print("\nWindows installation:")
                print("  1. Run PowerShell as Administrator")
                print("  2. cd d:\\ironwall\\preprocessing")
                print("  3. .\\install_windows.ps1")
            else:
                print("\nLinux installation:")
                print("  1. cd ~/ironwall/preprocessing")
                print("  2. chmod +x install_linux.sh")
                print("  3. ./install_linux.sh")
        
        print("\n" + "=" * 80 + "\n")
        
        return len(missing_critical) == 0
    
    def save_checklist(self, filename="dependency_checklist.json"):
        """Save checklist results to JSON."""
        output = {
            "timestamp": datetime.now().isoformat(),
            "platform": "Windows" if self.on_windows else "Linux",
            "results": self.results,
            "summary": {
                "total": len(self.results),
                "installed": sum(1 for r in self.results.values() if r["found"]),
                "missing": sum(1 for r in self.results.values() if not r["found"]),
                "missing_critical": sum(1 for r in self.results.values() if not r["found"] and r["critical"]),
                "ready": all(r["found"] for r in self.results.values() if r["critical"])
            }
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"Checklist saved to: {filename}")
        return output

def print_usage():
    """Print usage instructions."""
    print("""
DEPENDENCY CHECKLIST FOR BINARY PREPROCESSING MODULE

Usage:
    python checklist.py              # Interactive checklist
    python checklist.py --auto       # Auto-check and report
    python checklist.py --save       # Save results to JSON
    python checklist.py --help       # Show this help

Examples:
    python checklist.py              # Check all dependencies, show results
    python checklist.py --save       # Same, but also save to JSON file
""")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Dependency checklist for binary preprocessing module')
    parser.add_argument('--auto', action='store_true', help='Auto-run and exit')
    parser.add_argument('--save', action='store_true', help='Save results to JSON')
    parser.add_argument('--json-only', action='store_true', help='Output JSON only')
    
    args = parser.parse_args()
    
    checklist = DependencyChecklist()
    checklist.run_checks()
    
    if args.json_only:
        print(json.dumps(checklist.results, indent=2))
    else:
        success = checklist.print_checklist()
    
    if args.save:
        checklist.save_checklist()
    
    sys.exit(0 if success else 1)
