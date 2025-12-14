#!/usr/bin/env python
"""
Master verification script for binary preprocessing module.
Checks all system tools, Python packages, and optional components.

Usage:
    python verify_all.py
    python verify_all.py --json          # Output as JSON only
    python verify_all.py --install-help  # Show installation commands
"""

import os
import shutil
import subprocess
import sys
import json
from datetime import datetime

class Verifier:
    def __init__(self, verbose=True, json_output=False, install_help=False):
        self.verbose = verbose
        self.json_output = json_output
        self.install_help = install_help
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "system_tools": {},
            "python_packages": {},
            "optional_components": {},
            "summary": {}
        }
        self.on_windows = sys.platform.startswith('win')
        
    def print_if_verbose(self, msg):
        """Print only in verbose mode."""
        if self.verbose and not self.json_output:
            print(msg)
    
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
            return False, f"Not installed"
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
        
        self.print_if_verbose("\n[1/3] SYSTEM TOOLS")
        self.print_if_verbose("=" * 70)
        
        for tool, (cmd, desc) in tools.items():
            found, output = self.check_command(cmd[0], cmd[1:], tool)
            self.results['system_tools'][tool] = {
                'found': found,
                'description': desc,
                'output': output
            }
            
            status = "✓" if found else "✗"
            self.print_if_verbose(f"{status} {tool:20} {desc:30} {output}")
    
    def verify_python_packages(self):
        """Verify all Python packages."""
        packages = {
            'capstone': 'Disassembly engine',
            'lief': 'Binary parsing (PE/ELF/Mach-O)',
            'pefile': 'PE file parsing',
            'elftools': 'ELF file parsing',
            'networkx': 'Graph/CFG analysis',
        }
        
        self.print_if_verbose("\n[2/3] PYTHON PACKAGES (Required)")
        self.print_if_verbose("=" * 70)
        
        for pkg, desc in packages.items():
            found, output = self.check_python_package(pkg)
            self.results['python_packages'][pkg] = {
                'found': found,
                'description': desc,
                'output': output
            }
            
            status = "✓" if found else "✗"
            self.print_if_verbose(f"{status} {pkg:20} {desc:35} {output}")
    
    def verify_optional_components(self):
        """Verify optional components."""
        self.print_if_verbose("\n[3/3] OPTIONAL COMPONENTS")
        self.print_if_verbose("=" * 70)
        
        # Check Ghidra
        ghidra_paths = [
            (r'C:\tools\ghidra', 'Windows'),
            ('/opt/ghidra', 'Linux /opt'),
            (os.path.expanduser('~/ghidra'), 'Home directory'),
            (os.path.expanduser('~/tools/ghidra'), 'Home/tools'),
        ]
        
        ghidra_found = False
        ghidra_path = None
        for path, location in ghidra_paths:
            if os.path.exists(path):
                self.results['optional_components']['ghidra'] = {
                    'found': True,
                    'path': path,
                    'location': location
                }
                ghidra_path = path
                self.print_if_verbose(f"✓ {'Ghidra':20} Advanced disassembler        Found at {path}")
                ghidra_found = True
                break
        
        if not ghidra_found:
            self.results['optional_components']['ghidra'] = {
                'found': False,
                'note': 'Fallback to Capstone will be used'
            }
            self.print_if_verbose(f"⊘ {'Ghidra':20} Advanced disassembler        Not found (optional)")
        
        # Check Java
        found, output = self.check_command('java', ['-version'], 'java')
        self.results['optional_components']['java'] = {
            'found': found,
            'output': output
        }
        status = "✓" if found else "⊘"
        self.print_if_verbose(f"{status} {'Java/JDK':20} Required for Ghidra           {output}")
        
        # Check ghidra_bridge Python package
        found, output = self.check_python_package('ghidra-bridge', 'ghidra_bridge')
        self.results['optional_components']['ghidra_bridge'] = {
            'found': found,
            'output': output
        }
        status = "✓" if found else "⊘"
        self.print_if_verbose(f"{status} {'ghidra_bridge':20} Ghidra-Python bridge         {output}")
    
    def generate_summary(self):
        """Generate a summary and action items."""
        self.print_if_verbose("\n" + "=" * 70)
        self.print_if_verbose("SUMMARY")
        self.print_if_verbose("=" * 70)
        
        # Count missing items
        missing_tools = [k for k, v in self.results['system_tools'].items() if not v['found']]
        missing_packages = [k for k, v in self.results['python_packages'].items() if not v['found']]
        
        self.results['summary'] = {
            'missing_system_tools': missing_tools,
            'missing_python_packages': missing_packages,
            'status': 'READY' if not (missing_tools or missing_packages) else 'INCOMPLETE',
            'on_windows': self.on_windows
        }
        
        if missing_tools or missing_packages:
            self.print_if_verbose("\n⚠ MISSING COMPONENTS:\n")
            if missing_tools:
                self.print_if_verbose(f"  System Tools: {', '.join(missing_tools)}")
            if missing_packages:
                self.print_if_verbose(f"  Python Packages: {', '.join(missing_packages)}")
            
            if self.install_help:
                self.print_if_verbose("\nRECOMMENDED INSTALLATION COMMANDS:")
                if missing_tools:
                    if self.on_windows:
                        self.print_if_verbose("\n  WINDOWS (PowerShell as Administrator):")
                        for tool in missing_tools:
                            self.print_if_verbose(f"    choco install {tool} -y")
                    else:
                        self.print_if_verbose("\n  LINUX (Debian/Ubuntu):")
                        for tool in missing_tools:
                            self.print_if_verbose(f"    sudo apt-get install {tool} -y")
                
                if missing_packages:
                    self.print_if_verbose(f"\n  PYTHON:")
                    self.print_if_verbose(f"    pip install {' '.join(missing_packages)}")
        else:
            self.print_if_verbose("\n✓ ALL REQUIRED COMPONENTS ARE INSTALLED!")
            self.print_if_verbose("\nThe binary_preprocessing.py module is ready for full analysis:")
            self.print_if_verbose("  • File type detection (magic, format, arch)")
            self.print_if_verbose("  • Binary disassembly (Capstone)")
            self.print_if_verbose("  • Function recovery")
            self.print_if_verbose("  • CFG (Control Flow Graph) extraction")
            self.print_if_verbose("  • Data flow and taint analysis")
            self.print_if_verbose("  • String extraction")
            self.print_if_verbose("  • Binwalk embedded content scanning")
            self.print_if_verbose("  • ClamAV antivirus scanning")
            if self.results['optional_components']['ghidra']['found']:
                self.print_if_verbose("  • Ghidra-based advanced analysis (AVAILABLE)")
    
    def save_report(self, filename='verification_report.json'):
        """Save detailed report to JSON."""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        if self.verbose:
            print(f"\nDetailed report saved to: {filename}")
    
    def run_all(self):
        """Run all verifications."""
        if self.verbose and not self.json_output:
            print("\nBinary Preprocessing Module - Dependency Verification")
            print("=" * 70)
        
        self.verify_system_tools()
        self.verify_python_packages()
        self.verify_optional_components()
        self.generate_summary()
        self.save_report()
        
        if self.json_output:
            print(json.dumps(self.results, indent=2))
        
        return 0 if self.results['summary']['status'] == 'READY' else 1

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Verify binary preprocessing module dependencies'
    )
    parser.add_argument('--json', action='store_true', help='Output as JSON only')
    parser.add_argument('--install-help', action='store_true', help='Show installation commands')
    parser.add_argument('--quiet', action='store_true', help='Minimal output')
    
    args = parser.parse_args()
    
    verifier = Verifier(
        verbose=not args.quiet,
        json_output=args.json,
        install_help=args.install_help
    )
    sys.exit(verifier.run_all())

if __name__ == '__main__':
    main()
