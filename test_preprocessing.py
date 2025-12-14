#!/usr/bin/env python
"""
Test script for binary preprocessing module.

This script tests the preprocessing module on system binaries to verify all
components are working correctly.

Usage:
    python test_preprocessing.py              # Test with default system binary
    python test_preprocessing.py C:\\Windows\\System32\\notepad.exe  # Windows
    python test_preprocessing.py /bin/bash    # Linux
    python test_preprocessing.py --list       # Show available test binaries
"""

import sys
import os
import json
import argparse
from pathlib import Path

# Add parent directory to path so we can import binary_preprocessing
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from binary_preprocessing import BinaryPreprocessor
except ImportError as e:
    print(f"ERROR: Could not import binary_preprocessing module: {e}")
    print("\nMake sure you're running this script from the preprocessing directory")
    sys.exit(1)

class TestRunner:
    def __init__(self):
        self.bp = BinaryPreprocessor()
        self.test_binaries = self._find_test_binaries()
    
    def _find_test_binaries(self):
        """Find available system binaries to test with."""
        binaries = {}
        
        if sys.platform.startswith('win'):
            # Windows test binaries
            candidates = [
                (r'C:\Windows\System32\notepad.exe', 'Notepad'),
                (r'C:\Windows\System32\cmd.exe', 'Command Prompt'),
                (r'C:\Windows\System32\calc.exe', 'Calculator'),
                (r'C:\Program Files\PowerShell\7\pwsh.exe', 'PowerShell'),
            ]
        else:
            # Linux test binaries
            candidates = [
                ('/bin/bash', 'Bash shell'),
                ('/bin/ls', 'ls command'),
                ('/bin/cat', 'cat command'),
                ('/usr/bin/python3', 'Python 3'),
            ]
        
        for path, name in candidates:
            if os.path.isfile(path):
                binaries[name] = path
        
        return binaries
    
    def list_binaries(self):
        """List available test binaries."""
        print("\nAvailable test binaries:")
        print("=" * 50)
        if self.test_binaries:
            for name, path in self.test_binaries.items():
                print(f"  {name:30} {path}")
        else:
            print("  No test binaries found!")
            print("  You can run: python test_preprocessing.py <path_to_binary>")
    
    def test_binary(self, binary_path, json_output=False):
        """Test preprocessing on a single binary."""
        
        if not os.path.isfile(binary_path):
            print(f"\nERROR: Binary not found: {binary_path}")
            return False
        
        print(f"\n{'='*70}")
        print(f"Testing: {os.path.basename(binary_path)}")
        print(f"Path: {binary_path}")
        print(f"{'='*70}\n")
        
        try:
            # Run analysis
            print("Running analysis...")
            result = self.bp.analyze(binary_path)
            
            # Print results
            if json_output:
                print(json.dumps(result, indent=2))
            else:
                self._print_results(result)
            
            return True
        
        except Exception as e:
            print(f"\nERROR during analysis: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _print_results(self, result):
        """Pretty print analysis results."""
        
        print("\n[METADATA]")
        print("-" * 70)
        metadata = result.get('metadata', {})
        print(f"  Artifact ID:     {result.get('artifact_id')}")
        print(f"  File Size:       {metadata.get('file_size'):,} bytes")
        print(f"  SHA256:          {metadata.get('sha256')}")
        print(f"  Format:          {metadata.get('format')}")
        print(f"  Architecture:    {metadata.get('arch')}")
        print(f"  Magic:           {metadata.get('magic')}")
        
        imports = metadata.get('imports', [])
        if imports:
            print(f"  Imports:         {len(imports)} items")
            if len(imports) <= 5:
                for imp in imports[:5]:
                    print(f"    • {imp}")
            else:
                for imp in imports[:3]:
                    print(f"    • {imp}")
                print(f"    ... and {len(imports) - 3} more")
        
        print("\n[GHIDRA ANALYSIS]")
        print("-" * 70)
        ghidra = result.get('ghidra_analysis', {})
        functions = ghidra.get('functions', [])
        print(f"  Functions Found:        {len(functions)}")
        if functions and len(functions) <= 5:
            for func in functions[:5]:
                if isinstance(func, dict) and 'name' in func:
                    print(f"    • {func.get('name', 'unknown')} @ {func.get('entry', 'unknown')}")
        suspicious = ghidra.get('suspicious_functions', [])
        if suspicious:
            print(f"  Suspicious Symbols:     {len(suspicious)}")
            for sym in suspicious[:5]:
                print(f"    • {sym}")
        
        print(f"  Basic Blocks:           {ghidra.get('num_basic_blocks', 0)}")
        if ghidra.get('notes'):
            print(f"  Notes:                  {', '.join(ghidra['notes'])}")
        
        print("\n[CONTROL FLOW GRAPH (CFG)]")
        print("-" * 70)
        cfg = result.get('cfg', {})
        nodes = cfg.get('nodes', [])
        edges = cfg.get('edges', [])
        print(f"  Nodes:                  {len(nodes)}")
        print(f"  Edges:                  {len(edges)}")
        if cfg.get('notes'):
            print(f"  Notes:                  {', '.join(cfg['notes'])}")
        
        print("\n[DATA FLOW & TAINT ANALYSIS]")
        print("-" * 70)
        df = result.get('df', {})
        sources = df.get('sources', [])
        sinks = df.get('sinks', [])
        flows = df.get('flows', [])
        print(f"  Sources (read funcs):   {len(sources)}")
        if sources:
            for src in sources[:3]:
                print(f"    • {src}")
        print(f"  Sinks (write funcs):    {len(sinks)}")
        if sinks:
            for snk in sinks[:3]:
                print(f"    • {snk}")
        
        taint = result.get('taint', {})
        print(f"  Taint Flows Detected:   {taint.get('flows_detected', 0)}")
        if taint.get('details'):
            for flow in taint['details'][:3]:
                print(f"    • {flow['src']} -> {flow['sink']}")
        
        print("\n[BINWALK ANALYSIS]")
        print("-" * 70)
        binwalk = result.get('binwalk', {})
        findings = binwalk.get('findings', [])
        print(f"  Embedded Findings:      {len(findings)}")
        if findings:
            for finding in findings[:3]:
                print(f"    • {finding}")
        
        print("\n[STRING EXTRACTION]")
        print("-" * 70)
        strings = result.get('strings', [])
        print(f"  Total Strings Found:    {len(strings)}")
        
        # Group by type
        by_type = {}
        for s in strings:
            kind = s.get('kind', 'other')
            by_type[kind] = by_type.get(kind, 0) + 1
        
        if by_type:
            for kind, count in sorted(by_type.items()):
                print(f"    • {kind}: {count}")
        
        # Show interesting strings
        interesting = [s for s in strings if s.get('kind') != 'other']
        if interesting:
            print(f"\n  Interesting strings (first 5):")
            for s in interesting[:5]:
                print(f"    [{s['kind']}] {s['string'][:60]}")
        
        print("\n[CLAMAV ANTIVIRUS]")
        print("-" * 70)
        clamav = result.get('clamav', {})
        print(f"  Installed:              {'Yes' if clamav.get('installed') else 'No'}")
        print(f"  Infected:               {'Yes' if clamav.get('infected') else 'No'}")
        
        print("\n[WARNINGS & ERRORS]")
        print("-" * 70)
        warnings = result.get('warnings', [])
        errors = result.get('errors', [])
        
        if not warnings and not errors:
            print("  ✓ No warnings or errors")
        else:
            if warnings:
                print(f"  Warnings ({len(warnings)}):")
                for w in warnings[:5]:
                    print(f"    • {w}")
            if errors:
                print(f"  Errors ({len(errors)}):")
                for e in errors[:5]:
                    print(f"    • {e}")
        
        print("\n" + "=" * 70)
        print("ANALYSIS COMPLETE")
        print("=" * 70 + "\n")
    
    def run(self, binary_path=None, json_output=False, list_only=False):
        """Run tests."""
        
        if list_only:
            self.list_binaries()
            return 0
        
        # Determine which binary to test
        if binary_path:
            if not os.path.isfile(binary_path):
                print(f"ERROR: File not found: {binary_path}")
                return 1
            target = binary_path
        else:
            # Use first available test binary
            if not self.test_binaries:
                print("ERROR: No test binaries found!")
                print("\nRun: python test_preprocessing.py --list")
                print("Or:  python test_preprocessing.py <path_to_binary>")
                return 1
            target = list(self.test_binaries.values())[0]
            print(f"\nUsing default test binary: {target}")
            print("(Use --list to see other options)")
        
        success = self.test_binary(target, json_output=json_output)
        return 0 if success else 1

def main():
    parser = argparse.ArgumentParser(
        description='Test binary preprocessing module on system binaries'
    )
    parser.add_argument('binary', nargs='?', help='Binary file to test (optional)')
    parser.add_argument('--json', action='store_true', help='Output full JSON results')
    parser.add_argument('--list', action='store_true', help='List available test binaries')
    
    args = parser.parse_args()
    
    runner = TestRunner()
    return runner.run(
        binary_path=args.binary,
        json_output=args.json,
        list_only=args.list
    )

if __name__ == '__main__':
    sys.exit(main())
