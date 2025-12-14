"""
binary_preprocessing.py

BinaryPreprocessor: production-ready preprocessing module for binary/executable analysis.

Notes:
- Integrates with optional tools/libraries: lief, pefile, pyelftools, ghidra_bridge/pyghidra,
  capstone, binwalk, strings, clamscan. All are optional; the module falls back gracefully.
- Returns a structured dictionary suitable for security automation pipelines.

Usage:
    from binary_preprocessing import BinaryPreprocessor
    bp = BinaryPreprocessor()
    result = bp.analyze('sample.bin')

"""
from __future__ import annotations
import hashlib
import json
import os
import re
import shutil
import subprocess
import uuid
from collections import defaultdict
from typing import Dict, List, Tuple, Any

try:
    import lief
except Exception:
    lief = None

try:
    import pefile
except Exception:
    pefile = None

try:
    from elftools.elf.elffile import ELFFile
except Exception:
    ELFFile = None

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM
except Exception:
    Cs = None

try:
    import ghidra_bridge
except Exception:
    ghidra_bridge = None

SUSPICIOUS_SYMBOLS = [
    "strcpy",
    "strcat",
    "gets",
    "system",
    "exec",
    "execve",
    "VirtualAlloc",
    "WinExec",
    "memcpy",
    "read",
    "recv",
    "recvfrom",
    "CreateProcess",
]


def _run_subproc(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        out = p.stdout.decode(errors="replace")
        err = p.stderr.decode(errors="replace")
        return p.returncode, out, err
    except Exception as e:
        return 1, "", str(e)


class BinaryPreprocessor:
    """Main class for binary preprocessing and static approximation analysis.

    Features:
    - metadata (size, sha256, magic)
    - architecture detection (lief / pefile / pyelftools / file)
    - ghidra-like analysis (ghidra_bridge fallback to capstone)
    - CFG building (capstone fallback)
    - Data-flow and simple taint approximation
    - binwalk, strings, clamscan integrations (if installed)
    """

    def __init__(self, top_n_strings: int = 200):
        self.top_n_strings = top_n_strings
        self.warnings: List[str] = []
        self.errors: List[str] = []

    def analyze(self, path: str) -> Dict[str, Any]:
        """Run the full analysis pipeline and return a structured dict."""
        self.warnings = []
        self.errors = []
        if not os.path.isfile(path):
            raise FileNotFoundError(path)

        artifact_id = str(uuid.uuid4())
        metadata = self._extract_metadata(path)
        ghidra_analysis = self._ghidra_analysis(path, metadata)
        cfg = self._build_cfg(path, metadata, ghidra_analysis)
        df = self._data_flow_and_taint(path, metadata, ghidra_analysis, cfg)
        taint = df.get("taint_summary", {})
        binwalk = self._run_binwalk(path)
        strings = self._extract_strings(path)
        clamav = self._run_clamav(path)

        return {
            "artifact_id": artifact_id,
            "metadata": metadata,
            "ghidra_analysis": ghidra_analysis,
            "cfg": cfg,
            "df": df,
            "taint": taint,
            "binwalk": binwalk,
            "strings": strings,
            "clamav": clamav,
            "warnings": self.warnings,
            "errors": self.errors,
        }

    def _extract_metadata(self, path: str) -> Dict[str, Any]:
        md: Dict[str, Any] = {}
        try:
            st = os.stat(path)
            md["file_size"] = st.st_size
        except Exception as e:
            md["file_size"] = None
            self.warnings.append(f"stat failed: {e}")

        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            md["sha256"] = h.hexdigest()
        except Exception as e:
            md["sha256"] = None
            self.warnings.append(f"sha256 failed: {e}")

        file_cmd = shutil.which("file")
        if file_cmd:
            rc, out, err = _run_subproc([file_cmd, "-b", path])
            md["magic"] = out.strip() if out else None
        else:
            md["magic"] = None
            self.warnings.append("`file` utility not found")

        md.update(self._detect_architecture(path))
        md["imports"] = self._extract_imports(path)
        return md

    def _detect_architecture(self, path: str) -> Dict[str, Any]:
        info = {"format": None, "arch": None}
        try:
            if lief is not None:
                try:
                    b = lief.parse(path)
                    if b is not None:
                        info["format"] = getattr(b, "format", None)
                        info["arch"] = getattr(b, "arch", None)
                        return info
                except Exception:
                    pass

            if pefile is not None:
                try:
                    p = pefile.PE(path, fast_load=True)
                    info["format"] = "PE"
                    m = p.FILE_HEADER.Machine
                    if m == 0x014c:
                        info["arch"] = "x86"
                    elif m == 0x8664:
                        info["arch"] = "x64"
                    else:
                        info["arch"] = hex(m)
                    return info
                except Exception:
                    pass

            if ELFFile is not None:
                try:
                    with open(path, "rb") as f:
                        ef = ELFFile(f)
                        info["format"] = "ELF"
                        info["arch"] = ef.get_machine_arch()
                        return info
                except Exception:
                    pass

            # fallback to `file` output
            file_cmd = shutil.which("file")
            if file_cmd:
                rc, out, err = _run_subproc([file_cmd, "-b", path])
                if out:
                    txt = out.lower()
                    if "elf" in txt:
                        info["format"] = "ELF"
                    elif "pe32" in txt or "ms-dos" in txt:
                        info["format"] = "PE"
                    if "x86-64" in txt or "64-bit" in txt:
                        info["arch"] = "x64"
                    elif "80386" in txt or "i386" in txt:
                        info["arch"] = "x86"
                    elif "arm" in txt:
                        info["arch"] = "ARM"
        except Exception as e:
            self.warnings.append(f"arch detection failed: {e}")
        return info

    def _extract_imports(self, path: str) -> List[str]:
        imports: List[str] = []
        try:
            if lief is not None:
                try:
                    b = lief.parse(path)
                    if b is not None:
                        for lib in getattr(b, "libraries", []) or []:
                            imports.append(str(lib))
                        for sym in getattr(b, "symbols", []) or []:
                            name = getattr(sym, "name", None)
                            if name:
                                imports.append(name)
                        return sorted(set(imports))
                except Exception:
                    pass

            if pefile is not None:
                try:
                    p = pefile.PE(path, fast_load=True)
                    p.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                    if hasattr(p, 'DIRECTORY_ENTRY_IMPORT'):
                        for entry in p.DIRECTORY_ENTRY_IMPORT:
                            imports.append(entry.dll.decode(errors='replace'))
                            for imp in entry.imports:
                                if imp.name:
                                    imports.append(imp.name.decode(errors='replace'))
                        return sorted(set(imports))
                except Exception:
                    pass

            if ELFFile is not None:
                try:
                    with open(path, 'rb') as f:
                        ef = ELFFile(f)
                        sec = ef.get_section_by_name('.dynsym')
                        if sec:
                            for sym in sec.iter_symbols():
                                imports.append(sym.name)
                        return sorted(set([x for x in imports if x]))
                except Exception:
                    pass
        except Exception as e:
            self.warnings.append(f"imports failed: {e}")

        return sorted(set(imports))

    def _ghidra_analysis(self, path: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        analysis = {
            "functions": [],
            "num_basic_blocks": 0,
            "entry_function": None,
            "xrefs": {},
            "suspicious_functions": [],
            "notes": [],
        }

        imports = metadata.get("imports", []) or []
        for sym in imports:
            for s in SUSPICIOUS_SYMBOLS:
                if s.lower() in str(sym).lower():
                    analysis["suspicious_functions"].append(sym)

        # Try ghidra_bridge
        if ghidra_bridge is not None:
            try:
                gb = ghidra_bridge.GhidraBridge()
                script = (
                    "funcs = []\n"
                    "for f in currentProgram.getFunctionManager().getFunctions(True):\n"
                    "    funcs.append({'name':f.getName(),'entry':hex(f.getEntryPoint().getOffset())})\n"
                    "print(funcs)\n"
                )
                res = gb.run_script(script)
                if res:
                    try:
                        funcs = json.loads(res)
                        analysis["functions"] = funcs
                        if funcs:
                            analysis["entry_function"] = funcs[0]
                    except Exception:
                        analysis["notes"].append("raw ghidra output")
                        analysis["functions"] = [res]
                analysis["num_basic_blocks"] = len(analysis["functions"]) * 3
                return analysis
            except Exception as e:
                self.warnings.append(f"ghidra_bridge failed: {e}")

        # Fallback to capstone disassembly heuristics
        if Cs is None:
            analysis["notes"].append("no disassembly library installed")
            self.warnings.append("Capstone not installed; limited analysis")
            return analysis

        with open(path, "rb") as f:
            data = f.read()

        arch = metadata.get("arch") or ""
        if "x64" in str(arch) or "x86-64" in str(arch):
            cs_arch, mode = CS_ARCH_X86, CS_MODE_64
        elif "x86" in str(arch):
            cs_arch, mode = CS_ARCH_X86, CS_MODE_32
        elif "arm" in str(arch).lower():
            cs_arch, mode = CS_ARCH_ARM, CS_MODE_32
        else:
            cs_arch, mode = CS_ARCH_X86, CS_MODE_32

        try:
            md = Cs(cs_arch, mode)
            md.detail = True
            funcs = []
            xrefs = defaultdict(list)
            bb_count = 0
            for i in md.disasm(data, 0x1000):
                if i.mnemonic.lower().startswith("call"):
                    funcs.append({"addr": hex(i.address), "insn": f"{i.mnemonic} {i.op_str}"})
                    bb_count += 1
                    xrefs[hex(i.address)].append(i.op_str)

            analysis["functions"] = funcs
            analysis["num_basic_blocks"] = bb_count
            analysis["xrefs"] = dict(xrefs)
            if funcs:
                analysis["entry_function"] = funcs[0]
            return analysis
        except Exception as e:
            self.warnings.append(f"capstone analysis failed: {e}")
            analysis["notes"].append("disassembly error")
            return analysis

    def _build_cfg(self, path: str, metadata: Dict[str, Any], ghidra_analysis: Dict[str, Any]) -> Dict[str, Any]:
        cfg = {"nodes": [], "edges": [], "basic_blocks": []}
        if Cs is None:
            cfg["notes"] = ["Capstone not available; CFG unavailable"]
            return cfg

        with open(path, "rb") as f:
            data = f.read()

        arch = metadata.get("arch") or ""
        if "x64" in str(arch) or "x86-64" in str(arch):
            cs_arch, mode = CS_ARCH_X86, CS_MODE_64
        elif "arm" in str(arch).lower():
            cs_arch, mode = CS_ARCH_ARM, CS_MODE_32
        else:
            cs_arch, mode = CS_ARCH_X86, CS_MODE_32

        try:
            md = Cs(cs_arch, mode)
            md.detail = True
            blocks = []
            current = {"start": None, "end": None, "insns": []}
            last_addr = None
            for i in md.disasm(data, 0x1000):
                if current["start"] is None:
                    current["start"] = i.address
                current["insns"].append({"addr": hex(i.address), "mnemonic": i.mnemonic, "op_str": i.op_str})
                last_addr = i.address
                if i.mnemonic.lower().startswith(("ret", "jmp", "je", "jne", "jz", "jnz", "call")):
                    current["end"] = i.address
                    blocks.append(current)
                    current = {"start": None, "end": None, "insns": []}

            if current["start"] is not None:
                current["end"] = last_addr
                blocks.append(current)

            for b in blocks:
                node_id = hex(b["start"])
                cfg["nodes"].append({"id": node_id, "start": hex(b["start"]), "end": hex(b["end"]), "size": len(b["insns"])})
                cfg["basic_blocks"].append(b)

            for i in range(len(blocks) - 1):
                cfg["edges"].append({"from": hex(blocks[i]["start"]), "to": hex(blocks[i + 1]["start"]), "type": "fallthrough"})

            return cfg
        except Exception as e:
            self.warnings.append(f"cfg build failed: {e}")
            return cfg

    def _data_flow_and_taint(self, path: str, metadata: Dict[str, Any], ghidra_analysis: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        df = {"register_writes": [], "memory_writes": [], "flows": [], "taint_summary": {}}

        imports = metadata.get("imports", []) or []
        sources = [s for s in imports if any(x in s.lower() for x in ("read", "recv", "fread", "gets", "scanf"))]
        sinks = [s for s in imports if any(x in s.lower() for x in ("strcpy", "memcpy", "system", "exec", "winexec", "virtualalloc"))]

        df["sources"] = sources
        df["sinks"] = sinks

        try:
            with open(path, "rb") as f:
                data = f.read()
            txt = data.decode(errors="ignore")
            for s in SUSPICIOUS_SYMBOLS:
                if s in txt:
                    df.setdefault("suspicious_literals", []).append(s)
        except Exception:
            pass

        potential = []
        for src in sources:
            for snk in sinks:
                potential.append({"src": src, "sink": snk, "confidence": "low"})

        df["flows"] = potential
        df["taint_summary"] = {"sources": sources, "sinks": sinks, "flows_detected": len(potential), "details": potential}
        return df

    def _run_binwalk(self, path: str) -> Dict[str, Any]:
        out = {"raw": None, "findings": []}
        binwalk_cmd = shutil.which("binwalk")
        if not binwalk_cmd:
            self.warnings.append("binwalk not found; skipping")
            return out
        rc, stdout, stderr = _run_subproc([binwalk_cmd, path])
        out["raw"] = stdout
        for line in stdout.splitlines():
            if line.strip():
                out["findings"].append(line.strip())
        return out

    def _extract_strings(self, path: str) -> List[Dict[str, Any]]:
        strings_cmd = shutil.which("strings")
        strs: List[str] = []
        if strings_cmd:
            rc, out, err = _run_subproc([strings_cmd, "-a", "-n", "4", path])
            if out:
                strs = out.splitlines()
        else:
            with open(path, "rb") as f:
                data = f.read()
            candidate = re.findall(rb"[ -~]{4,}", data)
            strs = [c.decode(errors="replace") for c in candidate]

        url_re = re.compile(r"https?://[\w\-\./?=&%]+", re.I)
        creds_re = re.compile(r"([A-Za-z0-9._%+-]{3,}[:=][A-Za-z0-9@#$%^&*()_+\-]{3,})")
        interesting: List[Dict[str, Any]] = []
        seen = set()
        for s in strs:
            if len(interesting) >= self.top_n_strings:
                break
            s_strip = s.strip()
            if not s_strip or s_strip in seen:
                continue
            seen.add(s_strip)
            kind = "other"
            if url_re.search(s_strip):
                kind = "url"
            elif creds_re.search(s_strip):
                kind = "credential"
            elif any(tok in s_strip.lower() for tok in ("api", "token", "password", "passwd", "username")):
                kind = "potential_secret"
            elif any(tok in s_strip.lower() for tok in ("debug", "error", "failed", "trace")):
                kind = "log_message"

            interesting.append({"string": s_strip, "kind": kind})

        return interesting

    def _run_clamav(self, path: str) -> Dict[str, Any]:
        clamscan = shutil.which("clamscan")
        result = {"installed": False, "raw": None, "infected": False}
        if not clamscan:
            self.warnings.append("clamscan not found; skipping")
            return result
        result["installed"] = True
        rc, out, err = _run_subproc([clamscan, "--no-summary", path], timeout=120)
        result["raw"] = out + err
        if "FOUND" in out or "Infected files: 1" in out:
            result["infected"] = True
        return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Binary preprocessing analysis")
    parser.add_argument("file", help="Path to binary to analyze")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()
    bp = BinaryPreprocessor()
    res = bp.analyze(args.file)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print("Artifact:", res.get("artifact_id"))
        print("SHA256:", res.get("metadata", {}).get("sha256"))
        print("Warnings:", res.get("warnings"))
