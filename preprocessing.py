import os
import json
import uuid
import hashlib
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional


# ===============================
# Utility Functions
# ===============================

def run_cmd(command: str, cwd: Optional[str] = None) -> Dict[str, str]:
    """Run a shell command safely and return stdout + stderr."""
    try:
        result = subprocess.run(
            command, shell=True, cwd=cwd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        return {"stdout": result.stdout, "stderr": result.stderr}
    except Exception as e:
        return {"stdout": "", "stderr": str(e)}


def is_binary_file(path: str) -> bool:
    """Heuristic check for binary files."""
    try:
        with open(path, "rb") as f:
            chunk = f.read(2048)
        if b"\x00" in chunk:
            return True
        # Non-text bytes detection
        text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} |
                               set(range(0x20, 0x100)))
        return bool(chunk.translate(None, text_chars))
    except:
        return False


def sha256_file(path: str) -> str:
    """Calculate SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_all_files(path: str) -> List[str]:
    """Recursively collect files if path is directory."""
    p = Path(path)
    if p.is_file():
        return [str(p)]
    all_files = []
    for fp in p.rglob("*"):
        if fp.is_file():
            all_files.append(str(fp))
    return all_files


def detect_language(file: str) -> str:
    ext = Path(file).suffix.lower()
    mapping = {
        ".js": "javascript",
        ".ts": "typescript",
        ".py": "python",
        ".java": "java",
        ".c": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".go": "go",
        ".rs": "rust"
    }
    return mapping.get(ext, "other")


# ===============================
# Source Code Preprocessing
# ===============================

def run_semgrep(target_path: str) -> Dict[str, Any]:
    cmd = f"semgrep --json --quiet --config auto {target_path}"
    result = run_cmd(cmd)

    if result["stdout"]:
        try:
            return {"raw": json.loads(result["stdout"]), "error": None}
        except Exception as e:
            return {"raw": None, "error": f"Failed JSON parse: {str(e)}"}

    return {"raw": None, "error": result["stderr"]}


def build_js_ts_ast(files: List[str]) -> Dict[str, Any]:
    """
    OPTIONAL: requires pip install tree_sitter tree_sitter_javascript
    If not installed, we return empty / warning.
    """
    try:
        from tree_sitter import Language, Parser
    except ImportError:
        return {
            "total": 0,
            "parsed": 0,
            "errors": [{"error": "tree_sitter not installed"}]
        }

    Language.build_library(
        "build/my-languages.so",
        ["tree-sitter-javascript"]
    )
    JS_LANG = Language("build/my-languages.so", "javascript")

    parser = Parser()
    parser.set_language(JS_LANG)

    total = 0
    parsed = 0
    errors = []

    for f in files:
        if not (f.endswith(".js") or f.endswith(".ts")):
            continue
        total += 1
        try:
            code = open(f, "r", encoding="utf-8", errors="ignore").read()
            tree = parser.parse(bytes(code, "utf8"))
            if tree:
                parsed += 1
        except Exception as e:
            errors.append({"file": f, "error": str(e)})

    return {
        "total": total,
        "parsed": parsed,
        "errors": errors
    }


def preprocess_source_code(artifact_id: str, target_path: str) -> Dict[str, Any]:
    files = collect_all_files(target_path)
    languages = {detect_language(f) for f in files}

    semgrep = run_semgrep(target_path)

    # Only generate AST for JS/TS
    js_ts_files = [f for f in files if f.endswith(".js") or f.endswith(".ts")]
    ast_summary = build_js_ts_ast(js_ts_files)

    return {
        "artifactId": artifact_id,
        "type": "SOURCE_CODE",
        "fileCount": len(files),
        "languagesDetected": list(languages),
        "metadata": {
            "mainPath": target_path,
        },
        "semgrep": semgrep,
        "astSummary": ast_summary,
        "files": files
    }


# ===============================
# Binary Preprocessing
# ===============================

def preprocess_binary(artifact_id: str, file_path: str) -> Dict[str, Any]:
    file_out = run_cmd(f"file {file_path}")
    binwalk_out = run_cmd(f"binwalk {file_path}")
    strings_out = run_cmd(f"strings {file_path} | head -n 50")

    # clamscan is optional
    clam = run_cmd(f"clamscan {file_path}")
    infected = "FOUND" in (clam["stdout"] + clam["stderr"])

    return {
        "artifactId": artifact_id,
        "type": "BINARY",
        "metadata": {
            "fileName": os.path.basename(file_path),
            "sizeBytes": os.path.getsize(file_path),
            "sha256": sha256_file(file_path)
        },
        "fileOutput": file_out["stdout"],
        "binwalkOutput": binwalk_out["stdout"],
        "stringsSample": strings_out["stdout"].split("\n"),
        "clamav": {
            "output": clam["stdout"],
            "infected": infected
        }
    }


# ===============================
# Main API
# ===============================

def preprocess_artifact(path: str) -> Dict[str, Any]:
    artifact_id = str(uuid.uuid4())
    p = Path(path)

    if p.is_dir():
        return preprocess_source_code(artifact_id, path)

    # Decide based on content + extension
    if is_binary_file(path):
        return preprocess_binary(artifact_id, path)

    return preprocess_source_code(artifact_id, path)


# ===============================
# CLI Test
# ===============================

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python preprocessing.py <path-to-file-or-folder>")
        exit(1)

    result = preprocess_artifact(sys.argv[1])
    print(json.dumps(result, indent=2))
