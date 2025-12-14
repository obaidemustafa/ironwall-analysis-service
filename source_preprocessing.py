"""
Advanced Static Preprocessing Module for Source Code Security Analysis

This module performs comprehensive static analysis on uploaded source code projects,
including AST extraction, control flow graph generation, data flow analysis, taint
tracking, and Semgrep integration for a multi-language security pipeline.

Author: Security Analysis Pipeline
Version: 1.0.0
"""

import os
import sys
import json
import hashlib
import subprocess
import logging
import uuid
from pathlib import Path
from typing import Dict, List, Set, Tuple, Any, Optional
from dataclasses import dataclass, asdict, field
from collections import defaultdict
from enum import Enum
import ast
import re


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS AND DATA STRUCTURES
# ============================================================================

class SupportedLanguage(Enum):
    """Enumeration of supported programming languages."""
    JAVASCRIPT = "js"
    TYPESCRIPT = "ts"
    PYTHON = "py"
    JAVA = "java"
    C = "c"
    CPP = "cpp"
    GO = "go"
    RUST = "rs"

    @property
    def extensions(self) -> List[str]:
        """Get file extensions for the language."""
        extension_map = {
            SupportedLanguage.JAVASCRIPT: [".js", ".jsx", ".mjs"],
            SupportedLanguage.TYPESCRIPT: [".ts", ".tsx"],
            SupportedLanguage.PYTHON: [".py"],
            SupportedLanguage.JAVA: [".java"],
            SupportedLanguage.C: [".c", ".h"],
            SupportedLanguage.CPP: [".cpp", ".cc", ".cxx", ".hpp", ".h"],
            SupportedLanguage.GO: [".go"],
            SupportedLanguage.RUST: [".rs"],
        }
        return extension_map.get(self, [])


@dataclass
class FileMetadata:
    """Metadata for a source file."""
    path: str
    relative_path: str
    language: str
    sha256_hash: str
    size_bytes: int
    line_count: int


@dataclass
class ASTResult:
    """AST analysis result for a file."""
    node_count: int
    tree_depth: int
    functions: List[str]
    classes: List[str]
    imports: List[str]
    summary: str


@dataclass
class CFGNode:
    """A node in the Control Flow Graph."""
    node_id: str
    label: str
    node_type: str  # "entry", "exit", "basic_block", "branch"
    lineno: Optional[int] = None


@dataclass
class CFGEdge:
    """An edge in the Control Flow Graph."""
    source_id: str
    target_id: str
    edge_type: str  # "direct", "conditional_true", "conditional_false"
    condition: Optional[str] = None


@dataclass
class CFGResult:
    """CFG analysis result for a file."""
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    entry_points: List[str]
    suspicious_patterns: List[str] = field(default_factory=list)


@dataclass
class DataFlowVariable:
    """Represents a variable in data flow analysis."""
    name: str
    assigned_at: List[int]  # line numbers
    read_at: List[int]  # line numbers
    is_tainted: bool = False
    sources: List[str] = field(default_factory=list)
    sinks: List[str] = field(default_factory=list)


@dataclass
class DFResult:
    """Data flow analysis result for a file."""
    variables: Dict[str, Dict[str, Any]]
    taint_sources: List[Dict[str, Any]]
    taint_sinks: List[Dict[str, Any]]
    injection_points: List[Dict[str, Any]]
    summary: str


@dataclass
class TaintFlow:
    """Represents a taint flow from source to sink."""
    source: str
    source_line: int
    sink: str
    sink_line: int
    path: List[str]
    severity: str  # "critical", "high", "medium", "low"


@dataclass
class TaintResult:
    """Taint analysis result for a file."""
    flows: List[Dict[str, Any]]
    vulnerable_variables: List[str]
    severity_summary: Dict[str, int]  # severity -> count


@dataclass
class SemgrepFinding:
    """A Semgrep security finding."""
    rule_id: str
    message: str
    severity: str
    file: str
    line: int
    column: int
    code_snippet: str


# ============================================================================
# HELPER CLASSES FOR AST/CFG/TAINT ANALYSIS
# ============================================================================

class PythonASTAnalyzer:
    """Analyzes Python code using the built-in AST module."""

    @staticmethod
    def extract_ast_info(code: str) -> Optional[ASTResult]:
        """
        Extract AST information from Python code.

        Args:
            code: Python source code as string

        Returns:
            ASTResult or None if parsing fails
        """
        try:
            tree = ast.parse(code)
            analyzer = PythonASTVisitor()
            analyzer.visit(tree)

            return ASTResult(
                node_count=analyzer.node_count,
                tree_depth=analyzer.max_depth,
                functions=analyzer.functions,
                classes=analyzer.classes,
                imports=analyzer.imports,
                summary=analyzer.get_summary(),
            )
        except SyntaxError as e:
            logger.warning(f"Failed to parse Python AST: {e}")
            return None

    @staticmethod
    def build_cfg(code: str) -> Optional[CFGResult]:
        """
        Build Control Flow Graph from Python code.

        Args:
            code: Python source code

        Returns:
            CFGResult or None if building fails
        """
        try:
            tree = ast.parse(code)
            builder = PythonCFGBuilder()
            builder.visit(tree)
            return builder.get_cfg_result()
        except Exception as e:
            logger.warning(f"Failed to build Python CFG: {e}")
            return None


class PythonASTVisitor(ast.NodeVisitor):
    """Custom AST visitor for Python code analysis."""

    def __init__(self):
        self.node_count = 0
        self.max_depth = 0
        self.current_depth = 0
        self.functions: List[str] = []
        self.classes: List[str] = []
        self.imports: List[str] = []

    def visit(self, node):
        """Visit a node and track depth."""
        self.node_count += 1
        self.current_depth += 1
        self.max_depth = max(self.max_depth, self.current_depth)
        self.generic_visit(node)
        self.current_depth -= 1

    def visit_FunctionDef(self, node):
        """Track function definitions."""
        self.functions.append(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        """Track async function definitions."""
        self.functions.append(f"async {node.name}")
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        """Track class definitions."""
        self.classes.append(node.name)
        self.generic_visit(node)

    def visit_Import(self, node):
        """Track imports."""
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """Track from imports."""
        if node.module:
            self.imports.append(node.module)
        self.generic_visit(node)

    def get_summary(self) -> str:
        """Return a text summary of the AST."""
        return (
            f"Functions: {len(self.functions)}, "
            f"Classes: {len(self.classes)}, "
            f"Imports: {len(self.imports)}, "
            f"Total nodes: {self.node_count}, "
            f"Max depth: {self.max_depth}"
        )


class PythonCFGBuilder(ast.NodeVisitor):
    """Builds a Control Flow Graph from Python AST."""

    def __init__(self):
        self.nodes: Dict[str, CFGNode] = {}
        self.edges: List[CFGEdge] = []
        self.entry_points: List[str] = []
        self.current_block_id: Optional[str] = None
        self.node_counter = 0
        self.suspicious_patterns: List[str] = []

    def _new_node_id(self) -> str:
        """Generate a unique node ID."""
        self.node_counter += 1
        return f"node_{self.node_counter}"

    def _add_node(
        self,
        label: str,
        node_type: str,
        lineno: Optional[int] = None,
    ) -> str:
        """Add a CFG node and return its ID."""
        node_id = self._new_node_id()
        self.nodes[node_id] = CFGNode(
            node_id=node_id,
            label=label,
            node_type=node_type,
            lineno=lineno,
        )
        return node_id

    def _add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str = "direct",
        condition: Optional[str] = None,
    ) -> None:
        """Add a CFG edge."""
        self.edges.append(
            CFGEdge(
                source_id=source_id,
                target_id=target_id,
                edge_type=edge_type,
                condition=condition,
            )
        )

    def visit_FunctionDef(self, node):
        """Handle function definitions."""
        func_node_id = self._add_node(
            f"def {node.name}",
            "entry",
            lineno=node.lineno,
        )
        self.entry_points.append(func_node_id)

        prev_block = self.current_block_id
        self.current_block_id = func_node_id

        for stmt in node.body:
            self.visit(stmt)

        self.current_block_id = prev_block
        self.generic_visit(node)

    def visit_If(self, node):
        """Handle if statements."""
        condition_node_id = self._add_node(
            f"if condition",
            "branch",
            lineno=node.lineno,
        )

        if self.current_block_id:
            self._add_edge(self.current_block_id, condition_node_id)

        # True branch
        true_node_id = self._new_node_id()
        self.nodes[true_node_id] = CFGNode(
            node_id=true_node_id,
            label="if body",
            node_type="basic_block",
            lineno=node.lineno,
        )
        self._add_edge(
            condition_node_id,
            true_node_id,
            edge_type="conditional_true",
        )

        prev_block = self.current_block_id
        self.current_block_id = true_node_id
        for stmt in node.body:
            self.visit(stmt)

        # False branch (else)
        if node.orelse:
            false_node_id = self._new_node_id()
            self.nodes[false_node_id] = CFGNode(
                node_id=false_node_id,
                label="else body",
                node_type="basic_block",
                lineno=node.lineno,
            )
            self._add_edge(
                condition_node_id,
                false_node_id,
                edge_type="conditional_false",
            )
            self.current_block_id = false_node_id
            for stmt in node.orelse:
                self.visit(stmt)

        self.current_block_id = prev_block

    def visit_While(self, node):
        """Handle while loops."""
        loop_node_id = self._add_node(
            "while condition",
            "branch",
            lineno=node.lineno,
        )

        if self.current_block_id:
            self._add_edge(self.current_block_id, loop_node_id)

        body_node_id = self._new_node_id()
        self.nodes[body_node_id] = CFGNode(
            node_id=body_node_id,
            label="loop body",
            node_type="basic_block",
            lineno=node.lineno,
        )
        self._add_edge(loop_node_id, body_node_id, edge_type="conditional_true")
        self._add_edge(body_node_id, loop_node_id)  # Back edge

        prev_block = self.current_block_id
        self.current_block_id = body_node_id
        for stmt in node.body:
            self.visit(stmt)
        self.current_block_id = prev_block

    def visit_For(self, node):
        """Handle for loops."""
        loop_node_id = self._add_node(
            "for iteration",
            "branch",
            lineno=node.lineno,
        )

        if self.current_block_id:
            self._add_edge(self.current_block_id, loop_node_id)

        body_node_id = self._new_node_id()
        self.nodes[body_node_id] = CFGNode(
            node_id=body_node_id,
            label="loop body",
            node_type="basic_block",
            lineno=node.lineno,
        )
        self._add_edge(loop_node_id, body_node_id, edge_type="conditional_true")
        self._add_edge(body_node_id, loop_node_id)  # Back edge

        prev_block = self.current_block_id
        self.current_block_id = body_node_id
        for stmt in node.body:
            self.visit(stmt)
        self.current_block_id = prev_block

    def visit_Try(self, node):
        """Handle try-except blocks."""
        try_node_id = self._add_node(
            "try block",
            "basic_block",
            lineno=node.lineno,
        )

        if self.current_block_id:
            self._add_edge(self.current_block_id, try_node_id)

        prev_block = self.current_block_id
        self.current_block_id = try_node_id
        for stmt in node.body:
            self.visit(stmt)

        for handler in node.handlers:
            handler_node_id = self._add_node(
                f"except {handler.type}",
                "basic_block",
                lineno=handler.lineno,
            )
            self._add_edge(try_node_id, handler_node_id)
            self.current_block_id = handler_node_id
            for stmt in handler.body:
                self.visit(stmt)

        self.current_block_id = prev_block

    def visit_Call(self, node):
        """Detect suspicious function calls."""
        if isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec", "compile", "__import__"):
                self.suspicious_patterns.append(
                    f"Dangerous function call: {node.func.id} at line {node.lineno}"
                )
        self.generic_visit(node)

    def get_cfg_result(self) -> CFGResult:
        """Convert CFG to result format."""
        return CFGResult(
            nodes=[asdict(node) for node in self.nodes.values()],
            edges=[asdict(edge) for edge in self.edges],
            entry_points=self.entry_points,
            suspicious_patterns=self.suspicious_patterns,
        )


class DataFlowAnalyzer:
    """Performs lightweight data flow analysis."""

    TAINT_SOURCES = {
        "input": ["input", "raw_input"],
        "network": ["socket", "urllib", "requests", "httpx"],
        "file": ["open", "read"],
        "environment": ["environ", "getenv"],
        "command_line": ["argv", "sys.argv"],
    }

    TAINT_SINKS = {
        "eval": ["eval", "exec", "compile"],
        "os_command": ["system", "popen", "subprocess.run", "os.system"],
        "sql": ["execute", "query", "sql"],
        "code_execution": ["exec", "eval"],
    }

    def __init__(self, code: str):
        self.code = code
        self.tree = ast.parse(code)
        self.variables: Dict[str, DataFlowVariable] = {}
        self.taint_sources: List[Dict[str, Any]] = []
        self.taint_sinks: List[Dict[str, Any]] = []
        self.injection_points: List[Dict[str, Any]] = []

    def analyze(self) -> DFResult:
        """Perform data flow analysis."""
        self._extract_variables()
        self._detect_taint_sources()
        self._detect_taint_sinks()
        self._detect_injection_points()

        return DFResult(
            variables={k: asdict(v) for k, v in self.variables.items()},
            taint_sources=self.taint_sources,
            taint_sinks=self.taint_sinks,
            injection_points=self.injection_points,
            summary=self._generate_summary(),
        )

    def _extract_variables(self) -> None:
        """Extract variable assignments and uses."""
        visitor = VariableExtractor()
        visitor.visit(self.tree)

        for var_name, assignments, reads in visitor.get_variables():
            self.variables[var_name] = DataFlowVariable(
                name=var_name,
                assigned_at=assignments,
                read_at=reads,
            )

    def _detect_taint_sources(self) -> None:
        """Detect taint sources (user inputs, network, etc.)."""
        visitor = TaintSourceDetector(self.TAINT_SOURCES)
        visitor.visit(self.tree)

        for source in visitor.sources:
            self.taint_sources.append({
                "type": source["type"],
                "function": source["function"],
                "line": source["line"],
                "context": source["context"],
            })

    def _detect_taint_sinks(self) -> None:
        """Detect taint sinks (dangerous functions)."""
        visitor = TaintSinkDetector(self.TAINT_SINKS)
        visitor.visit(self.tree)

        for sink in visitor.sinks:
            self.taint_sinks.append({
                "type": sink["type"],
                "function": sink["function"],
                "line": sink["line"],
                "arguments": sink["arguments"],
            })

    def _detect_injection_points(self) -> None:
        """Detect potential injection points."""
        # Look for string formatting with variables that might be tainted
        visitor = InjectionPointDetector(self.variables.keys())
        visitor.visit(self.tree)

        for point in visitor.injection_points:
            self.injection_points.append({
                "type": point["type"],
                "variable": point["variable"],
                "line": point["line"],
                "context": point["context"],
            })

    def _generate_summary(self) -> str:
        """Generate a summary of data flow analysis."""
        return (
            f"Variables: {len(self.variables)}, "
            f"Taint sources: {len(self.taint_sources)}, "
            f"Taint sinks: {len(self.taint_sinks)}, "
            f"Injection points: {len(self.injection_points)}"
        )


class VariableExtractor(ast.NodeVisitor):
    """Extracts variable definitions and uses."""

    def __init__(self):
        self.assignments: Dict[str, List[int]] = defaultdict(list)
        self.reads: Dict[str, List[int]] = defaultdict(list)

    def visit_Assign(self, node):
        """Track assignments."""
        for target in node.targets:
            for name in self._extract_names(target):
                self.assignments[name].append(node.lineno)
        self.generic_visit(node)

    def visit_Name(self, node):
        """Track variable reads."""
        if isinstance(node.ctx, ast.Load):
            self.reads[node.id].append(node.lineno)
        self.generic_visit(node)

    def _extract_names(self, node) -> List[str]:
        """Extract variable names from assignment target."""
        names = []
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for elt in node.elts:
                names.extend(self._extract_names(elt))
        return names

    def get_variables(self) -> List[Tuple[str, List[int], List[int]]]:
        """Return list of (name, assignments, reads)."""
        all_vars = set(self.assignments.keys()) | set(self.reads.keys())
        return [
            (var, self.assignments.get(var, []), self.reads.get(var, []))
            for var in all_vars
        ]


class TaintSourceDetector(ast.NodeVisitor):
    """Detects taint sources in code."""

    def __init__(self, taint_sources: Dict[str, List[str]]):
        self.taint_sources = taint_sources
        self.sources: List[Dict[str, Any]] = []

    def visit_Call(self, node):
        """Detect taint source function calls."""
        func_name = self._get_func_name(node.func)

        for source_type, functions in self.taint_sources.items():
            if func_name in functions:
                self.sources.append({
                    "type": source_type,
                    "function": func_name,
                    "line": node.lineno,
                    "context": ast.unparse(node) if hasattr(ast, 'unparse') else '',
                })

        self.generic_visit(node)

    def _get_func_name(self, node) -> str:
        """Extract function name from Call node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""


class TaintSinkDetector(ast.NodeVisitor):
    """Detects taint sinks (dangerous functions)."""

    def __init__(self, taint_sinks: Dict[str, List[str]]):
        self.taint_sinks = taint_sinks
        self.sinks: List[Dict[str, Any]] = []

    def visit_Call(self, node):
        """Detect taint sink function calls."""
        func_name = self._get_func_name(node.func)

        for sink_type, functions in self.taint_sinks.items():
            if func_name in functions:
                args = [
                    ast.unparse(arg) if hasattr(ast, 'unparse') else ''
                    for arg in node.args
                ]
                self.sinks.append({
                    "type": sink_type,
                    "function": func_name,
                    "line": node.lineno,
                    "arguments": args,
                })

        self.generic_visit(node)

    def _get_func_name(self, node) -> str:
        """Extract function name from Call node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""


class InjectionPointDetector(ast.NodeVisitor):
    """Detects potential injection points."""

    def __init__(self, known_variables: set):
        self.known_variables = known_variables
        self.injection_points: List[Dict[str, Any]] = []

    def visit_Call(self, node):
        """Detect string formatting with potentially tainted variables."""
        if self._is_dangerous_format(node):
            for arg in node.args:
                var_name = self._extract_var_name(arg)
                if var_name and var_name in self.known_variables:
                    self.injection_points.append({
                        "type": "format_injection",
                        "variable": var_name,
                        "line": node.lineno,
                        "context": self._get_func_name(node.func),
                    })

        self.generic_visit(node)

    def _is_dangerous_format(self, node) -> bool:
        """Check if this is a dangerous format operation."""
        func_name = self._get_func_name(node.func)
        return func_name in ("format", "f-string")

    def _extract_var_name(self, node) -> Optional[str]:
        """Extract variable name from node."""
        if isinstance(node, ast.Name):
            return node.id
        return None

    def _get_func_name(self, node) -> str:
        """Extract function name."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return node.attr
        return ""


class TaintFlowAnalyzer:
    """Performs taint flow analysis combining DF analysis."""

    def __init__(self, df_result: DFResult):
        self.df_result = df_result
        self.flows: List[TaintFlow] = []

    def analyze(self) -> TaintResult:
        """Analyze taint flows from sources to sinks."""
        self._build_taint_flows()

        vulnerable_vars = self._extract_vulnerable_variables()
        severity_summary = self._count_severities()

        return TaintResult(
            flows=[asdict(flow) for flow in self.flows],
            vulnerable_variables=vulnerable_vars,
            severity_summary=severity_summary,
        )

    def _build_taint_flows(self) -> None:
        """Build taint flows from sources to sinks."""
        for source in self.df_result.taint_sources:
            for sink in self.df_result.taint_sinks:
                # Simple heuristic: if source line < sink line, assume potential flow
                if source["line"] < sink["line"]:
                    severity = self._calculate_severity(source, sink)
                    self.flows.append(
                        TaintFlow(
                            source=source["function"],
                            source_line=source["line"],
                            sink=sink["function"],
                            sink_line=sink["line"],
                            path=[
                                f"{source['function']} -> {sink['function']}"
                            ],
                            severity=severity,
                        )
                    )

    def _extract_vulnerable_variables(self) -> List[str]:
        """Extract variables involved in taint flows."""
        vulnerable = set()
        for flow in self.flows:
            if flow.severity in ("critical", "high"):
                # Extract variable names from paths
                for part in flow.path:
                    if "->" in part:
                        vulnerable.add(part.split("->")[0].strip())
        return list(vulnerable)

    def _count_severities(self) -> Dict[str, int]:
        """Count findings by severity."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for flow in self.flows:
            summary[flow.severity] = summary.get(flow.severity, 0) + 1
        return summary

    def _calculate_severity(
        self,
        source: Dict[str, Any],
        sink: Dict[str, Any],
    ) -> str:
        """Calculate severity of taint flow."""
        critical_sinks = ["eval", "exec", "os_command"]
        high_sinks = ["sql"]

        if sink["type"] in critical_sinks:
            return "critical"
        elif sink["type"] in high_sinks:
            return "high"
        else:
            return "medium"


# ============================================================================
# SEMGREP INTEGRATION
# ============================================================================

class SemgrepRunner:
    """Runs Semgrep and parses results."""

    def __init__(self, target_path: str):
        self.target_path = target_path
        self.findings: List[SemgrepFinding] = []

    def run(self) -> Dict[str, Any]:
        """
        Run Semgrep on target path.

        Returns:
            Dictionary with Semgrep results
        """
        try:
            result = subprocess.run(
                ["semgrep", "--config", "auto", "--json", self.target_path],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode not in (0, 1):
                logger.warning(f"Semgrep failed with return code {result.returncode}")
                return {"error": result.stderr, "findings": []}

            return self._parse_semgrep_output(result.stdout)

        except FileNotFoundError:
            logger.warning("Semgrep not found in PATH")
            return {
                "error": "Semgrep not installed",
                "findings": [],
                "suggestion": "Install semgrep: 'pip install semgrep' and ensure it's on PATH",
            }
        except subprocess.TimeoutExpired:
            logger.warning("Semgrep analysis timed out")
            return {"error": "Analysis timeout", "findings": []}
        except Exception as e:
            logger.error(f"Semgrep execution error: {e}")
            return {"error": str(e), "findings": []}

    def _parse_semgrep_output(self, output: str) -> Dict[str, Any]:
        """Parse Semgrep JSON output."""
        try:
            data = json.loads(output)
            findings = []

            for result in data.get("results", []):
                finding = {
                    "rule_id": result.get("check_id", "unknown"),
                    "message": result.get("extra", {}).get("message", ""),
                    "severity": result.get("extra", {}).get("severity", "unknown"),
                    "file": result.get("path", ""),
                    "line": result.get("start", {}).get("line", 0),
                    "column": result.get("start", {}).get("col", 0),
                    "code_snippet": result.get("extra", {}).get("lines", ""),
                }
                findings.append(finding)

            return {
                "findings": findings,
                "total": len(findings),
                "errors": data.get("errors", []),
            }
        except json.JSONDecodeError:
            logger.error("Failed to parse Semgrep JSON output")
            return {"error": "Invalid JSON output", "findings": []}


# ============================================================================
# MAIN PREPROCESSOR CLASS
# ============================================================================

class SourcePreprocessor:
    """
    Main preprocessing module for source code security analysis.

    This class orchestrates all analysis steps: file enumeration, metadata
    extraction, AST analysis, CFG generation, data flow analysis, taint tracking,
    and Semgrep integration.
    """

    def __init__(self, target_path: str):
        """
        Initialize the preprocessor.

        Args:
            target_path: Path to a single file or directory
        """
        self.target_path = Path(target_path)
        self.artifact_id = str(uuid.uuid4())
        self.source_files: List[FileMetadata] = []
        self.languages_detected: Set[str] = set()
        self.errors: List[str] = []
        self.warnings: List[str] = []

        # Analysis results
        self.ast_results: Dict[str, Optional[ASTResult]] = {}
        self.cfg_results: Dict[str, Optional[CFGResult]] = {}
        self.df_results: Dict[str, Optional[DFResult]] = {}
        self.taint_results: Dict[str, Optional[TaintResult]] = {}
        self.semgrep_results: Optional[Dict[str, Any]] = None
        self.file_hashes: Dict[str, str] = {}

    def preprocess(self) -> Dict[str, Any]:
        """
        Execute full preprocessing pipeline.

        Returns:
            Structured result dictionary
        """
        logger.info(f"Starting preprocessing of {self.target_path}")

        # Step 1: Enumerate files and extract metadata
        self._enumerate_files()

        if not self.source_files:
            self.errors.append(f"No source files found in {self.target_path}")
            return self._build_result()

        # Step 2: Analyze each file
        for file_meta in self.source_files:
            self._analyze_file(file_meta)

        # Step 3: Run Semgrep on the entire target
        self._run_semgrep()

        logger.info(f"Preprocessing complete. Artifact ID: {self.artifact_id}")
        return self._build_result()

    def _enumerate_files(self) -> None:
        """Enumerate all source files and extract metadata."""
        logger.info("Enumerating source files...")

        if self.target_path.is_file():
            files_to_process = [self.target_path]
        else:
            files_to_process = list(self.target_path.rglob("*"))

        for file_path in files_to_process:
            if not file_path.is_file():
                continue

            language = self._detect_language(file_path)
            if language is None:
                continue

            try:
                metadata = self._extract_file_metadata(file_path, language)
                self.source_files.append(metadata)
                self.languages_detected.add(language)
                logger.debug(f"Enumerated: {file_path}")
            except Exception as e:
                error_msg = f"Failed to process {file_path}: {e}"
                logger.error(error_msg)
                self.errors.append(error_msg)

        logger.info(f"Found {len(self.source_files)} source files")

    def _detect_language(self, file_path: Path) -> Optional[str]:
        """
        Detect programming language by file extension.

        Args:
            file_path: Path to the file

        Returns:
            Language code or None if unsupported
        """
        suffix = file_path.suffix.lower()
        for lang in SupportedLanguage:
            if suffix in lang.extensions:
                return lang.value
        return None

    def _extract_file_metadata(self, file_path: Path, language: str) -> FileMetadata:
        """
        Extract metadata for a source file.

        Args:
            file_path: Path to the file
            language: Programming language

        Returns:
            FileMetadata object
        """
        with open(file_path, "rb") as f:
            content = f.read()

        sha256_hash = hashlib.sha256(content).hexdigest()
        line_count = len(content.decode("utf-8", errors="ignore").splitlines())

        # Compute a robust relative path. Avoid relying on Path.is_relative_to()
        # for compatibility and handle cases where relative_to may fail.
        try:
            rel = file_path.relative_to(self.target_path)
        except Exception:
            try:
                # Try resolving both paths then compute relative
                rel = file_path.resolve().relative_to(self.target_path.resolve())
            except Exception:
                rel = file_path

        # Use file name if relative computation yields '.' or empty
        rel_str = str(rel)
        if rel_str in ("", "."):
            rel_str = str(file_path.name)

        return FileMetadata(
            path=str(file_path),
            relative_path=rel_str,
            language=language,
            sha256_hash=sha256_hash,
            size_bytes=len(content),
            line_count=line_count,
        )

    def _analyze_file(self, file_meta: FileMetadata) -> None:
        """
        Perform all analyses on a source file.

        Args:
            file_meta: File metadata
        """
        logger.info(f"Analyzing {file_meta.relative_path}...")

        try:
            with open(file_meta.path, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
        except Exception as e:
            error_msg = f"Failed to read {file_meta.path}: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)
            return

        file_key = file_meta.relative_path

        # Store hash
        self.file_hashes[file_key] = file_meta.sha256_hash

        # Language-specific analysis
        if file_meta.language == "py":
            self._analyze_python_file(file_key, code)
        else:
            self._analyze_generic_file(file_key, file_meta.language, code)

    def _analyze_python_file(self, file_key: str, code: str) -> None:
        """Analyze a Python file."""
        # AST analysis
        ast_result = PythonASTAnalyzer.extract_ast_info(code)
        self.ast_results[file_key] = ast_result

        # CFG analysis
        cfg_result = PythonASTAnalyzer.build_cfg(code)
        self.cfg_results[file_key] = cfg_result

        # Data flow analysis
        try:
            df_analyzer = DataFlowAnalyzer(code)
            df_result = df_analyzer.analyze()
            self.df_results[file_key] = df_result

            # Taint flow analysis
            taint_analyzer = TaintFlowAnalyzer(df_result)
            taint_result = taint_analyzer.analyze()
            self.taint_results[file_key] = taint_result
        except Exception as e:
            warning_msg = f"Failed data flow analysis for {file_key}: {e}"
            logger.warning(warning_msg)
            self.warnings.append(warning_msg)

    def _analyze_generic_file(
        self,
        file_key: str,
        language: str,
        code: str,
    ) -> None:
        """Analyze a non-Python file."""
        # For non-Python languages, attempt basic analysis
        try:
            # Attempt AST-like analysis through pattern matching
            ast_info = self._extract_generic_ast_info(language, code)
            self.ast_results[file_key] = ast_info
        except Exception as e:
            warning_msg = f"Failed AST analysis for {file_key}: {e}"
            logger.warning(warning_msg)
            self.warnings.append(warning_msg)

    def _extract_generic_ast_info(
        self,
        language: str,
        code: str,
    ) -> ASTResult:
        """Extract AST-like information from non-Python code."""
        # Simple regex-based extraction for generic languages
        functions = re.findall(
            r'(?:def|function|func|fn)\s+(\w+)\s*\(',
            code,
            re.IGNORECASE,
        )
        classes = re.findall(
            r'(?:class|interface|struct|type)\s+(\w+)',
            code,
            re.IGNORECASE,
        )
        imports = re.findall(
            r'(?:import|use|require|include)\s+["\']?([^\s"\']+)',
            code,
            re.IGNORECASE,
        )

        return ASTResult(
            node_count=len(code.split("\n")),
            tree_depth=0,
            functions=functions,
            classes=classes,
            imports=imports,
            summary=f"Language: {language}, Functions: {len(functions)}, "
            f"Classes: {len(classes)}, Imports: {len(imports)}",
        )

    def _run_semgrep(self) -> None:
        """Run Semgrep on the target."""
        logger.info("Running Semgrep analysis...")
        runner = SemgrepRunner(str(self.target_path))
        self.semgrep_results = runner.run()
        logger.info(
            f"Semgrep found {self.semgrep_results.get('total', 0)} issues"
        )

    def _build_result(self) -> Dict[str, Any]:
        """Build the final result dictionary."""
        return {
            "artifact_id": self.artifact_id,
            "source_files": [asdict(f) for f in self.source_files],
            "languages_detected": sorted(list(self.languages_detected)),
            "ast_results": {
                k: asdict(v) if v else None
                for k, v in self.ast_results.items()
            },
            "cfg_results": {
                k: asdict(v) if v else None
                for k, v in self.cfg_results.items()
            },
            "df_results": {
                k: asdict(v) if v else None
                for k, v in self.df_results.items()
            },
            "taint_results": {
                k: asdict(v) if v else None
                for k, v in self.taint_results.items()
            },
            "semgrep": self.semgrep_results or {},
            "hashes": self.file_hashes,
            "errors": self.errors,
            "warnings": self.warnings,
        }


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def preprocess_source(
    target_path: str,
    output_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Main entry point for source preprocessing.

    Args:
        target_path: Path to source file or directory
        output_file: Optional path to save results as JSON

    Returns:
        Preprocessing results dictionary
    """
    preprocessor = SourcePreprocessor(target_path)
    results = preprocessor.preprocess()

    if output_file:
        try:
            with open(output_file, "w") as f:
                json.dump(results, f, indent=2, default=str)
            logger.info(f"Results saved to {output_file}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")

    return results


if __name__ == "__main__":
    # Example usage
    if len(sys.argv) < 2:
        print("Usage: python source_preprocessing.py <path> [output_file]")
        sys.exit(1)

    target = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else None

    results = preprocess_source(target, output)
    print(json.dumps(results, indent=2, default=str))
