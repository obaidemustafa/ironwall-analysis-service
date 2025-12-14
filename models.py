"""
Pydantic Models for IronWall Analysis Service API

This module contains all request and response models for the FastAPI endpoints.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime


# ============================================================================
# ENUMS
# ============================================================================

class FileType(str, Enum):
    """Type of file being analyzed."""
    SOURCE = "source"
    BINARY = "binary"
    ANY = "any"


class AnalysisStatus(str, Enum):
    """Status of an analysis job."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(str, Enum):
    """Severity level for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ============================================================================
# REQUEST MODELS
# ============================================================================

class CVEAnalysisRequest(BaseModel):
    """Request model for CVE-based vulnerability analysis."""
    cve_id: str = Field(..., description="CVE identifier (e.g., CVE-2024-1234)")
    description: str = Field(..., description="Vulnerability description and details")
    file_type: FileType = Field(default=FileType.ANY, description="Type of advisory file")
    
    class Config:
        json_schema_extra = {
            "example": {
                "cve_id": "CVE-2024-1234",
                "description": "Heap buffer overflow in libpng when processing malformed PNG files",
                "file_type": "source"
            }
        }


class PreprocessingRequest(BaseModel):
    """Request model for file preprocessing."""
    artifact_path: str = Field(..., description="Path to the artifact to preprocess")
    
    class Config:
        json_schema_extra = {
            "example": {
                "artifact_path": "/tmp/uploads/vulnerable_app"
            }
        }


class DockerfileGenerationRequest(BaseModel):
    """Request model for Dockerfile generation."""
    cve_id: str = Field(..., description="CVE identifier")
    target_name: str = Field(default="", description="Name of the target application")
    language: str = Field(default="c", description="Primary programming language")
    dependencies: List[str] = Field(default=[], description="Required system dependencies")
    build_instructions: str = Field(default="", description="Custom build instructions")
    
    class Config:
        json_schema_extra = {
            "example": {
                "cve_id": "CVE-2024-1234",
                "target_name": "libpng-1.6.37",
                "language": "c",
                "dependencies": ["libpng-dev", "zlib1g-dev"],
                "build_instructions": "./configure && make"
            }
        }


class ExploitGenerationRequest(BaseModel):
    """Request model for exploit code generation."""
    cve_id: str = Field(..., description="CVE identifier")
    vulnerability_type: str = Field(..., description="Type of vulnerability (e.g., buffer_overflow, use_after_free)")
    target_info: Dict[str, Any] = Field(default={}, description="Target application information")
    preprocessing_result: Optional[Dict[str, Any]] = Field(default=None, description="Preprocessing analysis results")
    
    class Config:
        json_schema_extra = {
            "example": {
                "cve_id": "CVE-2024-1234",
                "vulnerability_type": "heap_buffer_overflow",
                "target_info": {
                    "name": "libpng",
                    "version": "1.6.37",
                    "architecture": "x86_64"
                }
            }
        }


class ValidationRequest(BaseModel):
    """Request model for exploit validation."""
    exploit_code: str = Field(..., description="The exploit code to validate")
    dockerfile: str = Field(..., description="Dockerfile for sandbox environment")
    timeout_seconds: int = Field(default=60, description="Maximum execution time")
    
    class Config:
        json_schema_extra = {
            "example": {
                "exploit_code": "#!/usr/bin/env python3\n...",
                "dockerfile": "FROM ubuntu:22.04\n...",
                "timeout_seconds": 60
            }
        }


# ============================================================================
# RESPONSE MODELS
# ============================================================================

class Finding(BaseModel):
    """A security finding from analysis."""
    id: str
    title: str
    severity: SeverityLevel
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None


class PreprocessingResponse(BaseModel):
    """Response model for preprocessing results."""
    artifact_id: str
    type: str
    status: AnalysisStatus
    file_count: int = 0
    languages_detected: List[str] = []
    findings: List[Finding] = []
    metadata: Dict[str, Any] = {}
    semgrep_results: Optional[Dict[str, Any]] = None
    ast_summary: Optional[Dict[str, Any]] = None
    cfg_results: Optional[Dict[str, Any]] = None
    df_results: Optional[Dict[str, Any]] = None
    taint_results: Optional[Dict[str, Any]] = None
    source_files: Optional[List[Dict[str, Any]]] = None
    file_hashes: Optional[Dict[str, str]] = None
    error: Optional[str] = None


class DockerfileResponse(BaseModel):
    """Response model for Dockerfile generation."""
    dockerfile: str
    filename: str = "Dockerfile"
    metadata: Dict[str, Any] = {}
    warnings: List[str] = []


class ExploitResponse(BaseModel):
    """Response model for exploit generation."""
    exploit_code: str
    filename: str = "exploit.py"
    vulnerability_type: str
    target_info: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}
    warnings: List[str] = []


class ValidationResult(BaseModel):
    """Result of exploit validation."""
    success: bool
    status: str
    execution_time: float
    crash_address: Optional[str] = None
    crash_type: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    evidence: Dict[str, Any] = {}


class ValidationResponse(BaseModel):
    """Response model for validation results."""
    validation_id: str
    status: AnalysisStatus
    result: Optional[ValidationResult] = None
    report: Optional[str] = None
    error: Optional[str] = None


class CampaignResponse(BaseModel):
    """Response model for a complete campaign."""
    campaign_id: str
    cve_id: str
    status: AnalysisStatus
    created_at: datetime
    preprocessing: Optional[PreprocessingResponse] = None
    dockerfile: Optional[DockerfileResponse] = None
    exploit: Optional[ExploitResponse] = None
    validation: Optional[ValidationResponse] = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    service: str
    version: str
    timestamp: datetime


class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    detail: Optional[str] = None
    status_code: int
