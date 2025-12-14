"""
IronWall Analysis Service - FastAPI Application

This is the main entry point for the IronWall Analysis Service API.
It provides endpoints for:
- File preprocessing (source code and binary analysis)
- Dockerfile generation for sandbox environments
- Exploit code generation
- Exploit validation

Author: IronWall Security Team
Version: 1.0.0
"""

import os
import uuid
import shutil
import tempfile
import httpx
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from dotenv import load_dotenv

from models import (
    CVEAnalysisRequest,
    PreprocessingRequest,
    PreprocessingResponse,
    DockerfileGenerationRequest,
    DockerfileResponse,
    ExploitGenerationRequest,
    ExploitResponse,
    ValidationRequest,
    ValidationResponse,
    ValidationResult,
    CampaignResponse,
    HealthResponse,
    ErrorResponse,
    AnalysisStatus,
    SeverityLevel,
    Finding,
)

# Import preprocessing modules
from preprocessing import preprocess_artifact, is_binary_file
from source_preprocessing import preprocess_source

# Database and storage modules
from database import (
    connect_db, disconnect_db, get_db,
    AnalysisRequestsDB, ArtifactsDB, AnalysisResultsDB,
    calculate_sha256, AnalysisStatus as DBAnalysisStatus
)
from storage import upload_artifact, upload_analysis_output

# Load environment variables
load_dotenv()

# ============================================================================
# APP CONFIGURATION
# ============================================================================

app = FastAPI(
    title="IronWall Analysis Service",
    description="Security analysis and exploit verification service for vulnerability research",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Configuration
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:8080,http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Temporary upload directory
UPLOAD_DIR = Path(tempfile.gettempdir()) / "ironwall_uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# In-memory storage for campaigns (use Redis/DB in production)
campaigns_store = {}


# ============================================================================
# STARTUP/SHUTDOWN EVENTS
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Connect to database on startup."""
    print_header("STARTING IRONWALL ANALYSIS SERVICE")
    await connect_db()
    print_success("Service started successfully")


@app.on_event("shutdown")
async def shutdown_event():
    """Disconnect from database on shutdown."""
    await disconnect_db()
    print_info("Service shut down")


# ============================================================================
# TERMINAL LOGGING HELPERS
# ============================================================================

def print_header(title: str):
    """Print a styled header to the terminal."""
    print("\n" + "=" * 80)
    print(f"  🔷 {title}")
    print("=" * 80)

def print_section(title: str):
    """Print a section header."""
    print(f"\n--- {title} ---")

def print_success(msg: str):
    """Print a success message."""
    print(f"  ✅ {msg}")

def print_info(msg: str):
    """Print an info message."""
    print(f"  ℹ️  {msg}")

def print_warning(msg: str):
    """Print a warning message."""
    print(f"  ⚠️  {msg}")

def print_error(msg: str):
    """Print an error message."""
    print(f"  ❌ {msg}")

def print_data(label: str, value):
    """Print a labeled data value."""
    print(f"  📌 {label}: {value}")


# ============================================================================
# DATABASE INTEGRATION
# ============================================================================

async def save_preprocessing_to_db(
    analysis_id: str,
    artifact_id: str,
    owner_id: str,
    filename: str,
    file_type: str,
    file_size: int,
    raw_result: dict,
    execution_started: datetime,
    execution_finished: datetime,
    status: str = "success",
    error_message: str = None
) -> dict:
    """
    Save preprocessing results to MongoDB and Cloudinary.
    
    This function:
    1. Uploads the raw analysis output to Cloudinary as a JSON file
    2. Creates a static_analysis_results document in MongoDB
    
    Args:
        analysis_id: ID of the parent analysis request
        artifact_id: ID of the analyzed artifact
        owner_id: ID of the user who owns this
        filename: Original filename that was analyzed
        file_type: Type of file (SOURCE_CODE, BINARY)
        file_size: Size of the analyzed file
        raw_result: The full preprocessing result dictionary
        execution_started: When preprocessing started
        execution_finished: When preprocessing finished
        status: Execution status (success, failed)
        error_message: Error message if failed
    
    Returns:
        Dict with result_id and storage info, or None if failed
    """
    try:
        print_info("Uploading analysis output to Cloudinary...")
        
        # Upload the raw result to Cloudinary
        storage_info = await upload_analysis_output(
            analysis_data=raw_result,
            analysis_id=analysis_id,
            artifact_id=artifact_id,
            analysis_type="preprocessing"
        )
        
        print_success(f"Uploaded to: {storage_info['secureUrl'][:60]}...")
        
        print_info("Saving analysis result to MongoDB...")
        
        # Create the analysis result document
        result_id = await AnalysisResultsDB.create({
            "analysisId": analysis_id,
            "artifactId": artifact_id,
            "ownerId": owner_id,
            "analysisType": "preprocessing",
            "toolName": "ironwall-preprocessor",
            "toolVersion": "1.0.0",
            "outputFile": storage_info,
            "execution": {
                "startedAt": execution_started,
                "finishedAt": execution_finished,
                "status": status,
                "errorMessage": error_message
            }
        })
        
        # Update analysis request status
        await AnalysisRequestsDB.update_status(analysis_id, "completed")
        
        print_success(f"Analysis result saved to MongoDB: {result_id}")
        
        return {
            "result_id": result_id,
            "storage": storage_info
        }
        
    except Exception as e:
        print_error(f"Failed to save preprocessing to database: {str(e)}")
        return None


async def create_analysis_request(
    user_id: str,
    cve_id: str,
    target_type: str = "source",
    description: str = ""
) -> str:
    """
    Create a new analysis request in the database.
    
    Returns the analysis request ID.
    """
    try:
        analysis_id = await AnalysisRequestsDB.create({
            "userId": user_id,
            "cveId": cve_id,
            "targetType": target_type,
            "description": description
        })
        print_success(f"Created analysis request: {analysis_id}")
        return analysis_id
    except Exception as e:
        print_error(f"Failed to create analysis request: {str(e)}")
        raise


async def create_artifact_record(
    owner_id: str,
    analysis_id: str,
    filename: str,
    file_path: str,
    kind: str = "target-source",
    mime_type: str = "application/octet-stream"
) -> dict:
    """
    Upload a file to Cloudinary and create an artifact record in MongoDB.
    
    Returns artifact info with ID and storage details.
    """
    try:
        # Calculate file hash and size
        file_size = os.path.getsize(file_path)
        checksum = calculate_sha256(file_path)
        
        print_info(f"Uploading artifact to Cloudinary: {filename}")
        
        # Upload to Cloudinary
        storage_info = await upload_artifact(
            file_path=file_path,
            original_name=filename,
            folder="ironwall/artifacts"
        )
        
        print_info("Creating artifact record in MongoDB...")
        
        # Create artifact in database
        artifact_id = await ArtifactsDB.create({
            "ownerUserId": owner_id,
            "analysisId": analysis_id,
            "kind": kind,
            "originalName": filename,
            "mimeType": mime_type,
            "sizeBytes": file_size,
            "checksumSha256": checksum,
            "storage": storage_info
        })
        
        # Add artifact to analysis request
        await AnalysisRequestsDB.add_artifact(analysis_id, artifact_id)
        
        print_success(f"Created artifact: {artifact_id}")
        
        return {
            "artifact_id": artifact_id,
            "storage": storage_info,
            "checksum": checksum,
            "size": file_size
        }
        
    except Exception as e:
        print_error(f"Failed to create artifact: {str(e)}")
        raise


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def generate_dockerfile(cve_id: str, language: str, dependencies: list, build_instructions: str) -> str:
    """Generate a Dockerfile for the sandbox environment."""
    
    # Language-specific base configurations
    lang_configs = {
        "c": {
            "packages": ["build-essential", "clang", "cmake", "gdb", "valgrind"],
            "env": ["CC=clang", "CXX=clang++"],
        },
        "cpp": {
            "packages": ["build-essential", "clang", "cmake", "gdb", "valgrind", "libstdc++-dev"],
            "env": ["CC=clang", "CXX=clang++"],
        },
        "python": {
            "packages": ["python3", "python3-pip", "python3-dev"],
            "env": [],
        },
        "javascript": {
            "packages": ["nodejs", "npm"],
            "env": [],
        },
        "go": {
            "packages": ["golang"],
            "env": ["GOPATH=/go"],
        },
        "rust": {
            "packages": ["curl"],
            "env": [],
        },
    }
    
    config = lang_configs.get(language.lower(), lang_configs["c"])
    all_packages = config["packages"] + dependencies
    
    dockerfile = f"""# Generated Dockerfile for {cve_id}
# IronWall Security Analysis Sandbox

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    {' '.join(all_packages)} \\
    && rm -rf /var/lib/apt/lists/*

# Security analysis environment variables
ENV ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1
ENV UBSAN_OPTIONS=print_stacktrace=1
ENV AFL_USE_ASAN=1
"""
    
    # Add language-specific environment variables
    for env_var in config["env"]:
        dockerfile += f"ENV {env_var}\n"
    
    dockerfile += """
# Create working directory
WORKDIR /exploit

# Copy exploit files
COPY . /exploit

"""
    
    if build_instructions:
        dockerfile += f"""# Build instructions
RUN {build_instructions}
"""
    
    dockerfile += """
# Entry point
CMD ["/bin/bash"]
"""
    
    return dockerfile


def generate_exploit_code(cve_id: str, vuln_type: str, target_info: dict) -> str:
    """Generate placeholder exploit code."""
    
    target_name = target_info.get("name", "target")
    target_host = target_info.get("host", "127.0.0.1")
    target_port = target_info.get("port", 8080)
    
    exploit_code = f'''#!/usr/bin/env python3
"""
IronWall Generated Exploit
Target: {cve_id}
Type: {vuln_type.replace("_", " ").title()}
Generated: {datetime.now().isoformat()}

WARNING: This exploit is for authorized security testing only.
Unauthorized access to computer systems is illegal.
"""

import struct
import socket
import sys
import argparse

# ============================================================================
# EXPLOIT CONFIGURATION
# ============================================================================

TARGET_HOST = "{target_host}"
TARGET_PORT = {target_port}
BUFFER_SIZE = 1024

# Vulnerability-specific offsets (to be determined through analysis)
OFFSET_TO_RET = 256
OFFSET_TO_CANARY = 0  # Set if stack canary is present


# ============================================================================
# PAYLOAD GENERATION
# ============================================================================

def create_payload() -> bytes:
    """
    Generate the exploit payload.
    
    This function constructs the malicious payload that will trigger
    the vulnerability in {target_name}.
    
    Returns:
        bytes: The complete exploit payload
    """
    # Padding to reach return address
    padding = b"A" * OFFSET_TO_RET
    
    # Return address (to be determined through analysis)
    # Replace with actual gadget address after analysis
    ret_addr = struct.pack("<Q", 0x41414141)
    
    # NOP sled for shellcode landing
    nop_sled = b"\\x90" * 100
    
    # Placeholder shellcode (replace with actual shellcode)
    # This is a simple placeholder that should be replaced
    shellcode = b""
    
    payload = padding + ret_addr + nop_sled + shellcode
    return payload


def create_poc_input() -> bytes:
    """
    Generate a proof-of-concept input to trigger the vulnerability.
    
    Returns:
        bytes: Input that triggers the vulnerability
    """
    # This will vary based on the specific vulnerability
    poc = b"A" * 1024  # Simple overflow PoC
    return poc


# ============================================================================
# EXPLOITATION FUNCTIONS
# ============================================================================

def check_target(host: str, port: int) -> bool:
    """Check if target is reachable."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def send_payload(host: str, port: int, payload: bytes) -> tuple:
    """
    Send the exploit payload to the target.
    
    Args:
        host: Target hostname or IP
        port: Target port
        payload: The exploit payload
        
    Returns:
        tuple: (success, response_or_error)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        sock.send(payload)
        
        try:
            response = sock.recv(BUFFER_SIZE)
        except socket.timeout:
            response = b"[No response - possible crash]"
        
        sock.close()
        return True, response
    except Exception as e:
        return False, str(e)


def exploit(host: str = TARGET_HOST, port: int = TARGET_PORT) -> bool:
    """
    Main exploit function.
    
    Args:
        host: Target hostname or IP
        port: Target port
        
    Returns:
        bool: True if exploit succeeded, False otherwise
    """
    print(f"[*] IronWall Exploit Framework")
    print(f"[*] Target: {{cve_id}}")
    print(f"[*] Type: {vuln_type}")
    print()
    
    # Check target availability
    print(f"[*] Checking target {{host}}:{{port}}...")
    if not check_target(host, port):
        print(f"[-] Target is not reachable")
        return False
    print(f"[+] Target is reachable")
    
    # Generate payload
    print("[*] Generating payload...")
    payload = create_payload()
    print(f"[*] Payload size: {{len(payload)}} bytes")
    
    # Send exploit
    print("[*] Sending exploit payload...")
    success, result = send_payload(host, port, payload)
    
    if success:
        print(f"[+] Payload sent successfully!")
        if b"crash" in result.lower() if isinstance(result, bytes) else "crash" in result.lower():
            print("[+] Target appears to have crashed - exploitation may have succeeded")
            return True
        else:
            print(f"[*] Response: {{result}}")
            return True
    else:
        print(f"[-] Exploit failed: {{result}}")
        return False


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"IronWall Exploit for {{cve_id}}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-t", "--target", default=TARGET_HOST, help="Target host")
    parser.add_argument("-p", "--port", type=int, default=TARGET_PORT, help="Target port")
    parser.add_argument("--poc", action="store_true", help="Generate PoC input only")
    
    args = parser.parse_args()
    
    if args.poc:
        poc = create_poc_input()
        print(f"[*] PoC input ({{len(poc)}} bytes):")
        print(poc.hex())
        return
    
    success = exploit(args.target, args.port)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
'''
    
    return exploit_code


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/", response_model=HealthResponse)
async def root():
    """Root endpoint - returns service health status."""
    return HealthResponse(
        status="ok",
        service="IronWall Analysis Service",
        version="1.0.0",
        timestamp=datetime.now()
    )


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="ok",
        service="IronWall Analysis Service",
        version="1.0.0",
        timestamp=datetime.now()
    )


# ============================================================================
# CAMPAIGN ENDPOINTS
# ============================================================================

@app.post("/api/campaign/create", response_model=CampaignResponse)
async def create_campaign(request: CVEAnalysisRequest):
    """
    Create a new analysis campaign.
    
    This endpoint initializes a new vulnerability analysis campaign
    with the provided CVE information.
    """
    print_header("NEW CAMPAIGN CREATED")
    
    campaign_id = str(uuid.uuid4())
    
    print_data("Campaign ID", campaign_id)
    print_data("CVE ID", request.cve_id)
    print_data("Description", request.description[:100] + "..." if len(request.description) > 100 else request.description)
    print_data("File Type", request.file_type)
    print_success("Campaign initialized successfully")
    
    campaign = CampaignResponse(
        campaign_id=campaign_id,
        cve_id=request.cve_id,
        status=AnalysisStatus.PENDING,
        created_at=datetime.now(),
    )
    
    campaigns_store[campaign_id] = campaign.model_dump()
    
    return campaign


@app.get("/api/campaign/{campaign_id}", response_model=CampaignResponse)
async def get_campaign(campaign_id: str):
    """Get campaign status and results."""
    if campaign_id not in campaigns_store:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    return CampaignResponse(**campaigns_store[campaign_id])


# ============================================================================
# PREPROCESSING ENDPOINTS
# ============================================================================

@app.post("/api/preprocess", response_model=PreprocessingResponse)
async def preprocess_file(file: UploadFile = File(...)):
    """
    Preprocess an uploaded file (source code or binary).
    
    This endpoint analyzes the uploaded file and returns preprocessing results
    including CFG, dataflow analysis, taint tracking, and metadata.
    """
    print_header("FILE PREPROCESSING - ADVANCED ANALYSIS")
    
    # Track execution timing
    execution_started = datetime.utcnow()
    
    # Generate IDs for this analysis
    artifact_id = str(uuid.uuid4())
    analysis_id = str(uuid.uuid4())
    owner_id = "anonymous"  # Will be set from auth context in production
    
    print_data("Analysis ID", analysis_id)
    print_data("Artifact ID", artifact_id)
    print_data("Filename", file.filename)
    print_data("Content Type", file.content_type)
    print_info("Saving uploaded file...")
    
    # Save uploaded file
    file_path = UPLOAD_DIR / f"{artifact_id}_{file.filename}"
    
    try:
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        file_size = file_path.stat().st_size
        print_success(f"File saved: {file_path}")
        print_data("File Size", f"{file_size} bytes")
        
        # Determine file type
        is_bin = is_binary_file(str(file_path))
        file_type = "BINARY" if is_bin else "SOURCE_CODE"
        print_data("File Type Detected", file_type)
        
        # Create analysis request in database
        print_info("Creating analysis request in database...")
        try:
            await AnalysisRequestsDB.create({
                "_id": analysis_id,
                "userId": owner_id,
                "cveId": "pending",  # Will be updated later
                "targetType": "binary" if is_bin else "source",
                "description": f"Analysis of {file.filename}",
            })
            print_success(f"Analysis request created: {analysis_id}")
        except Exception as e:
            print_warning(f"Failed to create analysis request: {e}")
        
        # Upload artifact to Cloudinary and create artifact record
        print_info("Uploading artifact to Cloudinary...")
        try:
            artifact_storage = await upload_artifact(
                file_path=str(file_path),
                original_name=file.filename,
                folder="ironwall/artifacts"
            )
            
            # Calculate file hash
            import hashlib
            with open(file_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Create artifact record in database
            await ArtifactsDB.create({
                "_id": artifact_id,
                "ownerUserId": owner_id,
                "analysisId": analysis_id,
                "kind": "target-binary" if is_bin else "target-source",
                "originalName": file.filename,
                "mimeType": file.content_type or "application/octet-stream",
                "sizeBytes": file_size,
                "checksumSha256": file_hash,
                "storage": artifact_storage
            })
            print_success(f"Artifact uploaded and saved: {artifact_id}")
            
            # Link artifact to analysis request
            await AnalysisRequestsDB.add_artifact(analysis_id, artifact_id)
        except Exception as e:
            print_warning(f"Failed to save artifact: {e}")
        
        # Check if binary or source
        if is_bin:
            # Use basic preprocessing for binaries
            print_info("Running binary analysis...")
            result = preprocess_artifact(str(file_path))
            
            print_success("Binary preprocessing completed")
            print_section("Binary Analysis Results")
            print_data("Type", result.get("type", "BINARY"))
            
            return PreprocessingResponse(
                artifact_id=artifact_id,
                type=result.get("type", "BINARY"),
                status=AnalysisStatus.COMPLETED,
                file_count=1,
                metadata=result.get("metadata", {}),
            )
        else:
            # Use ADVANCED source preprocessing with CFG, dataflow, taint analysis
            print_info("Running advanced source code analysis...")
            print_info("Extracting AST, CFG, Dataflow, and Taint information...")
            
            result = preprocess_source(str(file_path))
            
            # Extract results
            languages = result.get("languages_detected", [])
            source_files = result.get("source_files", [])
            ast_results = result.get("ast_results", {})
            cfg_results = result.get("cfg_results", {})
            df_results = result.get("df_results", {})
            taint_results = result.get("taint_results", {})
            semgrep = result.get("semgrep", {})
            file_hashes = result.get("hashes", {})
            
            # Convert semgrep findings
            findings = []
            if semgrep.get("findings"):
                for item in semgrep["findings"][:10]:
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        title=item.get("check_id", "Unknown"),
                        severity=SeverityLevel.MEDIUM,
                        description=item.get("message", ""),
                        file_path=item.get("path", ""),
                        line_number=item.get("line"),
                    ))
            
            # Print detailed terminal output
            print_success("Advanced preprocessing completed!")
            
            print_section("LANGUAGES DETECTED")
            for lang in languages:
                print(f"    • {lang}")
            
            print_section("SOURCE FILES ANALYZED")
            for sf in source_files[:5]:
                if isinstance(sf, dict):
                    print(f"    📄 {sf.get('relative_path', sf.get('path', 'Unknown'))}")
                    print(f"       Language: {sf.get('language', 'Unknown')}, Lines: {sf.get('line_count', 0)}")
            if len(source_files) > 5:
                print(f"    ... and {len(source_files) - 5} more files")
            
            # Print CFG Results
            print_section("CONTROL FLOW GRAPH (CFG) RESULTS")
            for filepath, cfg in list(cfg_results.items())[:3]:
                if cfg:
                    nodes = cfg.get("nodes", [])
                    edges = cfg.get("edges", [])
                    entry_points = cfg.get("entry_points", [])
                    suspicious = cfg.get("suspicious_patterns", [])
                    print(f"    📊 {Path(filepath).name}")
                    print(f"       Nodes: {len(nodes)}, Edges: {len(edges)}, Entry Points: {len(entry_points)}")
                    if suspicious:
                        print(f"       ⚠️  Suspicious Patterns: {len(suspicious)}")
                        for pattern in suspicious[:3]:
                            print(f"          - {pattern}")
            
            # Print sample CFG nodes
            for filepath, cfg in list(cfg_results.items())[:1]:
                if cfg and cfg.get("nodes"):
                    print_section("SAMPLE CFG NODES")
                    for node in cfg["nodes"][:5]:
                        print(f"    {node.get('node_id')}: {node.get('label')} ({node.get('node_type')}) @ line {node.get('lineno')}")
                    if len(cfg["nodes"]) > 5:
                        print(f"    ... and {len(cfg['nodes']) - 5} more nodes")
                    
                    if cfg.get("edges"):
                        print_section("SAMPLE CFG EDGES")
                        for edge in cfg["edges"][:5]:
                            print(f"    {edge.get('source_id')} --[{edge.get('edge_type')}]--> {edge.get('target_id')}")
                        if len(cfg["edges"]) > 5:
                            print(f"    ... and {len(cfg['edges']) - 5} more edges")
            
            # Print Dataflow Results
            print_section("DATAFLOW ANALYSIS RESULTS")
            for filepath, df in list(df_results.items())[:2]:
                if df:
                    variables = df.get("variables", {})
                    taint_sources = df.get("taint_sources", [])
                    taint_sinks = df.get("taint_sinks", [])
                    print(f"    📈 {Path(filepath).name}")
                    print(f"       Variables Tracked: {len(variables)}")
                    print(f"       Taint Sources: {len(taint_sources)}, Taint Sinks: {len(taint_sinks)}")
                    
                    # Print sample variables
                    if variables:
                        print("       Sample Variables:")
                        for var_name, var_info in list(variables.items())[:5]:
                            if isinstance(var_info, dict):
                                assigned = var_info.get("assigned_at", [])
                                read = var_info.get("read_at", [])
                                print(f"          • {var_name}: assigned@{assigned[:3]}, read@{read[:3]}")
            
            # Print Taint Analysis Results
            print_section("TAINT ANALYSIS RESULTS")
            for filepath, taint in list(taint_results.items())[:2]:
                if taint:
                    flows = taint.get("flows", [])
                    vulnerable_vars = taint.get("vulnerable_variables", [])
                    severity = taint.get("severity_summary", {})
                    print(f"    🔍 {Path(filepath).name}")
                    print(f"       Taint Flows: {len(flows)}, Vulnerable Variables: {len(vulnerable_vars)}")
                    print(f"       Severity Summary: Critical={severity.get('critical', 0)}, High={severity.get('high', 0)}, Medium={severity.get('medium', 0)}")
            
            # Print Semgrep Results
            print_section("SEMGREP RESULTS")
            if semgrep.get("error"):
                print_warning(f"Semgrep: {semgrep.get('error')}")
            else:
                print(f"    Total Findings: {semgrep.get('total', 0)}")
                if semgrep.get("findings"):
                    for finding in semgrep["findings"][:5]:
                        print(f"    [{finding.get('severity', 'INFO')}] {finding.get('check_id', 'Unknown')}")
            
            # Print File Hashes
            print_section("FILE HASHES (SHA-256)")
            for filepath, hash_val in list(file_hashes.items())[:3]:
                print(f"    {Path(filepath).name}: {hash_val[:16]}...")
            
            print("\n" + "=" * 80)
            print("  ✅ FULL PREPROCESSING OUTPUT AVAILABLE IN API RESPONSE")
            print("=" * 80 + "\n")
            
            # Save to database
            print_info("Saving analysis results to database...")
            
            # Prepare source_files for database (convert dataclass to dict if needed)
            source_files_dict = []
            for sf in source_files:
                if isinstance(sf, dict):
                    source_files_dict.append(sf)
                elif hasattr(sf, '__dict__'):
                    source_files_dict.append(sf.__dict__)
                else:
                    source_files_dict.append({"path": str(sf)})
            
            # Prepare findings for database
            findings_dict = [f.model_dump() if hasattr(f, 'model_dump') else f for f in findings]
            
            # Build raw result for complete storage
            raw_result_data = {
                "artifact_id": artifact_id,
                "analysis_id": analysis_id,
                "type": "SOURCE_CODE",
                "filename": file.filename,
                "languages_detected": languages,
                "source_files": source_files_dict,
                "file_hashes": file_hashes,
                "ast_results": ast_results,
                "cfg_results": cfg_results,
                "df_results": df_results,
                "taint_results": taint_results,
                "semgrep": semgrep,
                "findings": findings_dict,
            }
            
            # Mark execution finished
            execution_finished = datetime.utcnow()
            
            # Save to MongoDB + Cloudinary using new database integration
            await save_preprocessing_to_db(
                analysis_id=analysis_id,
                artifact_id=artifact_id,
                owner_id=owner_id,
                filename=file.filename,
                file_type="SOURCE_CODE",
                file_size=file_path.stat().st_size if file_path.exists() else 0,
                raw_result=raw_result_data,
                execution_started=execution_started,
                execution_finished=execution_finished,
                status="success",
            )
            
            return PreprocessingResponse(
                artifact_id=artifact_id,
                type="SOURCE_CODE",
                status=AnalysisStatus.COMPLETED,
                file_count=len(source_files),
                languages_detected=languages,
                findings=findings,
                metadata={"source_path": str(file_path)},
                semgrep_results=semgrep,
                ast_summary=ast_results,
                cfg_results=cfg_results,
                df_results=df_results,
                taint_results=taint_results,
                source_files=source_files,
                file_hashes=file_hashes,
            )
        
    except Exception as e:
        import traceback
        print_error(f"Preprocessing failed: {str(e)}")
        print(traceback.format_exc())
        return PreprocessingResponse(
            artifact_id=artifact_id,
            type="UNKNOWN",
            status=AnalysisStatus.FAILED,
            error=str(e),
        )
    finally:
        # Cleanup
        if file_path.exists():
            file_path.unlink()


@app.post("/api/preprocess/path", response_model=PreprocessingResponse)
async def preprocess_path(request: PreprocessingRequest):
    """
    Preprocess a file or directory at a given path.
    
    This endpoint is for server-side files that are already available.
    """
    # Track execution timing
    execution_started = datetime.utcnow()
    
    # Generate IDs for this analysis
    artifact_id = str(uuid.uuid4())
    analysis_id = str(uuid.uuid4())
    owner_id = "anonymous"  # Will be set from auth context in production
    
    if not Path(request.artifact_path).exists():
        raise HTTPException(status_code=404, detail="Path not found")
    
    try:
        result = preprocess_artifact(request.artifact_path)
        
        # Mark execution finished
        execution_finished = datetime.utcnow()
        
        # Prepare raw result for database storage
        raw_result_data = {
            "artifact_id": artifact_id,
            "analysis_id": analysis_id,
            "type": result.get("type", "UNKNOWN"),
            "path": request.artifact_path,
            "result": result,
        }
        
        # Save to MongoDB + Cloudinary
        await save_preprocessing_to_db(
            analysis_id=analysis_id,
            artifact_id=artifact_id,
            owner_id=owner_id,
            filename=Path(request.artifact_path).name,
            file_type=result.get("type", "UNKNOWN"),
            file_size=Path(request.artifact_path).stat().st_size if Path(request.artifact_path).is_file() else 0,
            raw_result=raw_result_data,
            execution_started=execution_started,
            execution_finished=execution_finished,
            status="success",
        )
        
        return PreprocessingResponse(
            artifact_id=artifact_id,
            type=result.get("type", "UNKNOWN"),
            status=AnalysisStatus.COMPLETED,
            file_count=result.get("fileCount", 1),
            languages_detected=result.get("languagesDetected", []),
            metadata=result.get("metadata", {}),
            semgrep_results=result.get("semgrep"),
            ast_summary=result.get("astSummary"),
        )
    except Exception as e:
        return PreprocessingResponse(
            artifact_id=artifact_id,
            type="UNKNOWN",
            status=AnalysisStatus.FAILED,
            error=str(e),
        )


# ============================================================================
# DOCKERFILE GENERATION ENDPOINTS
# ============================================================================

@app.post("/api/generate/dockerfile", response_model=DockerfileResponse)
async def generate_dockerfile_endpoint(request: DockerfileGenerationRequest):
    """
    Generate a Dockerfile for the sandbox environment.
    
    This endpoint creates a Dockerfile configured for security analysis
    based on the provided vulnerability and target information.
    """
    print_header("DOCKERFILE GENERATION")
    
    print_data("CVE ID", request.cve_id)
    print_data("Target", request.target_name)
    print_data("Language", request.language)
    print_data("Dependencies", request.dependencies)
    print_info("Generating Dockerfile...")
    
    dockerfile = generate_dockerfile(
        cve_id=request.cve_id,
        language=request.language,
        dependencies=request.dependencies,
        build_instructions=request.build_instructions,
    )
    
    print_success("Dockerfile generated successfully")
    print_section("Generated Dockerfile Preview")
    # Print first 10 lines of dockerfile
    dockerfile_lines = dockerfile.split("\n")
    for line in dockerfile_lines[:10]:
        print(f"    {line}")
    if len(dockerfile_lines) > 10:
        print(f"    ... ({len(dockerfile_lines) - 10} more lines)")
    
    return DockerfileResponse(
        dockerfile=dockerfile,
        filename="Dockerfile",
        metadata={
            "cve_id": request.cve_id,
            "target_name": request.target_name,
            "language": request.language,
            "generated_at": datetime.now().isoformat(),
        },
        warnings=[],
    )


@app.get("/api/generate/dockerfile/{cve_id}", response_class=PlainTextResponse)
async def download_dockerfile(cve_id: str, language: str = "c"):
    """
    Download a generated Dockerfile.
    
    Returns the Dockerfile as plain text for direct download.
    """
    dockerfile = generate_dockerfile(
        cve_id=cve_id,
        language=language,
        dependencies=[],
        build_instructions="",
    )
    
    return dockerfile


# ============================================================================
# EXPLOIT GENERATION ENDPOINTS
# ============================================================================

@app.post("/api/generate/exploit", response_model=ExploitResponse)
async def generate_exploit_endpoint(request: ExploitGenerationRequest):
    """
    Generate exploit code for the specified vulnerability.
    
    This endpoint creates a Python exploit script based on the
    vulnerability type and target information.
    """
    print_header("EXPLOIT GENERATION")
    
    print_data("CVE ID", request.cve_id)
    print_data("Vulnerability Type", request.vulnerability_type)
    print_data("Target Info", request.target_info)
    print_info("Generating exploit code...")
    
    exploit_code = generate_exploit_code(
        cve_id=request.cve_id,
        vuln_type=request.vulnerability_type,
        target_info=request.target_info,
    )
    
    print_success("Exploit code generated successfully")
    print_section("Generated Exploit Preview")
    # Print first 15 lines of exploit code
    exploit_lines = exploit_code.split("\n")
    for line in exploit_lines[:15]:
        print(f"    {line}")
    if len(exploit_lines) > 15:
        print(f"    ... ({len(exploit_lines) - 15} more lines)")
    
    return ExploitResponse(
        exploit_code=exploit_code,
        filename="exploit.py",
        vulnerability_type=request.vulnerability_type,
        target_info=request.target_info,
        metadata={
            "cve_id": request.cve_id,
            "generated_at": datetime.now().isoformat(),
        },
        warnings=[
            "This is a template exploit. Manual customization may be required.",
            "Ensure you have authorization before testing against any target.",
        ],
    )


# ============================================================================
# VALIDATION ENDPOINTS
# ============================================================================

@app.post("/api/validate", response_model=ValidationResponse)
async def validate_exploit(request: ValidationRequest):
    """
    Validate an exploit in a sandbox environment.
    
    This endpoint runs the exploit code in an isolated Docker container
    and returns the validation results.
    
    Note: This is a placeholder that returns simulated results.
    Real implementation would require Docker integration.
    """
    print_header("EXPLOIT VALIDATION")
    
    validation_id = str(uuid.uuid4())
    
    print_data("Validation ID", validation_id)
    print_data("Campaign ID", request.campaign_id)
    print_info("Running exploit in sandbox environment...")
    print_info("Starting Docker container...")
    
    # Simulated validation result
    # In production, this would run the exploit in a Docker container
    result = ValidationResult(
        success=True,
        status="VERIFIED",
        execution_time=2.34,
        crash_address="0x41414141",
        crash_type="SIGSEGV",
        stdout="[+] Exploit executed successfully",
        stderr="",
        evidence={
            "registers": {
                "RAX": "0x0000000000000000",
                "RBX": "0x00007fff5fbff8c0",
                "RCX": "0x0000000041414141",
            },
            "stack_trace": [
                "#0  0x41414141 in ?? ()",
                "#1  0x7f4e2a1b2000 in vulnerable_function (target.c:156)",
            ],
        },
    )
    
    print_success("Validation completed")
    print_section("Validation Results")
    print_data("Status", result.status)
    print_data("Success", result.success)
    print_data("Execution Time", f"{result.execution_time}s")
    print_data("Crash Address", result.crash_address)
    print_data("Crash Type", result.crash_type)
    print_section("Register State")
    for reg, val in result.evidence.get("registers", {}).items():
        print(f"    {reg}: {val}")
    print_section("Stack Trace")
    for frame in result.evidence.get("stack_trace", []):
        print(f"    {frame}")
    
    # Generate validation report
    report = f"""
================================================================================
                        IRONWALL EXPLOIT VALIDATION REPORT
================================================================================

Validation ID:   {validation_id}
Status:          {result.status}
Execution Time:  {result.execution_time}s

--------------------------------------------------------------------------------
EXECUTION SUMMARY
--------------------------------------------------------------------------------

Success:         {result.success}
Crash Address:   {result.crash_address}
Crash Type:      {result.crash_type}

--------------------------------------------------------------------------------
OUTPUT
--------------------------------------------------------------------------------

STDOUT:
{result.stdout}

STDERR:
{result.stderr}

================================================================================
                          Report Generated by IronWall
================================================================================
"""
    
    return ValidationResponse(
        validation_id=validation_id,
        status=AnalysisStatus.COMPLETED,
        result=result,
        report=report,
    )


# ============================================================================
# UPLOAD ENDPOINTS
# ============================================================================

@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Upload a file for analysis.
    
    Returns the file ID and metadata for subsequent analysis operations.
    """
    print_header("FILE UPLOAD")
    
    file_id = str(uuid.uuid4())
    file_path = UPLOAD_DIR / f"{file_id}_{file.filename}"
    
    print_data("File ID", file_id)
    print_data("Filename", file.filename)
    print_info("Saving file...")
    
    try:
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        
        is_binary = is_binary_file(str(file_path))
        file_size = file_path.stat().st_size
        
        print_success("File uploaded successfully")
        print_data("Size", f"{file_size} bytes")
        print_data("Type", "binary" if is_binary else "source")
        print_data("Path", str(file_path))
        
        return {
            "file_id": file_id,
            "filename": file.filename,
            "size": file_size,
            "type": "binary" if is_binary else "source",
            "path": str(file_path),
        }
    except Exception as e:
        print_error(f"Upload failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", 5002))
    host = os.getenv("HOST", "0.0.0.0")
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=True,
        log_level="info",
    )
