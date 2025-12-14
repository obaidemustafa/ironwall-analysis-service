"""
IronWall Analysis Service - Database Module

This module handles MongoDB connection and provides database models for:
- analysis_requests: Main document connecting user, CVE, and artifacts
- artifacts: Uploaded files with Cloudinary storage pointers
- analysis_results: Preprocessing output stored as files

Uses Motor for async MongoDB operations.
"""

import os
import json
import hashlib
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

# ============================================================================
# DATABASE CONNECTION
# ============================================================================

MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "ironwall")

# Global database client and db reference
_client: Optional[AsyncIOMotorClient] = None
_db = None


async def connect_db():
    """Connect to MongoDB."""
    global _client, _db
    
    if not MONGODB_URI:
        raise ValueError("MONGODB_URI environment variable is not set")
    
    try:
        _client = AsyncIOMotorClient(MONGODB_URI)
        _db = _client[DATABASE_NAME]
        
        # Test connection
        await _client.admin.command('ping')
        print("✅ Connected to MongoDB")
        
        # Create indexes
        await create_indexes()
        
        return _db
    except Exception as e:
        print(f"❌ Failed to connect to MongoDB: {e}")
        raise


async def disconnect_db():
    """Disconnect from MongoDB."""
    global _client
    if _client:
        _client.close()
        print("📴 Disconnected from MongoDB")


async def get_db():
    """Get database instance."""
    global _db
    if _db is None:
        await connect_db()
    return _db


async def create_indexes():
    """Create database indexes for better query performance."""
    global _db
    
    # analysis_requests indexes
    await _db.analysis_requests.create_index("userId")
    await _db.analysis_requests.create_index("cveId")
    await _db.analysis_requests.create_index("status")
    await _db.analysis_requests.create_index("createdAt")
    
    # artifacts indexes
    await _db.artifacts.create_index("ownerUserId")
    await _db.artifacts.create_index("analysisId")
    await _db.artifacts.create_index("kind")
    
    # analysis_results indexes
    await _db.analysis_results.create_index("analysisId")
    await _db.analysis_results.create_index("artifactId")
    await _db.analysis_results.create_index("ownerId")
    await _db.analysis_results.create_index("analysisType")
    
    print("📊 Database indexes created")


# ============================================================================
# ENUMS
# ============================================================================

class AnalysisStatus(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class TargetType(str, Enum):
    BINARY = "binary"
    SOURCE = "source"
    MIXED = "mixed"


class ArtifactKind(str, Enum):
    TARGET_BINARY = "target-binary"
    TARGET_SOURCE = "target-source"
    ADVISORY = "advisory"
    EXPLOIT = "exploit"
    DOCKERFILE = "dockerfile"
    OTHER = "other"


class AnalysisType(str, Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    HYBRID = "hybrid"
    PREPROCESSING = "preprocessing"


# ============================================================================
# PYDANTIC MODELS (for validation)
# ============================================================================

class StorageInfo(BaseModel):
    """Cloudinary storage information."""
    provider: str = "cloudinary"
    resourceType: str = "raw"
    publicId: str
    secureUrl: str
    format: Optional[str] = None
    version: Optional[int] = None
    sizeBytes: Optional[int] = None
    checksumSha256: Optional[str] = None


class ExecutionInfo(BaseModel):
    """Execution timing and status."""
    startedAt: datetime
    finishedAt: Optional[datetime] = None
    status: str = "running"
    errorMessage: Optional[str] = None


class AnalysisRequestCreate(BaseModel):
    """Model for creating an analysis request."""
    userId: str
    cveId: str
    targetType: TargetType = TargetType.SOURCE
    description: Optional[str] = None


class ArtifactCreate(BaseModel):
    """Model for creating an artifact."""
    ownerUserId: str
    analysisId: str
    kind: ArtifactKind
    originalName: str
    mimeType: str
    sizeBytes: int
    checksumSha256: Optional[str] = None
    storage: StorageInfo


class StaticAnalysisResultCreate(BaseModel):
    """Model for creating a static analysis result."""
    analysisId: str
    artifactId: str
    ownerId: str
    analysisType: AnalysisType = AnalysisType.PREPROCESSING
    toolName: str = "ironwall-preprocessor"
    toolVersion: str = "1.0.0"
    outputFile: StorageInfo
    execution: ExecutionInfo


# ============================================================================
# DATABASE OPERATIONS
# ============================================================================

class AnalysisRequestsDB:
    """Database operations for analysis_requests collection."""
    
    @staticmethod
    async def create(data: dict) -> str:
        """Create a new analysis request."""
        db = await get_db()
        
        # Use string IDs (UUID format) instead of ObjectId
        doc = {
            "_id": data.get("_id", str(ObjectId())),  # Allow custom ID or generate one
            "userId": data["userId"],  # Store as string
            "cveId": data["cveId"],
            "targetType": data.get("targetType", "source"),
            "description": data.get("description", ""),
            "status": AnalysisStatus.QUEUED.value,
            "artifactIds": [],
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        
        result = await db.analysis_requests.insert_one(doc)
        print(f"📝 Created analysis request: {result.inserted_id}")
        return str(result.inserted_id)
    
    @staticmethod
    async def get_by_id(analysis_id: str) -> Optional[dict]:
        """Get analysis request by ID."""
        db = await get_db()
        # Try string ID first, then ObjectId for backwards compatibility
        doc = await db.analysis_requests.find_one({"_id": analysis_id})
        if not doc:
            try:
                doc = await db.analysis_requests.find_one({"_id": ObjectId(analysis_id)})
            except:
                pass
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc
    
    @staticmethod
    async def update_status(analysis_id: str, status: str) -> bool:
        """Update analysis status."""
        db = await get_db()
        # Try string ID first
        result = await db.analysis_requests.update_one(
            {"_id": analysis_id},
            {"$set": {"status": status, "updatedAt": datetime.utcnow()}}
        )
        if result.modified_count == 0:
            try:
                result = await db.analysis_requests.update_one(
                    {"_id": ObjectId(analysis_id)},
                    {"$set": {"status": status, "updatedAt": datetime.utcnow()}}
                )
            except:
                pass
        return result.modified_count > 0
    
    @staticmethod
    async def add_artifact(analysis_id: str, artifact_id: str) -> bool:
        """Add an artifact ID to the analysis request."""
        db = await get_db()
        # Use string IDs
        result = await db.analysis_requests.update_one(
            {"_id": analysis_id},
            {
                "$push": {"artifactIds": artifact_id},
                "$set": {"updatedAt": datetime.utcnow()}
            }
        )
        return result.modified_count > 0
    
    @staticmethod
    async def get_by_user(user_id: str, limit: int = 50) -> List[dict]:
        """Get all analysis requests for a user."""
        db = await get_db()
        cursor = db.analysis_requests.find(
            {"userId": user_id}
        ).sort("createdAt", -1).limit(limit)
        
        results = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results


class ArtifactsDB:
    """Database operations for artifacts collection."""
    
    @staticmethod
    async def create(data: dict) -> str:
        """Create a new artifact."""
        db = await get_db()
        
        # Use string IDs (UUID format) instead of ObjectId
        doc = {
            "_id": data.get("_id", str(ObjectId())),  # Allow custom ID
            "ownerUserId": data["ownerUserId"],  # Store as string
            "analysisId": data["analysisId"],  # Store as string
            "kind": data["kind"],
            "originalName": data["originalName"],
            "mimeType": data["mimeType"],
            "sizeBytes": data["sizeBytes"],
            "checksumSha256": data.get("checksumSha256"),
            "storage": data["storage"],
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        
        result = await db.artifacts.insert_one(doc)
        print(f"📦 Created artifact: {result.inserted_id} ({data['originalName']})")
        return str(result.inserted_id)
    
    @staticmethod
    async def get_by_id(artifact_id: str) -> Optional[dict]:
        """Get artifact by ID."""
        db = await get_db()
        # Try string ID first
        doc = await db.artifacts.find_one({"_id": artifact_id})
        if not doc:
            try:
                doc = await db.artifacts.find_one({"_id": ObjectId(artifact_id)})
            except:
                pass
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc
    
    @staticmethod
    async def get_by_analysis(analysis_id: str) -> List[dict]:
        """Get all artifacts for an analysis."""
        db = await get_db()
        cursor = db.artifacts.find({"analysisId": analysis_id})
        
        results = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results


class AnalysisResultsDB:
    """Database operations for analysis_results collection."""
    
    @staticmethod
    async def create(data: dict) -> str:
        """Create a new analysis result."""
        db = await get_db()
        
        # Use string IDs (UUID format) instead of ObjectId
        doc = {
            "_id": data.get("_id", str(ObjectId())),  # Allow custom ID
            "analysisId": data["analysisId"],  # Store as string
            "artifactId": data["artifactId"],  # Store as string
            "ownerId": data["ownerId"],  # Store as string
            "analysisType": data.get("analysisType", "preprocessing"),
            "toolName": data.get("toolName", "ironwall-preprocessor"),
            "toolVersion": data.get("toolVersion", "1.0.0"),
            "outputFile": data["outputFile"],
            "execution": data["execution"],
            "createdAt": datetime.utcnow()
        }
        
        result = await db.analysis_results.insert_one(doc)
        print(f"📊 Created analysis result: {result.inserted_id}")
        return str(result.inserted_id)
    
    @staticmethod
    async def get_by_id(result_id: str) -> Optional[dict]:
        """Get analysis result by ID."""
        db = await get_db()
        doc = await db.analysis_results.find_one({"_id": result_id})
        if not doc:
            try:
                doc = await db.analysis_results.find_one({"_id": ObjectId(result_id)})
            except:
                pass
        if doc:
            doc["_id"] = str(doc["_id"])
        return doc
    
    @staticmethod
    async def get_by_analysis(analysis_id: str) -> List[dict]:
        """Get all analysis results for an analysis."""
        db = await get_db()
        cursor = db.analysis_results.find({"analysisId": analysis_id})
        
        results = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results
    
    @staticmethod
    async def get_by_artifact(artifact_id: str) -> List[dict]:
        """Get all analysis results for an artifact."""
        db = await get_db()
        cursor = db.analysis_results.find({"artifactId": artifact_id})
        
        results = []
        async for doc in cursor:
            doc["_id"] = str(doc["_id"])
            results.append(doc)
        return results


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def calculate_sha256(file_path: str) -> str:
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, ObjectId):
        return str(obj)
    raise TypeError(f"Type {type(obj)} not serializable")
