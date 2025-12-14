"""
IronWall Analysis Service - Cloudinary Storage Module

This module handles file storage to Cloudinary for:
- Uploaded artifacts (binaries, source code)
- Preprocessing output files (JSON analysis results)
"""

import os
import json
import tempfile
from datetime import datetime
from typing import Optional, Dict, Any

import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv

load_dotenv()

# ============================================================================
# CLOUDINARY CONFIGURATION
# ============================================================================

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True
)


# ============================================================================
# STORAGE FUNCTIONS
# ============================================================================

async def upload_artifact(
    file_path: str,
    original_name: str,
    folder: str = "ironwall/artifacts",
    resource_type: str = "raw",
    artifact_id: str = None
) -> Dict[str, Any]:
    """
    Upload an artifact file to Cloudinary.
    
    Args:
        file_path: Path to the file to upload
        original_name: Original filename
        folder: Cloudinary folder path (e.g., "ironwall/artifacts")
        resource_type: "raw" for non-image files
        artifact_id: Optional artifact ID to use in filename
    
    Returns:
        Storage info dict with Cloudinary details
    """
    try:
        # Generate a unique public_id
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base_name = os.path.splitext(original_name)[0]
        # Sanitize filename
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in base_name)
        
        if artifact_id:
            public_id = f"{folder}/{artifact_id}_{safe_name}"
        else:
            public_id = f"{folder}/{safe_name}_{timestamp}"
        
        # Upload to Cloudinary
        result = cloudinary.uploader.upload(
            file_path,
            resource_type=resource_type,
            public_id=public_id,
            overwrite=True
        )
        
        storage_info = {
            "provider": "cloudinary",
            "resourceType": resource_type,
            "publicId": result["public_id"],
            "secureUrl": result["secure_url"],
            "format": result.get("format"),
            "version": result.get("version"),
            "sizeBytes": result.get("bytes"),
        }
        
        print(f"☁️  Uploaded to Cloudinary: {result['public_id']}")
        return storage_info
        
    except Exception as e:
        print(f"❌ Cloudinary upload failed: {e}")
        raise


async def upload_analysis_output(
    analysis_data: Dict[str, Any],
    analysis_id: str,
    artifact_id: str,
    analysis_type: str = "preprocessing"
) -> Dict[str, Any]:
    """
    Upload analysis output as a JSON file to Cloudinary.
    
    Args:
        analysis_data: The analysis result dictionary
        analysis_id: ID of the analysis request
        artifact_id: ID of the analyzed artifact
        analysis_type: Type of analysis (preprocessing, static, etc.)
    
    Returns:
        Storage info dict with Cloudinary details
    """
    try:
        # Create a temporary JSON file
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.json',
            delete=False
        ) as temp_file:
            json.dump(analysis_data, temp_file, indent=2, default=str)
            temp_path = temp_file.name
        
        # Generate public_id with organized folder structure
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        # All analysis outputs go in ironwall/analysis_outputs/{type}/
        public_id = f"ironwall/analysis_outputs/{analysis_type}/{analysis_id}_{artifact_id}_{timestamp}"
        
        # Upload to Cloudinary
        result = cloudinary.uploader.upload(
            temp_path,
            resource_type="raw",
            public_id=public_id,
            overwrite=True
        )
        
        # Clean up temp file
        os.unlink(temp_path)
        
        storage_info = {
            "provider": "cloudinary",
            "resourceType": "raw",
            "publicId": result["public_id"],
            "secureUrl": result["secure_url"],
            "format": "json",
            "version": result.get("version"),
            "sizeBytes": result.get("bytes"),
        }
        
        print(f"☁️  Analysis output uploaded: {result['public_id']}")
        return storage_info
        
    except Exception as e:
        print(f"❌ Failed to upload analysis output: {e}")
        raise


async def delete_file(public_id: str, resource_type: str = "raw") -> bool:
    """
    Delete a file from Cloudinary.
    
    Args:
        public_id: Cloudinary public ID of the file
        resource_type: Type of resource
    
    Returns:
        True if deleted successfully
    """
    try:
        result = cloudinary.uploader.destroy(
            public_id,
            resource_type=resource_type
        )
        return result.get("result") == "ok"
    except Exception as e:
        print(f"❌ Failed to delete from Cloudinary: {e}")
        return False


def get_download_url(public_id: str, resource_type: str = "raw") -> str:
    """
    Get a download URL for a Cloudinary file.
    
    Args:
        public_id: Cloudinary public ID
        resource_type: Type of resource
    
    Returns:
        Download URL
    """
    return cloudinary.CloudinaryResource(
        public_id,
        resource_type=resource_type
    ).build_url()
