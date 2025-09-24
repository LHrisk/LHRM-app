"""
QR Code routes - QR Creation Only
Includes:
1. POST /qr/create - Create QR code for organization and site

REMOVED APIs:
- GET /qr/my-qr-image (Get My Qr Image) 
- POST /qr/scan (Scan Qr Code)
"""

from fastapi import APIRouter, HTTPException, status, Body, Depends, Query
from fastapi.responses import StreamingResponse
from typing import Dict, Any, Optional
import logging
from bson import ObjectId
from datetime import datetime
from pymongo.errors import DuplicateKeyError

# Import services and dependencies
from services.auth_service import get_current_supervisor
from database import get_qr_locations_collection, get_scan_events_collection, get_guards_collection
from config import settings

logger = logging.getLogger(__name__)

# Create router
qr_router = APIRouter()


# ============================================================================
# QR Code Creation API
# ============================================================================
@qr_router.post("/create")
async def create_qr_code(
    site: str = Body(..., embed=True, description="Site name created by the supervisor"),
    post_name: str = Body(..., embed=True, description="Post name (e.g., canteen, gate, etc.)"),
    current_supervisor: Dict[str, Any] = Depends(get_current_supervisor)
):
    """
    Create a QR code for a specific site and post.
    Only supervisors can create QR codes.
    Optionally assign a specific guard to this QR location.
    """
    qr_locations_collection = get_qr_locations_collection()

    if qr_locations_collection is None:
        raise HTTPException(status_code=503, detail="Database not available")

    # Normalize site name and convert supervisorId to ObjectId
    normalized_site = site.strip()
    supervisor_id = ObjectId(current_supervisor["_id"])
    
    # Debug logging
    logger.info(f"QR Create Request - Site: {normalized_site}, Supervisor ID: {supervisor_id}")

    # Check for existing QR location for this site and post
    existing_qr = await qr_locations_collection.find_one({
        "site": normalized_site,
        "post": post_name,
        "supervisorId": supervisor_id
    })

    if existing_qr:
        # Return existing QR code
        qr_id = str(existing_qr["_id"])
        qr_content = f"{normalized_site}:{post_name}:{qr_id}"
        
        import qrcode
        import io

        qr_img = qrcode.make(qr_content)
        buf = io.BytesIO()
        qr_img.save(buf, format="PNG")
        buf.seek(0)

        return StreamingResponse(buf, media_type="image/png")

    # Validate that the site exists in the database (check for site records without post field)
    site_query = {
        "site": normalized_site,
        "supervisorId": supervisor_id,
        "post": {"$exists": False}  # This identifies site records (not QR location records)
    }
    logger.info(f"Searching for site with query: {site_query}")
    existing_site = await qr_locations_collection.find_one(site_query)
    logger.info(f"Found site: {existing_site}")

    if not existing_site:
        # Check if site exists but belongs to a different supervisor
        any_site = await qr_locations_collection.find_one({
            "site": normalized_site,
            "post": {"$exists": False}
        })
        
        if any_site:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Site '{normalized_site}' exists but belongs to another supervisor (ID: {any_site.get('supervisorId')}). Current supervisor ID: {supervisor_id}"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="The specified site does not exist."
            )

    # Create new QR location
    qr_data = {
        "site": normalized_site,
        "post": post_name,
        "createdBy": str(current_supervisor["_id"]),
        "createdAt": datetime.now(),
        "updatedAt": datetime.now(),
        "supervisorId": supervisor_id  # Already converted to ObjectId above
    }

    try:
        logger.info(f"Attempting to insert QR data: {qr_data}")
        result = await qr_locations_collection.insert_one(qr_data)
        qr_id = str(result.inserted_id)
        logger.info(f"Successfully created QR location with ID: {qr_id}")
    except DuplicateKeyError as e:
        logger.error(f"DuplicateKeyError occurred: {e}")
        # If duplicate key error occurs, fetch the existing record
        query = {
            "site": normalized_site,
            "post": post_name,
            "supervisorId": supervisor_id
        }
        logger.info(f"Searching for existing QR with query: {query}")
        existing_qr = await qr_locations_collection.find_one(query)
        logger.info(f"Found existing QR: {existing_qr}")
        
        if existing_qr:
            qr_id = str(existing_qr["_id"])
            logger.info(f"Using existing QR ID: {qr_id}")
        else:
            logger.error("Failed to find existing QR location after duplicate key error")
            raise HTTPException(status_code=500, detail="Unable to create or find QR location")
    except Exception as e:
        logger.error(f"Unexpected error during QR creation: {e}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

    # Generate QR code with site, post, QR id
    qr_content = f"{normalized_site}:{post_name}:{qr_id}"

    import qrcode
    import io

    qr_img = qrcode.make(qr_content)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    buf.seek(0)

    return StreamingResponse(buf, media_type="image/png")


# ============================================================================
# QR Code List API
# ============================================================================
@qr_router.get("/list")
async def list_qr_codes(
    current_supervisor: Dict[str, Any] = Depends(get_current_supervisor),
    site: Optional[str] = Query(None, description="Filter by site name")
):
    """
    List all QR codes created by the current supervisor for a specific site.
    """
    try:
        qr_locations_collection = get_qr_locations_collection()
        if qr_locations_collection is None:
            raise HTTPException(status_code=503, detail="Database not available")

        # Convert supervisor ID to ObjectId for consistency
        supervisor_id = ObjectId(current_supervisor["_id"])

        # Build filter query
        filter_query = {"supervisorId": supervisor_id}

        # Add site filter if provided
        if site:
            filter_query["site"] = {"$regex": site.strip(), "$options": "i"}

        # Ensure 'post' field exists and is not empty (to get QR locations, not site records)
        filter_query["post"] = {"$exists": True, "$ne": ""}

        # Get filtered QR locations for this supervisor
        qr_locations = await qr_locations_collection.find(filter_query).sort("createdAt", -1).to_list(length=None)

        formatted_qrs = []
        for qr in qr_locations:
            qr_data = {
                "qr_id": str(qr["_id"]),
                "site": qr.get("site", ""),
                "post": qr.get("post", ""),
                "created_at": qr.get("createdAt").isoformat() if qr.get("createdAt") else None,
                "updated_at": qr.get("updatedAt").isoformat() if qr.get("updatedAt") else None
            }
            formatted_qrs.append(qr_data)

        # Prepare response message
        total_count = len(formatted_qrs)
        filter_message = f" for site '{site}'" if site else ""

        return {
            "qr_codes": formatted_qrs,
            "total": total_count,
            "site_filter": site,
            "message": f"Found {total_count} QR codes{filter_message}"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing QR codes: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
