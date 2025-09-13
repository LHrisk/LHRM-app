"""
QR Code routes - QR Creation Only
Includes:
1. POST /qr/create - Create QR code for organization and site

REMOVED APIs:
- GET /qr/my-qr-image (Get My Qr Image) 
- POST /qr/scan (Scan Qr Code)
"""

from fastapi import APIRouter, HTTPException, status, Body, Depends
from fastapi.responses import StreamingResponse
from typing import Dict, Any
import logging
from bson import ObjectId
from datetime import datetime

# Import services and dependencies
from services.auth_service import get_current_supervisor
from database import get_qr_locations_collection, get_scan_events_collection
from config import settings

logger = logging.getLogger(__name__)

# Create router
qr_router = APIRouter()


# ============================================================================
# QR Code Creation API
# ============================================================================
from fastapi import Body

@qr_router.post("/create")
async def create_qr_code(
    organization_name: str = Body(..., embed=True, description="Name of the building (company/college/etc.)"),
    site_name: str = Body(..., embed=True, description="Site name (e.g., canteen, gate, etc.)"),
    current_supervisor: Dict[str, Any] = Depends(get_current_supervisor)
):
    """
    Create a QR code for a specific building and site.
    Only supervisors can create QR codes.
    """
    qr_locations_collection = get_qr_locations_collection()
    if qr_locations_collection is None:
        raise HTTPException(status_code=503, detail="Database not available")

    # Check for existing QR location for this organization, site, and supervisor
    existing = await qr_locations_collection.find_one({
        "organization": organization_name,
        "site": site_name,
        "supervisorId": current_supervisor["_id"]
    })
    if existing:
        qr_id = str(existing["_id"])
    else:
        qr_data = {
            "organization": organization_name,
            "site": site_name,
            "createdBy": str(current_supervisor["_id"]),
            "createdAt": datetime.now(),
            "supervisorId": current_supervisor["_id"]
        }
        result = await qr_locations_collection.insert_one(qr_data)
        qr_id = str(result.inserted_id)

    # Generate QR code with building, site, and QR id
    import qrcode, io
    from fastapi.responses import StreamingResponse

    qr_content = f"{organization_name}:{site_name}:{qr_id}"
    qr_img = qrcode.make(qr_content)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    buf.seek(0)

    return StreamingResponse(buf, media_type="image/png")

# ============================================================================
# QR MANAGEMENT ENDPOINTS REMOVED
# The following endpoints have been removed:
# - GET /qr/my-qr-image (Get My Qr Image)
# - POST /qr/scan (Scan Qr Code)
# ============================================================================
