"""
Guard routes for QR scanning and attendance marking
GUARD role only - scan QR codes and view own scan history
"""

from fastapi import APIRouter, HTTPException, status, Depends, Query
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging
from bson import ObjectId

# Import services and dependencies
from services.auth_service import get_current_guard
from database import get_scan_events_collection
from config import settings

logger = logging.getLogger(__name__)

# Create router
guard_router = APIRouter()


@guard_router.get("/profile")
async def get_guard_profile(current_guard: Dict[str, Any] = Depends(get_current_guard)):
    """Get guard profile and statistics"""
    try:
        scan_events_collection = get_scan_events_collection()
        
        if scan_events_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
        
        guard_id = current_guard["_id"]
        guard_email = current_guard.get("email", "")
        
        # Get scan statistics - use guardEmail to find scans
        today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        today_scans = await scan_events_collection.count_documents({
            "guardEmail": guard_email,
            "scannedAt": {"$gte": today}
        })
        
        total_scans = await scan_events_collection.count_documents({
            "guardEmail": guard_email
        })
        
        # Convert ObjectId fields to strings for JSON serialization
        guard_data = {
            "_id": str(current_guard["_id"]),
            "email": current_guard.get("email", ""),
            "name": current_guard.get("name", ""),
            "role": current_guard.get("role", ""),
            "isActive": current_guard.get("isActive", True),
            "createdAt": current_guard.get("createdAt"),
            "lastLoginAt": current_guard.get("lastLoginAt")
        }
        
        return {
            "guard": guard_data,
            "statistics": {
                "today_scans": today_scans,
                "total_scans": total_scans
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting guard profile: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get guard profile"
        )


@guard_router.get("/scans")
async def get_guard_scans(
    current_guard: Dict[str, Any] = Depends(get_current_guard),
    limit: int = Query(50, ge=1, le=500, description="Number of scans to return"),
    skip: int = Query(0, ge=0, description="Number of scans to skip")
):
    """Get guard's own scan history"""
    try:
        scan_events_collection = get_scan_events_collection()
        
        if scan_events_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
        
        guard_id = current_guard["_id"]
        
        # Get scans with pagination - look for guard's email instead of guardId
        guard_email = current_guard.get("email", "")
        
        scans_cursor = scan_events_collection.find(
            {"guardEmail": guard_email}
        ).sort("scannedAt", -1).skip(skip).limit(limit)
        
        scans = []
        async for scan in scans_cursor:
            scan_data = {
                "_id": str(scan["_id"]),
                "guardId": str(scan.get("guardId", "")),
                "guardEmail": scan.get("guardEmail", ""),
                "qrId": str(scan.get("qrId", "")),
                "originalScanContent": scan.get("originalScanContent", ""),
                "scannedAt": scan.get("scannedAt"),
                "scannedLat": scan.get("deviceLat"),  # Map deviceLat to scannedLat
                "scannedLng": scan.get("deviceLng"),  # Map deviceLng to scannedLng
                "deviceLat": scan.get("deviceLat"),
                "deviceLng": scan.get("deviceLng"),
                "locationAddress": scan.get("address", ""),
                "formatted_address": scan.get("formatted_address", ""),
                "address_components": scan.get("address_components", {}),
                "address_lookup_success": scan.get("address_lookup_success", False),
                "timestamp": scan.get("timestampIST", ""),
                "timestampIST": scan.get("timestampIST", ""),
                "locationUpdated": scan.get("locationUpdated", False),
                "status": scan.get("status", "")
            }
            scans.append(scan_data)
        
        return scans
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting guard scans: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get scans"
        )


@guard_router.post("/scan")
async def scan_qr_code(
    qr_id: str,
    device_lat: float,
    device_lng: float,
    current_guard: Dict[str, Any] = Depends(get_current_guard)
):
    """
    Scan QR code and create scan event (simplified version)
    """
    try:
        from services.google_drive_excel_service import google_drive_excel_service
        from services.tomtom_service import tomtom_service
        from datetime import timezone, timedelta
        from database import get_qr_locations_collection
        
        scan_events_collection = get_scan_events_collection()
        qr_locations_collection = get_qr_locations_collection()
        
        if scan_events_collection is None or qr_locations_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
        
        guard_id = current_guard["_id"]
        guard_email = current_guard.get("email", "")
        guard_name = current_guard.get("name", "Unknown Guard")
        
        # Parse QR content - handle multiple formats
        actual_qr_id = qr_id
        qr_organization = None
        qr_site = None
        assigned_guard_name = None
        
        # Check if QR content contains organization, site, and possibly guard assignment
        if ":" in qr_id:
            parts = qr_id.split(":")
            if len(parts) >= 3:
                qr_organization, qr_site, actual_qr_id = parts[0], parts[1], parts[2]
                
                # Check if QR has guard assignment (format: Org:Site:ID:GUARD:GuardName)
                if len(parts) >= 5 and parts[3] == "GUARD":
                    assigned_guard_name = parts[4]
                    logger.info(f"QR code is assigned to guard: {assigned_guard_name}")
                
                logger.info(f"Parsed QR content: Organization={qr_organization}, Site={qr_site}, ID={actual_qr_id}")
            else:
                actual_qr_id = qr_id
        
        # Get QR location information from database
        try:
            qr_location = await qr_locations_collection.find_one({"_id": ObjectId(actual_qr_id)})
            logger.info(f"QR location found: {qr_location}")
        except Exception as e:
            logger.error(f"Error finding QR location for ID {actual_qr_id}: {e}")
            qr_location = None
        
        # If QR location found in database, check for guard assignment
        if qr_location and qr_location.get("assignedGuardId"):
            db_assigned_guard_id = str(qr_location["assignedGuardId"])
            current_guard_id = str(current_guard["_id"])
            
            # Validate that the current guard is the assigned guard
            if db_assigned_guard_id != current_guard_id:
                assigned_guard_name_db = qr_location.get("assignedGuardName", "Unknown Guard")
                logger.warning(f"Guard {guard_name} (ID: {current_guard_id}) attempted to scan QR assigned to {assigned_guard_name_db} (ID: {db_assigned_guard_id})")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"This QR code is assigned to {assigned_guard_name_db}. Only the assigned guard can scan this QR code."
                )
            
            logger.info(f"QR code assignment validated: Guard {guard_name} is authorized to scan this QR")
        
        # If QR content has guard assignment, validate it matches current guard  
        elif assigned_guard_name:
            if assigned_guard_name.lower() != guard_name.lower():
                logger.warning(f"Guard {guard_name} attempted to scan QR assigned to {assigned_guard_name}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"This QR code is assigned to {assigned_guard_name}. Only the assigned guard can scan this QR code."
                )
            
            logger.info(f"QR code assignment validated: Guard {guard_name} is authorized to scan this QR")
        
        if not qr_location:
            # Use parsed info from QR content if available, otherwise fallback
            qr_location = {
                "organization": qr_organization or "Unknown Organization",
                "site": qr_site or "Unknown Site",
                "lat": device_lat,
                "lng": device_lng,
                "supervisorId": None
            }
            logger.warning(f"QR location not found for ID: {actual_qr_id}, using parsed/fallback values")
        
        # Create scan event (simplified)
        scanned_at = datetime.utcnow()
        
        # Convert to IST for Excel and display
        from utils.timezone_utils import format_excel_datetime, format_excel_date, format_excel_time
        timestamp_ist = format_excel_datetime(scanned_at)
        date_ist = format_excel_date(scanned_at)
        time_ist = format_excel_time(scanned_at)
        
        # Get address from GPS coordinates using TomTom API
        address_info = await tomtom_service.get_address_from_coordinates(device_lat, device_lng)
        
        scan_event = {
            "qrId": actual_qr_id,
            "originalQrContent": qr_id,  # Store the original QR content
            "guardId": guard_id,
            "guardEmail": guard_email,
            "guardName": guard_name,
            "deviceLat": device_lat,
            "deviceLng": device_lng,
            "scannedAt": scanned_at,
            "createdAt": datetime.utcnow(),
            "timestampIST": timestamp_ist,
            # Add address information from TomTom API
            "address": address_info.get("address", f"Location at {device_lat:.4f}, {device_lng:.4f}"),
            "formatted_address": address_info.get("formatted_address", ""),
            "address_components": address_info.get("components", {}),
            "address_lookup_success": address_info.get("success", False),
            # Add building and site info from QR location
            "organization": qr_location.get("organization", "Unknown"),
            "site": qr_location.get("site", "Unknown"),
            "lat": qr_location.get("lat", device_lat),
            "lng": qr_location.get("lng", device_lng),
            "supervisorId": qr_location.get("supervisorId", None)
        }
        
        # Insert scan event
        result = await scan_events_collection.insert_one(scan_event)
        scan_event["_id"] = str(result.inserted_id)
        
        logger.info(f"Scan event created: ID={scan_event['_id']}, Organization={scan_event['organization']}, SupervisorId={scan_event['supervisorId']}, Guard={guard_name}")
        
        # Log to Google Drive Excel
        try:
            scan_data_for_excel = {
                "timestamp": timestamp_ist,
                "date": date_ist,
                "time": time_ist,
                "guard_name": guard_name,
                "guard_email": guard_email,
                "employee_code": "",  # Guard profile not available in simple version
                "supervisor_name": "Supervisor Name",
                "supervisor_area": qr_location.get("supervisorArea", "Unknown Area"),
                "area_city": qr_location.get("supervisorArea", "Unknown Area"), 
                "qr_location": f"{qr_location.get('organization', 'Unknown')} - {qr_location.get('site', 'Unknown')}",
                "latitude": device_lat,
                "longitude": device_lng,
                "distance_meters": 0.0,
                "status": "SUCCESS",
                "address": address_info.get("address", f"Location at {device_lat:.4f}, {device_lng:.4f}"),
                "landmark": address_info.get("formatted_address", ""),
                "remarks": f"Guard scan via /guard/scan endpoint - {address_info.get('address', 'GPS coordinates saved')}"
            }
            
            await google_drive_excel_service.add_scan_to_queue(scan_data_for_excel)
            
        except Exception as e:
            logger.error(f"Failed to log to Excel: {e}")
        
        logger.info(f"Guard {current_guard.get('name')} scanned QR {qr_id}")
        
        return {
            "message": "QR code scanned successfully",
            "scan_id": str(scan_event["_id"]),
            "timestamp": timestamp_ist,
            "qr_id": actual_qr_id,
            "original_qr_content": qr_id,
            "organization": qr_location.get("organization", "Unknown"),
            "site": qr_location.get("site", "Unknown"),
            "coordinates": {
                "scanned_lat": device_lat,
                "scanned_lng": device_lng
            },
            "location_address": {
                "address": address_info.get("address", f"Location at {device_lat:.4f}, {device_lng:.4f}"),
                "formatted_address": address_info.get("formatted_address", ""),
                "address_lookup_success": address_info.get("success", False),
                "components": address_info.get("components", {})
            },
            "note": f"Scan recorded successfully. Location: {address_info.get('address', 'GPS coordinates saved')}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing QR scan: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process QR scan"
        )
