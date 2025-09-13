"""
Supervisor routes for QR location management and guard oversight
SUPERVISOR role only - manage QR locations, view assigned guards, and access scan data
"""

from fastapi import APIRouter, HTTPException, status, Depends, Query
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging
import io
import os
from bson import ObjectId

# Import services and dependencies
from services.auth_service import get_current_supervisor
from services.tomtom_service import tomtom_service
from services.email_service import email_service
from services.jwt_service import jwt_service
#from services.excel_service import excel_service
from database import (
    get_supervisors_collection, get_guards_collection, get_qr_locations_collection,
    get_scan_events_collection, get_users_collection
)
from models import SupervisorAddGuardRequest, UserRole
from config import settings

# Configure logging
logger = logging.getLogger(__name__)

# Create router
supervisor_router = APIRouter()



# ============================================================================
# NEW: Supervisor Add Building API
# ============================================================================
from fastapi import Body

@supervisor_router.post("/building/add")
async def add_building(
    building_name: str = Body(..., embed=True, description="Name of the new building to add."),
    current_supervisor: Dict[str, Any] = Depends(get_current_supervisor)
):
    """
    Supervisor-only: Add a new building to the system. Sites and QR codes are handled separately.
    """
    qr_locations_collection = get_qr_locations_collection()
    if qr_locations_collection is None:
        raise HTTPException(status_code=503, detail="Database not available")

    # Check if building already exists for this supervisor
    existing = await qr_locations_collection.find_one({
        "organization": building_name,
        "supervisorId": current_supervisor["_id"]
    })
    if existing:
        raise HTTPException(status_code=400, detail="Building already exists for this supervisor")

    # Add building record (no site field)
    building_data = {
        "organization": building_name,
        "createdBy": str(current_supervisor["_id"]),
        "createdAt": datetime.now(),
        "supervisorId": current_supervisor["_id"]
    }
    result = await qr_locations_collection.insert_one(building_data)
    building_id = str(result.inserted_id)

    return {"building_id": building_id, "organization": building_name, "message": "Building added successfully. Add sites and generate QR codes using the QR code API."}

    # --- The following code should be inside get_supervisor_dashboard, not add_building ---

@supervisor_router.get("/dashboard")
async def get_supervisor_dashboard(current_supervisor: Dict[str, Any] = Depends(get_current_supervisor)):
    supervisors_collection = get_supervisors_collection()
    guards_collection = get_guards_collection()
    qr_locations_collection = get_qr_locations_collection()
    scan_events_collection = get_scan_events_collection()

    if (supervisors_collection is None or guards_collection is None or 
        qr_locations_collection is None or scan_events_collection is None):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database not available"
        )

    supervisor_user_id = str(current_supervisor["_id"])
    supervisor_state = current_supervisor["areaCity"]

    # Get assigned guards count (guards assigned to this supervisor)
    assigned_guards = await guards_collection.count_documents({
        "supervisorId": ObjectId(supervisor_user_id)
    })

    # Get QR locations count  
    qr_locations = await qr_locations_collection.count_documents({
        "supervisorId": ObjectId(supervisor_user_id)
    })

    # Improved scan filtering logic - try multiple approaches
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Primary filter: scans linked to this supervisor
    supervisor_scan_filter = {
        "$and": [
            {"scannedAt": {"$gte": today_start}},
            {"$or": [
                {"supervisorId": str(supervisor_user_id)},
                {"supervisorId": ObjectId(supervisor_user_id)}
            ]}
        ]
    }
    
    today_scans = await scan_events_collection.count_documents(supervisor_scan_filter)
    
    # If no scans found by supervisorId, try area-based filtering
    if today_scans == 0:
        area_scan_filter = {
            "$and": [
                {"scannedAt": {"$gte": today_start}},
                {"$or": [
                    {"organization": {"$regex": supervisor_state, "$options": "i"}},
                    {"site": {"$regex": supervisor_state, "$options": "i"}},
                    {"address": {"$regex": supervisor_state, "$options": "i"}},
                    {"formatted_address": {"$regex": supervisor_state, "$options": "i"}}
                ]}
            ]
        }
        today_scans = await scan_events_collection.count_documents(area_scan_filter)

    # Get this week's scan statistics using the same logic
    week_start = today_start - timedelta(days=today_start.weekday())
    week_supervisor_filter = {
        "$and": [
            {"scannedAt": {"$gte": week_start}},
            {"$or": [
                {"supervisorId": str(supervisor_user_id)},
                {"supervisorId": ObjectId(supervisor_user_id)}
            ]}
        ]
    }
    
    this_week_scans = await scan_events_collection.count_documents(week_supervisor_filter)
    
    # If no scans found by supervisorId, try area-based filtering for the week
    if this_week_scans == 0:
        week_area_filter = {
            "$and": [
                {"scannedAt": {"$gte": week_start}},
                {"$or": [
                    {"organization": {"$regex": supervisor_state, "$options": "i"}},
                    {"site": {"$regex": supervisor_state, "$options": "i"}},
                    {"address": {"$regex": supervisor_state, "$options": "i"}},
                    {"formatted_address": {"$regex": supervisor_state, "$options": "i"}}
                ]}
            ]
        }
        this_week_scans = await scan_events_collection.count_documents(week_area_filter)

    # Get recent scan events with improved filtering
    recent_scans_filter = {
        "$or": [
            {"supervisorId": str(supervisor_user_id)},
            {"supervisorId": ObjectId(supervisor_user_id)},
            {"organization": {"$regex": supervisor_state, "$options": "i"}},
            {"site": {"$regex": supervisor_state, "$options": "i"}},
            {"address": {"$regex": supervisor_state, "$options": "i"}},
            {"formatted_address": {"$regex": supervisor_state, "$options": "i"}}
        ]
    }
    
    recent_scans_cursor = scan_events_collection.find(recent_scans_filter).sort("scannedAt", -1).limit(10)
    recent_scans = await recent_scans_cursor.to_list(length=None)

    # Get guards with most activity - use the same improved filtering
    guard_activity_pipeline = [
        {"$match": {
            "$and": [
                {"scannedAt": {"$gte": week_start}},
                {"$or": [
                    {"supervisorId": str(supervisor_user_id)},
                    {"supervisorId": ObjectId(supervisor_user_id)},
                    {"organization": {"$regex": supervisor_state, "$options": "i"}},
                    {"site": {"$regex": supervisor_state, "$options": "i"}},
                    {"address": {"$regex": supervisor_state, "$options": "i"}},
                    {"formatted_address": {"$regex": supervisor_state, "$options": "i"}}
                ]}
            ]
        }},
        {"$group": {
            "_id": "$guardEmail",
            "guard_name": {"$first": "$guardName"},
            "scan_count": {"$sum": 1}
        }},
        {"$sort": {"scan_count": -1}},
        {"$limit": 5},
        {"$project": {
            "guard_email": "$_id",
            "guard_name": 1,
            "scan_count": 1,
            "_id": 0
        }}
    ]
    guard_activity = await scan_events_collection.aggregate(guard_activity_pipeline).to_list(length=None)

    # Guard activity already has proper structure, no ObjectId conversion needed

    return {
        "statistics": {
            "assigned_guards": assigned_guards,
            "qr_locations": qr_locations,
            "today_scans": today_scans,
            "this_week_scans": this_week_scans
        },
        "recent_scans": [
            {
                "id": str(scan["_id"]),
                "guard_email": scan.get("guardEmail", ""),
                "guard_id": str(scan.get("guardId", "")),
                "qr_id": scan.get("qrId", ""),
                "original_scan_content": scan.get("originalScanContent", ""),
                "location_name": scan.get("locationName", "Unknown Location"),
                "scanned_at": scan.get("scannedAt"),
                "timestamp": scan.get("timestampIST", ""),
                "device_lat": scan.get("deviceLat", 0),
                "device_lng": scan.get("deviceLng", 0),
                "address": scan.get("address", ""),
                "formatted_address": scan.get("formatted_address", ""),
                "address_lookup_success": scan.get("address_lookup_success", False)
            }
            for scan in recent_scans
        ],
        "guard_activity": guard_activity,
        "area_info": {
            "state": supervisor_state,
            "assigned_area": current_supervisor["areaCity"],
            "state_full": current_supervisor.get("areaState"),
            "country": current_supervisor.get("areaCountry")
        }
    }


@supervisor_router.post("/generate-excel-report")
async def generate_excel_report(
    current_supervisor: Dict[str, Any] = Depends(get_current_supervisor),
    days_back: int = Query(7, ge=1, le=30, description="Number of days to include in report"),
    building_name: Optional[str] = Query(None, description="Name of the building to filter (optional)")
):
    """
    Generate Excel report of scan data for supervisor's area and send to admin
    """
    try:
        logger.info("Starting Excel report generation...")
        scan_events_collection = get_scan_events_collection()
        if scan_events_collection is None:
            logger.error("Scan events collection is None")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )

        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        # Build query filter
        supervisor_id = current_supervisor["_id"]
        supervisor_area = current_supervisor.get("areaCity", "")
        
        logger.info(f"Excel report request - Days back: {days_back}, Building name: {building_name}")
        logger.info(f"Date range: {start_date} to {end_date}")
        logger.info(f"Supervisor ID: {supervisor_id}, Supervisor area: {supervisor_area}")
        
        # Primary query: Try both string and ObjectId for supervisorId filter
        query_filter = {
            "scannedAt": {"$gte": start_date, "$lte": end_date},
            "$or": [
                {"supervisorId": str(supervisor_id)},
                {"supervisorId": supervisor_id}
            ]
        }

        if building_name:
            # Case-insensitive search for building name
            query_filter["organization"] = {"$regex": building_name, "$options": "i"}

        # Filter scans by supervisor's area and date range
        scans = await scan_events_collection.find(query_filter).to_list(length=None)
        
        # If no scans found with supervisorId, try to find scans in the supervisor's area or by building name
        if not scans:
            logger.info(f"No scans found by supervisorId, trying alternative queries")
            
            alternative_query_filter = {
                "scannedAt": {"$gte": start_date, "$lte": end_date}
            }
            
            if building_name:
                # Case-insensitive search for building name in organization field
                alternative_query_filter["organization"] = {"$regex": building_name, "$options": "i"}
            
            # Get all scans in date range matching building name (regardless of supervisorId)
            scans = await scan_events_collection.find(alternative_query_filter).to_list(length=None)
            logger.info(f"Found {len(scans)} scans using alternative query (building name: {building_name})")
            
            # If still no scans and we have supervisor area, try area-based search
            if not scans and supervisor_area:
                area_query_filter = {
                    "scannedAt": {"$gte": start_date, "$lte": end_date}
                }
                
                # Get all scans in date range and filter by organization name matching area
                all_scans = await scan_events_collection.find(area_query_filter).to_list(length=None)
                scans = [scan for scan in all_scans 
                        if supervisor_area.lower() in scan.get("organization", "").lower() 
                        or supervisor_area.lower() in scan.get("site", "").lower()]
                logger.info(f"Found {len(scans)} scans in supervisor's area: {supervisor_area}")

        if not scans:
            logger.warning("No scan data found in the specified date range")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No scan data found in the specified date range"
            )

        # Debug: Log all scan events found by query
        logger.info(f"Total scan events found: {len(scans)}")
        
        # Prepare Excel data
        excel_data = []
        for scan in scans:
            try:
                date_time = scan["scannedAt"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(scan["scannedAt"], "strftime") else str(scan["scannedAt"])
                building = scan.get("organization", "Unknown Organization")
                site = scan.get("site", "Unknown Site")
                
                # Handle different guard name fields from different endpoints
                guard_name = scan.get("guardName") or scan.get("guard_name") or "Unknown Guard"
                
                # Include scan source information for debugging
                scan_source = "/guard/scan" if scan.get("guardId") else "/qr/scan"
                
                logger.info(f"Processing scan: Building={building}, Site={site}, Guard={guard_name}, Source={scan_source}")
                
                row_data = {
                    "Date + Time": date_time,
                    "Action": "QR Code Scan",
                    "Building Name": building,
                    "Site Name": site,
                    "Guard Name": guard_name,
                    "Scan Source": scan_source,
                    "Guard Email": scan.get("guardEmail", ""),
                    "QR ID": scan.get("qrId", ""),
                    "Address": scan.get("address", f"Lat: {scan.get('deviceLat', '')}, Lng: {scan.get('deviceLng', '')}"),
                    "Formatted Address": scan.get("formatted_address", ""),
                    "Latitude": scan.get("deviceLat", ""),
                    "Longitude": scan.get("deviceLng", "")
                }
                excel_data.append(row_data)
                
            except Exception as e:
                logger.error(f"Error processing scan event: {e}, scan: {scan}")
                continue

        if not excel_data:
            logger.warning("No valid scan data found for Excel report")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No valid scan data found for Excel report"
            )


        # Create Excel file in memory and return as response
        import io
        import pandas as pd
        from fastapi.responses import StreamingResponse

        output = io.BytesIO()
        df = pd.DataFrame(excel_data)
        df.to_excel(output, index=False, sheet_name="Scan Report")
        output.seek(0)

        filename = f"scan_report_{datetime.now().strftime('%Y%m%d%H%M%S')}.xlsx"
        headers = {
            "Content-Disposition": f"attachment; filename={filename}"
        }
        logger.info(f"Excel report generated successfully in memory: {filename}")
        return StreamingResponse(output, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers=headers)

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        logger.error(f"Error generating Excel report: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while generating the report: {str(e)}"
        )


# ============================================================================
# SUPERVISOR: Add Guard API
# ============================================================================

@supervisor_router.post("/add-guard")
async def add_guard(
    guard_data: SupervisorAddGuardRequest,
    current_supervisor: Dict[str, Any] = Depends(get_current_supervisor)
):
    """
    SUPERVISOR ONLY: Add a new guard to the system
    Creates guard account and sends credentials via email
    """
    try:
        users_collection = get_users_collection()
        guards_collection = get_guards_collection()
        
        if users_collection is None or guards_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
        
        supervisor_id = str(current_supervisor["_id"])
        supervisor_name = current_supervisor.get("name", current_supervisor.get("email", "Supervisor"))
        supervisor_area = current_supervisor.get("areaCity", "Unknown")
        
        # Check if user already exists
        existing_user = await users_collection.find_one({"email": guard_data.email})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User with email {guard_data.email} already exists"
            )
        
        # Hash the password
        hashed_password = jwt_service.hash_password(guard_data.password)
        
        # Create user record
        user_data = {
            "email": guard_data.email,
            "name": guard_data.name,
            "role": UserRole.GUARD.value,
            "passwordHash": hashed_password,
            "isActive": True,
            "isEmailVerified": True,  # Auto-verified since created by supervisor
            "createdBy": supervisor_id,
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow(),
            "areaCity": supervisor_area,
            "supervisorId": supervisor_id
        }
        
        # Insert user
        user_result = await users_collection.insert_one(user_data)
        user_id = str(user_result.inserted_id)
        
        # Generate employee code for guard
        guard_count = await guards_collection.count_documents({})
        employee_code = f"GRD{str(guard_count + 1).zfill(3)}"
        
        # Create guard record
        guard_data_record = {
            "userId": ObjectId(user_id),
            "supervisorId": ObjectId(supervisor_id),
            "employeeCode": employee_code,
            "email": guard_data.email,
            "name": guard_data.name,
            "areaCity": supervisor_area,
            "shift": "Day Shift",  # Default shift
            "phoneNumber": "",  # Can be updated later
            "emergencyContact": "",  # Can be updated later
            "isActive": True,
            "createdBy": supervisor_id,
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        
        # Insert guard
        guard_result = await guards_collection.insert_one(guard_data_record)
        guard_id = str(guard_result.inserted_id)
        
        # Send credentials email to guard
        email_sent = await email_service.send_guard_credentials_email(
            to_email=guard_data.email,
            name=guard_data.name,
            password=guard_data.password,
            supervisor_name=supervisor_name
        )
        
        logger.info(f"Supervisor {supervisor_name} created guard account for {guard_data.name} ({guard_data.email})")
        
        return {
            "message": "Guard added successfully",
            "guard": {
                "id": guard_id,
                "userId": user_id,
                "employeeCode": employee_code,
                "name": guard_data.name,
                "email": guard_data.email,
                "areaCity": supervisor_area,
                "supervisorId": supervisor_id,
                "supervisorName": supervisor_name,
                "createdAt": datetime.utcnow().isoformat()
            },
            "credentials_sent": email_sent,
            "note": "Guard has been created and credentials sent via email. Guard can change password using /auth/reset-password endpoint."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding guard: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add guard: {str(e)}"
        )


# ============================================================================
# SUPERVISOR: Delete Guard API
# ============================================================================

@supervisor_router.delete("/delete-guard")
async def delete_guard(
    name: str,
    email: str,
    current_supervisor: Dict[str, Any] = Depends(get_current_supervisor)
):
    """
    SUPERVISOR ONLY: Delete a guard from the system by name and email
    Removes guard from both guards and users collections
    """
    try:
        users_collection = get_users_collection()
        guards_collection = get_guards_collection()
        
        if users_collection is None or guards_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
        
        # Verify the guard belongs to this supervisor
        supervisor_id = str(current_supervisor["_id"])
        
        # First, let's check if any guard exists with this name and email (regardless of supervisor)
        any_guard = await guards_collection.find_one({
            "name": name.strip(),  # Remove any trailing spaces
            "email": email.strip()
        })
        
        if not any_guard:
            # Check for similar names (case-insensitive)
            similar_guard = await guards_collection.find_one({
                "name": {"$regex": f"^{name.strip()}$", "$options": "i"},
                "email": {"$regex": f"^{email.strip()}$", "$options": "i"}
            })
            
            if not similar_guard:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"No guard found with name '{name.strip()}' and email '{email.strip()}' in the system"
                )
        
        # Find guard by name and email that belongs to this supervisor
        guard = await guards_collection.find_one({
            "name": name.strip(),  # Remove any trailing spaces
            "email": email.strip(),
            "supervisorId": ObjectId(supervisor_id)
        })
        
        if not guard:
            # The guard exists but doesn't belong to this supervisor
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Guard with name '{name.strip()}' and email '{email.strip()}' exists but does not belong to your supervision"
            )
        
        guard_id = str(guard["_id"])
        user_id = guard.get("userId")
        
        # Delete from guards collection
        guard_result = await guards_collection.delete_one({"_id": guard["_id"]})
        
        # Delete from users collection if userId exists
        user_result = None
        if user_id:
            user_result = await users_collection.delete_one({"_id": user_id})
        
        # Send email notification to the guard
        supervisor_name = current_supervisor.get("name", current_supervisor.get("email", "Your supervisor"))
        email_sent = await email_service.send_account_removal_email(
            to_email=email,
            name=name,
            role="Guard",
            removed_by=supervisor_name
        )
        
        logger.info(f"Supervisor {supervisor_id} deleted guard {guard_id} ({name}, {email})")
        
        return {
            "message": "Guard deleted successfully",
            "guard_id": guard_id,
            "name": name,
            "email": email,
            "user_deleted": user_result.deleted_count > 0 if user_result else False,
            "email_sent": email_sent,
            "note": "Guard has been removed from the system and notification email sent"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting guard: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete guard: {str(e)}"
        )

