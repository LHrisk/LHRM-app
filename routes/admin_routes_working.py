"""
Admin routes for user management and system administration
ADMIN role only - manage supervisors, guards, and system configuration
Updated with specific email patterns: admin@lh.io.in, {area}supervisor@lh.io.in
"""

from fastapi import APIRouter, HTTPException, status, Depends, Query
from fastapi.responses import FileResponse
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging
import os
import io
from bson import ObjectId

# Import services and dependencies
from services.auth_service import get_current_admin
from services.google_drive_excel_service import google_drive_excel_service
from services.email_service import email_service
from services.jwt_service import jwt_service
from database import (
    get_users_collection, get_supervisors_collection, get_guards_collection,
    get_scan_events_collection, get_qr_locations_collection, get_database_health
)
from config import settings

# Import models
from models import (
    UserCreate, UserResponse, UserRole, SupervisorCreate, SupervisorResponse,
    GuardCreate, GuardResponse, ScanEventResponse, AreaReportRequest,
    ScanReportResponse, SuccessResponse, SystemConfig, SystemConfigUpdate,
    AdminAddSupervisorRequest, generate_supervisor_email, generate_guard_email
)

logger = logging.getLogger(__name__)

# Create router
admin_router = APIRouter()


@admin_router.get("/dashboard")
async def get_admin_dashboard(current_admin: Dict[str, Any] = Depends(get_current_admin)):
    """
    Admin dashboard with system statistics
    """
    try:
        users_collection = get_users_collection()
        supervisors_collection = get_supervisors_collection()
        guards_collection = get_guards_collection()
        scan_events_collection = get_scan_events_collection()
        
        if not all([
            users_collection is not None, 
            supervisors_collection is not None, 
            guards_collection is not None, 
            scan_events_collection is not None
        ]):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
        
        # Get basic counts
        total_users = await users_collection.count_documents({})
        total_supervisors = await supervisors_collection.count_documents({})
        total_guards = await guards_collection.count_documents({})
        
        # Get today's scans count with improved logic
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        total_scans_today = await scan_events_collection.count_documents({
            "scannedAt": {"$gte": today_start}
        })
        
        # Get recent activity with improved data display
        recent_scans_cursor = scan_events_collection.find({}) \
            .sort("scannedAt", -1) \
            .limit(10)
        
        recent_scans = []
        async for scan in recent_scans_cursor:
            # Get organization and site information
            organization = scan.get("organization", "Unknown Organization")
            site = scan.get("site", "Unknown Site") 
            guard_name = scan.get("guardName", scan.get("guardEmail", "Unknown Guard"))
            
            scan_data = {
                "_id": str(scan["_id"]),
                "guardId": str(scan.get("guardId", "")),
                "guardEmail": scan.get("guardEmail", ""),
                "guardName": guard_name,
                "organization": organization,
                "site": site,
                "qrId": str(scan.get("qrId", "")),
                "scannedAt": scan.get("scannedAt"),
                "deviceLat": scan.get("deviceLat"),
                "deviceLng": scan.get("deviceLng"),
                "address": scan.get("address", ""),
                "timestampIST": scan.get("timestampIST", ""),
                "supervisorId": str(scan.get("supervisorId", "")) if scan.get("supervisorId") else None
            }
            recent_scans.append(scan_data)
        
        # Convert admin ObjectIds to strings
        admin_info = {
            "_id": str(current_admin["_id"]),
            "email": current_admin["email"],
            "name": current_admin.get("name", "Admin"),
            "role": current_admin.get("role", "ADMIN")
        }
        
        return {
            "stats": {
                "totalUsers": total_users,
                "totalSupervisors": total_supervisors,
                "totalGuards": total_guards,
                "scansToday": total_scans_today
            },
            "recentActivity": recent_scans,
            "adminInfo": admin_info
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to load dashboard"
        )


@admin_router.get("/excel/area-wise-reports")
async def get_area_wise_excel_reports(
    current_admin: Dict[str, Any] = Depends(get_current_admin),
    days_back: int = Query(7, ge=1, le=30, description="Number of days to include in report"),
    area: Optional[str] = Query(None, description="Specific area/state to filter (optional)"),
    site: Optional[str] = Query(None, description="Name of the site to filter (optional)")
):
    """
    Generate area-wise Excel reports for all areas or a specific area
    """
    try:
        scan_events_collection = get_scan_events_collection()
        guards_collection = get_guards_collection()  # Get guards collection
        if scan_events_collection is None or guards_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )

        # Calculate date range using IST
        from utils.timezone_utils import parse_ist_date_range, format_excel_datetime
        start_date, end_date = parse_ist_date_range(days_back)

        # Build base filter for date range
        base_filter = {
            "scannedAt": {"$gte": start_date, "$lte": end_date}
        }

        # Add area filter if specified (case-insensitive)
        if area:
            base_filter["$or"] = [
                {"site": {"$regex": area, "$options": "i"}},
                {"address": {"$regex": area, "$options": "i"}},
                {"formatted_address": {"$regex": area, "$options": "i"}}
            ]

        # Add site filter if specified (case-insensitive)
        if site:
            base_filter["site"] = {"$regex": site, "$options": "i"}

        # Fetch scan data
        scans = await scan_events_collection.find(base_filter).to_list(length=None)

        if not scans:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No scan data found in the specified date range"
            )

        # Group data by area with improved organization and site display
        area_data = {}
        for scan in scans:
            # Fetch guard details using guardId
            guard_id = scan.get("guardId")
            guard_email = "Unknown Email"
            guard_phone = "Unknown Phone"

            if guard_id:
                try:
                    guard_id = ObjectId(guard_id)
                    guard = await guards_collection.find_one({"_id": guard_id})
                    if guard:
                        guard_email = guard.get("email") if guard and guard.get("email") else None
                        guard_phone = guard.get("phone") if guard and guard.get("phone") else "Unknown Phone"
                except Exception as e:
                    logger.error(f"Error fetching guard details for guardId {guard_id}: {e}")

            # Use guard email if available, otherwise fallback to phone number
            guard_contact = guard_email if guard_email else guard_phone

            area_name = scan.get("formatted_address") or scan.get("address", "Unknown Area")
            organization = scan.get("organization", "Unknown Organization")
            site_name = scan.get("site", "Unknown Site")
            guard_name = scan.get("guardName", "Unknown Guard")

            if area_name not in area_data:
                area_data[area_name] = []

            area_data[area_name].append({
                "timestamp": scan.get("scannedAt"),
                "organization": organization,
                "site": site_name,
                "guard_name": guard_name,
                "guard_contact": guard_contact,  # Added contact info
                "address": area_name,
                "coordinates": {
                    "lat": scan.get("deviceLat"),
                    "lng": scan.get("deviceLng")
                }
            })

        # Generate Excel response
        import io
        import pandas as pd
        from fastapi.responses import StreamingResponse

        # Prepare data for Excel
        excel_data = []
        for area_name, scans in area_data.items():
            for scan_data in scans:
                excel_data.append({
                    "Area": area_name,
                    "Site": scan_data["site"],
                    "Guard Name": scan_data["guard_name"],
                    "Guard Contact": scan_data["guard_contact"],
                    "Timestamp (IST)": format_excel_datetime(scan_data["timestamp"]),
                    "Latitude": scan_data["coordinates"]["lat"],
                    "Longitude": scan_data["coordinates"]["lng"],
                    "Address": scan_data["address"]
                })

        if not excel_data:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No scan data available for Excel generation"
            )

        # Create Excel file in memory
        output = io.BytesIO()
        df = pd.DataFrame(excel_data)
        df.to_excel(output, index=False, sheet_name="Area Wise Report")
        output.seek(0)

        # Generate filename
        area_suffix = f"_{area.replace(' ', '_')}" if area else "_all_areas"
        site_suffix = f"_{site.replace(' ', '_')}" if site else ""
        filename = f"area_report{area_suffix}{site_suffix}_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.xlsx"
        
        headers = {
            "Content-Disposition": f"attachment; filename={filename}"
        }
        
        logger.info(f"Area-wise Excel report generated: {filename}, Records: {len(excel_data)}")
        return StreamingResponse(
            output, 
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 
            headers=headers
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating area-wise Excel report: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate Excel report: {str(e)}"
        )


# ============================================================================
# ADMIN: Add Supervisor API
# ============================================================================

# Updated validation to allow either email or phone
@admin_router.post("/add-supervisor")
async def add_supervisor(
    supervisor_data: AdminAddSupervisorRequest,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """
    ADMIN ONLY: Add a new supervisor to the system
    Creates supervisor account and sends credentials via email only
    """
    try:
        supervisors_collection = get_supervisors_collection()

        if supervisors_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )

        admin_id = str(current_admin["_id"])
        admin_name = current_admin.get("name", current_admin.get("email", "Admin"))

        # Ensure at least one contact method is provided (check for empty strings too)
        has_email = supervisor_data.email and supervisor_data.email.strip()
        has_phone = supervisor_data.phone and supervisor_data.phone.strip()
        
        if not has_email and not has_phone:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Either email or phone must be provided"
            )

        # Determine if using email or phone
        contact_method = "email" if has_email else "phone"
        contact_value = supervisor_data.email.strip() if has_email else supervisor_data.phone.strip()

        # Check if supervisor already exists (only check non-empty values)
        or_conditions = []
        
        # Only check email if it's provided and not empty
        if supervisor_data.email and supervisor_data.email.strip():
            or_conditions.append({"email": supervisor_data.email.strip()})
        
        # Only check phone if it's provided and not empty
        if supervisor_data.phone and supervisor_data.phone.strip():
            or_conditions.append({"phone": supervisor_data.phone.strip()})
        
        # Only run the query if we have conditions to check
        if or_conditions:
            existing_supervisor = await supervisors_collection.find_one({
                "$or": or_conditions
            })

            if existing_supervisor:
                # Determine which field matched
                if (supervisor_data.email and supervisor_data.email.strip() and 
                    existing_supervisor.get("email") == supervisor_data.email.strip()):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Supervisor with email {supervisor_data.email} already exists"
                    )
                elif (supervisor_data.phone and supervisor_data.phone.strip() and 
                      existing_supervisor.get("phone") == supervisor_data.phone.strip()):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Supervisor with phone {supervisor_data.phone} already exists"
                    )

        # Hash the password
        hashed_password = jwt_service.hash_password(supervisor_data.password)

        # Create supervisor record
        supervisor_data_record = {
            "name": supervisor_data.name,
            "areaCity": supervisor_data.areaCity,
            "isActive": True,
            "createdBy": admin_id,
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }

        # Add email or phone to supervisor record (only if not empty)
        if supervisor_data.email and supervisor_data.email.strip():
            supervisor_data_record["email"] = supervisor_data.email.strip()
        if supervisor_data.phone and supervisor_data.phone.strip():
            supervisor_data_record["phone"] = supervisor_data.phone.strip()

        # Generate an incrementing id like sp1, sp2, etc.
        last_supervisor = await supervisors_collection.find_one(
            sort=[("id", -1)]  # Sort by id in descending order
        )
        if last_supervisor and "id" in last_supervisor:
            last_id = int(last_supervisor["id"].replace("sp", ""))
            new_id = f"sp{last_id + 1}"
        else:
            new_id = "sp1"

        # Add the new id and required fields to the supervisor record
        supervisor_data_record["id"] = new_id
        supervisor_data_record["code"] = new_id  # Use the same value for code field
        supervisor_data_record["userId"] = new_id  # Use the same value for userId field to avoid duplicate key errors

        # Add the hashed password to the supervisor record
        supervisor_data_record["passwordHash"] = hashed_password

        # Insert supervisor
        supervisor_result = await supervisors_collection.insert_one(supervisor_data_record)

        # Construct response with the new id (only include non-empty contact info)
        response_supervisor = {
            "id": new_id,
            "name": supervisor_data.name,
            "areaCity": supervisor_data.areaCity,
            "adminName": admin_name
        }
        
        # Add email and phone only if they were provided
        if has_email:
            response_supervisor["email"] = supervisor_data.email.strip()
        if has_phone:
            response_supervisor["phone"] = supervisor_data.phone.strip()
        
        return {
            "message": "Supervisor added successfully",
            "supervisor": response_supervisor
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding supervisor: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add supervisor: {str(e)}"
        )


# ============================================================================
# ADMIN: List Supervisors API
# ============================================================================

@admin_router.get("/supervisors")
async def list_supervisors(
    current_admin: Dict[str, Any] = Depends(get_current_admin),
    area_city: Optional[str] = Query(None, description="Filter by area/city")
):
    """
    ADMIN ONLY: List all supervisors in the system
    Supports filtering by area/city
    """
    try:
        supervisors_collection = get_supervisors_collection()
        
        if supervisors_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
        
        # Build query filter
        query_filter = {}
        
        if area_city:
            query_filter["areaCity"] = {"$regex": area_city, "$options": "i"}  # Case-insensitive search
        
        # Get supervisors
        supervisors_cursor = supervisors_collection.find(query_filter).sort("createdAt", -1)
        
        supervisors = []
        async for supervisor in supervisors_cursor:
            supervisor_data = {
                "id": supervisor.get("id", str(supervisor["_id"])),
                "name": supervisor["name"],
                "email": supervisor.get("email"),
                "phone": supervisor.get("phone"),
                "areaCity": supervisor["areaCity"],
                "isActive": supervisor.get("isActive", True),
                "createdAt": supervisor.get("createdAt"),
                "updatedAt": supervisor.get("updatedAt"),
                "lastLogin": supervisor.get("lastLogin"),
                "code": supervisor.get("code"),
                "userId": supervisor.get("userId")
            }
            supervisors.append(supervisor_data)
        
        return {
            "supervisors": supervisors,
            "filters": {
                "area_city": area_city
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing supervisors: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list supervisors: {str(e)}"
        )


# ============================================================================
# ADMIN: Delete Supervisor API
# ============================================================================

# Fixed the search criteria to match the database field names
@admin_router.delete("/delete-supervisor")
async def delete_supervisor(
    name: str,
    area: str,
    email: Optional[str] = None,
    phone: Optional[str] = None,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """
    ADMIN ONLY: Delete a supervisor from the system by name, area and (email OR phone)
    Removes supervisor from the supervisors collection only
    """
    try:
        # Validate that either email or phone is provided
        if not email and not phone:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either email or phone number must be provided"
            )

        supervisors_collection = get_supervisors_collection()

        if supervisors_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )

        # Clean inputs
        name = name.strip()
        area = area.strip()
        contact_value = email.strip() if email else phone.strip()
        contact_type = "email" if email else "phone"

        # Build search criteria
        search_criteria = {
            "name": name,
            "areaCity": area  # Corrected to match the database field name
        }

        if email:
            search_criteria["email"] = email

        # For phone search, check both phoneNumber and phone_number fields
        if phone:
            phone_digits = ''.join(filter(str.isdigit, phone))
            search_criteria = {
                "name": name,
                "areaCity": area,  # Corrected to match the database field name
                "$or": [
                    {"phone": phone},
                    {"phone": phone_digits}
                ]
            }

        # Find supervisor by name, area and contact
        supervisor = await supervisors_collection.find_one(search_criteria)

        if not supervisor:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Supervisor with name '{name}', area '{area}', and {contact_type} '{contact_value}' not found"
            )

        supervisor_id = str(supervisor["_id"])

        # Delete from supervisors collection
        supervisor_result = await supervisors_collection.delete_one({"_id": supervisor["_id"]})

        logger.info(f"Admin {current_admin.get('email')} deleted supervisor {supervisor_id} ({name}, {contact_type}: {contact_value}, {area})")

        return {
            "message": "Supervisor deleted successfully",
            "supervisor_id": supervisor_id,
            "name": name,
            "area": area,
            "deleted_by": contact_type,
            "contact_used": contact_value
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting supervisor: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete supervisor: {str(e)}"
        )
