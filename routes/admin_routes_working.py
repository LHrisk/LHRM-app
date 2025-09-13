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
    building_name: Optional[str] = Query(None, description="Name of the building to filter (optional)")
):
    """
    Generate area-wise Excel reports for all areas or a specific area
    """
    try:
        scan_events_collection = get_scan_events_collection()
        if scan_events_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )

        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)

        # Build base filter for date range
        base_filter = {
            "scannedAt": {"$gte": start_date, "$lte": end_date}
        }

        # Add area filter if specified (case-insensitive)
        if area:
            base_filter["$or"] = [
                {"organization": {"$regex": area, "$options": "i"}},
                {"site": {"$regex": area, "$options": "i"}},
                {"address": {"$regex": area, "$options": "i"}},
                {"formatted_address": {"$regex": area, "$options": "i"}}
            ]

        # Add building filter if specified (case-insensitive)
        if building_name:
            base_filter["organization"] = {"$regex": building_name, "$options": "i"}

        # Fetch scan data
        scans = await scan_events_collection.find(base_filter).to_list(length=None)

        # If no scans found with filters, try a broader search
        if not scans and (area or building_name):
            logger.info("No scans found with specific filters, trying broader search")
            broader_filter = {
                "scannedAt": {"$gte": start_date, "$lte": end_date}
            }
            
            # Apply less restrictive filtering
            or_conditions = []
            if area:
                or_conditions.extend([
                    {"organization": {"$regex": area, "$options": "i"}},
                    {"site": {"$regex": area, "$options": "i"}},
                    {"address": {"$regex": area, "$options": "i"}},
                    {"formatted_address": {"$regex": area, "$options": "i"}}
                ])
            if building_name:
                or_conditions.append({"organization": {"$regex": building_name, "$options": "i"}})
            
            if or_conditions:
                broader_filter["$or"] = or_conditions
                scans = await scan_events_collection.find(broader_filter).to_list(length=None)

        if not scans:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="No scan data found in the specified date range"
            )

        # Group data by area with improved organization and site display
        area_data = {}
        for scan in scans:
            # Use a combination of address and organization for area grouping
            area_name = scan.get("formatted_address") or scan.get("address", "Unknown Area")
            organization = scan.get("organization", "Unknown Organization")
            site = scan.get("site", "Unknown Site")
            guard_name = scan.get("guardName", scan.get("guardEmail", "Unknown Guard"))

            if area_name not in area_data:
                area_data[area_name] = []

            area_data[area_name].append({
                "timestamp": scan.get("scannedAt"),
                "organization": organization,
                "site": site,
                "guard_name": guard_name,
                "guard_email": scan.get("guardEmail", ""),
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
                    "Organization": scan_data["organization"],
                    "Site": scan_data["site"],
                    "Guard Name": scan_data["guard_name"],
                    "Guard Email": scan_data["guard_email"],
                    "Timestamp": scan_data["timestamp"],
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
        building_suffix = f"_{building_name.replace(' ', '_')}" if building_name else ""
        filename = f"area_report{area_suffix}{building_suffix}_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.xlsx"
        
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
        import traceback
        logger.error(f"Error generating area-wise Excel report: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while generating the area-wise report: {str(e)}"
        )


# ============================================================================
# ADMIN: Add Supervisor API
# ============================================================================

@admin_router.post("/add-supervisor")
async def add_supervisor(
    supervisor_data: AdminAddSupervisorRequest,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """
    ADMIN ONLY: Add a new supervisor to the system
    Creates supervisor account and sends credentials via email
    """
    try:
        users_collection = get_users_collection()
        supervisors_collection = get_supervisors_collection()
        
        if users_collection is None or supervisors_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
        
        admin_id = str(current_admin["_id"])
        admin_name = current_admin.get("name", current_admin.get("email", "Admin"))
        
        # Check if user already exists
        existing_user = await users_collection.find_one({"email": supervisor_data.email})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User with email {supervisor_data.email} already exists"
            )
        
        # Hash the password
        hashed_password = jwt_service.hash_password(supervisor_data.password)
        
        # Create user record
        user_data = {
            "email": supervisor_data.email,
            "name": supervisor_data.name,
            "role": UserRole.SUPERVISOR.value,
            "passwordHash": hashed_password,
            "isActive": True,
            "isEmailVerified": True,  # Auto-verified since created by admin
            "createdBy": admin_id,
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow(),
            "areaCity": supervisor_data.areaCity
        }
        
        # Insert user
        user_result = await users_collection.insert_one(user_data)
        user_id = str(user_result.inserted_id)
        
        # Generate supervisor code
        supervisor_count = await supervisors_collection.count_documents({})
        supervisor_code = f"SUP{str(supervisor_count + 1).zfill(3)}"
        
        # Create supervisor record
        supervisor_data_record = {
            "userId": ObjectId(user_id),
            "code": supervisor_code,
            "email": supervisor_data.email,
            "name": supervisor_data.name,
            "areaCity": supervisor_data.areaCity,
            "isActive": True,
            "createdBy": admin_id,
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        
        # Insert supervisor
        supervisor_result = await supervisors_collection.insert_one(supervisor_data_record)
        supervisor_id = str(supervisor_result.inserted_id)
        
        # Send credentials email to supervisor
        email_sent = await email_service.send_supervisor_credentials_email(
            to_email=supervisor_data.email,
            name=supervisor_data.name,
            password=supervisor_data.password,
            area_city=supervisor_data.areaCity,
            admin_name=admin_name
        )
        
        logger.info(f"Admin {admin_name} created supervisor account for {supervisor_data.name} ({supervisor_data.email}) - Area: {supervisor_data.areaCity}")
        
        return {
            "message": "Supervisor added successfully",
            "supervisor": {
                "id": supervisor_id,
                "userId": user_id,
                "code": supervisor_code,
                "name": supervisor_data.name,
                "email": supervisor_data.email,
                "areaCity": supervisor_data.areaCity,
                "createdBy": admin_id,
                "adminName": admin_name,
                "createdAt": datetime.utcnow().isoformat()
            },
            "credentials_sent": email_sent,
            "note": "Supervisor has been created and credentials sent via email. Supervisor can change password using /auth/reset-password endpoint."
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
# ADMIN: Delete Supervisor API
# ============================================================================

@admin_router.delete("/delete-supervisor")
async def delete_supervisor(
    name: str,
    email: str,
    area: str,
    current_admin: Dict[str, Any] = Depends(get_current_admin)
):
    """
    ADMIN ONLY: Delete a supervisor from the system by name, email and area
    Removes supervisor from both supervisors and users collections
    """
    try:
        users_collection = get_users_collection()
        supervisors_collection = get_supervisors_collection()
        
        if users_collection is None or supervisors_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
        
        # Find supervisor by name, email and area
        supervisor = await supervisors_collection.find_one({
            "name": name,
            "email": email,
            "areaCity": area
        })
        
        if not supervisor:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Supervisor with name '{name}', email '{email}', and area '{area}' not found"
            )
        
        supervisor_id = str(supervisor["_id"])
        
        # Delete from supervisors collection
        supervisor_result = await supervisors_collection.delete_one({"_id": supervisor["_id"]})
        
        # Delete from users collection if userId exists
        user_result = None
        if supervisor.get("userId"):
            user_result = await users_collection.delete_one({"_id": supervisor["userId"]})
        
        # Send email notification to the supervisor
        admin_name = current_admin.get("name", current_admin.get("email", "System Administrator"))
        email_sent = await email_service.send_account_removal_email(
            to_email=email,
            name=name,
            role="Field Officer",  # Using the new terminology
            removed_by=admin_name
        )
        
        logger.info(f"Admin {current_admin.get('email')} deleted supervisor {supervisor_id} ({name}, {email}, {area})")
        
        return {
            "message": "Supervisor deleted successfully",
            "supervisor_id": supervisor_id,
            "name": name,
            "email": email,
            "area": area,
            "user_deleted": user_result.deleted_count > 0 if user_result else False,
            "email_sent": email_sent,
            "note": "Supervisor has been removed from the system and notification email sent"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting supervisor: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete supervisor: {str(e)}"
        )
