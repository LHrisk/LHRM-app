"""
Pydantic models for the Guard Management System
Updated for Email-OTP authentication with JWT and role-based access
"""

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator, ConfigDict
from typing import List, Optional, Dict, Any, Annotated
from datetime import datetime
from enum import Enum
from bson import ObjectId


# Custom ObjectId type for Pydantic v2
PyObjectId = Annotated[str, Field(alias="_id")]


def generate_supervisor_email(area_city: str) -> str:
    """Generate supervisor email from area city: {area}supervisor@lh.io.in"""
    clean_area = area_city.lower().strip().replace(' ', '').replace('-', '')
    return f"{clean_area}supervisor@lh.io.in"


def generate_guard_email(guard_name: str, area_city: str) -> str:
    """Generate guard email: {firstname}.{area}@lh.io.in"""
    first_name = guard_name.split(' ')[0].lower().strip()
    clean_area = area_city.lower().strip().replace(' ', '').replace('-', '')
    return f"{first_name}.{clean_area}@lh.io.in"


class UserRole(str, Enum):
    """User roles enum"""
    ADMIN = "ADMIN"
    SUPERVISOR = "SUPERVISOR"
    GUARD = "GUARD"


class UserStatus(str, Enum):
    """User status enum"""
    ACTIVE = "active"
    INACTIVE = "inactive"  # Before email verification
    DISABLED = "disabled"  # Soft delete


class OTPPurpose(str, Enum):
    """OTP purpose enum"""
    SIGNUP = "SIGNUP"
    RESET = "RESET"


# Location Models
class Coordinates(BaseModel):
    """GPS coordinates model"""
    latitude: float = Field(..., ge=-90, le=90, description="Latitude coordinate")
    longitude: float = Field(..., ge=-180, le=180, description="Longitude coordinate")


class LocationCoordinates(BaseModel):
    """GPS coordinates model - alias for backwards compatibility"""
    latitude: float = Field(..., ge=-90, le=90, description="Latitude coordinate")
    longitude: float = Field(..., ge=-180, le=180, description="Longitude coordinate")


# User Models
class UserBase(BaseModel):
    """Base user model"""
    email: EmailStr = Field(..., description="User email address")
    name: str = Field(..., min_length=2, max_length=100, description="Full name")
    role: UserRole = Field(..., description="User role")
    areaCity: Optional[str] = Field(None, description="Area/City for supervisors")
    isActive: bool = Field(True, description="Account active status")


class UserCreate(BaseModel):
    """User creation model for signup"""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")
    name: str = Field(..., min_length=2, max_length=100, description="Full name")
    role: UserRole = Field(..., description="User role")
    areaCity: Optional[str] = Field(None, description="Area/City for supervisors")


class UserUpdate(BaseModel):
    """User update model"""
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    areaCity: Optional[str] = None
    isActive: Optional[bool] = None


class UserResponse(UserBase):
    """User response model"""
    id: Optional[str] = Field(None, alias="_id")
    createdAt: datetime
    updatedAt: datetime
    lastLogin: Optional[datetime] = None

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# Supervisor Models
class SupervisorBase(BaseModel):
    """Base supervisor model"""
    userId: str = Field(..., description="Reference to user ID")
    code: str = Field(..., description="Unique supervisor code (e.g., SUP001)")
    areaCity: str = Field(..., description="Assigned area/city")


class SupervisorCreate(SupervisorBase):
    """Supervisor creation model"""
    pass


class SupervisorResponse(SupervisorBase):
    """Supervisor response model"""
    id: Optional[str] = Field(None, alias="_id")
    createdAt: datetime
    updatedAt: datetime
    user: Optional[UserResponse] = None  # Populated user data

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# Guard Models
class GuardBase(BaseModel):
    """Base guard model"""
    userId: str = Field(..., description="Reference to user ID")
    supervisorId: str = Field(..., description="Assigned supervisor ID")
    employeeCode: str = Field(..., description="Unique employee code")


class GuardCreate(GuardBase):
    """Guard creation model"""
    pass


class GuardResponse(GuardBase):
    """Guard response model"""
    id: Optional[str] = Field(None, alias="_id")
    createdAt: datetime
    updatedAt: datetime
    user: Optional[UserResponse] = None  # Populated user data
    supervisor: Optional[SupervisorResponse] = None  # Populated supervisor data

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# QR Location Models
class QRLocationBase(BaseModel):
    """Base QR location model"""
    supervisorId: ObjectId = Field(..., description="Owner supervisor ID")
    site: str = Field(..., description="Site name created by the supervisor")
    label: str = Field(..., description="Human-readable label")
    lat: float = Field(..., ge=-90, le=90, description="Registered latitude")
    lng: float = Field(..., ge=-180, le=180, description="Registered longitude")
    active: bool = Field(True, description="QR location active status")

    model_config = ConfigDict(
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


class QRLocationCreate(QRLocationBase):
    """QR location creation model"""
    pass


class QRLocationUpdate(BaseModel):
    """QR location update model (label and coordinates can be updated)"""
    label: Optional[str] = None
    lat: Optional[float] = Field(None, ge=-90, le=90)
    lng: Optional[float] = Field(None, ge=-180, le=180)
    active: Optional[bool] = None


class QRLocationResponse(QRLocationBase):
    """QR location response model"""
    id: str = Field(..., alias="_id", description="QR ID (immutable)")
    createdAt: datetime
    updatedAt: datetime
    supervisor: Optional[SupervisorResponse] = None  # Populated supervisor data

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# Scan Event Models
class ScanEventBase(BaseModel):
    """Base scan event model"""
    qrId: str = Field(..., description="QR location ID")
    supervisorId: str = Field(..., description="QR owner supervisor ID")
    guardId: str = Field(..., description="Scanning guard ID")
    qrLat: float = Field(..., description="QR registered latitude")
    qrLng: float = Field(..., description="QR registered longitude")
    deviceLat: float = Field(..., description="Device GPS latitude")
    deviceLng: float = Field(..., description="Device GPS longitude")
    distanceMeters: float = Field(..., description="Distance between QR and device")
    withinRadius: bool = Field(..., description="Whether scan was within allowed radius")
    reverseAddress: Optional[str] = Field(None, description="TomTom reverse geocoded address")
    scannedAt: datetime = Field(..., description="When the scan occurred")


class ScanEventCreate(BaseModel):
    """Scan event creation model (from guard app)"""
    qrId: str = Field(..., description="QR location ID being scanned")
    guardId: str = Field(..., description="Guard performing the scan")
    deviceLat: float = Field(..., ge=-90, le=90, description="Device GPS latitude")
    deviceLng: float = Field(..., ge=-180, le=180, description="Device GPS longitude")
    scannedAt: datetime = Field(..., description="Timestamp of scan")


class ScanEventResponse(ScanEventBase):
    """Scan event response model"""
    id: Optional[str] = Field(None, alias="_id")
    createdAt: datetime
    timestampIST: str = Field(..., description="IST formatted timestamp for sheets")
    guard: Optional[GuardResponse] = None  # Populated guard data
    supervisor: Optional[SupervisorResponse] = None  # Populated supervisor data
    qrLocation: Optional[QRLocationResponse] = None  # Populated QR data

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# OTP Models
class OTPTokenBase(BaseModel):
    """Base OTP token model"""
    email: EmailStr = Field(..., description="Email for OTP")
    otpHash: str = Field(..., description="Hashed OTP value")
    purpose: OTPPurpose = Field(..., description="OTP purpose")
    expiresAt: datetime = Field(..., description="OTP expiration time")
    attempts: int = Field(0, description="Number of verification attempts")


class OTPTokenCreate(OTPTokenBase):
    """OTP token creation model"""
    pass


class OTPTokenResponse(OTPTokenBase):
    """OTP token response model"""
    id: Optional[str] = Field(None, alias="_id")
    createdAt: datetime

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# Refresh Token Models
class RefreshTokenBase(BaseModel):
    """Base refresh token model"""
    userId: str = Field(..., description="User ID")
    tokenHash: str = Field(..., description="Hashed refresh token")
    expiresAt: datetime = Field(..., description="Token expiration time")
    revoked: bool = Field(False, description="Token revocation status")


class RefreshTokenCreate(RefreshTokenBase):
    """Refresh token creation model"""
    pass


class RefreshTokenResponse(RefreshTokenBase):
    """Refresh token response model"""
    id: Optional[str] = Field(None, alias="_id")
    createdAt: datetime

    model_config = ConfigDict(
        populate_by_name=True,
        arbitrary_types_allowed=True,
        json_encoders={ObjectId: str}
    )


# Authentication Models
class SignupRequest(BaseModel):
    """Email signup request"""
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")
    name: str = Field(..., min_length=2, max_length=100, description="Full name")
    role: UserRole = Field(..., description="User role")
    areaCity: Optional[str] = Field(None, description="Area/City (required for supervisors)")

    @field_validator('areaCity')
    @classmethod
    def validate_area_city(cls, v, info):
        if info.data.get('role') == UserRole.SUPERVISOR and not v:
            raise ValueError('areaCity is required for SUPERVISOR role')
        return v


class VerifyOTPRequest(BaseModel):
    """OTP verification request - only requires OTP code"""
    otp: str = Field(..., min_length=6, max_length=6, description="6-digit OTP")


class LoginRequest(BaseModel):
    """Login request"""
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., description="Password")


class ResetPasswordRequest(BaseModel):
    """Password reset request"""
    email: EmailStr = Field(..., description="Email address")


class ResetPasswordConfirmRequest(BaseModel):
    """Password reset confirmation request"""
    email: EmailStr = Field(..., description="Email address")
    otp: str = Field(..., min_length=6, max_length=6, description="6-digit OTP")
    newPassword: str = Field(..., min_length=8, description="New password")


class TokenResponse(BaseModel):
    """Token response model"""
    accessToken: str = Field(..., description="JWT access token")
    refreshToken: str = Field(..., description="JWT refresh token")
    tokenType: str = Field("bearer", description="Token type")
    expiresIn: int = Field(..., description="Access token expiry in seconds")


class LoginResponse(BaseModel):
    """Login response model"""
    user: UserResponse
    tokens: TokenResponse
    message: str = "Login successful"


# QR Management Models
class QRGenerateRequest(BaseModel):
    """QR generation/update request for supervisors"""
    label: str = Field(..., description="QR location label")
    lat: float = Field(..., ge=-90, le=90, description="Latitude")
    lng: float = Field(..., ge=-180, le=180, description="Longitude")


class QRGenerateResponse(BaseModel):
    """QR generation response"""
    qrId: str = Field(..., description="Permanent QR ID")
    qrCodeImage: str = Field(..., description="Base64 encoded QR code image")
    qrLocation: QRLocationResponse = Field(..., description="QR location details")


# Reporting Models
class AreaReportRequest(BaseModel):
    """Area-wise report request"""
    areaCity: Optional[str] = None
    startDate: Optional[datetime] = None
    endDate: Optional[datetime] = None
    page: int = Field(1, ge=1)
    limit: int = Field(50, ge=1, le=1000)


class ScanReportResponse(BaseModel):
    """Scan report response"""
    scans: List[ScanEventResponse]
    total: int
    page: int
    totalPages: int
    summary: Dict[str, Any]


# Success/Error Response Models
class SuccessResponse(BaseModel):
    """Generic success response"""
    message: str
    data: Optional[Any] = None


class ErrorResponse(BaseModel):
    """Generic error response"""
    error: str
    details: Optional[str] = None


# Configuration Models
class SystemConfig(BaseModel):
    """System configuration model"""
    withinRadiusMeters: float = Field(100.0, description="Default radius for scan validation")
    otpExpireMinutes: int = Field(10, description="OTP expiration time")
    accessTokenExpireMinutes: int = Field(30, description="Access token expiration")
    refreshTokenExpireDays: int = Field(7, description="Refresh token expiration")


class SystemConfigUpdate(BaseModel):
    """System configuration update model"""
    withinRadiusMeters: Optional[float] = Field(None, ge=1.0, le=1000.0)
    otpExpireMinutes: Optional[int] = Field(None, ge=1, le=60)
    accessTokenExpireMinutes: Optional[int] = Field(None, ge=5, le=1440)
    refreshTokenExpireDays: Optional[int] = Field(None, ge=1, le=30)


# Pagination Models
class PaginatedResponse(BaseModel):
    """Generic paginated response"""
    items: List[Any]
    total: int
    page: int
    totalPages: int
    hasNext: bool
    hasPrevious: bool


# Health Check Models
class HealthCheckResponse(BaseModel):
    """Health check response"""
    status: str = "healthy"
    timestamp: datetime
    version: str = "1.0.0"
    services: Dict[str, str]  # Service name -> status


# QR Scanning Models for New System
class QRScanRequest(BaseModel):
    """QR scan request for authenticated guard"""
    qrId: str = Field(..., description="QR code identifier")
    coordinates: Coordinates = Field(..., description="Guard's current GPS coordinates")
    notes: Optional[str] = Field(None, max_length=500, description="Optional scan notes")


class QRScanResponse(BaseModel):
    """QR scan response"""
    scanEventId: str = Field(..., description="Scan event ID")
    qrId: str = Field(..., description="QR code identifier")
    locationName: str = Field(..., description="Location name")
    isWithinRadius: bool = Field(..., description="Whether scan was within allowed radius")
    distanceFromQR: float = Field(..., description="Distance from QR location in meters")
    address: str = Field(..., description="Current address from TomTom")
    scannedAt: datetime = Field(..., description="Scan timestamp")
    message: str = Field(..., description="Scan result message")


class QRCodePublicScanRequest(BaseModel):
    """Public QR scan request (no auth required)"""
    qrId: str = Field(..., description="QR code identifier")
    guardEmail: EmailStr = Field(..., description="Guard email for identification")
    coordinates: Coordinates = Field(..., description="Guard's current GPS coordinates")
    notes: Optional[str] = Field(None, max_length=500, description="Optional scan notes")
    deviceInfo: Optional[str] = Field(None, max_length=200, description="Device information")


class QRCodePublicScanResponse(BaseModel):
    """Public QR scan response"""
    message: str
    qr_id: str
    building: str
    site: str
    scanned_at: str
    coordinates: Dict[str, float]


# ============================================================================
# NEW MODELS FOR PHONE/EMAIL SUPPORT
# ============================================================================

class ContactMethod(str, Enum):
    """Contact method enum"""
    EMAIL = "email"
    PHONE = "phone"


class SupervisorCreateFlexibleRequest(BaseModel):
    """Flexible supervisor creation request supporting email or phone"""
    name: str = Field(..., min_length=2, max_length=100, description="Full name")
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")
    areaCity: str = Field(..., description="Area/City assignment")
    contact_method: ContactMethod = Field(..., description="Contact method (email or phone)")
    email: Optional[EmailStr] = Field(None, description="Email address (required if contact_method is email)")
    phone_number: Optional[str] = Field(None, description="Phone number with country code (required if contact_method is phone)")

    @field_validator('email')
    @classmethod
    def validate_email(cls, v, info):
        if info.data.get('contact_method') == ContactMethod.EMAIL and not v:
            raise ValueError('Email is required when contact_method is email')
        return v

    @field_validator('phone_number')
    @classmethod
    def validate_phone_number(cls, v, info):
        if info.data.get('contact_method') == ContactMethod.PHONE and not v:
            raise ValueError('Phone number is required when contact_method is phone')
        if v and not v.startswith('+'):
            raise ValueError('Phone number must include country code (e.g., +91)')
        return v


class GuardCreateFlexibleRequest(BaseModel):
    """Flexible guard creation request supporting email or phone"""
    name: str = Field(..., min_length=2, max_length=100, description="Full name")
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")
    contact_method: ContactMethod = Field(..., description="Contact method (email or phone)")
    email: Optional[EmailStr] = Field(None, description="Email address (required if contact_method is email)")
    phone_number: Optional[str] = Field(None, description="Phone number with country code (required if contact_method is phone)")

    @field_validator('email')
    @classmethod
    def validate_email(cls, v, info):
        if info.data.get('contact_method') == ContactMethod.EMAIL and not v:
            raise ValueError('Email is required when contact_method is email')
        return v

    @field_validator('phone_number')
    @classmethod
    def validate_phone_number(cls, v, info):
        if info.data.get('contact_method') == ContactMethod.PHONE and not v:
            raise ValueError('Phone number is required when contact_method is phone')
        if v and not v.startswith('+'):
            raise ValueError('Phone number must include country code (e.g., +91)')
        return v


class QRAssignmentRequest(BaseModel):
    """Request to assign/unassign guard to QR code"""
    qr_id: str = Field(..., description="QR code ID")
    guard_id: Optional[str] = Field(None, description="Guard ID to assign (null to unassign)")


class QRAssignmentResponse(BaseModel):
    """Response for QR code assignment"""
    message: str
    qr_id: str
    guard_id: Optional[str] = None
    guard_name: Optional[str] = None


class BuildingListResponse(BaseModel):
    """Response for building list"""
    buildings: List[Dict[str, Any]]
    total: int
    page: int
    total_pages: int
    has_next: bool
    has_previous: bool


class GuardListResponse(BaseModel):
    """Response for guard list"""
    guards: List[Dict[str, Any]]
    total: int
    page: int
    total_pages: int
    has_next: bool
    has_previous: bool
    filters_applied: Dict[str, Any]


class QRListResponse(BaseModel):
    """Response for QR codes list"""
    qr_codes: List[Dict[str, Any]]
    total: int


class FlexibleLoginRequest(BaseModel):
    """Login request supporting email or phone"""
    contact_method: ContactMethod = Field(..., description="Contact method (email or phone)")
    email: Optional[EmailStr] = Field(None, description="Email address")
    phone_number: Optional[str] = Field(None, description="Phone number")
    password: str = Field(..., description="Password")

    @field_validator('email')
    @classmethod
    def validate_email(cls, v, info):
        if info.data.get('contact_method') == ContactMethod.EMAIL and not v:
            raise ValueError('Email is required when contact_method is email')
        return v

    @field_validator('phone_number')
    @classmethod
    def validate_phone_number(cls, v, info):
        if info.data.get('contact_method') == ContactMethod.PHONE and not v:
            raise ValueError('Phone number is required when contact_method is phone')
        return v


class FlexibleOTPRequest(BaseModel):
    """OTP request supporting email or phone"""
    contact_method: ContactMethod = Field(..., description="Contact method (email or phone)")
    email: Optional[EmailStr] = Field(None, description="Email address")
    phone_number: Optional[str] = Field(None, description="Phone number")

    @field_validator('email')
    @classmethod
    def validate_email(cls, v, info):
        if info.data.get('contact_method') == ContactMethod.EMAIL and not v:
            raise ValueError('Email is required when contact_method is email')
        return v

    @field_validator('phone_number')
    @classmethod
    def validate_phone_number(cls, v, info):
        if info.data.get('contact_method') == ContactMethod.PHONE and not v:
            raise ValueError('Phone number is required when contact_method is phone')
        return v


class NotificationResponse(BaseModel):
    """Response for notification sending"""
    success: bool
    method: str  # "email" or "sms"
    message: str
    details: Optional[Dict[str, Any]] = None


class QRCodeGenerateRequest(BaseModel):
    """QR code generation request"""
    qrId: str = Field(..., description="QR location ID")
    size: int = Field(10, ge=5, le=50, description="QR code box size")


class QRCodeGenerateResponse(BaseModel):
    """QR code generation response"""
    qrId: str = Field(..., description="QR code identifier")
    locationName: str = Field(..., description="Location name")
    qrCodeImage: str = Field(..., description="Base64 encoded QR code image")
    size: int = Field(..., description="QR code box size")
    coordinates: Coordinates = Field(..., description="QR location coordinates")
    address: str = Field(..., description="QR location address")
    generatedAt: datetime = Field(..., description="Generation timestamp")


class QRLocationUpdate(BaseModel):
    """QR location update model"""
    locationName: Optional[str] = Field(None, min_length=2, max_length=100)
    coordinates: Optional[Coordinates] = None
    isActive: Optional[bool] = None


class GuardProfileResponse(BaseModel):
    """Guard profile response"""
    id: str = Field(..., description="Guard ID")
    userId: str = Field(..., description="User ID")
    supervisorId: str = Field(..., description="Supervisor ID")
    email: EmailStr = Field(..., description="Email")
    name: str = Field(..., description="Name")
    areaCity: str = Field(..., description="Area city")
    shift: str = Field(..., description="Shift information")
    phoneNumber: str = Field(..., description="Phone number")
    emergencyContact: str = Field(..., description="Emergency contact")
    isActive: bool = Field(..., description="Active status")
    createdAt: datetime = Field(..., description="Creation timestamp")
    updatedAt: datetime = Field(..., description="Last update timestamp")


# Updated Supervisor and Guard Models for New System
class SupervisorCreate(BaseModel):
    """Supervisor creation model for new system"""
    email: EmailStr = Field(..., description="Email address")
    name: str = Field(..., min_length=2, max_length=100, description="Full name")
    areaCity: str = Field(..., min_length=2, max_length=100, description="Area city")
    areaState: str = Field(..., min_length=2, max_length=100, description="Area state")
    areaCountry: str = Field(..., min_length=2, max_length=100, description="Area country")
    sheetId: Optional[str] = Field(None, description="Google Sheets ID for logging")
    
    @field_validator('email')
    @classmethod
    def validate_supervisor_email(cls, v: str) -> str:
        """Validate supervisor email format: area + supervisor@lh.io.in"""
        if not v.endswith('@lh.io.in'):
            raise ValueError('Supervisor email must end with @lh.io.in')
        
        email_local = v.split('@')[0].lower()
        if not email_local.endswith('supervisor'):
            raise ValueError('Supervisor email must be in format: {area}supervisor@lh.io.in')
        
        # Extract area from email
        area = email_local.replace('supervisor', '')
        if len(area) < 2:
            raise ValueError('Area name must be at least 2 characters')
            
        return v.lower()
    
    @field_validator('areaCity')
    @classmethod
    def validate_area_city(cls, v: str) -> str:
        """Ensure area city matches email format"""
        return v.lower().strip()


class SupervisorResponse(BaseModel):
    """Supervisor response model for new system"""
    id: str = Field(..., description="Supervisor ID")
    userId: str = Field(..., description="User ID")
    email: EmailStr = Field(..., description="Email")
    name: str = Field(..., description="Name")
    areaCity: str = Field(..., description="Area city")
    areaState: str = Field(..., description="Area state")
    areaCountry: str = Field(..., description="Area country")
    sheetId: Optional[str] = Field(None, description="Google Sheets ID")
    assignedGuards: List[str] = Field(default_factory=list, description="Assigned guard IDs")
    isActive: bool = Field(..., description="Active status")
    createdAt: datetime = Field(..., description="Creation timestamp")
    updatedAt: datetime = Field(..., description="Last update timestamp")


class AdminAddSupervisorRequest(BaseModel):
    """Model for admin adding a new supervisor"""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Vinayak Gupta",
                "email": "",
                "phone": "",
                "password": "Test@123",
                "areaCity": "Delhi"
            }
        }
    )
    
    name: str = Field(..., min_length=2, max_length=100, description="Supervisor's full name")
    email: Optional[str] = Field(
        default=None, 
        description="Supervisor's email address (optional - provide either email or phone)"
    )
    phone: Optional[str] = Field(
        default=None, 
        description="Supervisor's phone number (optional - provide either email or phone)"
    )
    password: str = Field(..., min_length=6, max_length=50, description="Supervisor's initial password")
    areaCity: str = Field(..., min_length=2, max_length=100, description="Area/City to supervise")

    @model_validator(mode='after')
    def validate_contact_method(self):
        """Ensure either email or phone is provided"""
        # Treat empty strings as None
        email = self.email.strip() if self.email else None
        phone = self.phone.strip() if self.phone else None
        
        if not email and not phone:
            raise ValueError("Either email or phone number must be provided")
        
        # Update the fields to clean values
        self.email = email if email else None
        self.phone = phone if phone else None
        return self

    @field_validator('email')
    @classmethod
    def validate_supervisor_email(cls, v: Optional[str]) -> Optional[str]:
        """Validate supervisor email format"""
        if v:
            v = v.strip()
            # Treat empty string as None
            if not v:
                return None
            if "@" not in v:
                raise ValueError("value is not a valid email address: An email address must have an @-sign.")
            return v.lower()
        return v

    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v: Optional[str]) -> Optional[str]:
        """Validate phone number format"""
        if v:
            v = v.strip()
            # Treat empty string as None
            if not v:
                return None
            # Remove non-digits and validate format
            digits_only = ''.join(filter(str.isdigit, v))
            if len(digits_only) != 10:
                raise ValueError("Phone number must be exactly 10 digits")
            return digits_only
        return v
        if v:
            # Remove non-digits and validate format
            digits_only = ''.join(filter(str.isdigit, v))
            if len(digits_only) != 10:
                raise ValueError("Phone number must be exactly 10 digits")
            return digits_only
        return v


class SupervisorAddGuardRequest(BaseModel):
    """
    Request model for adding a guard by a supervisor
    """
    name: str = Field(..., min_length=2, max_length=100, description="Guard's full name")
    email: Optional[str] = Field(
        "",
        description="Guard's email address (optional, default empty, no validation if empty)"
    )
    phone: Optional[str] = Field(
        "",
        description="Guard's phone number (optional, must be 10 digits if provided, default empty)"
    )

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v):
        if v:
            # Validate only if phone is not empty
            if not v.isdigit() or len(v) != 10:
                raise ValueError("Phone number must be exactly 10 digits")
        return v

    password: str = Field(..., min_length=8, description="Password for the guard (min 8 characters)")


