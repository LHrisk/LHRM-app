"""
Authentication routes for Email-OTP signup and verification
Supports signup with email verification and password reset
"""

from fastapi import APIRouter, HTTPException, status, Depends, Form
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import logging
from bson import ObjectId

# Import services and dependencies
from services.jwt_service import jwt_service
from services.email_service import email_service
from services.auth_service import get_current_user
from database import (
    get_users_collection, get_supervisors_collection, get_guards_collection,
    get_otp_tokens_collection
)
from config import settings

# Import models
from models import (
    SignupRequest, VerifyOTPRequest, LoginRequest,
    ResetPasswordRequest, ResetPasswordConfirmRequest,
    SuccessResponse, UserResponse,
    UserRole, OTPPurpose
)

logger = logging.getLogger(__name__)

# Create router
auth_router = APIRouter()


async def generate_and_send_otp(email: str, purpose: OTPPurpose) -> bool:
    """
    Generate OTP, store hash in database, and send email
    
    Args:
        email: User email address
        purpose: OTP purpose (SIGNUP or RESET)
        
    Returns:
        True if OTP sent successfully, False otherwise
    """
    try:
        # Check rate limiting - allow one OTP per minute per email
        otp_collection = get_otp_tokens_collection()
        if otp_collection is None:
            return False
        
        # Check for recent OTP requests
        recent_otp = await otp_collection.find_one({
            "email": email,
            "purpose": purpose.value,
            "createdAt": {"$gte": datetime.utcnow() - timedelta(minutes=settings.OTP_RATE_LIMIT_MINUTES)}
        })
        
        if recent_otp:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Please wait {settings.OTP_RATE_LIMIT_MINUTES} minute(s) before requesting another OTP"
            )
        
        # Generate OTP
        otp = jwt_service.generate_otp()
        otp_hash = jwt_service.hash_otp(otp)
        
        # Store OTP in database
        expires_at = datetime.utcnow() + timedelta(minutes=settings.OTP_EXPIRE_MINUTES)
        
        otp_data = {
            "email": email,
            "otpHash": otp_hash,
            "purpose": purpose.value,
            "expiresAt": expires_at,
            "attempts": 0,
            "createdAt": datetime.utcnow()
        }
        
        # Remove any existing OTP for this email and purpose
        await otp_collection.delete_many({"email": email, "purpose": purpose.value})
        
        # Insert new OTP
        await otp_collection.insert_one(otp_data)
        
        # Send email
        purpose_text = "verification" if purpose == OTPPurpose.SIGNUP else "reset"
        email_sent = await email_service.send_otp_email(email, otp, purpose_text)
        
        if not email_sent:
            # Clean up if email failed
            await otp_collection.delete_one({"email": email, "purpose": purpose.value})
            return False
        
        logger.info(f"OTP sent for {purpose.value} to {email}")
        return True
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate and send OTP: {e}")
        return False


async def verify_otp_code_only(otp: str, purpose: OTPPurpose) -> Optional[str]:
    """
    Verify OTP code and return the associated email
    
    Args:
        otp: OTP code to verify
        purpose: OTP purpose (SIGNUP or RESET)
        
    Returns:
        Email address if OTP is valid, None otherwise
    """
    try:
        logger.info(f"verify_otp_code_only called with OTP: {otp}, purpose: {purpose.value}")
        
        otp_collection = get_otp_tokens_collection()
        if otp_collection is None:
            logger.error("OTP collection is None")
            return None
        
        # Find OTP record by purpose only (since we don't have email)
        otp_records = await otp_collection.find({"purpose": purpose.value}).to_list(None)
        logger.info(f"Found {len(otp_records)} OTP records for purpose: {purpose.value}")
        
        for otp_record in otp_records:
            logger.info(f"Checking OTP record for email: {otp_record.get('email')}")
            
            # Check if OTP has expired
            if datetime.utcnow() > otp_record["expiresAt"]:
                logger.info(f"OTP expired for {otp_record.get('email')}, deleting...")
                await otp_collection.delete_one({"_id": otp_record["_id"]})
                continue
            
            # Check attempt limit
            if otp_record["attempts"] >= settings.OTP_MAX_ATTEMPTS:
                logger.info(f"OTP max attempts reached for {otp_record.get('email')}, deleting...")
                await otp_collection.delete_one({"_id": otp_record["_id"]})
                continue
            
            # Verify OTP
            logger.info(f"Verifying OTP against stored hash...")
            if jwt_service.verify_otp(otp, otp_record["otpHash"]):
                # OTP is valid - remove it and return email
                email = otp_record["email"]
                logger.info(f"OTP verified successfully for email: {email}")
                await otp_collection.delete_one({"_id": otp_record["_id"]})
                return email
            else:
                logger.info(f"OTP verification failed, incrementing attempts...")
                # Increment attempt counter for this record
                await otp_collection.update_one(
                    {"_id": otp_record["_id"]},
                    {"$inc": {"attempts": 1}}
                )
        
        logger.warning(f"No valid OTP found for code: {otp}")
        return None
            
    except Exception as e:
        logger.error(f"Failed to verify OTP: {e}")
        return None


async def verify_otp_code(email: str, otp: str, purpose: OTPPurpose) -> bool:
    """
    Verify OTP code against stored hash
    
    Args:
        email: User email address
        otp: OTP code to verify
        purpose: OTP purpose (SIGNUP or RESET)
        
    Returns:
        True if OTP is valid, False otherwise
    """
    try:
        otp_collection = get_otp_tokens_collection()
        if otp_collection is None:
            return False
        
        # Find OTP record
        otp_record = await otp_collection.find_one({
            "email": email,
            "purpose": purpose.value
        })
        
        if not otp_record:
            return False
        
        # Check if OTP has expired
        if datetime.utcnow() > otp_record["expiresAt"]:
            await otp_collection.delete_one({"_id": otp_record["_id"]})
            return False
        
        # Check attempt limit
        if otp_record["attempts"] >= settings.OTP_MAX_ATTEMPTS:
            await otp_collection.delete_one({"_id": otp_record["_id"]})
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Maximum OTP attempts exceeded. Please request a new OTP."
            )
        
        # Verify OTP
        if jwt_service.verify_otp(otp, otp_record["otpHash"]):
            # OTP is valid - remove it
            await otp_collection.delete_one({"_id": otp_record["_id"]})
            return True
        else:
            # Increment attempt counter
            await otp_collection.update_one(
                {"_id": otp_record["_id"]},
                {"$inc": {"attempts": 1}}
            )
            return False
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to verify OTP: {e}")
        return False


@auth_router.post("/signup", response_model=SuccessResponse)
async def signup(signup_data: SignupRequest):
    """
    Email signup with OTP verification
    User account is created but remains inactive until email is verified
    """
    try:
        users_collection = get_users_collection()
        if users_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
        
        # Check if user already exists
        existing_user = await users_collection.find_one({"email": signup_data.email})
        if existing_user:
            # If user exists but is inactive, allow re-signup (resend OTP)
            if existing_user.get("isActive", False):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="User with this email already exists and is active"
                )
            else:
                # Delete inactive user to allow fresh signup
                await users_collection.delete_one({"email": signup_data.email})
        
        # Create user record (inactive)
        user_data = {
            "email": signup_data.email,
            "passwordHash": jwt_service.hash_password(signup_data.password),
            "name": signup_data.name,
            "role": signup_data.role.value,
            "areaCity": signup_data.areaCity,
            "isActive": False,  # Inactive until email verified
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
        
        result = await users_collection.insert_one(user_data)
        
        # Generate and send OTP
        otp_sent = await generate_and_send_otp(signup_data.email, OTPPurpose.SIGNUP)
        
        if not otp_sent:
            # Cleanup user if OTP failed
            await users_collection.delete_one({"_id": result.inserted_id})
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification email. Please try again."
            )
        
        return SuccessResponse(
            message=f"Signup successful! Please check your email for verification code. OTP expires in {settings.OTP_EXPIRE_MINUTES} minutes.",
            data={"email": signup_data.email}
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Signup error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during signup"
        )


@auth_router.post("/verify-otp")
async def verify_otp(verify_data: VerifyOTPRequest):
    """
    Verify OTP and activate user account - MINIMAL VERSION
    """
    try:
        logger.info(f"=== MINIMAL OTP VERIFICATION START ===")
        logger.info(f"OTP received: {verify_data.otp}")
        
        # Step 1: Verify OTP
        email = await verify_otp_code_only(verify_data.otp, OTPPurpose.SIGNUP)
        logger.info(f"Email from OTP verification: {email}")
        
        if not email:
            return {"error": "Invalid or expired OTP"}
        
        # Step 2: Get user and activate
        users_collection = get_users_collection()
        if users_collection is None:
            return {"error": "Database not available"}
        
        user = await users_collection.find_one_and_update(
            {"email": email, "isActive": False},
            {"$set": {"isActive": True}},
            return_document=True
        )
        
        if not user:
            return {"error": "User not found or already activated"}
        
        # Step 3: Return minimal success response
        logger.info(f"=== SUCCESS: User {email} activated ===")
        return {
            "success": True,
            "message": "OTP verified successfully!",
            "email": email,
            "name": user.get("name", ""),
            "role": user.get("role", "")
        }
        
    except Exception as e:
        logger.error(f"=== ERROR in minimal verification: {str(e)} ===")
        import traceback
        logger.error(f"=== TRACEBACK: {traceback.format_exc()} ===")
        return {"error": f"Verification failed: {str(e)}"}


@auth_router.post("/login")
async def login(username: str = Form(...), password: str = Form(...)):
    """
    OAuth2 compatible login with username (email or phone) and password
    Dynamically queries the correct collection based on the role.
    """
    try:
        print(f"🔍 LOGIN ATTEMPT: username={username}")
        
        # Get database collections
        try:
            users_collection = get_users_collection()
            supervisors_collection = get_supervisors_collection()
            guards_collection = get_guards_collection()
            print(f"✅ Collections retrieved successfully")
        except Exception as e:
            print(f"❌ Error getting collections: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database connection error"
            )

        if users_collection is None or supervisors_collection is None or guards_collection is None:
            print(f"❌ One or more collections is None")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database collections not available"
            )

        # Check in users collection (admins) first
        print(f"🔍 Searching in users collection for admin...")
        try:
            user = await users_collection.find_one({"$or": [{"email": username}, {"phone": username}]})
            if user:
                print(f"✅ Admin user found in users collection")
                role = "ADMIN"
            else:
                print(f"❌ Admin user not found in users collection")
                # Check in supervisors collection
                print(f"🔍 Searching in supervisors collection...")
                user = await supervisors_collection.find_one({"$or": [{"email": username}, {"phone": username}]})
                if user:
                    print(f"✅ Supervisor found in supervisors collection")
                    role = "SUPERVISOR"
                else:
                    print(f"❌ Supervisor not found in supervisors collection")
                    # Check in guards collection
                    print(f"🔍 Searching in guards collection...")
                    user = await guards_collection.find_one({"$or": [{"email": username}, {"phone": username}]})
                    if user:
                        print(f"✅ Guard found in guards collection")
                        role = "GUARD"
                    else:
                        print(f"❌ User not found in any collection")
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid email/phone or password"
                        )
        except Exception as e:
            print(f"❌ Database query error: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Database query failed: {str(e)}"
            )

        # Verify password
        print(f"🔍 Verifying password...")
        password_hash = user.get("passwordHash")
        if not password_hash:
            print(f"❌ No passwordHash field found in user document")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="User data corrupted - missing password"
            )
        
        # Debug information
        print(f"🔍 Password length: {len(password)} characters")
        print(f"🔍 Password bytes length: {len(password.encode('utf-8'))} bytes")
        print(f"🔍 Hash format looks valid: {password_hash.startswith('$2b$')}")
        
        print(f"🔍 Attempting password verification...")
        print(f"🔍 Hash preview: {password_hash[:20]}...")
        
        password_valid = jwt_service.verify_password(password, password_hash)
        if not password_valid:
            print(f"❌ Password verification failed")
            # Try one more debug attempt with a simple test
            print(f"🔍 Testing with empty password as debug...")
            debug_result = jwt_service.verify_password("", password_hash)
            print(f"🔍 Debug empty password result: {debug_result}")
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email/phone or password"
            )
        print(f"✅ Password verification succeeded")

        # Check if user is active
        print(f"🔍 Checking if user is active...")
        if not user.get("isActive", False):
            print(f"❌ User account is not active")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Account not activated. Please contact the administrator."
            )
        print(f"✅ User account is active")

        # Update last login
        print(f"🔍 Updating last login...")
        try:
            collection = {
                "ADMIN": users_collection,
                "SUPERVISOR": supervisors_collection,
                "GUARD": guards_collection
            }[role]
            await collection.update_one(
                {"_id": user["_id"]},
                {"$set": {"lastLogin": datetime.utcnow()}}
            )
            user["lastLogin"] = datetime.utcnow()
            print(f"✅ Last login updated")
        except Exception as e:
            print(f"❌ Failed to update last login: {e}")
            # Continue anyway, this is not critical

        # Create JWT access token
        print(f"🔍 Creating JWT access token...")
        try:
            access_token = jwt_service.create_access_token({
                "user_id": str(user["_id"]),
                "email": user.get("email"),
                "phone": user.get("phone"),
                "role": role
            })
            print(f"✅ JWT token created successfully")
        except Exception as e:
            print(f"❌ JWT token creation failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Token creation failed: {str(e)}"
            )

        # Return OAuth2 compatible response
        print(f"✅ Login successful for {role} user")
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": str(user["_id"]),
                "email": user.get("email"),
                "phone": user.get("phone"),
                "name": user["name"],
                "role": role,
                "areaCity": user.get("areaCity"),
                "isActive": user["isActive"],
                "lastLogin": user.get("lastLogin")
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        print(f"❌ CRITICAL LOGIN ERROR: {e}")
        import traceback
        print(f"❌ TRACEBACK: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal server error during login: {str(e)}"
        )


@auth_router.post("/reset-password", response_model=SuccessResponse)
async def reset_password(reset_data: ResetPasswordRequest):
    """
    Request password reset via email OTP
    """
    try:
        users_collection = get_users_collection()
        if users_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
        
        # Check if user exists and is active
        user = await users_collection.find_one({
            "email": reset_data.email,
            "isActive": True
        })
        
        if not user:
            # Don't reveal if email exists or not for security
            return SuccessResponse(
                message="If the email exists, a password reset code has been sent."
            )
        
        # Generate and send OTP
        otp_sent = await generate_and_send_otp(reset_data.email, OTPPurpose.RESET)
        
        if not otp_sent:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send reset email. Please try again."
            )
        
        return SuccessResponse(
            message=f"Password reset code sent! Please check your email. Code expires in {settings.OTP_EXPIRE_MINUTES} minutes."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset request error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during password reset request"
        )


@auth_router.post("/reset-password-confirm", response_model=SuccessResponse)
async def reset_password_confirm(reset_data: ResetPasswordConfirmRequest):
    """
    Confirm password reset with OTP and new password
    """
    try:
        # Verify OTP
        otp_valid = await verify_otp_code(reset_data.email, reset_data.otp, OTPPurpose.RESET)
        
        if not otp_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP"
            )
        
        users_collection = get_users_collection()
        if users_collection is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database not available"
            )
        
        # Update password
        new_password_hash = jwt_service.hash_password(reset_data.newPassword)
        
        result = await users_collection.update_one(
            {"email": reset_data.email, "isActive": True},
            {
                "$set": {
                    "passwordHash": new_password_hash,
                    "updatedAt": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Note: No need to revoke refresh tokens since we don't use them anymore
        
        return SuccessResponse(
            message="Password reset successful!"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password reset confirmation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during password reset"
        )


@auth_router.post("/resend-otp", response_model=SuccessResponse)
async def resend_otp(email: str, purpose: str = "signup"):
    """
    Resend OTP for signup or password reset
    """
    try:
        otp_purpose = OTPPurpose.SIGNUP if purpose.lower() == "signup" else OTPPurpose.RESET
        
        # For signup, check if user exists and is inactive
        if otp_purpose == OTPPurpose.SIGNUP:
            users_collection = get_users_collection()
            if users_collection:
                user = await users_collection.find_one({"email": email})
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="No pending signup found for this email"
                    )
                if user.get("isActive", False):
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Email already verified"
                    )
        
        # Generate and send OTP
        otp_sent = await generate_and_send_otp(email, otp_purpose)
        
        if not otp_sent:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send OTP. Please try again."
            )
        
        purpose_text = "verification" if otp_purpose == OTPPurpose.SIGNUP else "password reset"
        return SuccessResponse(
            message=f"New {purpose_text} code sent! Please check your email."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Resend OTP error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during OTP resend"
        )


# Helper functions

async def create_role_specific_record(user: Dict[str, Any]):
    """Create supervisor or guard record based on user role"""
    try:
        user_role = user["role"]
        logger.info(f"Creating role-specific record for role: {user_role}")
        
        if user_role == UserRole.SUPERVISOR.value or user_role == "SUPERVISOR":
            supervisors_collection = get_supervisors_collection()
            if supervisors_collection:
                # Generate supervisor code
                count = await supervisors_collection.count_documents({})
                supervisor_code = f"SUP{str(count + 1).zfill(3)}"
                
                supervisor_data = {
                    "userId": str(user["_id"]),
                    "code": supervisor_code,
                    "areaCity": user.get("areaCity", ""),
                    "createdAt": datetime.utcnow(),
                    "updatedAt": datetime.utcnow()
                }
                
                await supervisors_collection.insert_one(supervisor_data)
                logger.info(f"Created supervisor record: {supervisor_code}")
        
        elif user_role == UserRole.GUARD.value or user_role == "GUARD":
            guards_collection = get_guards_collection()
            if guards_collection:
                # Note: supervisorId should be set when admin assigns guard to supervisor
                # For now, create basic record without supervisor assignment
                count = await guards_collection.count_documents({})
                employee_code = f"GRD{str(count + 1).zfill(3)}"
                
                guard_data = {
                    "userId": str(user["_id"]),
                    "supervisorId": "",  # To be assigned by admin
                    "employeeCode": employee_code,
                    "createdAt": datetime.utcnow(),
                    "updatedAt": datetime.utcnow()
                }
                
                await guards_collection.insert_one(guard_data)
                logger.info(f"Created guard record: {employee_code}")
        else:
            logger.info(f"No role-specific record needed for role: {user_role}")
                
    except Exception as e:
        logger.error(f"Failed to create role-specific record: {e}")
        # Don't raise exception, just log it so verification can continue


