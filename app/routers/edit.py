from fastapi import APIRouter, Form, Request, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.models.user import User
from app.models.profile import Profile
from app.database import get_db
from app.routers.auth import get_current_user, get_password_hash, verify_password
from typing import Optional

router = APIRouter(prefix="/edit", tags=["Edit"])
templates = Jinja2Templates(directory="app/templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ------------------------------------------------USER EDIT ENDPOINTS----------------------------------------------------

@router.get("/user", response_class=HTMLResponse)
async def edit_user_page(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Display the user edit form with current user information"""
    return templates.TemplateResponse(
        "user_edit.html", 
        {
            "request": request, 
            "user": current_user
        }
    )

@router.post("/user")
async def update_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    current_password: Optional[str] = Form(None),
    new_password: Optional[str] = Form(None),
    confirm_password: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update user information (username, email, password)"""
    
    # Check if username is taken by another user
    if username != current_user.username:
        existing_username = db.query(User).filter(
            User.username == username, 
            User.user_id != current_user.user_id
        ).first()
        if existing_username:
            raise HTTPException(
                status_code=400, 
                detail="Username already taken"
            )
    
    # Check if email is taken by another user
    if email != current_user.email:
        existing_email = db.query(User).filter(
            User.email == email, 
            User.user_id != current_user.user_id
        ).first()
        if existing_email:
            raise HTTPException(
                status_code=400, 
                detail="Email already registered"
            )
    
    # Handle password change
    if new_password:
        if not current_password:
            raise HTTPException(
                status_code=400, 
                detail="Current password required to change password"
            )
        
        if not verify_password(current_password, current_user.password):
            raise HTTPException(
                status_code=400, 
                detail="Current password is incorrect"
            )
        
        if new_password != confirm_password:
            raise HTTPException(
                status_code=400, 
                detail="New passwords do not match"
            )
        
        if len(new_password) < 6:
            raise HTTPException(
                status_code=400, 
                detail="Password must be at least 6 characters long"
            )
        
        # Update password
        current_user.password = get_password_hash(new_password)
    
    # Update user information
    current_user.username = username
    current_user.email = email
    
    try:
        db.commit()
        db.refresh(current_user)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail="Error updating user information"
        )
    
    return RedirectResponse(
        url="/profile/my_profile?success=user_updated", 
        status_code=status.HTTP_303_SEE_OTHER
    )

# ------------------------------------------------PROFILE EDIT ENDPOINTS----------------------------------------------------

@router.get("/profile", response_class=HTMLResponse)
async def edit_profile_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Display the profile edit form with current profile information"""
    profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    
    if not profile:
        return RedirectResponse(
            url="/profile/create", 
            status_code=status.HTTP_302_FOUND
        )
    
    return templates.TemplateResponse(
        "profile_edit.html", 
        {
            "request": request, 
            "profile": profile,
            "user": current_user
        }
    )

@router.post("/profile")
async def update_profile(
    request: Request,
    full_name: str = Form(...),
    mobile_no: str = Form(...),
    upi_id: str = Form(...),
    address: Optional[str] = Form(None),
    transaction_limit: float = Form(10000.00),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update profile information"""
    profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    
    if not profile:
        raise HTTPException(
            status_code=404, 
            detail="Profile not found"
        )
    
    # Validate mobile number format (basic validation)
    if len(mobile_no) < 10:
        raise HTTPException(
            status_code=400, 
            detail="Invalid mobile number"
        )
    
    # Validate transaction limit
    if transaction_limit < 0 or transaction_limit > 100000:
        raise HTTPException(
            status_code=400, 
            detail="Transaction limit must be between 0 and 100,000"
        )
    
    # Check if UPI ID is taken by another user
    if upi_id != profile.upi_id:
        existing_upi = db.query(Profile).filter(
            Profile.upi_id == upi_id,
            Profile.user_id != current_user.user_id
        ).first()
        if existing_upi:
            raise HTTPException(
                status_code=400, 
                detail="UPI ID already registered"
            )
    
    # Update profile information
    profile.full_name = full_name
    profile.mobile_no = mobile_no
    profile.upi_id = upi_id
    profile.address = address
    profile.transaction_limit = transaction_limit
    
    try:
        db.commit()
        db.refresh(profile)
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail="Error updating profile information"
        )
    
    return RedirectResponse(
        url="/profile/my_profile?success=profile_updated", 
        status_code=status.HTTP_303_SEE_OTHER
    )

# ------------------------------------------------COMBINED EDIT ENDPOINTS----------------------------------------------------

@router.get("/", response_class=HTMLResponse)
async def edit_combined_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Display a combined edit form for both user and profile information"""
    profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    
    if not profile:
        return RedirectResponse(
            url="/profile/create", 
            status_code=status.HTTP_302_FOUND
        )
    
    return templates.TemplateResponse(
        "profile_edit.html", 
        {
            "request": request, 
            "profile": profile,
            "user": current_user,
            "combined_edit": True
        }
    )

@router.post("/")
async def update_combined(
    request: Request,
    # User fields
    username: str = Form(...),
    email: str = Form(...),
    current_password: Optional[str] = Form(None),
    new_password: Optional[str] = Form(None),
    confirm_password: Optional[str] = Form(None),
    # Profile fields
    full_name: str = Form(...),
    mobile_no: str = Form(...),
    upi_id: str = Form(...),
    address: Optional[str] = Form(None),
    transaction_limit: float = Form(10000.00),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update both user and profile information in one request"""
    
    # Get the profile
    profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    # Validate user updates
    if username != current_user.username:
        existing_username = db.query(User).filter(
            User.username == username, 
            User.user_id != current_user.user_id
        ).first()
        if existing_username:
            raise HTTPException(status_code=400, detail="Username already taken")
    
    if email != current_user.email:
        existing_email = db.query(User).filter(
            User.email == email, 
            User.user_id != current_user.user_id
        ).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="Email already registered")
    
    # Handle password change
    if new_password:
        if not current_password:
            raise HTTPException(status_code=400, detail="Current password required")
        if not verify_password(current_password, current_user.password):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        if new_password != confirm_password:
            raise HTTPException(status_code=400, detail="New passwords do not match")
        if len(new_password) < 6:
            raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        current_user.password = get_password_hash(new_password)
    
    # Validate profile updates
    if len(mobile_no) < 10:
        raise HTTPException(status_code=400, detail="Invalid mobile number")
    
    if transaction_limit < 0 or transaction_limit > 100000:
        raise HTTPException(status_code=400, detail="Transaction limit must be between 0 and 100,000")
    
    if upi_id != profile.upi_id:
        existing_upi = db.query(Profile).filter(
            Profile.upi_id == upi_id,
            Profile.user_id != current_user.user_id
        ).first()
        if existing_upi:
            raise HTTPException(status_code=400, detail="UPI ID already registered")
    
    # Update user information
    current_user.username = username
    current_user.email = email
    
    # Update profile information
    profile.full_name = full_name
    profile.mobile_no = mobile_no
    profile.upi_id = upi_id
    profile.address = address
    profile.transaction_limit = transaction_limit
    
    try:
        db.commit()
        db.refresh(current_user)
        db.refresh(profile)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Error updating information")
    
    return RedirectResponse(
        url="/profile/my_profile?success=all_updated", 
        status_code=status.HTTP_303_SEE_OTHER
    )

# ------------------------------------------------DELETE ENDPOINTS----------------------------------------------------

@router.post("/delete-account")
async def delete_account(
    request: Request,
    confirm_password: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete user account and associated profile"""
    
    # Verify password before deletion
    if not verify_password(confirm_password, current_user.password):
        raise HTTPException(
            status_code=400, 
            detail="Password is incorrect"
        )
    
    try:
        # Delete profile first (due to foreign key constraint)
        profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
        if profile:
            db.delete(profile)
        
        # Delete user
        db.delete(current_user)
        db.commit()
        
        # Redirect to home page with success message
        response = RedirectResponse(url="/?deleted=true", status_code=status.HTTP_303_SEE_OTHER)
        response.delete_cookie("access_token")  # Clear authentication cookie
        return response
        
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail="Error deleting account"
        )
