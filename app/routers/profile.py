from fastapi import APIRouter, Depends, HTTPException, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from fastapi import status
from app.schemas.profile import ProfileCreate
from app.models.profile import Profile
from app.database import get_db
from app.routers.auth import get_current_user
from app.models.user import User
from sqlalchemy.orm.exc import NoResultFound

router = APIRouter(prefix="/profile", tags=["Profile"])
templates = Jinja2Templates(directory="app/templates")

@router.get("/create", response_class=HTMLResponse)
async def profile_create_page(request: Request,current_user: User = Depends(get_current_user)):
    return templates.TemplateResponse("profile_create.html", {"request": request})

@router.post("/")
async def create_profile(
    full_name: str = Form(...),
    mobile_no: str = Form(...),
    upi_id: str = Form(...),
    country: str = Form("India"),
    transaction_limit: float = Form(10000.00),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    user_id = current_user.user_id
    
    # Check if profile already exists
    existing = db.query(Profile).filter(Profile.user_id == user_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Profile already exists")
    
    new_profile = Profile(
        user_id=user_id,
        full_name=full_name,
        mobile_no=mobile_no,
        upi_id=upi_id,
        country=country,
        transaction_limit=transaction_limit
    )
    
    db.add(new_profile)
    db.commit()
    db.refresh(new_profile)
    
    return RedirectResponse(url='/', status_code=303)

@router.put("/")
def update_profile(
    profile: ProfileCreate, 
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    db_profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    if not db_profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    for field, value in profile.model_dump().items():
        setattr(db_profile, field, value)
    db.commit()
    return db_profile

@router.delete("/")
def delete_profile(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    db_profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    if not db_profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    db.delete(db_profile)
    db.commit()
    return {"msg": "Profile deleted"}

@router.get("/")
def get_profile(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    db_profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    if not db_profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return  db_profile



# at the bottom of app/routers/profile.py
@router.get("/my_profile", response_class=HTMLResponse)
def my_profile_alias(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Alias for GET /profile/ so that /profile/my_profile works
    (matches the navbar link).
    """
    profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    if not profile:
        return RedirectResponse(url="/profile/create", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(
        "my_profile.html",
        {"request": request, "user": profile}
    )

@router.get("/my_profile/edit", response_class=HTMLResponse)
def edit_profile_alias(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    if not profile:
        return RedirectResponse(url="/profile/create", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(
        "profile_create.html",
        {"request": request, "user": profile}
    )

@router.post("/my_profile/edit", response_class=HTMLResponse)
def edit_profile_form_alias(
    request: Request,
    full_name: str = Form(...),
    mobile_no: str = Form(...),
    upi_id: str = Form(...),
    country: str = Form("India"),
    transaction_limit: float = Form(10000.00),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    profile = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    profile.full_name = full_name
    profile.mobile_no = mobile_no
    profile.upi_id = upi_id
    profile.country = country
    profile.transaction_limit = transaction_limit
    db.commit()
    return RedirectResponse(url="/profile/my_profile", status_code=status.HTTP_303_SEE_OTHER)

