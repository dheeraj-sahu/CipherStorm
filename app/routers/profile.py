from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.schemas.profile import ProfileCreate
from app.models.profile import Profile
from app.database import get_db
from app.routers.auth import get_current_user
from app.models.user import User  

router = APIRouter(prefix="/profile", tags=["Profile"])

@router.post("/")
def create_profile(
    profile: ProfileCreate, 
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    existing = db.query(Profile).filter(Profile.user_id == current_user.user_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Profile already exists")
    
    db_profile = Profile(user_id=current_user.user_id,**profile.model_dump())
    
    db.add(db_profile)
    db.commit()
    db.refresh(db_profile)
    
    return db_profile

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
    return db_profile