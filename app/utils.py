from fastapi import Request, Depends
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
import logging

logger = logging.getLogger(__name__)

def get_current_user(request: Request):
    return request.cookies.get("user")

def get_current_user_util(request: Request, db: Session = Depends(get_db)):
    """Get current user from database"""
    username = request.cookies.get("user")
    if not username:
        return None
        
    user = db.query(User).filter(User.username == username).first()
    logger.info(f"Found user in database: {user}")
    return user

def require_login(request: Request):
    """Check if user is logged in, redirect to login if not"""
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/auth/login", status_code=302)
    return None
