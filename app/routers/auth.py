from fastapi import APIRouter, Form, Request, Response, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.schemas.user import UserCreate
from jose import JWTError, jwt
from app.models.user import User
from app.models.profile import Profile
from app.database import get_db
from app.config import settings
from fastapi.templating import Jinja2Templates
import random, os
import aiosmtplib
from email.message import EmailMessage
from dotenv import load_dotenv
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
from fastapi import Cookie

load_dotenv()
router = APIRouter(prefix="/auth", tags=["Auth"])

templates = Jinja2Templates(directory="app/templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
otp_store = {}

# ------------------------------------------------UTILITIES----------------------------------------------------

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password):
        return None
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


async def get_current_user(
    access_token: str = Cookie(default=None),
    db: Session = Depends(get_db),
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials (missing token)",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not access_token:
        raise credentials_exception

    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.user_id == user_id).first()
    if user is None:
        raise credentials_exception

    return user


async def send_email(to_email: str, otp: str):
    msg = EmailMessage()
    msg["Subject"] = "CipherStorm Email Verification"
    msg["From"] = os.getenv("EMAIL_FROM")
    msg["To"] = to_email
    msg.set_content(f"Your OTP is: {otp}")

    await aiosmtplib.send(
        msg,
        hostname="smtp.gmail.com",
        port=587,
        start_tls=True,
        username=os.getenv("SMTP_EMAIL"),
        password=os.getenv("SMTP_PASSWORD")
    )

# -------------------------------------------------ROUTES-------------------------------------------------

@router.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@router.post("/signup")
async def register_user(
    request: Request,
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    # Check if user already exists
    existing_user = db.query(User).filter(User.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Hash password and create new user
    hashed_password = get_password_hash(password)
    new_user = User(
        username=username,
        email=email,
        password=hashed_password,
        is_verified=False
    )
    db.add(new_user)
    try:
        db.commit()
        db.refresh(new_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Username already exists")

    # Generate and send OTP
    otp = str(random.randint(100000, 999999))
    otp_store[email] = otp
    await send_email(email, otp)

    return RedirectResponse(url=f"/auth/verify-otp?email={email}", status_code=302)

@router.get("/verify-otp", response_class=HTMLResponse)
async def verify_otp_page(request: Request, email: str = ""):
    return templates.TemplateResponse("verify_otp.html", {"request": request, "email": email})

@router.post("/verify-otp")
async def verify_otp(request: Request, otp: str = Form(...), db: Session = Depends(get_db)):
    email = request.query_params.get("email")  # extract from URL query
    if not email or otp_store.get(email) != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    if otp_store.get(email) == otp:
        del otp_store[email]
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.is_verified = True
            db.commit()

        return RedirectResponse(url="/auth/login", status_code=302)
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/login")
async def login_form(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password):
        # Return to login page with error message
        return templates.TemplateResponse(
            "login.html", 
            {
                "request": request, 
                "error": "Invalid username or password. Please try again.",
                "username": username  # Preserve the username field
            }
        )

    existing = db.query(Profile).filter(Profile.user_id == user.user_id).first()
    access_token = create_access_token(data={"user_id": user.user_id})
    if not existing:
        response = RedirectResponse(url="/profile/create", status_code=302)
    else:
        response = RedirectResponse(url="/dashboard", status_code=302)
    
    response.set_cookie("access_token", access_token, httponly=True, max_age=7200)
    response.set_cookie("user", username)
    return response
    return response

@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/")
    response.delete_cookie("user")
    response.delete_cookie("access_token")
    return response


