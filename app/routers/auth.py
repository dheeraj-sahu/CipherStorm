from fastapi import APIRouter, Form, Request, Response, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse, RedirectResponse
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.schemas.user import UserCreate
from jose import JWTError, jwt
from app.models.user import User
from app.database import get_db
from app.config import settings
from fastapi.templating import Jinja2Templates
import random, os
import aiosmtplib
from email.message import EmailMessage
from dotenv import load_dotenv
from datetime import datetime, timedelta
from sqlalchemy.exc import IntegrityError
from app.schemas.profile import ProfileCreate
from sqlalchemy.orm.exc import NoResultFound

load_dotenv()
router = APIRouter(prefix="/auth", tags=["Auth"])

templates = Jinja2Templates(directory="app/templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
otp_store = {}

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

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

@router.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, email=user.email, password=hashed_password)
    db.add(new_user)
    try:
        db.commit()
        db.refresh(new_user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Username or email already exists")
    return {"msg": "User registered successfully"}

@router.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"user_id": user.user_id})
    return {"access_token": access_token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
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
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
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
        raise HTTPException(status_code=400, detail="Username or email already exists")

    # Generate and send OTP
    otp = str(random.randint(100000, 999999))
    otp_store[email] = otp
    await send_email(email, otp)

    return RedirectResponse(url=f"/auth/verify-otp?email={email}", status_code=302)

@router.get("/verify-otp", response_class=HTMLResponse)
async def verify_otp_page(request: Request, email: str = ""):
    return templates.TemplateResponse("verify_otp.html", {"request": request, "email": email})

@router.post("/verify-otp")
async def verify_otp(email: str = Form(...), otp: str = Form(...), db: Session = Depends(get_db)):
    if otp_store.get(email) == otp:
        del otp_store[email]
        user = db.query(User).filter(User.email == email).first()
        if user:
            user.is_verified = True
            db.commit()
        return RedirectResponse(url="/auth/profile/create", status_code=302)
    else:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    


@router.get("/profile/create", response_class=HTMLResponse)
async def profile_create_page(request: Request):
    email = request.query_params.get("email")
    return templates.TemplateResponse("profile_create.html", {"request": request, "email": email})




@router.post("/profile/create")
async def profile_create(
    request: Request,
    full_name: str = Form(...),
    mobile_no: str = Form(...),
    upi_id: str = Form(...),
    address: str = Form(None),
    transaction_limit: float = Form(10000.00),
    db: Session = Depends(get_db),
):
    # Get email from query param or form (as passed from previous step)
    email = request.query_params.get("email") or request.form().get("email")

    # Lookup user by email
    try:
        user = db.query(User).filter(User.email == email).one()
    except NoResultFound:
        raise HTTPException(status_code=404, detail="User not found")

    new_profile = ProfileCreate(
        user_id=user.user_id,
        full_name=full_name,
        mobile_no=mobile_no,
        upi_id=upi_id,
        address=address,
        transaction_limit=transaction_limit
    )
    db.add(new_profile)
    db.commit()

    return RedirectResponse(url="/auth/login", status_code=303)


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
        raise HTTPException(status_code=401, detail="Invalid username or password")

    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie("user", username)
    return response

@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/")
    response.delete_cookie("user")
    return response