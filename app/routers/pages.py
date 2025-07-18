from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from app.utils import get_current_user, require_login
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.transaction import Transaction
from app.models.user import User
from app.models.url import URLScan
from app.models.customer_care import CustomerCare
import json

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

# Add custom filter for parsing JSON
def parse_json(text):
    if not text:
        return {}
    try:
        return json.loads(text)
    except:
        return {}

templates.env.filters["from_json"] = parse_json

@router.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "user": get_current_user(request)})

@router.get("/features", response_class=HTMLResponse)
async def features(request: Request):
    return templates.TemplateResponse("features.html", {"request": request, "user": get_current_user(request)})

@router.get("/contact", response_class=HTMLResponse)
async def contact(request: Request):
    # Check if user is logged in, redirect to login if not
    login_redirect = require_login(request)
    if login_redirect:
        return login_redirect
    
    return templates.TemplateResponse("contact.html", {"request": request, "user": get_current_user(request)})

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    # Check if user is logged in, redirect to login if not
    login_redirect = require_login(request)
    if login_redirect:
        return login_redirect

    username = get_current_user(request)
    # Get user from database
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return RedirectResponse(url="/login")

    transactions = db.query(Transaction).filter(
        Transaction.user_id == user.user_id
    ).order_by(Transaction.created_at.desc()).limit(12).all()
    
    url_scans = db.query(URLScan).filter(
        URLScan.user_id == user.user_id
    ).order_by(URLScan.scanned_at.desc()).limit(12).all()
    
    customer_care_records = db.query(CustomerCare).filter(
        CustomerCare.user_id == user.user_id
    ).order_by(CustomerCare.created_at.desc()).limit(12).all()
    
    return templates.TemplateResponse(
        "dashboard.html", 
        {
            "request": request, 
            "user": username, 
            "transactions": transactions, 
            "url_scans": url_scans,
            "customer_care_records": customer_care_records,
            "dashboard": True
        }
    )
