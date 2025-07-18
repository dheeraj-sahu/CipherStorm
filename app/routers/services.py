from fastapi import APIRouter, Request, Form, Depends, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import os
import shutil
from datetime import datetime
from app.utils import get_current_user as get_current_user_util, require_login
from app.database import get_db
from app.models.user import User
from app.models.customer_care import CustomerCare
from app.services.fake_customer_service import verify_phone_number
from app.services.vishing_service import vishing_service
from app.routers.auth import get_current_user
import logging

router = APIRouter(prefix="/services", tags=["Services"])
templates = Jinja2Templates(directory="app/templates")

# Add the zip filter to Jinja2 environment
templates.env.filters["zip"] = zip

logger = logging.getLogger(__name__)

@router.get("/", response_class=HTMLResponse)
async def services_page(request: Request):
    """Main services page displaying all available security services"""
    # Check if user is logged in, redirect to login if not
    login_redirect = require_login(request)
    if login_redirect:
        return login_redirect
    
    user = get_current_user_util(request)
    return templates.TemplateResponse(
        "services.html", 
        {
            "request": request,
            "user": user
        }
    )

@router.get('/make-transaction',response_class=HTMLResponse)
async def make_transaction_page(request: Request):
    """Page to make a transaction"""
    # Check if user is logged in, redirect to login if not
    login_redirect = require_login(request)
    if login_redirect:
        return login_redirect
    
    user = get_current_user_util(request)
    return templates.TemplateResponse(
        "transaction_form.html", 
        {
            "request": request,
            "user": user
        }
    )

@router.get('/text', response_class=HTMLResponse)
async def text_analysis_page(request: Request):
    """Page for text analysis input"""
    # Check if user is logged in, redirect to login if not
    login_redirect = require_login(request)
    if login_redirect:
        return login_redirect
    
    user = get_current_user_util(request)
    return templates.TemplateResponse(
        "text_input.html", 
        {
            "request": request,
            "user": user
        }
    )


#URL form page
@router.get('/url', response_class=HTMLResponse)
async def url_analysis_page(request: Request):
    """Page for URL scanning input"""
    # Check if user is logged in, redirect to login if not
    login_redirect = require_login(request)
    if login_redirect:
        return login_redirect
    
    user = get_current_user_util(request)
    return templates.TemplateResponse(
        "url_input.html", 
        {
            "request": request,
            "user": user
        }
    )



#Customer care form page
@router.get('/customer_care', response_class=HTMLResponse)
async def customer_care_analysis_page(request: Request):
    """Page for customer care number verification input"""
    # Check if user is logged in, redirect to login if not
    login_redirect = require_login(request)
    if login_redirect:
        return login_redirect
    
    user = get_current_user_util(request)
    return templates.TemplateResponse(
        "customer_care_input.html", 
        {
            "request": request,
            "user": user
        }
    )


#Vishing form page
@router.get('/vishing', response_class=HTMLResponse)
async def vishing_analysis_page(request: Request):
    """Page for customer care number verification input"""
    # Check if user is logged in, redirect to login if not
    login_redirect = require_login(request)
    if login_redirect:
        return login_redirect
    
    user = get_current_user_util(request)
    return templates.TemplateResponse(
        "vishing_input.html", 
        {
            "request": request,
            "user": user
        }
    )



@router.post("/vishing/analyze", response_class=HTMLResponse)
async def analyze_vishing(
    request: Request,
    audio_file: UploadFile = File(...),
    user_opinion: str = Form(...),
    db: Session = Depends(get_db)
):
    """Process vishing audio analysis"""
    try:
        # Validate file and user opinion
        if not audio_file.filename.lower().endswith(('.wav', '.mp3')):
            raise HTTPException(400, "Invalid file format. Only WAV and MP3 files are supported.")
        
        if user_opinion not in ["confirm_suspicious", "insufficient_evidence"]:
            raise HTTPException(400, "Invalid opinion value")

        # Get current user (if logged in)
        try:
            current_user = get_current_user(request)
        except:
            current_user = None

        # Save the file
        file_path = f"uploads/audio/{datetime.now().strftime('%Y%m%d_%H%M%S')}_{audio_file.filename}"
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, "wb") as f:
            shutil.copyfileobj(audio_file.file, f)

        # Get user ID if user is logged in
        user_id = None
        if isinstance(current_user, User) and hasattr(current_user, 'id'):
            user_id = current_user.id

        # Process with vishing service
        result = vishing_service.process_audio(
            audio_file_path=file_path,
            user_id=user_id
        )

        # Structure the result for the template
        analysis_data = {
            "analysis_result": result,
            "recording_info": {
                "transcript": result.get("transcript", ""),
                "filename": audio_file.filename,
                "duration": "N/A"  # Duration will be added if needed
            }
        }

        return templates.TemplateResponse(
            "vishing_output.html",
            {
                "request": request,
                "analysis": analysis_data,
                "user": current_user
            }
        )

    except Exception as e:
        logger.error(f"Error in vishing analysis: {str(e)}")
        raise HTTPException(500, f"Error processing request: {str(e)}")
