from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import Optional, List
import tempfile
import os
import shutil
import logging
from datetime import datetime
from app.models.constant import IST

from models.vishing import VishingRecording
from models.user import User
from schemas.vishing import (
    VishingRecordingCreate, 
    VishingRecordingResponse,
    VishingAnalysisResponse,
    VishingAnalysisResult,
    UserOpinion
)
from database import get_db
from routers.auth import get_current_user
from services.vishing_service import vishing_service

# Set up logging
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vishing", tags=["Vishing Detection"])
templates = Jinja2Templates(directory="app/templates")

UPLOAD_DIR = "uploaded_audio"
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {".wav", ".mp3", ".m4a", ".flac", ".ogg"}

def validate_audio_file(filename: str) -> bool:
    """Validate if the uploaded file is an audio file"""
    return any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)

@router.get("/services/vishing", response_class=HTMLResponse)
async def vishing_page(request: Request):
    """Render the vishing input page"""
    return templates.TemplateResponse("vishing_input.html", {"request": request})

@router.post("/analyze")  # Updated analyze endpoint
async def analyze_vishing_audio(
    request: Request,
    audio_file: UploadFile = File(...),
    user_opinion: str = Form(...),
    current_user: Optional[User] = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Analyze uploaded audio file for vishing detection and render results
    """
    # Validate opinion
    if user_opinion not in ["confirm_suspicious", "insufficient_evidence"]:
        raise HTTPException(status_code=400, detail="Invalid user opinion")

    # Validate file type
    if not validate_audio_file(audio_file.filename):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
        )
    
    try:
        # Save and analyze the file as before
        timestamp = datetime.now(IST).strftime("%Y%m%d_%H%M%S")
        file_extension = os.path.splitext(audio_file.filename)[1]
        saved_filename = f"user_{timestamp}{file_extension}"
        file_path = os.path.join(UPLOAD_DIR, saved_filename)
        
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(audio_file.file, buffer)
        
        # Process the audio using vishing service
        analysis_result = vishing_service.process_audio(
            file_path, 
            None,  # No transcript provided through form
            current_user.user_id if current_user else None
        )
        
        # If user is authenticated, save to database
        if current_user:
            db_recording = VishingRecording(
                user_id=current_user.user_id,
                audio_file_path=analysis_result.get("saved_audio_path", file_path),
                transcript=analysis_result["transcript"],
                user_opinion=user_opinion
            )
            db.add(db_recording)
            db.commit()
            db.refresh(db_recording)
        
        # Prepare template data
        template_data = {
            "request": request,
            "analysis": {
                "risk_level": "high" if analysis_result["prediction"] > 0.7 else "medium",
                "confidence_score": analysis_result["prediction"],
                "voice_features": analysis_result["voice_features"],
                "detected_patterns": analysis_result["text_scores"],
                "transcript": analysis_result["transcript"],
                "recommendation": (
                    "Block and report the number" 
                    if analysis_result["prediction"] > 0.7 
                    else "Exercise caution"
                )
            },
            "filename": audio_file.filename,
            "user_opinion": user_opinion
        }
        
        return templates.TemplateResponse("vishing_output.html", template_data)
        
    except Exception as e:
        # Clean up file if error occurs
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Rollback database transaction if needed
        if current_user:
            db.rollback()
        
        raise HTTPException(
            status_code=500,
            detail=f"Error processing audio file: {str(e)}"
        )


@router.get("/recordings", response_model=List[VishingRecordingResponse])
def get_user_recordings(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all vishing recordings for the current user"""
    recordings = db.query(VishingRecording).filter(
        VishingRecording.user_id == current_user.user_id
    ).order_by(VishingRecording.created_at.desc()).all()
    
    return recordings