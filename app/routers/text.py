from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from app.schemas.text import TextAnalysisCreate, TextAnalysisResponse, TextAnalysisResult, TextAnalysisComplete
from app.models.text import TextAnalysis
from app.models.user import User
from app.database import get_db
from app.routers.auth import get_current_user
from app.services.text_service import text_analysis_service
from app.utils import get_current_user as get_current_user_util
from typing import List, Union
from datetime import datetime
from app.models.constant import IST
import logging

router = APIRouter(prefix="/text", tags=["Text Analysis"])
templates = Jinja2Templates(directory="app/templates")
logger = logging.getLogger(__name__)

@router.post("/analyze")
async def analyze_text(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    text_data: TextAnalysisCreate = None,
    text_content: str = Form(None)
):
    """
    Analyze text for phishing detection using ensemble of ML models
    Handles both JSON API requests and HTML form submissions
    """
    try:
        # Determine if this is a form submission or API request
        content_type = request.headers.get("content-type", "")
        is_form_submission = "application/x-www-form-urlencoded" in content_type
        
        # Get the text content from either form or JSON
        if is_form_submission:
            if not text_content or not text_content.strip():
                raise HTTPException(status_code=400, detail="Text cannot be empty")
            text_to_analyze = text_content.strip()
        else:
            if not text_data or not text_data.text or not text_data.text.strip():
                raise HTTPException(status_code=400, detail="Text cannot be empty")
            text_to_analyze = text_data.text.strip()
        
        # Validate text length
        if len(text_to_analyze) > 5000:
            raise HTTPException(status_code=400, detail="Text too long (max 5000 characters)")
        
        # Save text to database
        db_text = TextAnalysis(
            user_id=current_user.user_id,
            text=text_to_analyze
        )
        db.add(db_text)
        db.commit()
        db.refresh(db_text)
        
        # Perform text analysis
        analysis_result = text_analysis_service.analyze_text_complete(text_to_analyze)
        
        # Add text_id to result
        analysis_result['text_id'] = db_text.text_id
        
        # Handle form submission - return HTML response
        if is_form_submission:
            # Add some additional metadata to the raw analysis result
            analysis_result['timestamp'] = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
            analysis_result['analysis_id'] = f"TXT_{datetime.now(IST).strftime('%Y%m%d%H%M%S')}"
            analysis_result['processing_time'] = '< 1 second'
            analysis_result['model_version'] = 'v1.0'
            
            # Map is_phishing to is_suspicious for template compatibility
            analysis_result['is_suspicious'] = analysis_result.get('is_phishing', False)
            
            # Get user info for template
            user_info = get_current_user_util(request)
            
            return templates.TemplateResponse(
                "text_output.html",
                {
                    "request": request,
                    "user": user_info,
                    "analysis_result": analysis_result,  # Pass raw analysis result
                    "analyzed_text": text_to_analyze
                }
            )
        
        # Handle API request - return JSON response
        else:
            return TextAnalysisComplete(
                text_analysis=TextAnalysisResponse(
                    text_id=db_text.text_id,
                    user_id=db_text.user_id,
                    text=db_text.text,
                    created_at=db_text.created_at
                ),
                analysis_result=TextAnalysisResult(**analysis_result)
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error analyzing text: {str(e)}")
        db.rollback()
        
        # Handle form submission errors
        if is_form_submission:
            user_info = get_current_user_util(request)
            return templates.TemplateResponse(
                "text_output.html",
                {
                    "request": request,
                    "user": user_info,
                    "analysis_result": None,
                    "analyzed_text": text_to_analyze if 'text_to_analyze' in locals() else "",
                    "error": "An error occurred during text analysis. Please try again."
                }
            )
        else:
            raise HTTPException(status_code=500, detail=f"Error analyzing text: {str(e)}")

@router.get("/history", response_model=List[TextAnalysisResponse])
def get_text_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 10,
    offset: int = 0
):
    """
    Get user's text analysis history
    """
    try:
        texts = db.query(TextAnalysis).filter(
            TextAnalysis.user_id == current_user.user_id
        ).order_by(TextAnalysis.created_at.desc()).offset(offset).limit(limit).all()
        
        return [TextAnalysisResponse.from_orm(text) for text in texts]
        
    except Exception as e:
        logger.error(f"Error fetching text history: {str(e)}")
        raise HTTPException(status_code=500, detail="Error fetching text history")

@router.delete("/{text_id}")
def delete_text(
    text_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Delete a text analysis
    """
    try:
        text = db.query(TextAnalysis).filter(
            TextAnalysis.text_id == text_id,
            TextAnalysis.user_id == current_user.user_id
        ).first()
        
        if not text:
            raise HTTPException(status_code=404, detail="Text analysis not found")
        
        db.delete(text)
        db.commit()
        
        return {"message": "Text analysis deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting text: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Error deleting text")