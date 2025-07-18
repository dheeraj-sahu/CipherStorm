# routers/url.py
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Request, Form, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
import logging
from app.models.url import URLScan
from app.schemas.url import URLScanRequest, URLScanResponse, URLHistoryResponse
from app.database import get_db
from app.routers.auth import get_current_user
from app.services.url_service import url_detector
from app.utils import get_current_user_util, require_login
from datetime import datetime
from app.models.constant import IST

router = APIRouter(prefix="/url", tags=["URL"])
# Use absolute path for templates
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def create_url_scan(db: Session, user_id: int, url: str, analysis_result: dict) -> Optional[URLScan]:
    """Helper function to create and save URLScan record"""
    try:
        features = analysis_result.get('features', {})
        logger.info(f"Creating URL scan - User ID: {user_id}, URL: {url}, Analysis: {analysis_result}")
        url_scan = URLScan(
            user_id=user_id,
            url=url,
            is_phishing=analysis_result.get('is_phishing', False),
            risk_score=analysis_result.get('risk_score', 0),
            having_ip_address=features.get('having_IP_Address', 0),
            url_length=features.get('URL_Length', 0),
            shortening_service=features.get('Shortining_Service', 0),
            having_at_symbol=features.get('having_At_Symbol', 0),
            double_slash_redirecting=features.get('double_slash_redirecting', 0),
            prefix_suffix=features.get('Prefix_Suffix', 0),
            having_sub_domain=features.get('having_Sub_Domain', 0),
            domain_registration_length=features.get('Domain_registeration_length', 0),
            age_of_domain=features.get('age_of_domain', 0),
            dns_record=features.get('DNSRecord', 0),
            web_traffic=features.get('web_traffic', 0),
            page_rank=features.get('Page_Rank', 0),
            ssl_final_state=features.get('SSLfinal_State', 0),
            pop_up_window=features.get('pop_up_window', 0),
            right_click_disabled=features.get('right_click_disabled', 0),
            on_mouseover=features.get('on_mouseover', 0),
            favicon=features.get('favicon', 0),
            iframe=features.get('iframe', 0),
            sfh=features.get('sfh', 0)
        )
        db.add(url_scan)
        db.commit()
        db.refresh(url_scan)
        return url_scan
    except Exception as e:
        logger.warning(f"Failed to save URL scan to database: {str(e)}")
        db.rollback()
        return None

@router.post("/scan/api", response_model=URLScanResponse)
def scan_url_api(
    request: URLScanRequest,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Scan a URL for phishing detection and save results to database
    """
    try:
        # Get prediction from the model
        prediction_result = url_detector.predict_phishing(request.url)
        
        if 'error' in prediction_result:
            raise HTTPException(status_code=500, detail=f"Prediction error: {prediction_result['error']}")
        
        # Extract features for database storage
        features = prediction_result.get('features', {})
        raw_details = prediction_result.get('raw_details', {})
        # Create new URL scan record
        url_scan = URLScan(
            user_id=current_user.user_id,
            url=request.url,
            is_phishing=prediction_result['is_phishing'],
            risk_score=prediction_result.get('risk_score', 0),
            # Feature columns
            having_ip_address=features.get('having_IP_Address', 0),
            url_length=features.get('URL_Length', 0),
            shortening_service=features.get('Shortining_Service', 0),
            having_at_symbol=features.get('having_At_Symbol', 0),
            double_slash_redirecting=features.get('double_slash_redirecting', 0),
            prefix_suffix=features.get('Prefix_Suffix', 0),
            having_sub_domain=features.get('having_Sub_Domain', 0),
            domain_registration_length=features.get('Domain_registeration_length', 0),
            age_of_domain=features.get('age_of_domain', 0),
            dns_record=features.get('DNSRecord', 0),
            web_traffic=features.get('web_traffic', 0),
            page_rank=features.get('Page_Rank', 0),
            ssl_final_state=features.get('SSLfinal_State', 0),
            pop_up_window=features.get('pop_up_window', 0),
            right_click_disabled=features.get('right_click_disabled', 0),
            on_mouseover=features.get('on_mouseover', 0),
            favicon=features.get('favicon', 0),
            iframe=features.get('iframe', 0),
            sfh=features.get('sfh', 0)
        )
        db.add(url_scan)
        db.commit()
        db.refresh(url_scan)
        # Return both DB scan and raw_details for API response
        return {**url_scan._dict_, 'raw_details': raw_details}
        
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to scan URL: {str(e)}")

@router.get("/history", response_model=URLHistoryResponse)
def get_url_history(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(10, ge=1, le=100, description="Number of records to return"),
    phishing_only: Optional[bool] = Query(None, description="Filter by phishing status")
):
    """
    Get URL scan history for the current user
    """
    try:
        # Build query
        query = db.query(URLScan).filter(URLScan.user_id == current_user.user_id)
        
        # Apply phishing filter if specified
        if phishing_only is not None:
            query = query.filter(URLScan.is_phishing == phishing_only)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        scans = query.order_by(URLScan.scanned_at.desc()).offset(skip).limit(limit).all()
        
        return URLHistoryResponse(
            scans=scans,
            total=total
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch URL history: {str(e)}")

@router.delete("/scan/{scan_id}")
def delete_url_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Delete a specific URL scan
    """
    try:
        # Query for the specific scan belonging to the current user
        url_scan = db.query(URLScan).filter(
            URLScan.id == scan_id,
            URLScan.user_id == current_user.user_id
        ).first()
        
        if not url_scan:
            raise HTTPException(status_code=404, detail="URL scan not found")
        
        db.delete(url_scan)
        db.commit()
        
        return {"message": "URL scan deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to delete URL scan: {str(e)}")

@router.post("/scan", response_class=HTMLResponse)
async def scan_url_form(
    request: Request,
    url: str = Form(...),
    db: Session = Depends(get_db)
):
    """Handle URL scanning form submission and render results"""
    login_redirect = require_login(request)
    if login_redirect:
        return login_redirect
    """
    Handle URL scanning form submission and render results
    """
    # Initialize variables
    result = None
    user = None
    
    def create_response(result=None, error_msg=None):
        logger.debug(f"Creating response with result: {result}")
        # Convert result to dict if it's a model instance
        if hasattr(result, '__dict__'):
            result = result.__dict__
        response_data = {
            "request": request,
            "user": user,
            "url_scan": result,
            "analyzed_url": url,
            "error": error_msg
        }
        logger.debug(f"Template context data: {response_data}")
        try:
            response = templates.TemplateResponse(
                "url_output.html",
                response_data
            )
            logger.debug("Template response created successfully")
            return response
        except Exception as e:
            logger.error(f"Error creating template response: {str(e)}")
            raise
    
    try:
        # Get user info first
        user = get_current_user_util(request, db)
        logger.info(f"Current user: {user}")
        
        if not user:
            return create_response(error_msg="User not found in database")
            
        # Validate URL
        if not url or not url.strip():
            return create_response(error_msg="URL cannot be empty")
        
        url = str(url).strip()
        logger.info(f"Analyzing URL: {url}")
        
        # Basic URL validation
        if not (url.startswith('http://') or url.startswith('https://')):
            return create_response(error_msg="URL must start with http:// or https://")
        
        # Perform URL analysis
        result = url_detector.predict_phishing(url)
        logger.info(f"URL analysis result: {result}")
        
        if not result:
            return create_response(error_msg="Failed to analyze URL. Please try again.")
            
        # Log current user info
        logger.info(f"User object: {user}")
        if user:
            logger.info(f"User ID: {user.user_id if hasattr(user, 'user_id') else 'No user_id found'}")
            
        # Add timestamp and analysis ID
        result['timestamp'] = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S")
        result['analysis_id'] = f"URL_{datetime.now(IST).strftime('%Y%m%d%H%M%S')}"
        
        # Save to database if analysis was successful and we have a user
        if not result.get('error') and user:
            # Check if user has user_id attribute
            if hasattr(user, 'user_id'):
                logger.info(f"Saving URL scan to database for user ID: {user.user_id}")
                saved_scan = create_url_scan(db, user.user_id, url, result)
                if saved_scan:
                    logger.info(f"Successfully saved URL scan with ID: {saved_scan.id}")
                else:
                    logger.error("Failed to save URL scan")
            else:
                logger.error(f"User object missing user_id attribute: {user}")
        
        response = create_response(result=result)
        logger.info("Returning template response")
        return response
        
    except HTTPException as he:
        logger.error(f"HTTP Exception in URL analysis: {str(he)}")
        raise
    except Exception as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        user = get_current_user_util(request)
        return templates.TemplateResponse(
            "url_output.html",
            {
                "request": request,
                "user": user,
                "url_scan": None,  # Changed from result to url_scan
                "analyzed_url": url if 'url' in locals() else "",
                "error": "An error occurred during URL analysis. Please try again."
            }
        )

@router.get("/", response_class=HTMLResponse)
async def get_url_input_page(request: Request, current_user: dict = Depends(get_current_user_util)):
    """Render the URL input page"""
    return templates.TemplateResponse("url_input.html", {"request": request, "user": current_user})

