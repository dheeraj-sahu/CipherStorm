from fastapi import APIRouter, Depends, HTTPException, status, Form
from sqlalchemy.orm import Session
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
from app.utils import get_current_user as get_current_user_util
from datetime import datetime
from app.models.constant import IST
import logging
import json

from app.database import get_db
from app.models.customer_care import CustomerCare
from app.models.user import User
from app.schemas.customer_care import CustomerCareVerifyRequest, CustomerCareVerifyResponse
from app.routers.auth import get_current_user
from app.services.fake_customer_service import verify_phone_number

router = APIRouter(prefix="/customer_care", tags=["Customer Care"])
templates = Jinja2Templates(directory="app/templates")
logger = logging.getLogger(__name__)

@router.post("/verify")
async def verify_customer_care_number(
    request: Request,
    company_name: str = Form(...),
    phone_number: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Verify if a customer care number is legitimate for a given company and render the results
    """
    try:
        # Call the verification service
        result = verify_phone_number(company_name, phone_number)
        
        # Store the result in database
        db_customer_care = CustomerCare(
            user_id=current_user.user_id,
            company_name=result.company_name,
            phone_number=result.phone_number,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            confidence=result.confidence,
            number_type=result.number_type,
            toll_free=result.toll_free,
            landline=result.landline,
            mobile=result.mobile,
            numbers_found_in_sources=result.numbers_found_in_sources,
            risk_details=json.dumps(result.risk_details),
            recommendation=result.recommendation,
            found_numbers=json.dumps(result.found_numbers),
            enhanced_info=json.dumps(result.enhanced_info) if result.enhanced_info else None
        )
        
        db.add(db_customer_care)
        db.commit()
        db.refresh(db_customer_care)
        
        # Return response
        return CustomerCareVerifyResponse(
            id=db_customer_care.id,
            company_name=db_customer_care.company_name,
            phone_number=db_customer_care.phone_number,
            risk_score=db_customer_care.risk_score,
            risk_level=db_customer_care.risk_level,
            confidence=db_customer_care.confidence,
            number_type=db_customer_care.number_type,
            toll_free=db_customer_care.toll_free,
            landline=db_customer_care.landline,
            mobile=db_customer_care.mobile,
            numbers_found_in_sources=db_customer_care.numbers_found_in_sources,
            risk_details=json.loads(db_customer_care.risk_details),
            recommendation=db_customer_care.recommendation,
            found_numbers=json.loads(db_customer_care.found_numbers),
            enhanced_info=json.loads(db_customer_care.enhanced_info) if db_customer_care.enhanced_info else None,
            created_at=db_customer_care.created_at
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error verifying customer care number: {str(e)}"
        )

@router.post("/verify_form", response_class=HTMLResponse)
async def verify_customer_care_form(
    request: Request,
    company_name: str = Form(...),
    phone_number: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Handle customer care verification form submission and render results
    """
    try:
        # Validate inputs
        if not company_name or not company_name.strip():
            raise HTTPException(status_code=400, detail="Company name cannot be empty")
            
        # Call the verification service
        result = verify_phone_number(company_name, phone_number)
        
        # Store the result in database
        db_customer_care = CustomerCare(
            user_id=current_user.user_id,
            company_name=result.company_name,
            phone_number=result.phone_number,
            risk_score=result.risk_score,
            risk_level=result.risk_level,
            confidence=result.confidence,
            number_type=result.number_type,
            toll_free=result.toll_free,
            landline=result.landline,
            mobile=result.mobile,
            numbers_found_in_sources=result.numbers_found_in_sources,
            risk_details=json.dumps(result.risk_details),
            recommendation=result.recommendation,
            found_numbers=json.dumps(result.found_numbers),
            enhanced_info=json.dumps(result.enhanced_info) if result.enhanced_info else None
        )
        
        db.add(db_customer_care)
        db.commit()
        db.refresh(db_customer_care)
        
        # Convert result to dict and fix JSON fields
        result_dict = {
            "id": db_customer_care.id,
            "phone_number": result.phone_number,
            "company_name": result.company_name,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "confidence": result.confidence,
            "number_type": result.number_type,
            "toll_free": result.toll_free,
            "landline": result.landline,
            "mobile": result.mobile,
            "numbers_found_in_sources": result.numbers_found_in_sources,
            "risk_details": result.risk_details,  # Already a list
            "recommendation": result.recommendation,
            "found_numbers": result.found_numbers,  # Already a list
            "enhanced_info": result.enhanced_info,  # Include enhanced info
            "created_at": db_customer_care.created_at.strftime("%Y-%m-%d %H:%M:%S") if db_customer_care.created_at else None
        }

        # Render the template with results and user context
        return templates.TemplateResponse(
            "customer_care_output.html",
            {
                "request": request,
                "result": result_dict,
                "user": current_user  # Add the user context
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error analyzing customer care number: {str(e)}")
        user = get_current_user_util(request)
        return templates.TemplateResponse(
            "customer_care_output.html",
            {
                "request": request,
                "user": user,
                "analysis_result": None,
                "analyzed_company": company_name if 'company_name' in locals() else "",
                "analyzed_phone": phone_number if 'phone_number' in locals() else "",
                "error": "An error occurred during customer care number verification. Please try again."
            }
        )

@router.get("/last_records")
async def get_last_customer_care_records(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get last 20 customer care verification records for the current user"""
    records = db.query(CustomerCare).filter(
        CustomerCare.user_id == current_user.user_id
    ).order_by(CustomerCare.created_at.desc()).limit(20).all()
    return records