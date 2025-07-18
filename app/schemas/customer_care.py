from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

class CustomerCareVerifyRequest(BaseModel):
    company_name: str
    phone_number: str

class CustomerCareVerifyResponse(BaseModel):
    id: int
    company_name: str
    phone_number: str
    risk_score: int
    risk_level: str
    confidence: int
    number_type: str
    toll_free: bool
    landline: bool
    mobile: bool
    numbers_found_in_sources: int
    risk_details: List[str]
    recommendation: str
    found_numbers: List[str]
    enhanced_info: Optional[Dict[str, Any]]
    created_at: datetime
    
    class Config:
        from_attributes = True