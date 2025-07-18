from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

class TextAnalysisCreate(BaseModel):
    text: str

class TextAnalysisResponse(BaseModel):
    text_id: int
    user_id: int
    text: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class TextAnalysisResult(BaseModel):
    is_phishing: bool
    phishing_score: float
    confidence: float
    classification: str
    analysis_details: Dict[str, Any]
    text_id: Optional[int] = None
    
class TextAnalysisComplete(BaseModel):
    text_analysis: TextAnalysisResponse
    analysis_result: TextAnalysisResult