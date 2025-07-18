from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

class UserOpinion(str, Enum):
    CONFIRM_SUSPICIOUS = "confirm_suspicious"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"

class VishingRecordingCreate(BaseModel):
    user_opinion: Optional[UserOpinion] = None

class VishingRecordingResponse(BaseModel):
    id: int
    user_id: int
    audio_file_path: str
    transcript: Optional[str]
    user_opinion: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True

class TextScores(BaseModel):
    threat_score: float = Field(..., description="Threat detection score")
    urgency_score: float = Field(..., description="Urgency detection score") 
    manipulative_emotion_score: float = Field(..., description="Manipulative emotion detection score")
    vishing_score: float = Field(..., description="Overall vishing likelihood score")

class VishingAnalysisResult(BaseModel):
    prediction: Dict[str, Any]
    voice_features: List[float]
    text_scores: TextScores
    transcript: str

class VishingAnalysisResponse(BaseModel):
    recording_id: int
    analysis_result: VishingAnalysisResult
    recording_info: VishingRecordingResponse

