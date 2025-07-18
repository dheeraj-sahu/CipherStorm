from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.models.constant import IST
from app.database import Base
from datetime import datetime

class VishingRecording(Base):
    __tablename__ = "vishing_recordings"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    audio_file_path = Column(String(500), nullable=False)
    transcript = Column(Text, nullable=True)
    user_opinion = Column(String(50), nullable=True)  # "confirm_suspicious" or "insufficient_evidence"
    created_at = Column(DateTime, default=lambda: datetime.now(IST))
    
    # Relationship with User
    user = relationship("User", back_populates="vishing_recordings")