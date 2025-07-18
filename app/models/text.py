from sqlalchemy import Column, Integer, String, Text, ForeignKey, DateTime
from app.models.constant import IST
from app.database import Base
from datetime import datetime

class TextAnalysis(Base):
    __tablename__ = "text_analysis"
    
    text_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(IST))