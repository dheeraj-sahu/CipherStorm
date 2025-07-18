from sqlalchemy import Column, Integer, String, DateTime, Boolean
from sqlalchemy.orm import relationship
from app.models.constant import IST
from app.database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    user_id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(IST))
    is_verified = Column(Boolean, default=False)
    
    # Use string references to avoid circular import issues
    customer_care_checks = relationship("CustomerCare", back_populates="user")
    vishing_recordings = relationship("VishingRecording", back_populates="user", lazy="dynamic")