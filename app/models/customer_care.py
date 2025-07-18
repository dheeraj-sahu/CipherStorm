from sqlalchemy import Column, Integer, String, Text, Boolean, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.constant import IST
from datetime import datetime

class CustomerCare(Base):
    __tablename__ = "customer_care"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    company_name = Column(String(255), nullable=False)
    phone_number = Column(String(20), nullable=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(10), nullable=False)
    confidence = Column(Integer, nullable=False)
    number_type = Column(String(20), nullable=False)
    toll_free = Column(Boolean, default=False)
    landline = Column(Boolean, default=False)
    mobile = Column(Boolean, default=False)
    numbers_found_in_sources = Column(Integer, default=0)
    risk_details = Column(Text)  # JSON string of risk details
    recommendation = Column(Text)
    found_numbers = Column(Text)  # JSON string of found numbers
    enhanced_info = Column(Text)  # JSON string of enhanced info
    
    created_at = Column(DateTime, default=lambda: datetime.now(IST))
    updated_at = Column(DateTime, default=lambda: datetime.now(IST), onupdate=lambda: datetime.now(IST))
    
    # Relationship
    user = relationship("User", back_populates="customer_care_checks")