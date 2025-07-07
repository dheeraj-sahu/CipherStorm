from sqlalchemy import Column, Integer, String, Text, ForeignKey, DECIMAL, DateTime
from datetime import datetime, timezone
from app.database import Base

class Profile(Base):
    __tablename__ = "profiles"
    profile_id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), unique=True)
    full_name = Column(String(100))
    mobile_no = Column(String(20))
    upi_id = Column(String(50))
    address = Column(Text)
    transaction_limit = Column(DECIMAL(10, 2))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))