# models/transaction.py
from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, Boolean, DECIMAL
from datetime import datetime, timezone
from app.database import Base

class Transaction(Base):
    __tablename__ = "transaction_table"

    transaction_id = Column(String(35), primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id"))

    # Core transaction fields
    amount = Column(DECIMAL(9, 2))
    transaction_type = Column(String(20))  # P2P, P2M
    payment_instrument = Column(String(10))  # UPI, Card

    # Global model fields
    payer_vpa = Column(String(50))
    beneficiary_vpa = Column(String(50))
    initiation_mode = Column(String(10))

    # Local model fields
    device_id = Column(String(40))
    ip_address = Column(String(20))
    latitude = Column(Float)
    longitude = Column(Float)
    country = Column(String(50))
    city = Column(String(50))

    # Time features
    day_of_week = Column(Integer)
    hour = Column(Integer)
    minute = Column(Integer)
    is_night = Column(Boolean)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_fraud = Column(Boolean, default=False)  # Model output