# models/url.py
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, DateTime
from sqlalchemy.sql import func
from app.database import Base
from app.models.constant import IST
from datetime import datetime

class URLScan(Base):
    __tablename__ = "url_scan"
    
    # Primary identification
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    url = Column(String(2048), nullable=False)
    is_phishing = Column(Boolean, default=False)
    scanned_at = Column(DateTime(timezone=True), default=lambda: datetime.now(IST))
    risk_score = Column(Integer, default=0)
    
    # Feature columns used by XGBoost model
    # Each feature stores the extracted value (-1, 0, or 1)
    
    # URL-based features
    having_ip_address = Column(Integer, default=0)  # -1: legitimate, 1: phishing
    url_length = Column(Integer, default=0)  # -1: short, 0: medium, 1: long
    shortening_service = Column(Integer, default=0)  # -1: no shortening, 1: uses shortening
    having_at_symbol = Column(Integer, default=0)  # -1: no @, 1: has @
    double_slash_redirecting = Column(Integer, default=0)  # -1: no redirect, 1: redirect
    prefix_suffix = Column(Integer, default=0)  # -1: no dash, 1: has dash
    having_sub_domain = Column(Integer, default=0)  # -1: legitimate, 0: suspicious, 1: phishing
    
    # Domain-based features
    domain_registration_length = Column(Integer, default=0)  # -1: long registration, 1: short
    age_of_domain = Column(Integer, default=0)  # 1: old domain, -1: new domain
    dns_record = Column(Integer, default=0)  # 1: has DNS, -1: no DNS
    
    # Traffic and ranking features
    web_traffic = Column(Integer, default=0)  # 1: high traffic, 0: medium, -1: low
    page_rank = Column(Integer, default=0)  # 1: high rank, 0: medium, -1: low
    
    # Security features
    ssl_final_state = Column(Integer, default=0)  # 1: valid SSL, 0: issues, -1: no SSL
    
    # Content-based features
    pop_up_window = Column(Integer, default=0)  # 1: no popup, -1: has popup
    right_click_disabled = Column(Integer, default=0)  # 1: enabled, -1: disabled
    on_mouseover = Column(Integer, default=0)  # 1: legitimate, -1: suspicious
    favicon = Column(Integer, default=0)  # 1: same domain, -1: different domain
    iframe = Column(Integer, default=0)  # 1: no hidden iframe, -1: has hidden iframe
    sfh = Column(Integer, default=0)  # -1: legitimate, 0: suspicious, 1: phishing
    
    def _repr_(self):
        return f"<URLScan(id={self.id}, url='{self.url}', is_phishing={self.is_phishing})>"