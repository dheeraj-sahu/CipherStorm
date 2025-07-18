# schemas/url.py
from pydantic import BaseModel, field_validator
from typing import Optional, Dict, Any, List
from datetime import datetime
import re

class URLScanRequest(BaseModel):
    url: str
    
    @field_validator('url')
    def validate_url(cls, v):
        if not v:
            raise ValueError('URL cannot be empty')
        
        # Basic URL format validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(v):
            raise ValueError('Invalid URL format')
        
        return v

class URLScanResponse(BaseModel):
    id: int
    user_id: int
    url: str
    is_phishing: bool
    scanned_at: Optional[datetime] = None
    risk_score: Optional[int] = None
    
    # Feature values (optional for basic response)
    having_ip_address: Optional[int] = None
    url_length: Optional[int] = None
    shortening_service: Optional[int] = None
    having_at_symbol: Optional[int] = None
    double_slash_redirecting: Optional[int] = None
    prefix_suffix: Optional[int] = None
    having_sub_domain: Optional[int] = None
    domain_registration_length: Optional[int] = None
    age_of_domain: Optional[int] = None
    dns_record: Optional[int] = None
    web_traffic: Optional[int] = None
    page_rank: Optional[int] = None
    ssl_final_state: Optional[int] = None
    pop_up_window: Optional[int] = None
    right_click_disabled: Optional[int] = None
    on_mouseover: Optional[int] = None
    favicon: Optional[int] = None
    iframe: Optional[int] = None
    sfh: Optional[int] = None
    raw_details: Optional[Dict[str, Any]] = None
    
    class Config:
        from_attributes = True

class URLScanDetailedResponse(URLScanResponse):
    """Detailed response including feature explanations"""
    feature_explanations: Optional[Dict[str, str]] = None
    
    @field_validator('feature_explanations', mode='before')
    def add_feature_explanations(cls, v, values):
        """Add human-readable explanations for features"""
        explanations = {}
        
        # Map feature values to explanations
        feature_mappings = {
            'having_ip_address': {-1: 'Uses domain name (legitimate)', 1: 'Uses IP address (suspicious)'},
            'url_length': {-1: 'Short URL (legitimate)', 0: 'Medium length URL', 1: 'Long URL (suspicious)'},
            'shortening_service': {-1: 'No URL shortening', 1: 'Uses URL shortening service (suspicious)'},
            'having_at_symbol': {-1: 'No @ symbol', 1: 'Contains @ symbol (suspicious)'},
            'double_slash_redirecting': {-1: 'No double slash redirect', 1: 'Has double slash redirect (suspicious)'},
            'prefix_suffix': {-1: 'No dash in domain', 1: 'Has dash in domain (suspicious)'},
            'having_sub_domain': {-1: 'Normal domain', 0: 'Has subdomain', 1: 'Multiple subdomains (suspicious)'},
            'domain_registration_length': {-1: 'Long registration period', 1: 'Short registration period (suspicious)'},
            'age_of_domain': {1: 'Old domain (legitimate)', -1: 'New domain (suspicious)'},
            'dns_record': {1: 'Has DNS record', -1: 'No DNS record (suspicious)'},
            'web_traffic': {1: 'High web traffic', 0: 'Medium web traffic', -1: 'Low web traffic (suspicious)'},
            'page_rank': {1: 'High page rank', 0: 'Medium page rank', -1: 'Low page rank (suspicious)'},
            'ssl_final_state': {1: 'Valid SSL certificate', 0: 'SSL issues', -1: 'No SSL (suspicious)'},
            'pop_up_window': {1: 'No pop-ups', -1: 'Has pop-ups (suspicious)'},
            'right_click_disabled': {1: 'Right-click enabled', -1: 'Right-click disabled (suspicious)'},
            'on_mouseover': {1: 'Normal mouseover behavior', -1: 'Suspicious mouseover behavior'},
            'favicon': {1: 'Favicon from same domain', -1: 'Favicon from different domain (suspicious)'},
            'iframe': {1: 'No hidden iframes', -1: 'Has hidden iframes (suspicious)'},
            'sfh': {-1: 'Normal form handling', 0: 'Suspicious form handling', 1: 'Phishing form handling'}
        }
        
        for feature, mapping in feature_mappings.items():
            feature_value = values.get(feature)
            if feature_value is not None and feature_value in mapping:
                explanations[feature] = mapping[feature_value]
        
        return explanations

class URLPredictionResponse(BaseModel):
    """Response for URL phishing prediction"""
    is_phishing: bool
    confidence_score: Optional[float] = None
    features: Dict[str, int]
    error: Optional[str] = None
    raw_details: Optional[Dict[str, Any]] = None

class URLHistoryResponse(BaseModel):
    scans: List[URLScanResponse]
    total: int