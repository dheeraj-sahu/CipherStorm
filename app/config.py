import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:///./fraud_detection_2.db"
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # OpenPageRank API Key (optional)
    OPR_API_KEY: str = "k0o4g8k000o8cgogws4c84w4ocsgws4oo40k4ogs"
    # VirusTotal API Key
    VT_API_KEY: str = "a3d2691e06a5bfe9ae39837470b54ca8a06bac12277ddb52d5edf144e2074dd8"
    
    # XGBoost Model Path
    XGBOOST_MODEL_PATH: str = "ml_models/xgb_phishing_model.pkl"
    
    # Rate limiting settings
    URL_SCAN_RATE_LIMIT: int = 100  # scans per hour per user
    BULK_SCAN_MAX_URLS: int = 10

    model_config = {
        "extra": "allow",
        "env_file": ".env"
    }

settings = Settings()