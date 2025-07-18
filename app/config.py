import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database Configuration
    DATABASE_URL: str = "sqlite:///./CIPHERSTORM_2.db"
    
    # Security Configuration
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Email Configuration
    SMTP_SERVER: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_EMAIL: str = "ankitkr1801@gmail.com"
    SMTP_PASSWORD: str = "kdgozojsgxumbdae"  # Your Gmail App Password
    
    # External API Keys
    # OpenPageRank API Key (optional)
    OPR_API_KEY: str = "k0o4g8k000o8cgogws4c84w4ocsgws4oo40k4ogs"
    # VirusTotal API Key
    VT_API_KEY: str = "a3d2691e06a5bfe9ae39837470b54ca8a06bac12277ddb52d5edf144e2074dd8"
    
    # Machine Learning Model Paths
    XGBOOST_MODEL_PATH: str = "app/ml_models/xgb_phishing_model.pkl"
    
    # Rate limiting settings
    URL_SCAN_RATE_LIMIT: int = 100  # scans per hour per user
    BULK_SCAN_MAX_URLS: int = 10
    
    # Application Settings
    DEBUG: bool = False
    ENVIRONMENT: str = "production"
    LOG_LEVEL: str = "INFO"
    
    # Redis Configuration
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # File Upload Settings
    MAX_FILE_SIZE: int = 10485760  # 10MB in bytes
    ALLOWED_EXTENSIONS: str = ".txt,.csv,.json,.wav,.mp3,.mp4"
    
    # ML Model Settings
    MODEL_CACHE_TIMEOUT: int = 3600  # 1 hour in seconds
    PREDICTION_THRESHOLD: float = 0.5
    CONFIDENCE_THRESHOLD: float = 0.7

    model_config = {
        "extra": "allow",
        "env_file": ".env"
    }

settings = Settings()



