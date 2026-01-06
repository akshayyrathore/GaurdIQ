from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Percepta - AI Brain for WAF"
    
    # Database
    DATABASE_URL: str = "sqlite:///./percepta.db"
    
    # Security
    SECRET_KEY: str = "changeme_in_production"
    ALGORITHM: str = "HS256"
    
    # ML / Model Settings
    ANOMALY_THRESHOLD: float = -0.5  # Isolation Forest score threshold
    
    class Config:
        env_file = ".env"

settings = Settings()
