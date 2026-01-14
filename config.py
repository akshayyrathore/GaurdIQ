from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    # --------------------------------------------------
    # Project
    # --------------------------------------------------
    PROJECT_NAME: str = "Percepta - AI Brain for WAF"
    ENVIRONMENT: str = "development"  # development | staging | production
    DEBUG: bool = True
    VERSION: str = "0.1.0"

    # --------------------------------------------------
    # Server
    # --------------------------------------------------
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    ALLOWED_HOSTS: List[str] = ["*"]
    CORS_ORIGINS: List[str] = ["*"]

    # --------------------------------------------------
    # Database
    # --------------------------------------------------
    DATABASE_URL: str = "sqlite:///./percepta.db"
    DB_ECHO: bool = False
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # --------------------------------------------------
    # Security / Auth
    # --------------------------------------------------
    SECRET_KEY: str = "changeme_in_production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # IP Reputation
    BLOCKED_IP_TTL_SECONDS: int = 3600
    TRUSTED_IPS: List[str] = []

    # --------------------------------------------------
    # ML / AI Engine
    # --------------------------------------------------
    ANOMALY_THRESHOLD: float = -0.5  # Isolation Forest score threshold
    MODEL_PATH: str = "models/isolation_forest.joblib"
    MODEL_RETRAIN_INTERVAL_HOURS: int = 24
    MIN_TRAINING_SAMPLES: int = 1000

    # Decision Weights
    WEIGHT_RATE_LIMIT: float = 0.3
    WEIGHT_ANOMALY: float = 0.5
    WEIGHT_SIGNATURE: float = 0.2

    # Auto-Response
    AUTO_BLOCK_ENABLED: bool = True
    AUTO_CHALLENGE_ENABLED: bool = True

    # --------------------------------------------------
    # Logging & Monitoring
    # --------------------------------------------------
    LOG_LEVEL: str = "INFO"
    LOG_TO_FILE: bool = True
    LOG_FILE_PATH: str = "logs/percepta.log"

    # Metrics / Observability
    METRICS_ENABLED: bool = True
    PROMETHEUS_ENABLED: bool = False

    # --------------------------------------------------
    # Alerting
    # --------------------------------------------------
    ALERTS_ENABLED: bool = True
    ALERT_THREAT_THRESHOLD: int = 20  # threats per minute
    ALERT_EMAILS: List[str] = []

    # Webhooks (Slack / Discord / SIEM)
    WEBHOOK_URL: str | None = None

    # --------------------------------------------------
    # External Integrations
    # --------------------------------------------------
    GEOIP_DB_PATH: str = "data/GeoLite2-Country.mmdb"
    THREAT_INTEL_ENABLED: bool = False
    THREAT_INTEL_API_KEY: str | None = None

    # --------------------------------------------------
    # Feature Toggles
    # --------------------------------------------------
    ENABLE_LIVE_TRAFFIC: bool = True
    ENABLE_STATS: bool = True
    ENABLE_EXPORTS: bool = True
    ENABLE_DASHBOARD: bool = True

    # --------------------------------------------------
    # Environment
    # --------------------------------------------------
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
