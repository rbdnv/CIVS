from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    DATABASE_URL: str = "postgresql+asyncpg://civs_user:civs_password@localhost:5432/civs_db"
    SECRET_KEY: str = "dev-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Crypto settings
    SIGNATURE_ALGORITHM: str = "Ed25519"
    HASH_ALGORITHM: str = "SHA256"
    
    # Trust score thresholds
    TRUST_THRESHOLD_ACCEPT: float = 0.7
    TRUST_THRESHOLD_QUARANTINE: float = 0.4
    
    # Replay attack window (seconds)
    REPLAY_WINDOW_SECONDS: int = 30
    
@lru_cache()
def get_settings() -> Settings:
    return Settings()
