from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql://cve:cvepassword@localhost:5432/cve_db"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # App
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"
    PROJECT_NAME: str = "网络安全漏洞情报平台"
    
    # API Keys
    GITHUB_TOKEN: Optional[str] = None
    NVD_API_KEY: Optional[str] = None
    VULNCHECK_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    
    class Config:
        env_file = ".env"


settings = Settings()
