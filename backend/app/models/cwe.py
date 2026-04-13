from sqlalchemy import Column, String, DateTime, Integer, Text
from sqlalchemy.sql import func
from app.database import Base


class CWE(Base):
    __tablename__ = "cwes"

    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String(20), unique=True, index=True, nullable=False)
    
    # Content
    name = Column(String(500))
    description = Column(Text)
    
    # Metadata
    cve_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
