from sqlalchemy import Column, String, DateTime, Text, Integer, ForeignKey, Index, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class Reference(Base):
    __tablename__ = "references"

    id = Column(Integer, primary_key=True, index=True)
    
    # CVE Reference
    cve_id = Column(String(20), ForeignKey("cves.cve_id"), index=True, nullable=False)
    
    # Reference Information
    url = Column(String(500), nullable=False)
    title = Column(String(500))
    ref_type = Column(String(50))  # advisory, exploit, patch, article, etc.
    source = Column(String(50))  # nvd, cve.org, vendor, etc.
    
    # Tags
    tags = Column(ARRAY(String(50)))
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationship
    cve = relationship("CVE", back_populates="references")
    
    __table_args__ = (
        Index('idx_reference_type', 'ref_type'),
        Index('idx_reference_source', 'source'),
    )
