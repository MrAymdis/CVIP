from sqlalchemy import Column, String, Float, DateTime, Boolean, Text, Integer, ARRAY, ForeignKey, Index, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class CVE(Base):
    __tablename__ = "cves"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(20), unique=True, index=True, nullable=False)
    
    # Title and Description
    title = Column(String(500))
    title_zh = Column(String(500))
    description = Column(Text)
    description_zh = Column(Text)
    
    # CVSS Scores
    cvss_v3_score = Column(Float)
    cvss_v3_severity = Column(String(10))
    cvss_v3_vector = Column(String(200))

    cvss_v4_score = Column(Float)
    cvss_v4_severity = Column(String(10))
    cvss_v4_vector = Column(String(200))
    
    # EPSS Score
    epss_score = Column(Float)
    epss_percentile = Column(Float)
    
    # CISA KEV
    cisa_kev = Column(Boolean, default=False)
    cisa_kev_date_added = Column(DateTime)
    cisa_due_date = Column(DateTime)
    cisa_required_action = Column(Text)
    
    # Vendor and Product
    vendor_id = Column(Integer, ForeignKey("vendors.id"))
    product_id = Column(Integer, ForeignKey("products.id"))
    
    # Dates
    published_date = Column(DateTime, index=True)
    modified_date = Column(DateTime)
    
    # Metadata
    cwes = Column(ARRAY(String(20)))
    references_count = Column(Integer, default=0)
    exploits_count = Column(Integer, default=0)
    
    # Data source tracking
    data_sources = Column(ARRAY(String(50)))
    
    # Affected products and versions
    affected_versions = Column(JSON, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    vendor = relationship("Vendor", back_populates="cves")
    product = relationship("Product", back_populates="cves")
    exploits = relationship("Exploit", back_populates="cve", cascade="all, delete-orphan")
    references = relationship("Reference", back_populates="cve", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_cve_cvss_v3', 'cvss_v3_score'),
        Index('idx_cve_epss', 'epss_score'),
        Index('idx_cve_published', 'published_date'),
        Index('idx_cve_cisa_kev', 'cisa_kev'),
        Index('idx_cve_vendor', 'vendor_id'),
        Index('idx_cve_product', 'product_id'),
    )
