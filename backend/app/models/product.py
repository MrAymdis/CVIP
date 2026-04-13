from sqlalchemy import Column, String, DateTime, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(500), nullable=False)
    
    # Vendor
    vendor_id = Column(Integer, ForeignKey("vendors.id"))
    
    # Ecosystem (npm, pypi, maven, etc.)
    ecosystem = Column(String(50))
    
    # Metadata
    cve_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    vendor = relationship("Vendor", back_populates="products")
    cves = relationship("CVE", back_populates="product")
