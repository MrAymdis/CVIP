from sqlalchemy import Column, String, DateTime, Integer, Text, Float, ARRAY, JSON, Index
from sqlalchemy.sql import func
from app.database import Base


class CWE(Base):
    __tablename__ = "cwes"

    id = Column(Integer, primary_key=True, index=True)
    cwe_id = Column(String(20), unique=True, index=True, nullable=False)
    
    # Basic Information
    name = Column(String(500))
    name_zh = Column(String(500))
    description = Column(Text)
    description_zh = Column(Text)
    
    # Weakness Classification
    weakness_type = Column(String(50))  # Weakness, Category, View, Compound Element
    status = Column(String(50))  # Draft, Accepted, Deprecated, Incomplete
    
    # CVSS-like Metrics (from CWE Common Weakness Scoring System)
    attack_vector = Column(String(50))  # Local, Adjacent, Network, Physical
    attack_complexity = Column(String(50))  # Low, High
    privileges_required = Column(String(50))  # None, Low, High
    user_interaction = Column(String(50))  # None, Required
    scope = Column(String(50))  # Unchanged, Changed
    
    # Impact Metrics
    confidentiality_impact = Column(String(50))  # None, Low, High
    integrity_impact = Column(String(50))  # None, Low, High
    availability_impact = Column(String(50))  # None, Low, High
    
    # Severity Scores
    base_score = Column(Float)
    base_severity = Column(String(20))  # None, Low, Medium, High, Critical
    
    # Weakness Attributes
    likelihood_of_exploit = Column(String(50))  # Low, Medium, High
    detection_difficulty = Column(String(50))  # Easy, Medium, Hard
    
    # Mitigation Information
    mitigation = Column(Text)
    mitigation_zh = Column(Text)
    
    # Related Weaknesses
    related_weaknesses = Column(ARRAY(String(20)))  # List of related CWE IDs
    parent_weaknesses = Column(ARRAY(String(20)))  # Parent CWE IDs
    child_weaknesses = Column(ARRAY(String(20)))  # Child CWE IDs
    
    # Taxonomy Mapping
    taxonomy_mappings = Column(JSON)  # Mapping to other taxonomies (e.g., OWASP Top 10)
    
    # References
    references = Column(ARRAY(String(500)))  # URLs to external references
    
    # Metadata
    cve_count = Column(Integer, default=0)
    cwe_category = Column(String(100))  # e.g., "Input Validation and Representation"
    cwe_subcategory = Column(String(100))
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    __table_args__ = (
        Index('idx_cwe_cve_count', 'cve_count'),
        Index('idx_cwe_severity', 'base_severity'),
        Index('idx_cwe_type', 'weakness_type'),
        Index('idx_cwe_category', 'cwe_category'),
    )
