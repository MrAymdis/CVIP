from pydantic import BaseModel
from typing import Optional, List, Any
from datetime import datetime


class CWEBase(BaseModel):
    cwe_id: str
    name: Optional[str] = None
    name_zh: Optional[str] = None
    description: Optional[str] = None
    description_zh: Optional[str] = None
    
    # Weakness Classification
    weakness_type: Optional[str] = None
    status: Optional[str] = None
    
    # CVSS-like Metrics
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    
    # Impact Metrics
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None
    
    # Severity Scores
    base_score: Optional[float] = None
    base_severity: Optional[str] = None
    
    # Weakness Attributes
    likelihood_of_exploit: Optional[str] = None
    detection_difficulty: Optional[str] = None
    
    # Mitigation Information
    mitigation: Optional[str] = None
    mitigation_zh: Optional[str] = None
    
    # Related Weaknesses
    related_weaknesses: Optional[List[str]] = None
    parent_weaknesses: Optional[List[str]] = None
    child_weaknesses: Optional[List[str]] = None
    
    # Taxonomy Mapping
    taxonomy_mappings: Optional[dict] = None
    
    # References
    references: Optional[List[str]] = None
    
    # Metadata
    cve_count: int = 0
    cwe_category: Optional[str] = None
    cwe_subcategory: Optional[str] = None


class CWECreate(CWEBase):
    cwe_id: str
    name: Optional[str] = None


class CWEUpdate(CWEBase):
    cwe_id: Optional[str] = None


class CWEResponse(CWEBase):
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class CWEListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[CWEResponse]


class CWEBatchCreate(BaseModel):
    items: List[CWECreate]


class CWEBatchResponse(BaseModel):
    success_count: int
    failed_count: int
    failed_items: List[dict] = []


class CWECVEResponse(BaseModel):
    total: int
    cwe_id: str
    cwe_name: str
    items: List[Any]
