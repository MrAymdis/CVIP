from pydantic import BaseModel
from typing import Optional, List, Any
from datetime import datetime


class CVEBase(BaseModel):
    cve_id: str
    title: Optional[str] = None
    title_zh: Optional[str] = None
    description: Optional[str] = None
    description_zh: Optional[str] = None
    cvss_v3_score: Optional[float] = None
    cvss_v3_severity: Optional[str] = None
    cvss_v4_score: Optional[float] = None
    cvss_v4_severity: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    cisa_kev: bool = False
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    cwes: Optional[List[str]] = None
    exploits_count: int = 0
    references_count: int = 0
    affected_versions: Optional[List[Any]] = None


class CVEResponse(CVEBase):
    id: int
    vendor_name: Optional[str] = None
    product_name: Optional[str] = None
    
    class Config:
        from_attributes = True


class CVEListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[CVEResponse]


class CVESearchParams(BaseModel):
    q: Optional[str] = None
    severity: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    ecosystem: Optional[str] = None
    cwe: Optional[str] = None
    year: Optional[int] = None
    min_cvss: Optional[float] = None
    max_cvss: Optional[float] = None
    min_epss: Optional[float] = None
    max_epss: Optional[float] = None
    cisa_kev: Optional[bool] = None
    has_exploit: Optional[bool] = None
    sort_by: str = "published_date"
    sort_order: str = "desc"
    page: int = 1
    page_size: int = 20
