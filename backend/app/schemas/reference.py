from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class ReferenceBase(BaseModel):
    cve_id: str
    url: str
    title: Optional[str] = None
    ref_type: Optional[str] = None
    source: Optional[str] = None
    tags: Optional[List[str]] = None


class ReferenceResponse(ReferenceBase):
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True
