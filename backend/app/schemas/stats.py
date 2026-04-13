from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime


class StatsOverview(BaseModel):
    total_cves: int
    total_exploits: int
    total_vendors: int
    total_products: int
    cves_this_year: int
    exploits_this_year: int
    cisa_kev_count: int
    high_severity_count: int


class TrendData(BaseModel):
    date: str
    count: int


class VendorRank(BaseModel):
    name: str
    cve_count: int
    exploited_count: int


class CWERank(BaseModel):
    cwe_id: str
    name: Optional[str] = None
    cve_count: int


class StatsResponse(BaseModel):
    overview: StatsOverview
    monthly_trends: List[TrendData]
    top_vendors: List[VendorRank]
    top_cwes: List[CWERank]
