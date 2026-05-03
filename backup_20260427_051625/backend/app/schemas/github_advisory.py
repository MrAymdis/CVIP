"""
GitHub Advisory漏洞数据Schema定义
"""
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Any


class GitHubAdvisoryBase(BaseModel):
    """GitHub Advisory基础信息"""
    ghsa_id: str = Field(..., description="GHSA唯一标识")
    cve_id: Optional[str] = Field(None, description="关联的CVE ID")
    aliases: Optional[List[str]] = Field(None, description="所有关联标识符（CVE、GHSA等）")
    summary: Optional[str] = Field(None, description="漏洞摘要")
    description: Optional[str] = Field(None, description="漏洞描述")
    severity: Optional[str] = Field(None, description="严重程度")
    cvss_score: Optional[float] = Field(None, description="CVSS评分")
    cvss_vector: Optional[str] = Field(None, description="CVSS向量")
    cwe_ids: Optional[List[str]] = Field(None, description="CWE ID列表")
    affected_packages: Optional[List[Any]] = Field(None, description="受影响的包")
    patched_versions: Optional[List[Any]] = Field(None, description="已修复版本")
    unaffected_versions: Optional[List[str]] = Field(None, description="未受影响版本")
    references: Optional[List[Any]] = Field(None, description="参考链接")
    github_url: Optional[str] = Field(None, description="GitHub Advisory URL")
    repository_url: Optional[str] = Field(None, description="源代码位置")
    published_at: Optional[datetime] = Field(None, description="发布时间")
    updated_at: Optional[datetime] = Field(None, description="更新时间")
    withdrawn_at: Optional[datetime] = Field(None, description="撤回时间")


class GitHubAdvisoryResponse(GitHubAdvisoryBase):
    """GitHub Advisory详情响应"""
    id: int = Field(..., description="数据库ID")
    created_at: datetime = Field(..., description="创建时间")
    updated_at: datetime = Field(..., description="更新时间")

    class Config:
        orm_mode = True


class GitHubAdvisoryListResponse(BaseModel):
    """GitHub Advisory列表响应"""
    data: List[GitHubAdvisoryResponse] = Field(..., description="漏洞列表")
    total: int = Field(..., description="总数")
    page: int = Field(..., description="当前页码")
    page_size: int = Field(..., description="每页大小")


class GitHubAdvisoryStatsResponse(BaseModel):
    """GitHub Advisory统计响应"""
    total_count: int = Field(..., description="总数量")
    critical_count: int = Field(..., description="严重漏洞数量")
    high_count: int = Field(..., description="高危漏洞数量")
    medium_count: int = Field(..., description="中危漏洞数量")
    low_count: int = Field(..., description="低危漏洞数量")
    avg_cvss_score: Optional[float] = Field(None, description="平均CVSS评分")
    with_cve_count: int = Field(..., description="关联CVE的数量")
    without_cve_count: int = Field(..., description="未关联CVE的数量")


class GitHubAdvisorySearchParams(BaseModel):
    """GitHub Advisory搜索参数"""
    q: Optional[str] = Field(None, description="搜索关键词")
    severity: Optional[str] = Field(None, description="严重程度筛选")
    ecosystem: Optional[str] = Field(None, description="生态系统筛选")
    has_cve: Optional[bool] = Field(None, description="是否关联CVE")
    page: int = Field(1, description="页码")
    page_size: int = Field(20, description="每页大小")
