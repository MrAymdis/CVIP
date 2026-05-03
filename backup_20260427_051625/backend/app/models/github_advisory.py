"""
GitHub Advisory Database 漏洞数据模型
支持存储 GitHub Advisory Database 中的安全漏洞信息
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON, Boolean, Float
from datetime import datetime
from app.database import Base


class GitHubAdvisory(Base):
    """GitHub Advisory 漏洞数据模型"""
    __tablename__ = "github_advisories"

    id = Column(Integer, primary_key=True, index=True)
    ghsa_id = Column(String(50), unique=True, index=True, nullable=False)
    cve_id = Column(String(20), index=True)
    aliases = Column(JSON)  # 存储所有关联标识符（CVE、GHSA等）
    
    # 基本信息
    summary = Column(Text)
    description = Column(Text)
    severity = Column(String(20))  # critical, high, medium, low
    
    # CVSS 评分
    cvss_score = Column(Float)
    cvss_vector = Column(String(200))
    
    # CWE
    cwe_ids = Column(JSON)
    
    # 受影响的包和版本范围
    affected_packages = Column(JSON)
    
    # 修复信息
    patched_versions = Column(JSON)
    unaffected_versions = Column(JSON)
    
    # 引用链接
    references = Column(JSON)
    
    # GitHub 元数据
    github_url = Column(String(500))
    repository_url = Column(String(500))
    
    # 状态
    published_at = Column(DateTime)
    updated_at = Column(DateTime)
    withdrawn_at = Column(DateTime)
    severity_updated_at = Column(DateTime)
    
    # 数据源跟踪
    data_sources = Column(JSON)
    
    # 数据库时间戳
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<GitHubAdvisory {self.ghsa_id}>"
