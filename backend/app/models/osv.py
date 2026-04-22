"""
OSV (Open Source Vulnerability) 漏洞数据模型
支持存储 OSV 漏洞数据库中的漏洞信息
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, JSON
from datetime import datetime
from app.database import Base


class OSVVulnerability(Base):
    """OSV漏洞数据模型"""
    __tablename__ = "osv_vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    osv_id = Column(String(200), unique=True, index=True, nullable=False)
    schema_version = Column(String(20))
    published = Column(DateTime)
    modified = Column(DateTime)
    withdrawn = Column(DateTime)
    aliases = Column(JSON)
    related = Column(JSON)
    summary = Column(Text)
    details = Column(Text)
    affected = Column(JSON)
    references = Column(JSON)
    severity = Column(JSON)
    database_specific = Column(JSON)
    exploits_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<OSVVulnerability {self.osv_id}>"