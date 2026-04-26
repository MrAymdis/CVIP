from sqlalchemy import Column, String, Text, DateTime, Integer, Boolean, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base


class PacketStormExploit(Base):
    __tablename__ = "packetstorm_exploits"

    id = Column(Integer, primary_key=True, index=True)
    
    # PacketStorm 唯一标识（从 URL 提取）
    packetstorm_id = Column(String(50), unique=True, index=True)
    
    # CVE 关联（可能有多个，用逗号分隔）
    cve_ids = Column(Text)
    
    # 漏洞标题
    title = Column(String(500))
    
    # 漏洞详情 URL
    url = Column(String(500), unique=True)
    
    # 漏洞类型
    exploit_type = Column(String(100))  # RCE, SQLi, XSS, LFI, etc.
    
    # 目标平台/软件
    platform = Column(String(200))
    software = Column(String(200))
    version = Column(String(100))
    
    # 作者信息
    author = Column(String(200))
    
    # 发布日期
    published_date = Column(DateTime)
    
    # 漏洞描述
    description = Column(Text)
    
    # 漏洞利用代码（如果能获取到）
    exploit_code = Column(Text)
    
    # 来源分类
    category = Column(String(100))  # advisory, exploit, etc.
    
    # 标签
    tags = Column(Text)
    
    # 格式信息
    format_type = Column(String(100))  # text/plain, application/x-bzip2, etc.
    file_size = Column(String(50))     # 文件大小
    sha256 = Column(String(100))       # SHA-256 哈希
    
    # 状态标记
    verified = Column(Boolean, default=False)
    
    # 时间戳
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    __table_args__ = (
        Index('idx_packetstorm_id', 'packetstorm_id'),
        Index('idx_packetstorm_cve', 'cve_ids'),
        Index('idx_packetstorm_title', 'title'),
        Index('idx_packetstorm_platform', 'platform'),
    )
