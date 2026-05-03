"""
组件信息模型 - 参考深信服安全平台组件信息页面
支持存储厂商、产品、组件的详细信息
"""
from sqlalchemy import Column, Integer, String, Text, JSON, DateTime, Index
from sqlalchemy.sql import func
from app.database import Base

class Component(Base):
    """组件信息模型"""
    __tablename__ = "components"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(500), nullable=False)
    name_en = Column(String(500))
    component_id = Column(String(100), unique=True, index=True)
    
    # 厂商信息
    vendor_name = Column(String(500))
    vendor_name_en = Column(String(500))
    vendor_country = Column(String(100))
    
    # 分类信息
    category = Column(String(50), index=True)
    sub_category = Column(String(100))
    
    # 产品信息
    product_name = Column(String(500))
    product_version = Column(Text)
    version_range = Column(Text)
    
    # 技术信息
    ecosystem = Column(String(200))  # npm, pypi, maven, etc.
    affected_versions = Column(JSON)
    
    # 状态信息
    recognition_support = Column(String(50), default="暂不支持识别")
    
    # 数据源
    data_source = Column(String(100))
    source_url = Column(String(500))
    
    # 关联信息
    related_vuln_ids = Column(JSON)
    
    # 描述
    description = Column(Text)
    
    # 时间戳
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    __table_args__ = (
        Index('idx_component_name', 'name'),
        Index('idx_component_vendor', 'vendor_name'),
        Index('idx_component_category', 'category'),
        Index('idx_component_product', 'product_name'),
    )

    def __repr__(self):
        return f"<Component {self.name} ({self.component_id})>"


# 组件分类定义
COMPONENT_CATEGORIES = [
    "云平台设备",
    "工控设备",
    "应用服务",
    "服务器设备",
    "互联网设备",
    "移动设备",
    "中间件",
    "操作系统",
    "数据库",
    "物联网设备",
    "开发语言",
    "开发框架",
    "网络设备",
    "内网设备",
    "网络安全设备",
    "终端设备",
    "未知"
]