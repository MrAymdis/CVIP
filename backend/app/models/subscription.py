from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer
from sqlalchemy.sql import func
from app.database import Base


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    
    # Notification channels
    wechat_webhook = Column(String(500), nullable=True)
    dingtalk_webhook = Column(String(500), nullable=True)
    email = Column(String(200), nullable=True)
    
    # Configuration
    severity_threshold = Column(String(20), default="high")
    enabled = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
