from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class SubscriptionBase(BaseModel):
    wechat_webhook: Optional[str] = None
    dingtalk_webhook: Optional[str] = None
    email: Optional[str] = None
    severity_threshold: str = "high"
    enabled: bool = False


class SubscriptionCreate(SubscriptionBase):
    pass


class SubscriptionUpdate(SubscriptionBase):
    pass


class SubscriptionResponse(SubscriptionBase):
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class SubscriptionTestRequest(BaseModel):
    type: str
    config: SubscriptionBase
