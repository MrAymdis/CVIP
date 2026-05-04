from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Subscription
from app.schemas import SubscriptionResponse, SubscriptionCreate, SubscriptionUpdate, SubscriptionTestRequest
from app.services.notification_service import NotificationService

router = APIRouter(prefix="/subscription", tags=["Subscription"])


@router.get("", response_model=SubscriptionResponse)
def get_subscription(db: Session = Depends(get_db)):
    """Get subscription configuration."""
    subscription = db.query(Subscription).first()
    if not subscription:
        # Return default configuration if none exists
        return SubscriptionResponse(
            id=0,
            wechat_webhook="",
            dingtalk_webhook="",
            email="",
            severity_threshold="high",
            enabled=False
        )
    return subscription


@router.post("", response_model=SubscriptionResponse)
def save_subscription(config: SubscriptionCreate, db: Session = Depends(get_db)):
    """Save subscription configuration."""
    subscription = db.query(Subscription).first()
    
    if subscription:
        # Update existing subscription
        for key, value in config.model_dump().items():
            setattr(subscription, key, value)
    else:
        # Create new subscription
        subscription = Subscription(**config.model_dump())
        db.add(subscription)
    
    db.commit()
    db.refresh(subscription)
    return subscription


@router.post("/test")
def test_notification(request: SubscriptionTestRequest):
    """Test notification channel."""
    config_dict = request.config.model_dump()
    
    success = NotificationService.send_test_message(request.type, config_dict)
    
    if success:
        return {"message": "Test notification sent successfully"}
    else:
        raise HTTPException(status_code=400, detail="Failed to send test notification")
