from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    role_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserWithRole(UserResponse):
    role_name: str


class Token(BaseModel):
    access_token: str
    token_type: str
    refresh_token: str
    user_id: Optional[int] = None
    username: Optional[str] = None
    role: Optional[str] = None


class TokenData(BaseModel):
    user_id: Optional[int] = None


class PasswordChange(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=6)


class Message(BaseModel):
    message: str
