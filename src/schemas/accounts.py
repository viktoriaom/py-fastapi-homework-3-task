from datetime import datetime

from pydantic import BaseModel, EmailStr, field_validator, Field, ConfigDict

from database import accounts_validators, UserGroupModel


# Write your code here
class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    email: EmailStr = Field(..., max_length=255)
    password: str = Field(..., max_length=255)


class UserRegistrationResponseSchema(UserBase):
    id: int

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(UserBase):
    email: EmailStr = Field(...)
    token: str = Field(...)


class PasswordResetRequestSchema(UserBase):
    email: EmailStr = Field(...)

    model_config = ConfigDict(from_attributes=True)


class PasswordResetCompleteRequestSchema(UserBase):
    email: EmailStr = Field(...)
    token: str = Field(...)
    password: str = Field(...)

    model_config = ConfigDict(from_attributes=True)


class UserLoginRequestSchema(UserBase):
    email: EmailStr = Field(...)
    password: str = Field(...)

    model_config = ConfigDict(from_attributes=True)


class UserLoginResponseSchema(BaseModel):
    access_token: str = Field(...)
    refresh_token: str = Field(...)
    token_type: str = Field(...)

    model_config = ConfigDict(from_attributes=True)


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str = Field(...)

    model_config = ConfigDict(from_attributes=True)


class TokenRefreshResponseSchema(BaseModel):
    access_token: str = Field(...)

    model_config = ConfigDict(from_attributes=True)
