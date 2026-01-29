from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from pydantic import EmailStr, ValidationError
from sqlalchemy import select, delete, and_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import BaseSecurityError, TokenExpiredError, InvalidTokenError
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema
)
from security.interfaces import JWTAuthManagerInterface


router = APIRouter()


# Write your code here
async def get_or_create_user_group(db: AsyncSession) -> UserGroupModel:
    result = await db.execute(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    user_group = result.scalar_one_or_none()
    if not user_group:
        user_group = UserGroupModel(name=UserGroupEnum.USER)
        db.add(user_group)
        await db.flush()
        await db.commit()
        await db.refresh(user_group)
    return user_group


async def get_user_by_email(email: EmailStr, db: AsyncSession) -> UserModel:
    result = await db.execute(select(UserModel).where(UserModel.email == email))
    new_user = result.scalar_one_or_none()
    return new_user


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def register_account(
        user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db),
):
    new_user = await get_user_by_email(email=user.email, db=db)

    if new_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists."
        )

    try:
        user_group = await get_or_create_user_group(db=db)
        db_user = UserModel(
            email=user.email,
            group=user_group
        )

        db_user.password = user.password

        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)

        db_user.activation_token = ActivationTokenModel(user_id=cast(int, db_user.id))
        db.add(db_user.activation_token)
        await db.commit()
        await db.refresh(db_user.activation_token)
        return db_user

    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    except Exception:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred during user creation."
        )


@router.post("/activate/", status_code=200)
async def activate_account(
        user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    user_record = await get_user_by_email(email=user.email, db=db)

    if not user_record:
        raise HTTPException(status_code=404, detail="User not found.")

    result = await db.execute(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == cast(int, user_record.id),
            ActivationTokenModel.token == user.token))
    token_record = result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    token_record.expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
    if token_record.expires_at < datetime.now(timezone.utc):

        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if token_record.token == user.token:
        if user_record.is_active:
            raise HTTPException(status_code=400, detail="User account is already active.")
        else:
            user_record.is_active = True
            await db.commit()
            await db.refresh(user_record)

            await db.delete(token_record)
            await db.commit()

            return {"message": "User account activated successfully."}
    else:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")


@router.post("/password-reset/request/", status_code=200)
async def request_password_reset(user: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    user_record = await get_user_by_email(email=user.email, db=db)
    if user_record:
        if user_record.is_active:
            result = await db.execute(
                select(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == cast(int, user_record.id)))
            token_record = result.scalar_one_or_none()
            if token_record:
                await db.delete(token_record)
            new_token = PasswordResetTokenModel(user_id=cast(int, user_record.id))
            db.add(new_token)
            await db.commit()
            await db.refresh(new_token)

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", status_code=200)
async def reset_password_complete(
        user_data: PasswordResetCompleteRequestSchema,
        db: AsyncSession = Depends(get_db)
):
    user = await get_user_by_email(email=user_data.email, db=db)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    result = await db.execute(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == cast(int, user.id)))
    token_record = result.scalar_one_or_none()
    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    else:
        token_record.expires_at = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)
        if token_record.expires_at < datetime.now(timezone.utc):
            await db.delete(token_record)
            await db.commit()
            raise HTTPException(status_code=400, detail="Invalid email or token.")
        else:
            if token_record.token == user_data.token:
                try:
                    user.password = user_data.password
                    await db.delete(token_record)
                    await db.commit()
                    return {"message": "Password reset successfully."}
                except Exception:
                    await db.rollback()
                    raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")
            else:
                await db.delete(token_record)
                await db.commit()
                raise HTTPException(status_code=400, detail="Invalid email or token.")


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login_user(
        user_data: UserLoginRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    user = await get_user_by_email(email=user_data.email, db=db)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    else:
        if user.verify_password(user_data.password):
            if user.is_active:
                try:
                    access_token = jwt_manager.create_access_token({"user_id": user.id})
                    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})
                    result = UserLoginResponseSchema(
                        access_token=access_token,
                        refresh_token=refresh_token,
                        token_type="bearer",
                    )
                    refresh_token_record = RefreshTokenModel.create(
                        user_id=cast(int, user.id),
                        token=refresh_token,
                        days_valid=10
                    )
                    db.add(refresh_token_record)
                    await db.commit()
                    await db.refresh(refresh_token_record)
                    return result
                except Exception:
                    await db.rollback()
                    raise HTTPException(status_code=500, detail="An error occurred while processing the request.")
            else:
                raise HTTPException(status_code=403, detail="User account is not activated.")

        else:
            raise HTTPException(status_code=401, detail="Invalid email or password.")


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_token(
        user_data: TokenRefreshRequestSchema,
        db: AsyncSession = Depends(get_db),
        jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_refresh_token(user_data.refresh_token)
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(status_code=400, detail="Token has expired.")

    uid = cast(int, payload["user_id"])

    result = await db.execute(select(RefreshTokenModel).where(
        and_(
            RefreshTokenModel.user_id == uid,
            RefreshTokenModel.token == user_data.refresh_token
        )
    ))
    token_record = result.scalar_one_or_none()
    if not token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    result = await db.execute(select(UserModel).where(UserModel.id == uid))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = jwt_manager.create_access_token({"user_id": uid})
    result = TokenRefreshResponseSchema(
        access_token=new_access_token
    )
    return result
