from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import pyotp
import base64
import qrcode
from io import BytesIO
import hashlib
#test

import kms
from models import User, get_db
# YU modified
import pqc

router = APIRouter()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def generate_otp_secret_and_qr(username: str):
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="StarCSE")
    qr = qrcode.make(uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    qr_data_url = f"data:image/png;base64,{img_str}"
    return secret, qr_data_url


@router.post("/api/register")
async def register(data: dict, db: AsyncSession = Depends(get_db)):
    email = data.get("email")
    username = data.get("username")
    password = data.get("password")

    if not email or not username or not password:
        return JSONResponse(status_code=400, content={"message": "Missing fields"})

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = hash_password(password)
    otp_secret, qr_code_url = generate_otp_secret_and_qr(username)

    user_pk, user_sk = kms.create_user_keys(tag=f"user-key-{username}")
    # YU modified
    #kyber_pk, kyber_sk = pqc.keygen()
    kyber_pk, kyber_sk = "", ""
    dilithium_pk, dilithium_sk = "", ""
    new_user = User(
        username=username,
        email=email,
        password_hash=hashed_pw,
        otp_secret=otp_secret,
        user_sk=user_sk,
        user_pk=user_pk,
        kyber_pk=kyber_pk,
        kyber_sk=kyber_sk,
        dilithium_pk=dilithium_pk,
        dilithium_sk=dilithium_sk,
    )
    db.add(new_user)
    await db.commit()

    return {"message": "User registered successfully", "qrCodeUrl": qr_code_url}


@router.post("/api/login")
async def login(data: dict, db: AsyncSession = Depends(get_db)):
    username = data.get("username")
    password = data.get("password")
    otp = data.get("otp")

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if hash_password(password) != user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    totp = pyotp.TOTP(user.otp_secret)
    if not totp.verify(otp):
        raise HTTPException(status_code=401, detail="Invalid OTP code")

    return {"message": "Login successful"}


@router.get("/api/users")
async def search_users(
    q: Optional[str] = Query(None), db: AsyncSession = Depends(get_db)
):
    stmt = select(User)
    if q:
        stmt = stmt.where(User.username.ilike(f"%{q}%"))
    result = await db.execute(stmt)
    users = result.scalars().all()
    return [user.username for user in users]
