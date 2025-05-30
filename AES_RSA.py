import base64
from io import BytesIO
import json
import zipfile
from fastapi import FastAPI, Form, Request, UploadFile, File, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from typing import List
import shutil
import os
from sqlalchemy import Tuple, select
from sqlalchemy.ext.asyncio import AsyncSession
from cryptography import x509
from cryptography.hazmat.backends import default_backend

#from models import Base, engine
#from auth import router as auth_router

#import kms
from models import User, get_db
#import certificat

#################################################
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#################################################
async def get_user_keys(username: str, db: AsyncSession):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Username not found")
    user_pk = bytes.fromhex(user.user_pk)
    user_sk = bytes.fromhex(user.user_sk)

    return user_pk, user_sk


async def encrypt_files_with_AES(files: List[UploadFile], AES_key: bytes):
    encrypted_files = []
    for file in files:
        content = await file.read()

        # AES-GCM 加密
        nonce = os.urandom(12)
        aesgcm = AESGCM(AES_key)
        encrypted = aesgcm.encrypt(nonce, content, associated_data=None)
        encrypted_data = nonce + encrypted

        # 加密檔案命名：原檔名 + .enc
        filename = file.filename + ".enc"

        encrypted_files.append({"filename": filename, "content": encrypted_data})

    return encrypted_files


def sign_encrypted_files(
    user_sk: bytes,
    encrypted_files: list,
) -> list:
    private_key = load_der_private_key(user_sk, password=None)

    signatures = []

    for file in encrypted_files:
        encrypted_data = file["content"]
        filename = file["filename"]

        signature = private_key.sign(
            encrypted_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        # 儲存 filename 與對應簽章 (base64 編碼可讀性更好)
        signatures.append(
            {
                "filename": filename,
                "signature": base64.b64encode(signature).decode("utf-8"),
            }
        )

    return signatures


def encrypt_AES_key(AES_key: bytes, user_pk: bytes) -> bytes:
    public_key = serialization.load_der_public_key(user_pk, backend=default_backend())

    AES_key_enc = public_key.encrypt(
        AES_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return AES_key_enc
