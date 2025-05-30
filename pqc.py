from dilithium_py.ml_dsa import ML_DSA_44 as dilithium
from kyber_py.ml_kem import ML_KEM_512 as kyber
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import base64
from typing import List, Dict, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import Tuple, select
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import Certificate
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
import requests
from fastapi import FastAPI, Form, Request, UploadFile, File, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import datetime
import os

from io import BytesIO
import json
import zipfile
import shutil

from models import Base, engine

import kms
from models import User, get_db
import certificate

#####################################################################################
#              Key Exchange with Kyber & Encrypt with ChaCha20                      #
#####################################################################################
# 封裝
def kyber_keygen():
    kyber_pk, kyber_sk = kyber.keygen()
    return kyber_pk.hex(), kyber_sk.hex()

async def get_kyber_keys(username: str, db: AsyncSession):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Username not found")
    kyber_pk = user.kyber_pk
    kyber_sk = user.kyber_sk

    return kyber_pk, kyber_sk

# 🔒 用 Kyber 加密資料（封裝 symmetric key，並用 AES-GCM 加密資料）
def kyber_kem(public_key: bytes):
    shared_secret, encapsulated_key = kyber.encaps(public_key)
    print(type(shared_secret), type(encapsulated_key))
    return {
        "encapsulated_key": encapsulated_key.hex(), #base64.b64encode(encapsulated_key).decode("utf-8"),
        "shared_secret": shared_secret #base64.b64encode(shared_secret).decode("utf-8")
    }

# 解封裝
def kyber_decapsulate(encapsulated_key: bytes, secret_key: bytes):
    shared_secret = kyber.decaps(secret_key, encapsulated_key)
    return shared_secret

async def encrypt_files_with_ChaCha20_Poly1305(files: List[UploadFile], ChaCha20_Poly_key: bytes):
    encrypted_files = []
    for file in files:
        content = await file.read()
        nonce = os.urandom(12)
        cipher = ChaCha20_Poly1305.new(key=ChaCha20_Poly_key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(content)
        encrypted_data = nonce + ciphertext + tag

        # 加密檔案命名：原檔名 + .enc
        filename = file.filename + ".enc"

        encrypted_files.append({"filename": filename, "content": encrypted_data})

    return encrypted_files


#####################################################################################
#                            Signature with Dilithium                               #
#####################################################################################
def dilithium_keygen():
    public_key, secret_key = dilithium.keygen()
    return public_key.hex(), secret_key.hex()

async def get_dilithium_keys(username: str, db: AsyncSession):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Username not found")
    dilithium_pk = user.dilithium_pk
    dilithium_sk = user.dilithium_sk

    return dilithium_pk, dilithium_sk

def dilithium_sign_encrypted_files(
    user_sk: bytes,
    encrypted_files: list,
) -> list:
    signatures = []

    for file in encrypted_files:
        encrypted_data = file["content"]
        filename = file["filename"]

        signature = dilithium.sign(user_sk, encrypted_data)
        #print(type(signature))
        #print("Signature:", signature.hex())

        # 儲存 filename 與對應簽章 (base64 編碼可讀性更好)
        signatures.append(
            {
                "filename": filename,
                "signature": base64.b64encode(signature).decode("utf-8"),
            }
        )

    return signatures

def dilithium_sign_verify(msg: bytes, user_pk: bytes, sign: bytes):
    is_valid = dilithium.verify(user_pk, msg, sign)
    return is_valid