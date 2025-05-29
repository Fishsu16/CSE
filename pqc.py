from pqclean.kem import kyber512
from pqclean.sign import dilithium2
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import base64
from typing import List, Dict, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import Certificate
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
import requests
from fastapi import HTTPException, UploadFile
from pydantic import BaseModel
import datetime
import os

#####################################################################################
#              Key Exchange with Kyber & Encrypt with ChaCha20                      #
#####################################################################################
def kyber_keygen():
    public_key, secret_key = kyber512.generate_keypair()
    return public_key, secret_key

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
    encapsulated_key, shared_secret = kyber512.encrypt(public_key)
    return {
        "encapsulated_key": base64.b64encode(encapsulated_key).decode(),
        "shared_secret": base64.b64encode(shared_secret).decode()
    }

# 解封裝
def kyber_decapsulate(encapsulated_key: bytes, secret_key: bytes):
    shared_secret = kyber512.decrypt(base64.b64decode(encapsulated_key), secret_key)
    return base64.b64encode(shared_secret).decode()

async def get_kyber_keys(username: str, db: AsyncSession):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Username not found")
    kyber_pk = user.kyber_pk
    kyber_sk = user.kyber_sk

    return kyber_pk, kyber_sk

async def encrypt_files_with_ChaCha20_Poly1305(files: List[UploadFile], ChaCha20_Poly_key: bytes):
    encrypted_files = []
    for file in files:
        content = await file.read()
        nonce = os.urandom(12)
        cipher = ChaCha20_Poly1305.new(key=chacha_key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        encrypted_data = nonce + ciphertext + tag

        # 加密檔案命名：原檔名 + .enc
        filename = file.filename + ".enc"

        encrypted_files.append({"filename": filename, "content": encrypted_data})

    return encrypted_files


#####################################################################################
#                            Signature with Dilithium                               #
#####################################################################################
def dilithium_keygen():
    public_key, secret_key = dilithium2.generate_keypair()
    return public_key, secret_key

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

        signature = dilithium2.sign(encrypted_data, secret_key)
        #print("Signature:", signature.hex())

        # 儲存 filename 與對應簽章 (base64 編碼可讀性更好)
        signatures.append(
            {
                "filename": filename,
                "signature": base64.b64encode(signature).decode("utf-8"),
            }
        )

    return signatures