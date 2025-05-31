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
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from models import Base, engine
from auth import router as auth_router

import kms
from models import User, get_db
import certificate
import pqc
import AES_RSA

#################################################
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

#################################################

# FastAPI app init
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# File paths
BASE_UPLOAD_FOLDER = "uploads"
ENCRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "encrypt")
DECRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "decrypt")
os.makedirs(ENCRYPT_FOLDER, exist_ok=True)
os.makedirs(DECRYPT_FOLDER, exist_ok=True)

# Register auth router
app.include_router(auth_router)


# Create tables
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

# YU modified
async def aes_encrypt_files(
    username: str,
    recipients: str,  # JSON 字串形式的使用者名稱清單
    files: List[UploadFile],
    db: AsyncSession,
):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    recipient_list = json.loads(recipients)
    all_recipients = [username] + recipient_list  # 包含自己

    # 1. 產生 AES 金鑰
    AES_key: bytes = kms.generate_AES_key()

    # 2. 加密檔案
    encrypted_files: List[dict] = await AES_RSA.encrypt_files_with_AES(
        files=files, AES_key=AES_key
    )
    # dict 結構: {"filename": "file.txt", "content": b"...encrypted..."}

    # 3. 取得簽名用的金鑰與產生cert
    user_pk, user_sk = await AES_RSA.get_user_keys(username=username, db=db)
    signatures: List[dict] = AES_RSA.sign_encrypted_files(
        user_sk=user_sk, encrypted_files=encrypted_files
    )
    try:
        cert = certificate.gencsr(user_sk, user_pk, b"RSA")
    except Exception as e:
        import traceback
        print("[/api/encrypt] Encryption failed:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))


    # dict 結構: {"filename": ..., "signature": ...}

    # 4. 為每位共享者建立一份獨立的 ZIP 包（含專屬的 AES key 加密）
    outer_zip_buffer = BytesIO()
    with zipfile.ZipFile(outer_zip_buffer, "w", zipfile.ZIP_DEFLATED) as outer_zip:
        for recipient in all_recipients:
            recipient_pk, _ = await AES_RSA.get_user_keys(username=recipient, db=db)
            enc_AES_key = AES_RSA.encrypt_AES_key(AES_key, recipient_pk)

            # 建立該 recipient 的子 ZIP
            sub_zip_buffer = BytesIO()
            with zipfile.ZipFile(sub_zip_buffer, "w", zipfile.ZIP_DEFLATED) as sub_zip:
                for file in encrypted_files:
                    sub_zip.writestr(file["filename"], file["content"])

                sub_zip.writestr("signatures.json", json.dumps(signatures, indent=2))
                sub_zip.writestr(f"{recipient}.key.enc", enc_AES_key)
                sub_zip.writestr(cert[0]["filename"], cert[0]["content"])

            sub_zip_buffer.seek(0)
            outer_zip.writestr(f"{recipient}.zip", sub_zip_buffer.read())

    outer_zip_buffer.seek(0)
    return StreamingResponse(
        outer_zip_buffer,
        media_type="application/x-zip-compressed",
        headers={"Content-Disposition": f"attachment; filename=encrypted_packages.zip"},
    )


async def aes_decrypt_files(
    username: str,
    files: dict[str, bytes],
    db: AsyncSession,
    public_key,
):
    # 1. 取得使用者私鑰
    user_pk_bytes, user_sk_bytes = await AES_RSA.get_user_keys(username, db)
    private_key = serialization.load_der_private_key(
        user_sk_bytes, password=None, backend=default_backend()
    )

    # 2. 解密 AES 金鑰
    aes_key_name = f"{username}.key.enc"
    if aes_key_name not in files:
        raise HTTPException(
            status_code=400,
            detail=f"{username}.key.enc 加密過屬於您的解密鑰遺失"
        )

    try:
        AES_key = private_key.decrypt(
            files[aes_key_name],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"無法解密 AES 金鑰：{str(e)}，可能金鑰錯誤或您沒有權限瀏覽",
        )

    # 3. 解析簽章 JSON
    if "signatures.json" not in files:
        raise HTTPException(status_code=400, detail="簽名 signatures.json 遺失")

    signatures = json.loads(files["signatures.json"])

    # 4. 驗簽 + 解密每個檔案
    decrypted_files = []

    for file_info in signatures:
        enc_filename = file_info["filename"]
        signature_b64 = file_info["signature"]

        if enc_filename not in files:
            raise HTTPException(
                status_code=400, detail=f"加密檔 {enc_filename} 遺失"
            )

        enc_content = files[enc_filename]
        signature = base64.b64decode(signature_b64)

        # 驗簽
        try:
            public_key.verify(
                signature,
                enc_content,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception:
            raise HTTPException(
                status_code=400,
                detail=f"Signature verification失敗，{enc_filename} 可能遭到竄改",
            )

        # AES-GCM 解密
        nonce = enc_content[:12]
        ciphertext = enc_content[12:]
        aesgcm = AESGCM(AES_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

        orig_filename = (
            enc_filename[:-4] if enc_filename.endswith(".enc") else enc_filename
        )
        decrypted_files.append({"filename": orig_filename, "content": plaintext})

    # 5. 封裝回 zip
    output_zip_buffer = BytesIO()
    with zipfile.ZipFile(output_zip_buffer, "w", zipfile.ZIP_DEFLATED) as out_zip:
        for f in decrypted_files:
            out_zip.writestr(f["filename"], f["content"])
    output_zip_buffer.seek(0)

    return StreamingResponse(output_zip_buffer, media_type="application/zip")


async def pqc_encrypt_files(
    username: str,
    recipients: str,  # JSON 字串形式的使用者名稱清單
    files: List[UploadFile],
    db: AsyncSession,
):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    recipient_list = json.loads(recipients)
    all_recipients = [username] + recipient_list  # 包含自己

    # 1. 取得簽名用的金鑰、產生cert的金鑰與產生cert
    dili_pk, dili_sk = await pqc.get_dilithium_keys(username=username, db=db)
    _, rsa_sk = await AES_RSA.get_user_keys(username=username, db=db)
    cert = certificate.gencsr(rsa_sk, dili_pk, b"Dilithium")

    # 2. 為每位共享者建立一份獨立的 ZIP 包並加密（含專屬的 AES key 加密）
    outer_zip_buffer = BytesIO()
    with zipfile.ZipFile(outer_zip_buffer, "w", zipfile.ZIP_DEFLATED) as outer_zip:
        for recipient in all_recipients:
            recipient_pk, _ = await pqc.get_kyber_keys(username=recipient, db=db)
            sub_zip_buffer = BytesIO()
            with zipfile.ZipFile(sub_zip_buffer, "w", zipfile.ZIP_DEFLATED) as sub_zip:
                # 2.1 生成 AES_KEY 並加密 AES_KEY
                kem_results = pqc.kyber_kem(recipient_pk)
                ChaCha_key: bytes = kem_results["shared_secret"]
                enc_ChaCha_key: bytes = kem_results["encapsulated_key"]
                # 2.2 加密檔案
                encrypted_files: List[dict] = await pqc.encrypt_files_with_ChaCha20_Poly1305(
                    files, ChaCha_key
                )
                # 2.3 產生加密檔案簽章
                #recipient_dili_pk, _ = await pqc.get_dilithium_keys(username=username, db=db)
                signatures: List[dict] = pqc.dilithium_sign_encrypted_files(
                    user_sk=dili_sk, encrypted_files=encrypted_files
                )

                # 2.4 建立該recipient的子 ZIP
                for file in encrypted_files:
                    sub_zip.writestr(file["filename"], file["content"])
                sub_zip.writestr("signatures.json", json.dumps(signatures, indent=2))
                sub_zip.writestr(f"{recipient}.key.enc", enc_ChaCha_key)
                sub_zip.writestr(cert[0]["filename"], cert[0]["content"])

            sub_zip_buffer.seek(0)
            outer_zip.writestr(f"{recipient}.zip", sub_zip_buffer.read())

    outer_zip_buffer.seek(0)
    return StreamingResponse(
        outer_zip_buffer,
        media_type="application/x-zip-compressed",
        headers={"Content-Disposition": f"attachment; filename=encrypted_packages.zip"},
    )


async def pqc_decrypt_files(
    username: str,
    files: dict[str, bytes],
    db: AsyncSession,
    public_key,
):
    # 1. 從 DB 取得使用者 Kyber 私鑰
    kyber_pk, kyber_sk = await pqc.get_kyber_keys(username, db)

    # 2. 解密 ChaCha 金鑰
    chacha_key_name = f"{username}.key.enc"
    if chacha_key_name not in files:
        raise HTTPException(
            status_code=400,
            detail=f"{username}.key.enc 加密過屬於您的解密鑰遺失"
        )

    chacha_key_enc = files[chacha_key_name]
    try:
        chacha_key = pqc.kyber_decapsulate(chacha_key_enc, kyber_sk)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"無法解密 ChaCha 金鑰：{str(e)}，可能金鑰錯誤或您沒有權限瀏覽",
        )

    # 3. 解析簽章
    if "signatures.json" not in files:
        raise HTTPException(status_code=400, detail="簽名 signatures.json 遺失")

    signatures = json.loads(files["signatures.json"])

    decrypted_files = []

    # 4. 驗簽並解密
    for file_info in signatures:
        enc_filename = file_info["filename"]
        signature_b64 = file_info["signature"]

        if enc_filename not in files:
            raise HTTPException(
                status_code=400, detail=f"加密檔 {enc_filename} 遺失"
            )

        enc_content = files[enc_filename]
        signature = base64.b64decode(signature_b64)

        # 驗簽
        is_valid = pqc.dilithium_sign_verify(enc_content, public_key, signature)
        if not is_valid:
            raise HTTPException(
                status_code=400,
                detail=f"Signature verification失敗，{enc_filename} 可能遭到竄改",
            )

        # ChaCha20 解密 (前 12 bytes 為 nonce)
        nonce = enc_content[:12]
        ciphertext = enc_content[12:]
        chacha = ChaCha20Poly1305(chacha_key)
        plaintext = chacha.decrypt(nonce, ciphertext, associated_data=None)

        # 移除 .enc 副檔名
        orig_filename = (
            enc_filename[:-4] if enc_filename.endswith(".enc") else enc_filename
        )

        decrypted_files.append({"filename": orig_filename, "content": plaintext})

    # 5. 封裝回 zip
    output_zip_buffer = BytesIO()
    with zipfile.ZipFile(output_zip_buffer, "w", zipfile.ZIP_DEFLATED) as out_zip:
        for f in decrypted_files:
            out_zip.writestr(f["filename"], f["content"])
    output_zip_buffer.seek(0)

    return StreamingResponse(
        output_zip_buffer,
        media_type="application/x-zip-compressed",
        headers={"Content-Disposition": f"attachment; filename=decrypted_files.zip"},
    )

@app.post("/api/encrypt")
async def encrypt_files(
    username: str = Form(...),
    recipients: str = Form(...),  # JSON 字串形式的使用者名稱清單
    algorithm: str = Form(...),
    files: List[UploadFile] = File(...),
    db: AsyncSession = Depends(get_db),
):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")
    
    if algorithm == "AES":
        encrypt_zip = await aes_encrypt_files(username, recipients, files, db)
    else:
        encrypt_zip = await pqc_encrypt_files(username, recipients, files, db)
    
    return encrypt_zip


@app.post("/api/decrypt")
async def decrypt_files(
    username: str = Form(...),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    if not file:
        raise HTTPException(status_code=400, detail="No files uploaded")
    
    # 1. 從 DB 取該使用者的私鑰（用來解密 AES key）
    kyber_pk, kyber_sk = await pqc.get_kyber_keys(username, db)

    # 2. 讀取上傳的 zip 檔
    file_bytes = await file.read()
    zip_buffer = BytesIO(file_bytes)

    # 3. 解壓縮
    with zipfile.ZipFile(zip_buffer, "r") as zip_file:
        namelist = zip_file.namelist()

        # 3.1 檢驗憑證與抽取sender public key
        if "certificate.pem" not in namelist:
            raise HTTPException(status_code=400, detail="certificate遺失")
        cert = zip_file.read("certificate.pem")
        cert_obj = x509.load_pem_x509_certificate(cert, default_backend())
        try:
            verify_status = certificate.verify_cert(cert_obj)
            if verify_status["status"] != "success":
                raise HTTPException(status_code=400, detail="Certificate驗證失敗")
            else:
                sender_pk = verify_status["public_key"]
                encrypt_algorithm = verify_status["sign_tag"]
                
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Verify failed: {e}")

        # 把解壓後的內容轉成 dict
        files_content = {
            name: zip_file.read(name)
            for name in namelist
            if name != "certificate.pem"
        }
        
        # 3.2 依據演算法解密
        if encrypt_algorithm == "RSA":
            decrypt_zip = await aes_decrypt_files(username, files_content, db, sender_pk)
        else:
            decrypt_zip = await pqc_decrypt_files(username, files_content, db, sender_pk)

        return decrypt_zip