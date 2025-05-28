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

from models import Base, engine
from auth import router as auth_router


import kms
from models import User, get_db
import certificate

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


def extract_user_keys(user_key_id: str) -> bytes:
    with open(f"user_keys/user_sk/{user_key_id}.json", "r") as f:
        user_sk_json = json.load(f)

    try:
        key_material = None
        for item in user_sk_json["value"]:
            for subitem in item["value"]:
                if subitem["tag"] == "KeyValue":
                    for kv in subitem["value"]:
                        if kv["tag"] == "KeyMaterial":
                            key_material = kv["value"]
                            break

        if key_material:
            user_sk = bytes.fromhex(key_material)
    except:
        return None

    with open(f"user_keys/user_pk/{user_key_id}_pk.json", "r") as f:
        user_pk_json = json.load(f)

    try:
        key_material = None
        for item in user_pk_json["value"]:
            for subitem in item["value"]:
                if subitem["tag"] == "KeyValue":
                    for kv in subitem["value"]:
                        if kv["tag"] == "KeyMaterial":
                            key_material = kv["value"]
                            break

        if key_material:
            user_pk = bytes.fromhex(key_material)
    except:
        return None

    return user_pk, user_sk


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


@app.post("/api/encrypt")
async def encrypt_files(
    username: str = Form(...),
    recipients: str = Form(...),  # JSON 字串形式的使用者名稱清單
    files: List[UploadFile] = File(...),
    db: AsyncSession = Depends(get_db),
):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    recipient_list = json.loads(recipients)
    all_recipients = [username] + recipient_list  # 包含自己

    # 1. 產生 AES 金鑰
    AES_key: bytes = kms.generate_AES_key()

    # 2. 加密檔案
    encrypted_files: List[dict] = await encrypt_files_with_AES(
        files=files, AES_key=AES_key
    )
    # dict 結構: {"filename": "file.txt", "content": b"...encrypted..."}

    # YU modified
    # 3. 取得簽名用的金鑰與產生cert
    user_pk, user_sk = await get_user_keys(username=username, db=db)
    signatures: List[dict] = sign_encrypted_files(
        user_sk=user_sk, encrypted_files=encrypted_files
    )
    #user_pk_pem = serialization.load_der_public_key(
    #    user_pk, backend=default_backend()
    #).public_bytes(
    #    encoding=serialization.Encoding.PEM,
    #    format=serialization.PublicFormat.SubjectPublicKeyInfo,
    #)
    try:
        cert = certificate.gencsr(user_sk)
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
            recipient_pk, _ = await get_user_keys(username=recipient, db=db)
            enc_AES_key = encrypt_AES_key(AES_key, recipient_pk)

            # 建立該 recipient 的子 ZIP
            sub_zip_buffer = BytesIO()
            with zipfile.ZipFile(sub_zip_buffer, "w", zipfile.ZIP_DEFLATED) as sub_zip:
                for file in encrypted_files:
                    sub_zip.writestr(file["filename"], file["content"])

                sub_zip.writestr("signatures.json", json.dumps(signatures, indent=2))
                sub_zip.writestr(f"{recipient}.key.enc", enc_AES_key)
                # YU modified
                #sub_zip.writestr("verify.key", user_pk_pem)
                sub_zip.writestr(cert[0]["filename"], cert[0]["content"])

            sub_zip_buffer.seek(0)
            outer_zip.writestr(f"{recipient}.zip", sub_zip_buffer.read())

    outer_zip_buffer.seek(0)
    return StreamingResponse(
        outer_zip_buffer,
        media_type="application/x-zip-compressed",
        headers={"Content-Disposition": f"attachment; filename=encrypted_packages.zip"},
    )


@app.post("/api/decrypt")
async def decrypt_files(
    username: str = Form(...),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded")

    # 1. 從 DB 取該使用者的私鑰（用來解密 AES key）
    user_pk_bytes, user_sk_bytes = await get_user_keys(username, db)
    private_key = serialization.load_der_private_key(
        user_sk_bytes, password=None, backend=default_backend()
    )

    # 2. 讀取上傳的 zip 檔
    file_bytes = await file.read()
    zip_buffer = BytesIO(file_bytes)

    decrypted_files = []
    signatures = None
    AES_key = None

    with zipfile.ZipFile(zip_buffer, "r") as zip_file:
        namelist = zip_file.namelist()

        # YU modified
        # 檢驗憑證與抽取sender public key
        if "certificate.pem" not in namelist:
            raise HTTPException(status_code=400, detail="certificate遺失")
        cert = zip_file.read("certificate.pem")
        cert_obj = x509.load_pem_x509_certificate(cert, default_backend())
        try:
            verify_status = certificate.verify_cert(cert_obj)
            if verify_status["status"] != "success":
                raise HTTPException(status_code=400, detail="Certificate驗證失敗")
            else:
                public_key_pem = verify_status["public_key"]
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Verify failed: {e}")
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem, backend=default_backend()
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Load sender public key failed: {e}")

        # 讀 verify.key (PEM 格式公鑰)
        #if "verify.key" not in namelist:
        #    raise HTTPException(status_code=400, detail="verify.key遺失")
#
        #verify_key_pem = zip_file.read("verify.key")
        #try:
        #    public_key = serialization.load_pem_public_key(
        #        verify_key_pem, backend=default_backend()
        #    )
        #except Exception as e:
        #    raise HTTPException(status_code=400, detail=f"Load verify.key failed: {e}")

        # 找出 aes_key 檔
        aes_key_name = f"{username}.key.enc"
        if aes_key_name not in namelist:
            raise HTTPException(
                status_code=400, detail=f"{username}.key.enc 加密過屬於您的解密鑰遺失"
            )

        aes_key_enc = zip_file.read(aes_key_name)

        # 解密 AES key
        try:
            AES_key = private_key.decrypt(
                aes_key_enc,
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

        # 讀簽章 JSON
        if "signatures.json" not in namelist:
            raise HTTPException(status_code=400, detail="簽名 signatures.json 遺失")

        signatures_json = zip_file.read("signatures.json")
        signatures = json.loads(signatures_json)

        # 依序驗簽並解密各個加密檔案
        for file_info in signatures:
            enc_filename = file_info["filename"]
            signature_b64 = file_info["signature"]

            if enc_filename not in namelist:
                raise HTTPException(
                    status_code=400, detail=f"加密檔 {enc_filename} 遺失"
                )

            enc_content = zip_file.read(enc_filename)
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
                    detail=f"Signature verification失敗， {enc_filename} 可能遭到竄改",
                )

            # AES-GCM 解密 (nonce 為前 12 bytes)
            nonce = enc_content[:12]
            ciphertext = enc_content[12:]
            aesgcm = AESGCM(AES_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

            # 移除 .enc 副檔名回復原始檔名
            orig_filename = (
                enc_filename[:-4] if enc_filename.endswith(".enc") else enc_filename
            )

            decrypted_files.append({"filename": orig_filename, "content": plaintext})

    # 回傳一個 zip 包含所有解密檔案
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
