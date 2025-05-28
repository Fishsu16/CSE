from typing import List, Dict, Optional
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.base import Certificate
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
import requests
from fastapi import HTTPException
from pydantic import BaseModel
import datetime
#################################################

#################################################
#from fastapi import APIRouter, Depends, HTTPException, Query
#from fastapi.responses import JSONResponse
#from sqlalchemy.ext.asyncio import AsyncSession
#from sqlalchemy import select
#from typing import List
#import shutil
#import os
#import pyotp
#import base64
#import qrcode
#from io import BytesIO
#import hashlib

#import kms
#from models import User, get_db
#from auth import router as auth_router

api_url = "https://certificate-ed4n.onrender.com/api/issue"


def gencsr(user_sk) -> List[Dict[str, bytes]]:
    private_key = load_der_private_key(user_sk, password=None, backend=default_backend())
    # === 1. 建立 CSR ===
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TW"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Hsinchu"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"East"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NYCU"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Oasis_Star"),
    ])).sign(private_key, hashes.SHA256(), backend=default_backend())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # === 2. 發送 CSR 給 CA Server ===
    #api_url = "https://certificate-ed4n.onrender.com/api/issue"

    response = requests.post(
        api_url,
        files={"file": ("csr.pem", csr_pem, "application/x-pem-file")},
    )

    # === 3. 處理回應 ===
    certificate_files = []
    if response.status_code == 200:
        filename = "certificate.pem"
        content = response.content
        certificate_files = {"filename": filename, "content": content}
        print("✅ 憑證已簽發並儲存為 certificate.pem")
        #certificate_files.append({
        #    "filename": filename,
        #    "content": content
        #})
    else:
        raise HTTPException(status_code=response.status_code, detail=response.content.decode('utf-8'))

    return [certificate_files]

class CertVerifyRequest(BaseModel):
    client_cert_pem: str  # 使用者憑證 PEM 字串

def load_cert_from_pem(pem_data: str) -> Certificate:
    return x509.load_pem_x509_certificate(pem_data.encode(), default_backend())

def load_cert_from_url(url: str) -> Certificate:
    response = requests.get(url)
    response.raise_for_status()
    return x509.load_pem_x509_certificate(response.content, default_backend())

def verify_certificate_chain(cert: Certificate, issuer: Certificate):
    issuer_public_key = issuer.public_key()
    issuer_public_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )

#@auth_router.post("/verify-cert")
#def verify_cert(data: CertVerifyRequest):
def verify_cert(client_cert):
    try:
        # 載入使用者憑證
        #client_cert = load_cert_from_pem(data.client_cert_pem)

        # 從 CA server 下載 intermediate cert
        intermediate_cert = load_cert_from_url("https://certificate-ed4n.onrender.com/api/intermediate_cert")

        # 載入 Root CA cert（本地信任）
        root_cert = load_cert_from_pem(open("ca/root/root.cert.pem", "r").read())

        # 驗證 client cert 是否由 intermediate 簽發
        verify_certificate_chain(client_cert, intermediate_cert)

        # 驗證 intermediate cert 是否由 root 簽發
        verify_certificate_chain(intermediate_cert, root_cert)

        # 驗證時間是否有效
        now = datetime.datetime.utcnow()
        if not (client_cert.not_valid_before <= now <= client_cert.not_valid_after):
            raise HTTPException(status_code=400, detail="Client certificate is not valid at this time")

        # 取得 public key 並轉為 PEM 格式字串
        public_key = client_cert.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    except requests.HTTPError:
        raise HTTPException(status_code=502, detail="Failed to download intermediate certificate from CA server")
    except x509.ExtensionNotFound as e:
        raise HTTPException(status_code=400, detail=f"Certificate extension error: {e}")
    except Exception as e:
        # 包含 InvalidSignature、ValueError、時間錯誤等
        raise HTTPException(status_code=400, detail=f"Certificate verification failed: {str(e)}")
    

    return {"status": "success",
            "message": "Certificate is valid and trusted.",
            "public_key": public_key_pem}