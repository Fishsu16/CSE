from typing import List, Dict, Optional
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import Certificate
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
import requests
from fastapi import HTTPException
from pydantic import BaseModel
import datetime
import base64

api_url = "https://certificate-ed4n.onrender.com/api/issue"



#####################################################################################
#                                   RSA Certificate                                 #
#####################################################################################
# 自訂 OID（須符合規範，可從企業 OID 範圍或測試 OID 開始）
OID_SIGN_TAG = ObjectIdentifier("1.3.6.1.4.1.55555.1.1")  # 企業 OID 下的自定欄位
OID_KEY_TAG = ObjectIdentifier("1.3.6.1.4.1.55555.1.2")

def gencsr(user_sk, user_pk, tag) -> List[Dict[str, bytes]]:

    private_key = load_der_private_key(user_sk, password=None, backend=default_backend())
    # === 1. 建立 CSR ===
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TW"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Hsinchu"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"East"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NYCU"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Oasis_Star"),
    ])

    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    # 加入自訂 Extended Info
    encoded_pk = base64.b64encode(user_pk)
    builder = builder.add_extension(x509.UnrecognizedExtension(OID_KEY_TAG, encoded_pk), critical=False)
    builder = builder.add_extension(x509.UnrecognizedExtension(OID_SIGN_TAG, b"RSA"), critical=False)
    #builder = builder.add_extension(x509.UnrecognizedExtension(OID_SIGN_TAG, tag), critical=False)

    csr = builder.sign(private_key, hashes.SHA256(), backend=default_backend())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # === 2. 發送 CSR 給 CA Server ===
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

def verify_cert(client_cert):
    #try:
        #if isinstance(b"RSA", x509.UnrecognizedExtension):
    try:
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
        #public_key = client_cert.public_key()
        #public_key_pem = public_key.public_bytes(
        #    encoding=serialization.Encoding.PEM,
        #    format=serialization.PublicFormat.SubjectPublicKeyInfo
        #)
        try:
            ext = client_cert.extensions.get_extension_for_oid(OID_SIGN_TAG)
            sign_tag = ext.value.value.decode("utf-8", errors="ignore")#value = ext.value.value  # bytes
            #print("🔖 Extended Info (raw bytes):", value)
            #print("📝 Extended Info (decoded):", value.decode("utf-8", errors="ignore"))
            ext = client_cert.extensions.get_extension_for_oid(OID_KEY_TAG)
            public_key_encoded = ext.value.value
            public_key = base64.b64decode(public_key_encoded)
            #print("🔖 Extended Info (raw bytes):", value)
            #print("📝 Extended Info (decoded):", value.decode("utf-8", errors="ignore"))
        except x509.ExtensionNotFound:
            raise HTTPException(status_code=400, detail=f"certificate decode public key error: {e}")
            #print("❌ 找不到自訂 Extended Info")

    except requests.HTTPError:
        raise HTTPException(status_code=502, detail="Failed to download intermediate certificate from CA server")
    except x509.ExtensionNotFound as e:
        raise HTTPException(status_code=400, detail=f"Certificate extension error: {e}")
    except Exception as e:
        # 包含 InvalidSignature、ValueError、時間錯誤等
        raise HTTPException(status_code=400, detail=f"Certificate verification failed: {str(e)}")
    

    return {"status": "success",
            "message": "Certificate is valid and trusted.",
            "public_key": public_key}



#####################################################################################
#                               Dilithium Certificate                               #
#####################################################################################
#def dilithium_gencsr(user_sk) -> List[Dict[str, bytes]]:
#    # 自訂一個 OID（不能和已定義的衝突）
#    dilithium_oid = ObjectIdentifier("1.3.6.1.4.1.99999.1.1")
#
#    # 建立憑證
#    builder = x509.CertificateBuilder().subject_name(
#        x509.Name([
#            x509.NameAttribute(NameOID.COMMON_NAME, u'example.com'),
#        ])
#    ).issuer_name(
#        x509.Name([
#            x509.NameAttribute(NameOID.COMMON_NAME, u'example CA'),
#        ])
#    ).public_key(
#        x509.load_der_public_key(dilithium_pubkey, backend=default_backend())  # 若你轉成 DER 格式
#    ).serial_number(
#        x509.random_serial_number()
#    ).not_valid_before(
#        datetime.datetime.utcnow()
#    ).not_valid_after(
#        datetime.datetime.utcnow() + datetime.timedelta(days=365)
#    )
#
#
#    private_key = load_der_private_key(user_sk, password=None, backend=default_backend())
#    # === 1. 建立 CSR ===
#    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
#        x509.NameAttribute(NameOID.COUNTRY_NAME, u"TW"),
#        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Hsinchu"),
#        x509.NameAttribute(NameOID.LOCALITY_NAME, u"East"),
#        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"NYCU"),
#        x509.NameAttribute(NameOID.COMMON_NAME, u"Oasis_Star"),
#    ])).sign(private_key, hashes.SHA256(), backend=default_backend())
#
#    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
#
#    # === 2. 發送 CSR 給 CA Server ===
#    response = requests.post(
#        api_url,
#        files={"file": ("csr.pem", csr_pem, "application/x-pem-file")},
#    )
#
#    # === 3. 處理回應 ===
#    certificate_files = []
#    if response.status_code == 200:
#        filename = "certificate.pem"
#        content = response.content
#        certificate_files = {"filename": filename, "content": content}
#        print("✅ 憑證已簽發並儲存為 certificate.pem")
#    else:
#        raise HTTPException(status_code=response.status_code, detail=response.content.decode('utf-8'))
#
#    return [certificate_files]