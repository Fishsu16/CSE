import os
import re
import subprocess
import json

CMD = [
    "./cosmian",
    "--kms-url",
    "https://066f-219-85-10-48.ngrok-free.app",
    "--kms-accept-invalid-certs",
    "kms",
]


def extract_aes_key():
    with open("aes.json", "r") as f:
        aes_json = json.load(f)

    os.remove("aes.json")
    try:
        key_block = aes_json["value"][0]
        key_value = key_block["value"][1]

        for item in key_value["value"]:
            if item["tag"] == "KeyMaterial":
                return item["value"]
    except:
        return None


def extract_user_keys(user_key_id: str):
    with open(f"user_keys/user_sk/{user_key_id}.json", "r") as f:
        user_sk_json = json.load(f)
    os.remove(f"user_keys/user_sk/{user_key_id}.json")

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
            user_sk = key_material
    except:
        return None, None

    with open(f"user_keys/user_pk/{user_key_id}_pk.json", "r") as f:
        user_pk_json = json.load(f)
    os.remove(f"user_keys/user_pk/{user_key_id}_pk.json")

    try:
        key_material = None, None
        for item in user_pk_json["value"]:
            for subitem in item["value"]:
                if subitem["tag"] == "KeyValue":
                    for kv in subitem["value"]:
                        if kv["tag"] == "KeyMaterial":
                            key_material = kv["value"]
                            break

        if key_material:
            user_pk = key_material
    except:
        return None, None

    return user_pk, user_sk


def export_file(export_cmd: list):
    cmd = CMD + export_cmd
    result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")

    if result.returncode == 0:
        return True
    else:
        return False


def create_user_keys(tag: str = "user-key"):
    cmd = CMD + [
        "rsa",
        "keys",
        "create",
        "--tag",
        tag,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return None

    match = re.search(r"Public key unique identifier:\s*([a-f0-9\-]+)", result.stdout)
    if not match:
        return None

    key_id = match.group(1)
    export_cmd = [
        "rsa",
        "keys",
        "export",
        "--key-id",
        key_id,
        f"user_keys/user_sk/{key_id}.json",
    ]

    if not export_file(export_cmd):
        return None

    export_cmd = [
        "rsa",
        "keys",
        "export",
        "--key-id",
        key_id + "_pk",
        f"user_keys/user_pk/{key_id}_pk.json",
    ]

    if not export_file(export_cmd):
        return None

    user_pk, user_sk = extract_user_keys(key_id)

    return user_pk, user_sk


def generate_AES_key() -> bytes:
    cmd = CMD + [
        "sym",
        "keys",
        "create",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        return None

    match = re.search(r"Unique identifier:\s*([a-f0-9\-]+)", result.stdout)
    if not match:
        return None

    key_id = match.group(1)
    export_cmd = [
        "sym",
        "keys",
        "export",
        "--key-id",
        key_id,
        "aes.json",
    ]

    if not export_file(export_cmd):
        return None

    AES_key = extract_aes_key()

    return bytes.fromhex(AES_key)
