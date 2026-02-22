from flask import Flask, request, jsonify
import hmac
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
from protobuf_decoder.protobuf_decoder import Parser
import codecs
import time
from datetime import datetime
import urllib3
import base64
import concurrent.futures
import threading
import os
import sys

# Disable only the InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ---------------- KEYS ---------------- #
hex_key = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(hex_key)

REGION_LANG = {
    "ME": "ar","IND": "hi","ID": "id","VN": "vi","TH": "th","BD": "bn",
    "PK": "ur","TW": "zh","EU": "en","RU": "ru","NA": "en","SAC": "es","BR": "pt"
}

REGION_URLS = {
    "IND": "https://client.ind.freefiremobile.com/",
    "ID": "https://clientbp.ggblueshark.com/",
    "BR": "https://client.us.freefiremobile.com/",
    "ME": "https://clientbp.common.ggbluefox.com/",
    "VN": "https://clientbp.ggblueshark.com/",
    "TH": "https://clientbp.common.ggbluefox.com/",
    "RU": "https://clientbp.ggblueshark.com/",
    "BD": "https://clientbp.ggblueshark.com/",
    "PK": "https://clientbp.ggblueshark.com/",
    "SG": "https://clientbp.ggblueshark.com/",
    "NA": "https://client.us.freefiremobile.com/",
    "SAC": "https://client.us.freefiremobile.com/",
    "EU": "https://clientbp.ggblueshark.com/",
    "TW": "https://clientbp.ggblueshark.com/"
}

def get_region(language_code: str) -> str:
    return REGION_LANG.get(language_code)

def get_region_url(region_code: str) -> str:
    return REGION_URLS.get(region_code, None)

# ---------------- THREAD SAFE SESSION ---------------- #
thread_local = threading.local()

def get_session():
    if not hasattr(thread_local, "session"):
        session = requests.Session()
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        thread_local.session = session
    return thread_local.session

# ---------------- PROTOBUF ---------------- #
def EnC_Vr(N):
    H = []
    while True:
        b = N & 0x7F
        N >>= 7
        if N: b |= 0x80
        H.append(b)
        if not N:
            break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    return EnC_Vr((field_number << 3) | 0) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value

def CrEaTe_ProTo(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        elif isinstance(value, (str, bytes)):
            packet.extend(CrEaTe_LenGTh(field, value))
    return packet

# ---------------- AES ---------------- #
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key_bytes = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain_text, AES.block_size)).hex()

# ---------------- NAME / PASSWORD ---------------- #
def generate_random_name(prefix):
    chars = string.ascii_letters + string.digits
    return prefix + ''.join(random.choice(chars) for _ in range(6)).upper()

def generate_custom_password():
    chars = string.ascii_letters + string.digits
    return "HRE-" + ''.join(random.choice(chars) for _ in range(9)).upper() + "-CODEX"

# ---------------- ACCOUNT FLOW ---------------- #
def create_single_account(args):
    name_prefix, region = args
    for _ in range(3):
        try:
            r = create_acc(region, name_prefix)
            if r and r.get("status") == "full_login":
                return r
            time.sleep(1)
        except:
            time.sleep(1)
    return None

def create_acc(region, name_prefix):
    password = generate_custom_password()
    session = get_session()

    data = f"password={password}&client_type=2&source=2&app_id=100067"
    sig = hmac.new(key, data.encode(), hashlib.sha256).hexdigest()

    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P8(Android)",
        "Authorization": "Signature " + sig,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        r = session.post(
            "https://100067.connect.garena.com/oauth/guest/register",
            headers=headers,
            data=data,
            timeout=30
        ).json()
        uid = r.get("uid")
        if not uid:
            return None
        return token(uid, password, region, name_prefix)
    except:
        return None

def token(uid, password, region, name_prefix):
    session = get_session()
    body = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": key,
        "client_id": "100067"
    }
    try:
        r = session.post(
            "https://100067.connect.garena.com/oauth/guest/token/grant",
            data=body,
            timeout=30
        ).json()
        open_id = r.get("open_id")
        access_token = r.get("access_token")
        if not open_id or not access_token:
            return None
        return {
            "uid": uid,
            "password": password,
            "name": generate_random_name(name_prefix),
            "region": region,
            "status": "full_login",
            "stage": "complete"
        }
    except:
        return None

# ---------------- API ---------------- #
@app.route('/gen', methods=['GET'])
def generate_accounts():
    name = request.args.get('name', 'HUSTLER')
    count = int(request.args.get('count', 1))
    region = request.args.get('region', 'IND').upper()

    if region not in REGION_LANG:
        region = "IND"
    if count < 1:
        count = 1
    if count > 15:
        count = 15

    results = []
    attempts = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as exe:
        while len(results) < count and attempts < count * 10:
            futures = [exe.submit(create_single_account, (name, region)) for _ in range(5)]
            for f in concurrent.futures.as_completed(futures):
                attempts += 1
                r = f.result()
                if r:
                    results.append(r)
                if len(results) >= count:
                    break
            time.sleep(1)

    return jsonify({
        "success": True,
        "total_requested": count,
        "total_created": len(results),
        "accounts": results,
        "attempts_made": attempts
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/')
def home():
    return jsonify({
        "message": "FreeFire Account Generator API",
        "endpoint": "/gen?name=NAME&count=COUNT&region=REGION"
    })

# ---------------- START ---------------- #
if __name__ == '__main__':
    print("🚀 API Started")
    print("🌐 http://0.0.0.0:3000")
    app.run(host='0.0.0.0', port=3000, debug=False)