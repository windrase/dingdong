import os
import logging
import json
import sys
import time
import base64
import sqlite3
from datetime import datetime, timezone, timedelta
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton, ReplyKeyboardMarkup, KeyboardButton
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes, ConversationHandler
from dotenv import load_dotenv
import qrcode
from io import BytesIO

# Load environment variables
load_dotenv()

# Enable logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Define conversation states
PHONE, OTP = range(2)

# Global variables for tokens and user data
refresh_tokens = []
api_key = ""

# Setup logging for user activities
user_logger = logging.getLogger("user_activity")
user_logger.setLevel(logging.INFO)
handler = logging.FileHandler("user_activity.log")
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
user_logger.addHandler(handler)

# Initialize SQLite database
def init_db():
    """Initialize the SQLite database for storing user IDs."""
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (user_id INTEGER PRIMARY KEY, 
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

# Global variable for bot application
application_instance = None

class AuthInstance:
    """Simple authentication instance to manage user tokens."""
    _instance_ = None
    
    def __new__(cls):
        if cls._instance_ is None:
            cls._instance_ = super().__new__(cls)
        return cls._instance_
    
    def __init__(self):
        if not hasattr(self, 'initialized'):
            self.load_tokens()
            self.initialized = True
    
    def load_tokens(self):
        global refresh_tokens, api_key
        try:
            if os.path.exists("refresh-tokens.json"):
                with open("refresh-tokens.json", "r", encoding="utf-8") as f:
                    refresh_tokens = json.load(f)
            # Load API key from .env file first, then from api.key file as fallback
            if os.getenv("API_KEY"):
                global api_key
                api_key = os.getenv("API_KEY")
            elif os.path.exists("api.key"):
                with open("api.key", "r", encoding="utf-8") as f:
                    api_key = f.read().strip()
        except Exception as e:
            logger.error("Error loading tokens: %s", e)
    
    def add_refresh_token(self, number: int, refresh_token: str):
        global refresh_tokens
        # Check if number already exist, if yes, replace it, if not append
        existing = next((rt for rt in refresh_tokens if rt["number"] == number), None)
        if existing:
            existing["refresh_token"] = refresh_token
        else:
            refresh_tokens.append({
                "number": int(number),
                "refresh_token": refresh_token
            })
        
        # Save to file
        with open("refresh-tokens.json", "w", encoding="utf-8") as f:
            json.dump(refresh_tokens, f, indent=2)
    
    def remove_refresh_token(self, number: int):
        global refresh_tokens
        refresh_tokens = [rt for rt in refresh_tokens if rt["number"] != number]
        
        # Save to file
        with open("refresh-tokens.json", "w", encoding="utf-8") as f:
            json.dump(refresh_tokens, f, indent=4)
    
    def get_user_tokens(self, number: int):
        """Get tokens for a specific user"""
        rt_entry = next((rt for rt in refresh_tokens if rt["number"] == number), None)
        if not rt_entry:
            return None
            
        tokens = get_new_token(rt_entry["refresh_token"])
        if not tokens:
            # If token refresh failed, remove the refresh token
            self.remove_refresh_token(number)
            return None
            
        return tokens
    
    def get_active_user(self, context: ContextTypes.DEFAULT_TYPE):
        """Get active user for current chat"""
        if 'active_user' in context.user_data:
            user = context.user_data['active_user']
            # Verify tokens are still valid
            tokens = self.get_user_tokens(user["number"])
            if tokens:
                user["tokens"] = tokens
                return user
        return None
    
    def set_active_user(self, context: ContextTypes.DEFAULT_TYPE, number: int):
        """Set active user for current chat"""
        tokens = self.get_user_tokens(number)
        if not tokens:
            return False
            
        context.user_data['active_user'] = {
            "number": int(number),
            "tokens": tokens
        }
        return True
    
    def remove_active_user(self, context: ContextTypes.DEFAULT_TYPE):
        """Remove active user for current chat"""
        if 'active_user' in context.user_data:
            del context.user_data['active_user']

# Initialize AuthInstance
auth_instance = AuthInstance()

# Import functions from api_request (avoiding circular imports)
import requests
import uuid
from datetime import timezone, timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Load API configuration from environment variables
API_KEY = os.getenv("API_KEY", "vT8tINqHaOxXbGE7eOWAhA==")
XDATA_DECRYPT_URL = "https://crypto.mashu.lol/api/decrypt"
XDATA_ENCRYPT_SIGN_URL = "https://crypto.mashu.lol/api/encryptsign"
PAYMENT_SIGN_URL = "https://crypto.mashu.lol/api/sign-payment"
AX_SIGN_URL = "https://crypto.mashu.lol/api/sign-ax"
BOUNTY_SIGN_URL = "https://crypto.mashu.lol/api/sign-bounty"
BASE_API_URL = os.getenv("BASE_API_URL", "https://api.myxl.xlaxiata.co.id")
BASE_CIAM_URL = os.getenv("BASE_CIAM_URL", "https://gede.ciam.xlaxiata.co.id")
BASIC_AUTH = os.getenv("BASIC_AUTH", "OWZjOTdlZDEtNmEzMC00OGQ1LTk1MTYtNjBjNTNjZTNhMTM1OllEV21GNExKajlYSUt3UW56eTJlMmxiMHRKUWIyOW8z")
AX_DEVICE_ID = os.getenv("AX_DEVICE_ID", "92fb44c0804233eb4d9e29f838223a14")
AX_FP = os.getenv("AX_FP", "YmQLy9ZiLLBFAEVcI4Dnw9+NJWZcdGoQyewxMF/9hbfk/8GbKBgtZxqdiiam8+m2lK31E/zJQ7kjuPXpB3EE8naYL0Q8+0WLhFV1WAPl9Eg=")
USER_AGENT = os.getenv("UA", "myXL / 8.6.0(1179); com.android.vending; (samsung; SM-N935F; SDK 33; Android 13)")

def random_iv_hex16():
    return os.urandom(8).hex()

def b64(data, urlsafe):
    enc = base64.urlsafe_b64encode if urlsafe else base64.b64encode
    return enc(data).decode("ascii")

def build_encrypted_field(iv_hex16=None, urlsafe_b64=False):
    key = os.getenv("AES_KEY_ASCII", "5dccbf08920a5527").encode("ascii")
    iv_hex = iv_hex16 or random_iv_hex16()
    iv = iv_hex.encode("ascii") 

    pt = pad(b"", AES.block_size)
    ct = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pt)

    return b64(ct, urlsafe_b64) + iv_hex

def java_like_timestamp(now):
    ms2 = f"{int(now.microsecond/10000):02d}"
    tz = now.strftime("%z")
    tz_colon = tz[:-2] + ":" + tz[-2:] if tz else "+00:00"
    return now.strftime(f"%Y-%m-%dT%H:%M:%S.{ms2}") + tz_colon

def ts_gmt7_without_colon(dt):
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone(timedelta(hours=7)))
    else:
        dt = dt.astimezone(timezone(timedelta(hours=7)))
    millis = f"{int(dt.microsecond / 1000):03d}"
    tz = dt.strftime("%z")
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{millis}") + tz

def ax_api_signature(api_key, ts_for_sign, contact, code, contact_type):
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }
    
    request_body = {
        "ts_for_sign": ts_for_sign,
        "contact": contact,
        "code": code,
        "contact_type": contact_type
    }
    
    response = requests.request("POST", AX_SIGN_URL, json=request_body, headers=headers, timeout=30)
    if response.status_code == 200:
        return response.json().get("ax_signature")
    else:
        raise Exception(f"Signature generation failed: {response.text}")

def encryptsign_xdata(api_key, method, path, id_token, payload):
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }
    
    request_body = {
        "id_token": id_token,
        "method": method,
        "path": path,
        "body": payload
    }

    response = requests.request("POST", XDATA_ENCRYPT_SIGN_URL, json=request_body, headers=headers, timeout=30)
    
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Encryption failed: {response.text}")

def decrypt_xdata(api_key, encrypted_payload):
    if not isinstance(encrypted_payload, dict) or "xdata" not in encrypted_payload or "xtime" not in encrypted_payload:
        raise ValueError("Invalid encrypted data format. Expected a dictionary with 'xdata' and 'xtime' keys.")
    
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }
    
    response = requests.request("POST", XDATA_DECRYPT_URL, json=encrypted_payload, headers=headers, timeout=30)
    
    if response.status_code == 200:
        return response.json().get("plaintext")
    else:
        raise Exception(f"Decryption failed: {response.text}")

def get_x_signature_payment(api_key, access_token, sig_time_sec, package_code, token_payment, payment_method):
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }
    
    request_body = {
        "access_token": access_token,
        "sig_time_sec": sig_time_sec,
        "package_code": package_code,
        "token_payment": token_payment,
        "payment_method": payment_method
    }
    
    response = requests.request("POST", PAYMENT_SIGN_URL, json=request_body, headers=headers, timeout=30)
    
    if response.status_code == 200:
        return response.json().get("x_signature")
    else:
        raise Exception(f"Signature generation failed: {response.text}")

def get_x_signature_bounty(api_key, access_token, sig_time_sec, package_code, token_payment):
    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
    }
    
    request_body = {
        "access_token": access_token,
        "sig_time_sec": sig_time_sec,
        "package_code": package_code,
        "token_payment": token_payment
    }
    
    response = requests.request("POST", BOUNTY_SIGN_URL, json=request_body, headers=headers, timeout=30)
    
    if response.status_code == 200:
        return response.json().get("x_signature")
    else:
        raise Exception(f"Signature generation failed: {response.text}")

def validate_contact(contact):
    if not contact.startswith("628") or len(contact) < 10 or len(contact) > 14:
        print("Invalid number")
        return False
    return True

def get_otp(contact):
    # Contact example: "6287896089467"
    if not validate_contact(contact):
        return None
    
    url = f"{BASE_CIAM_URL}/realms/xl-ciam/auth/otp"

    querystring = {
        "contact": contact,
        "contactType": "SMS",
        "alternateContact": "false"
    }
    
    now = datetime.now(timezone(timedelta(hours=7)))
    ax_request_at = java_like_timestamp(now)  # format: "2023-10-20T12:34:56.78+07:00"
    ax_request_id = str(uuid.uuid4())

    payload = ""
    headers = {
        "Accept-Encoding": "gzip, deflate, br",
        "Authorization": f"Basic {BASIC_AUTH}",
        "Ax-Device-Id": AX_DEVICE_ID,
        "Ax-Fingerprint": AX_FP,
        "Ax-Request-At": ax_request_at,
        "Ax-Request-Device": "samsung",
        "Ax-Request-Device-Model": "SM-N935F",
        "Ax-Request-Id": ax_request_id,
        "Ax-Substype": "PREPAID",
        "Content-Type": "application/json",
        "Host": BASE_CIAM_URL.replace("https://", ""),
        "User-Agent": USER_AGENT
    }

    print("Requesting OTP...")
    try:
        response = requests.request("GET", url, data=payload, headers=headers, params=querystring, timeout=30)
        print("response body", response.text)
        json_body = json.loads(response.text)
    
        if "subscriber_id" not in json_body:
            error_msg = json_body.get("error", "No error message in response")
            error_desc = json_body.get("error_description", "")
            
            # Handle specific error cases
            if "reach limit" in error_msg.lower() or "reach limit" in error_desc.lower():
                print("OTP request limit reached")
                raise ValueError("OTP request limit reached. Please wait before requesting another OTP.")
            elif response.status_code == 429:
                print("Too many requests")
                raise ValueError("Too many requests. Please wait before requesting another OTP.")
            else:
                print(error_msg)
                raise ValueError(f"Failed to request OTP: {error_msg}")
        
        return json_body["subscriber_id"]
    except requests.RequestException as e:
        if "429" in str(e) or "too many requests" in str(e).lower():
            print("Too many requests")
            raise ValueError("Too many requests. Please wait before requesting another OTP.")
        else:
            print(f"Network error requesting OTP: {e}")
            return None
    except ValueError:
        # Re-raise ValueError exceptions
        raise
    except Exception as e:
        print(f"Error requesting OTP: {e}")
        return None

def submit_otp(api_key, contact, code):
    if not validate_contact(contact):
        print("Invalid number")
        return None
    
    if not code or len(code) != 6:
        print("Invalid OTP code format")
        return None
    
    url = f"{BASE_CIAM_URL}/realms/xl-ciam/protocol/openid-connect/token"

    now_gmt7 = datetime.now(timezone(timedelta(hours=7)))
    ts_for_sign = ts_gmt7_without_colon(now_gmt7)
    ts_header = ts_gmt7_without_colon(now_gmt7 - timedelta(minutes=5))
    signature = ax_api_signature(api_key, ts_for_sign, contact, code, "SMS")

    payload = f"contactType=SMS&code={code}&grant_type=password&contact={contact}&scope=openid"

    headers = {
        "Accept-Encoding": "gzip, deflate, br",
        "Authorization": f"Basic {BASIC_AUTH}",
        "Ax-Api-Signature": signature,
        "Ax-Device-Id": AX_DEVICE_ID,
        "Ax-Fingerprint": AX_FP,
        "Ax-Request-At": ts_header,
        "Ax-Request-Device": "samsung",
        "Ax-Request-Device-Model": "SM-N935F",
        "Ax-Request-Id": str(uuid.uuid4()),
        "Ax-Substype": "PREPAID",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": USER_AGENT,
    }

    try:
        response = requests.post(url, data=payload, headers=headers, timeout=30)
        json_body = json.loads(response.text)
        
        if "error" in json_body:
            error_msg = json_body['error_description']
            print(f"[Error submit_otp]: {error_msg}")
            
            # Handle specific error cases
            if "reach limit" in error_msg.lower():
                raise ValueError("OTP verification limit reached. Please wait before trying again.")
            elif response.status_code == 429:
                raise ValueError("Too many requests. Please wait before trying again.")
            else:
                return None
        
        print("Login successful.")
        return json_body
    except requests.RequestException as e:
        if "429" in str(e) or "too many requests" in str(e).lower():
            print("[Error submit_otp]: Too many requests")
            raise ValueError("Too many requests. Please wait before trying again.")
        else:
            print(f"[Error submit_otp]: {e}")
            return None
    except ValueError:
        # Re-raise ValueError exceptions
        raise
    except Exception as e:
        print(f"[Error submit_otp]: {e}")
        return None

def get_new_token(refresh_token):
    url = f"{BASE_CIAM_URL}/realms/xl-ciam/protocol/openid-connect/token"

    now = datetime.now(timezone(timedelta(hours=7)))  # GMT+7
    ax_request_at = now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0700"
    ax_request_id = str(uuid.uuid4())

    headers = {
        "Host": BASE_CIAM_URL.replace("https://", ""),
        "ax-request-at": ax_request_at,
        "ax-device-id": AX_DEVICE_ID,
        "ax-request-id": ax_request_id,
        "ax-request-device": "samsung",
        "ax-request-device-model": "SM-N935F",
        "ax-fingerprint": AX_FP,
        "authorization": f"Basic {BASIC_AUTH}",
        "user-agent": USER_AGENT,
        "ax-substype": "PREPAID",
        "content-type": "application/x-www-form-urlencoded"
    }

    data = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }

    try:
        resp = requests.post(url, headers=headers, data=data, timeout=30)
        if resp.status_code == 400:
            error_desc = resp.json().get("error_description", "")
            if error_desc == "Session not active":
                logger.info("Refresh token expired. Please remove and re-add the account.")
                return None
            elif resp.status_code == 429:
                logger.info("Too many requests when refreshing token.")
                return None  # Return None instead of raising exception
            
        if resp.status_code == 429:
            logger.info("Too many requests when refreshing token.")
            return None  # Return None instead of raising exception
            
        resp.raise_for_status()

        body = resp.json()
        
        if "id_token" not in body:
            logger.error("ID token not found in response")
            return None
        if "error" in body:
            logger.error("Error in response: %s - %s", body['error'], body.get('error_description', ''))
            return None
        
        return body
    except requests.exceptions.RequestException as e:
        if "429" in str(e):
            logger.info("Too many requests when refreshing token: %s", str(e))
            return None  # Return None instead of raising exception
        else:
            logger.error("Request error when refreshing token: %s", str(e))
            return None

def send_api_request(api_key, path, payload_dict, id_token, method="POST"):
    encrypted_payload = encryptsign_xdata(
        api_key=api_key,
        method=method,
        path=path,
        id_token=id_token,
        payload=payload_dict
    )
    
    xtime = int(encrypted_payload["encrypted_body"]["xtime"])
    
    now = datetime.now(timezone.utc).astimezone()
    sig_time_sec = (xtime // 1000)

    body = encrypted_payload["encrypted_body"]
    x_sig = encrypted_payload["x_signature"]
    
    headers = {
        "host": BASE_API_URL.replace("https://", ""),
        "content-type": "application/json; charset=utf-8",
        "user-agent": USER_AGENT,
        "x-api-key": API_KEY,
        "authorization": f"Bearer {id_token}",
        "x-hv": "v3",
        "x-signature-time": str(sig_time_sec),
        "x-signature": x_sig,
        "x-request-id": str(uuid.uuid4()),
        "x-request-at": java_like_timestamp(now),
        "x-version-app": "8.6.0",
    }

    url = f"{BASE_API_URL}/{path}"
    resp = requests.post(url, headers=headers, data=json.dumps(body), timeout=30)

    try:
        decrypted_body = decrypt_xdata(api_key, json.loads(resp.text))
        return decrypted_body
    except Exception as e:
        print("[decrypt err]", e)
        return resp.text

def get_balance(api_key, id_token):
    path = "api/v8/packages/balance-and-credit"
    
    raw_payload = {
        "is_enterprise": False,
        "lang": "en"
    }
    
    print("Fetching balance...")
    try:
        res = send_api_request(api_key, path, raw_payload, id_token, "POST")
        
        if "data" in res:
            if "balance" in res["data"]:
                return res["data"]["balance"]
        else:
            print("Error getting balance:", res.get("error", "Unknown error"))
            return None
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            print("Rate limit exceeded when fetching balance")
            raise ValueError("Too many requests. Please wait before trying again.")
        else:
            print("Error getting balance:", str(e))
            return None
    except Exception as e:
        print("Error getting balance:", str(e))
        return None

def get_family(api_key, tokens, family_code):
    print("Fetching package family...")
    path = "api/v8/xl-stores/options/list"
    id_token = tokens.get("id_token")
    payload_dict = {
        "is_show_tagging_tab": True,
        "is_dedicated_event": True,
        "is_transaction_routine": False,
        "migration_type": "NONE",
        "package_family_code": family_code,
        "is_autobuy": False,
        "is_enterprise": False,
        "is_pdlp": True,
        "referral_code": "",
        "is_migration": False,
        "lang": "en"
    }
    
    try:
        res = send_api_request(api_key, path, payload_dict, id_token, "POST")
        if res.get("status") != "SUCCESS":
            print(f"Failed to get family {family_code}")
            print(json.dumps(res, indent=2))
            return None
        
        return res["data"]
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            print("Rate limit exceeded when fetching family packages")
            raise ValueError("Too many requests. Please wait before trying again.")
        else:
            print("Error fetching family packages:", str(e))
            return None
    except Exception as e:
        print("Error fetching family packages:", str(e))
        return None

def get_package(api_key, tokens, package_option_code):
    path = "api/v8/xl-stores/options/detail"
    
    raw_payload = {
        "is_transaction_routine": False,
        "migration_type": "NONE",
        "package_family_code": "",
        "family_role_hub": "",
        "is_autobuy": False,
        "is_enterprise": False,
        "is_shareable": False,
        "is_migration": False,
        "lang": "en",
        "package_option_code": package_option_code,
        "is_upsell_pdp": False,
        "package_variant_code": ""
    }
    
    print("Fetching package...")
    try:
        res = send_api_request(api_key, path, raw_payload, tokens["id_token"], "POST")
        
        if "data" not in res:
            print("Error getting package:", res.get("error", "Unknown error"))
            return None
            
        return res["data"]
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            print("Rate limit exceeded when fetching package details")
            raise ValueError("Too many requests. Please wait before trying again.")
        else:
            print("Error getting package:", str(e))
            return None
    except Exception as e:
        print("Error getting package:", str(e))
        return None

def get_addons(api_key, tokens, package_option_code):
    path = "api/v8/xl-stores/options/addons-pinky-box"
    
    raw_payload = {
        "is_enterprise": False,
        "lang": "en",
        "package_option_code": package_option_code
    }
    
    print("Fetching addons...")
    try:
        res = send_api_request(api_key, path, raw_payload, tokens["id_token"], "POST")
        
        if "data" not in res:
            print("Error getting addons:", res.get("error", "Unknown error"))
            return None
            
        return res["data"]
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            print("Rate limit exceeded when fetching addons")
            raise ValueError("Too many requests. Please wait before trying again.")
        else:
            print("Error getting addons:", str(e))
            return None
    except Exception as e:
        print("Error getting addons:", str(e))
        return None

def fetch_my_packages(api_key, tokens):
    """Fetch user's current packages"""
    if not tokens:
        print("No active user tokens found.")
        return None
    
    id_token = tokens.get("id_token")
    
    path = "api/v8/packages/quota-details"
    
    payload = {
        "is_enterprise": False,
        "lang": "en",
        "family_member_id": ""
    }
    
    print("Fetching my packages...")
    try:
        res = send_api_request(api_key, path, payload, id_token, "POST")
        if res.get("status") != "SUCCESS":
            print("Failed to fetch packages")
            print("Response:", res)
            return None
        
        return res["data"]["quotas"]
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            print("Rate limit exceeded when fetching packages")
            raise ValueError("Too many requests. Please wait before trying again.")
        else:
            print("Error fetching packages:", str(e))
            return None
    except Exception as e:
        print("Error fetching my packages:", str(e))
        return None

def get_payment_methods(api_key, tokens, token_confirmation, payment_target):
    payment_path = "payments/api/v8/payment-methods-option"
    payment_payload = {
        "payment_type": "PURCHASE",
        "is_enterprise": False,
        "payment_target": payment_target,
        "lang": "en",
        "is_referral": False,
        "token_confirmation": token_confirmation
    }
    
    try:
        payment_res = send_api_request(api_key, payment_path, payment_payload, tokens["id_token"], "POST")
        if payment_res["status"] != "SUCCESS":
            print("Failed to fetch payment methods.")
            print(f"Error: {payment_res}")
            return None
        
        return payment_res["data"]
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            print("Rate limit exceeded when fetching payment methods")
            raise ValueError("Too many requests. Please wait before trying again.")
        else:
            print("Error fetching payment methods:", str(e))
            return None
    except Exception as e:
        print("Error fetching payment methods:", str(e))
        return None

def settlement_qris(api_key, tokens, token_payment, ts_to_sign, payment_target, price, item_name=""):
    # Settlement request
    path = "payments/api/v8/settlement-multipayment/qris"
    settlement_payload = {
        "akrab": {
            "akrab_members": [],
            "akrab_parent_alias": "",
            "members": []
        },
        "can_trigger_rating": False,
        "total_discount": 0,
        "coupon": "",
        "payment_for": "BUY_PACKAGE",
        "topup_number": "",
        "is_enterprise": False,
        "autobuy": {
            "is_using_autobuy": False,
            "activated_autobuy_code": "",
            "autobuy_threshold_setting": {
            "label": "",
            "type": "",
            "value": 0
            }
        },
        "cc_payment_type": "",
        "access_token": tokens["access_token"],
        "is_myxl_wallet": False,
        "additional_data": {
            "original_price": price,
            "is_spend_limit_temporary": False,
            "migration_type": "",
            "spend_limit_amount": 0,
            "is_spend_limit": False,
            "tax": 0,
            "benefit_type": "",
            "quota_bonus": 0,
            "cashtag": "",
            "is_family_plan": False,
            "combo_details": [],
            "is_switch_plan": False,
            "discount_recurring": 0,
            "has_bonus": False,
            "discount_promo": 0
        },
        "total_amount": price,
        "total_fee": 0,
        "is_use_point": False,
        "lang": "en",
        "items": [{
            "item_code": payment_target,
            "product_type": "",
            "item_price": price,
            "item_name": item_name,
            "tax": 0
        }],
        "verification_token": token_payment,
        "payment_method": "QRIS",
        "timestamp": int(time.time())
    }
    
    try:
        encrypted_payload = encryptsign_xdata(
            api_key=api_key,
            method="POST",
            path=path,
            id_token=tokens["id_token"],
            payload=settlement_payload
        )
        
        xtime = int(encrypted_payload["encrypted_body"]["xtime"])
        sig_time_sec = (xtime // 1000)
        x_requested_at = datetime.fromtimestamp(sig_time_sec, tz=timezone.utc).astimezone()
        settlement_payload["timestamp"] = ts_to_sign
        
        body = encrypted_payload["encrypted_body"]
        x_sig = get_x_signature_payment(
                api_key,
                tokens["access_token"],
                ts_to_sign,
                payment_target,
                token_payment,
                "QRIS"
            )
        
        headers = {
            "host": BASE_API_URL.replace("https://", ""),
            "content-type": "application/json; charset=utf-8",
            "user-agent": USER_AGENT,
            "x-api-key": API_KEY,
            "authorization": f"Bearer {tokens['id_token']}",
            "x-hv": "v3",
            "x-signature-time": str(sig_time_sec),
            "x-signature": x_sig,
            "x-request-id": str(uuid.uuid4()),
            "x-request-at": java_like_timestamp(x_requested_at),
            "x-version-app": "8.6.0",
        }
        
        url = f"{BASE_API_URL}/{path}"
        print("Sending settlement request...")
        resp = requests.post(url, headers=headers, data=json.dumps(body), timeout=30)
        
        try:
            decrypted_body = decrypt_xdata(api_key, json.loads(resp.text))
            if decrypted_body["status"] != "SUCCESS":
                print("Failed to initiate settlement.")
                print(f"Error: {decrypted_body}")
                return None
            
            transaction_id = decrypted_body["data"]["transaction_code"]
            
            return transaction_id
        except Exception as e:
            print("[decrypt err]", e)
            return resp.text
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            print("Rate limit exceeded when processing QRIS payment")
            raise ValueError("Too many requests. Please wait before trying again.")
        else:
            print("Error processing QRIS payment:", str(e))
            raise
    except Exception as e:
        print("Error processing QRIS payment:", str(e))
        raise

def get_qris_code(api_key, tokens, transaction_id):
    path = "payments/api/v8/pending-detail"
    payload = {
        "transaction_id": transaction_id,
        "is_enterprise": False,
        "lang": "en",
        "status": ""
    }
    
    try:
        res = send_api_request(api_key, path, payload, tokens["id_token"], "POST")
        if res["status"] != "SUCCESS":
            print("Failed to fetch QRIS code.")
            print(f"Error: {res}")
            return None
        
        return res["data"]["qr_code"]
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            print("Rate limit exceeded when fetching QRIS code")
            raise ValueError("Too many requests. Please wait before trying again.")
        else:
            print("Error fetching QRIS code:", str(e))
            raise
    except Exception as e:
        print("Error fetching QRIS code:", str(e))
        raise

def purchase_package_with_balance(api_key, tokens, package_option_code):
    """Purchase package using balance"""
    try:
        # Get package details first
        package_details = get_package(api_key, tokens, package_option_code)
        if not package_details:
            return {"success": False, "error": "Failed to get package details. The package may no longer be available or there might be a network connectivity issue."}
            
        token_confirmation = package_details["token_confirmation"]
        payment_target = package_option_code
        
        # Get variant and option names
        variant_name = package_details["package_detail_variant"].get("name", "")
        option_name = package_details["package_option"].get("name", "")
        item_name = f"{variant_name} {option_name}".strip()
        
        price = package_details["package_option"]["price"]
        
        # Get payment methods
        payment_path = "payments/api/v8/payment-methods-option"
        payment_payload = {
            "payment_type": "PURCHASE",
            "is_enterprise": False,
            "payment_target": payment_target,
            "lang": "en",
            "is_referral": False,
            "token_confirmation": token_confirmation
        }
        
        print("Initiating payment...")
        payment_res = send_api_request(api_key, payment_path, payment_payload, tokens["id_token"], "POST")
        if payment_res.get("status") != "SUCCESS":
            error_msg = "Failed to initiate payment. "
            if "error" in payment_res:
                error_msg += f"Server response: {payment_res['error']}. "
            error_msg += "Possible reasons: Insufficient balance, package no longer available, or network connectivity issues."
            return {"success": False, "error": error_msg}
        
        token_payment = payment_res["data"]["token_payment"]
        ts_to_sign = payment_res["data"]["timestamp"]
        
        # Settlement request for balance payment
        settlement_path = "payments/api/v8/settlement-balance"
        settlement_payload = {
            "total_discount": 0,
            "is_enterprise": False,
            "payment_token": "",
            "token_payment": token_payment,
            "activated_autobuy_code": "",
            "cc_payment_type": "",
            "is_myxl_wallet": False,
            "pin": "",
            "ewallet_promo_id": "",
            "members": [],
            "total_fee": 0,
            "fingerprint": "",
            "autobuy_threshold_setting": {
                "label": "",
                "type": "",
                "value": 0
            },
            "is_use_point": False,
            "lang": "en",
            "payment_method": "BALANCE",
            "timestamp": int(time.time()),
            "points_gained": 0,
            "can_trigger_rating": False,
            "akrab_members": [],
            "akrab_parent_alias": "",
            "referral_unique_code": "",
            "coupon": "",
            "payment_for": "BUY_PACKAGE",
            "with_upsell": False,
            "topup_number": "",
            "stage_token": "",
            "authentication_id": "",
            "encrypted_payment_token": build_encrypted_field(urlsafe_b64=True),
            "token": "",
            "token_confirmation": "",
            "access_token": tokens["access_token"],
            "wallet_number": "",
            "encrypted_authentication_id": build_encrypted_field(urlsafe_b64=True),
            "additional_data": {},
            "total_amount": price,
            "is_using_autobuy": False,
            "items": [{
                "item_code": payment_target,
                "product_type": "",
                "item_price": price,
                "item_name": item_name,
                "tax": 0
            }]
        }
        
        print("Processing purchase with balance...")
        # Send payment request
        encrypted_payload = encryptsign_xdata(
            api_key=api_key,
            method="POST",
            path=settlement_path,
            id_token=tokens["id_token"],
            payload=settlement_payload
        )
        
        xtime = int(encrypted_payload["encrypted_body"]["xtime"])
        sig_time_sec = (xtime // 1000)
        x_requested_at = datetime.fromtimestamp(sig_time_sec, tz=timezone.utc).astimezone()
        settlement_payload["timestamp"] = ts_to_sign
        
        body = encrypted_payload["encrypted_body"]
        x_sig = get_x_signature_payment(
            api_key,
            tokens["access_token"],
            ts_to_sign,
            package_option_code,
            token_payment,
            "BALANCE"
        )
        
        headers = {
            "host": "api.myxl.xlaxiata.co.id",
            "content-type": "application/json; charset=utf-8",
            "user-agent": "myXL / 8.6.0(1179); com.android.vending; (samsung; SM-N935F; SDK 33; Android 13)",
            "x-api-key": API_KEY,
            "authorization": f"Bearer {tokens['id_token']}",
            "x-hv": "v3",
            "x-signature-time": str(sig_time_sec),
            "x-signature": x_sig,
            "x-request-id": str(uuid.uuid4()),
            "x-request-at": java_like_timestamp(x_requested_at),
            "x-version-app": "8.6.0",
        }
        
        url = f"{BASE_API_URL}/{settlement_path}"
        resp = requests.post(url, headers=headers, data=json.dumps(body), timeout=30)
        
        try:
            decrypted_body = decrypt_xdata(api_key, json.loads(resp.text))
            if decrypted_body.get("status") == "SUCCESS":
                return {"success": True, "data": decrypted_body}
            else:
                # Format the API error response for user-friendly display
                # Get package information for error message
                variant_name = package_details.get("package_detail_variant", {}).get("name", "")
                option_name = package_details.get("package_option", {}).get("name", "")
                package_title = f"{variant_name} {option_name}".strip()
                price = package_details.get("package_option", {}).get("price", 0)
                error_msg = format_api_error(decrypted_body, package_title, price, "Balance")
                return {"success": False, "error": error_msg}
        except Exception as e:
            return {"success": False, "error": f"Decryption error: {e}. This may indicate a network connectivity issue or server maintenance."}
            
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            return {"success": False, "error": "Too many requests. Please wait before trying again."}
        else:
            return {"success": False, "error": f"Purchase error: {e}. This may indicate a network connectivity issue, server maintenance, or temporary service disruption."}
    except Exception as e:
        return {"success": False, "error": f"Purchase error: {e}. This may indicate a network connectivity issue, server maintenance, or temporary service disruption."}

def purchase_package_with_balance_custom_amount(api_key, tokens, package_option_code, amount: int):
    """Purchase package using balance with custom amount"""
    try:
        # Get package details first
        package_details = get_package(api_key, tokens, package_option_code)
        if not package_details:
            return {"success": False, "error": "Failed to get package details. The package may no longer be available or there might be a network connectivity issue."}
            
        token_confirmation = package_details["token_confirmation"]
        payment_target = package_option_code
        
        # Get variant and option names
        variant_name = package_details["package_detail_variant"].get("name", "")
        option_name = package_details["package_option"].get("name", "")
        item_name = f"{variant_name} {option_name}".strip()
        
        price = package_details["package_option"]["price"]
        
        # Get payment methods
        payment_path = "payments/api/v8/payment-methods-option"
        payment_payload = {
            "payment_type": "PURCHASE",
            "is_enterprise": False,
            "payment_target": payment_target,
            "lang": "en",
            "is_referral": False,
            "token_confirmation": token_confirmation
        }
        
        print("Initiating payment...")
        payment_res = send_api_request(api_key, payment_path, payment_payload, tokens["id_token"], "POST")
        if payment_res.get("status") != "SUCCESS":
            error_msg = "Failed to initiate payment. "
            if "error" in payment_res:
                error_msg += f"Server response: {payment_res['error']}. "
            error_msg += "Possible reasons: Insufficient balance, package no longer available, or network connectivity issues."
            return {"success": False, "error": error_msg}
        
        token_payment = payment_res["data"]["token_payment"]
        ts_to_sign = payment_res["data"]["timestamp"]
        
        # Settlement request for balance payment with custom amount
        settlement_path = "payments/api/v8/settlement-balance"
        settlement_payload = {
            "total_discount": 0,
            "is_enterprise": False,
            "payment_token": "",
            "token_payment": token_payment,
            "activated_autobuy_code": "",
            "cc_payment_type": "",
            "is_myxl_wallet": False,
            "pin": "",
            "ewallet_promo_id": "",
            "members": [],
            "total_fee": 0,
            "fingerprint": "",
            "autobuy_threshold_setting": {
                "label": "",
                "type": "",
                "value": 0
            },
            "is_use_point": False,
            "lang": "en",
            "payment_method": "BALANCE",
            "timestamp": int(time.time()),
            "points_gained": 0,
            "can_trigger_rating": False,
            "akrab_members": [],
            "akrab_parent_alias": "",
            "referral_unique_code": "",
            "coupon": "",
            "payment_for": "BUY_PACKAGE",
            "with_upsell": False,
            "topup_number": "",
            "stage_token": "",
            "authentication_id": "",
            "encrypted_payment_token": build_encrypted_field(urlsafe_b64=True),
            "token": "",
            "token_confirmation": "",
            "access_token": tokens["access_token"],
            "wallet_number": "",
            "encrypted_authentication_id": build_encrypted_field(urlsafe_b64=True),
            "additional_data": {},
            "total_amount": amount,  # Use custom amount instead of price
            "is_using_autobuy": False,
            "items": [{
                "item_code": payment_target,
                "product_type": "",
                "item_price": price,
                "item_name": item_name,
                "tax": 0
            }]
        }
        
        print("Processing purchase with balance...")
        # Send payment request
        encrypted_payload = encryptsign_xdata(
            api_key=api_key,
            method="POST",
            path=settlement_path,
            id_token=tokens["id_token"],
            payload=settlement_payload
        )
        
        xtime = int(encrypted_payload["encrypted_body"]["xtime"])
        sig_time_sec = (xtime // 1000)
        x_requested_at = datetime.fromtimestamp(sig_time_sec, tz=timezone.utc).astimezone()
        settlement_payload["timestamp"] = ts_to_sign
        
        body = encrypted_payload["encrypted_body"]
        x_sig = get_x_signature_payment(
            api_key,
            tokens["access_token"],
            ts_to_sign,
            package_option_code,
            token_payment,
            "BALANCE"
        )
        
        headers = {
            "host": "api.myxl.xlaxiata.co.id",
            "content-type": "application/json; charset=utf-8",
            "user-agent": "myXL / 8.6.0(1179); com.android.vending; (samsung; SM-N935F; SDK 33; Android 13)",
            "x-api-key": API_KEY,
            "authorization": f"Bearer {tokens['id_token']}",
            "x-hv": "v3",
            "x-signature-time": str(sig_time_sec),
            "x-signature": x_sig,
            "x-request-id": str(uuid.uuid4()),
            "x-request-at": java_like_timestamp(x_requested_at),
            "x-version-app": "8.6.0",
        }
        
        url = f"{BASE_API_URL}/{settlement_path}"
        resp = requests.post(url, headers=headers, data=json.dumps(body), timeout=30)
        
        try:
            decrypted_body = decrypt_xdata(api_key, json.loads(resp.text))
            if decrypted_body.get("status") == "SUCCESS":
                return {"success": True, "data": decrypted_body}
            else:
                # Format the API error response for user-friendly display
                # Get package information for error message
                variant_name = package_details.get("package_detail_variant", {}).get("name", "")
                option_name = package_details.get("package_option", {}).get("name", "")
                package_title = f"{variant_name} {option_name}".strip()
                price = package_details.get("package_option", {}).get("price", 0)
                error_msg = format_api_error(decrypted_body, package_title, price, "Balance")
                return {"success": False, "error": error_msg}
        except Exception as e:
            return {"success": False, "error": f"Decryption error: {e}. This may indicate a network connectivity issue or server maintenance."}
            
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            return {"success": False, "error": "Too many requests. Please wait before trying again."}
        else:
            return {"success": False, "error": f"Purchase error: {e}. This may indicate a network connectivity issue, server maintenance, or temporary service disruption."}
    except Exception as e:
        return {"success": False, "error": f"Purchase error: {e}. This may indicate a network connectivity issue, server maintenance, or temporary service disruption."}

async def send_log_to_group(message: str):
    """Send log message to Telegram group"""
    global application_instance
    if application_instance and os.getenv("TELEGRAM_LOG_GROUP_ID"):
        try:
            await application_instance.bot.send_message(
                chat_id=os.getenv("TELEGRAM_LOG_GROUP_ID"),
                text=message,
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error("Failed to send log to Telegram group: %s", e)

async def send_error_to_admin(message: str):
    """Send error message to admin user"""
    global application_instance
    admin_id = os.getenv("ADMIN_ID")
    if application_instance and admin_id:
        try:
            await application_instance.bot.send_message(
                chat_id=admin_id,
                text=message,
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error("Failed to send error to admin: %s", e)

# XUT package code
PACKAGE_FAMILY_CODE = "08a3b1e6-8e78-4e45-a540-b40f06871cfe"

def get_package_xut():
    global api_key
    # Get active user from context
    # This function will be called with proper context in the bot handlers
    pass

# Global variable to store packages for reference by index
xut_packages_cache = {}

# Global variable for family packages cache (index -> package)
family_packages_cache = {}

def is_family_package(package_code: str) -> bool:
    """Check if a package is a family package by looking it up in the family_packages_cache"""
    global family_packages_cache
    for pkg in family_packages_cache.values():
        if pkg.get("code") == package_code:
            return True
    return False

def format_api_error(error_response, package_title="", price=0, payment_method="") -> str:
    """Format API error response into a user-friendly message with detailed information"""
    if isinstance(error_response, dict):
        # Extract error details
        code = error_response.get('code', 'UNKNOWN_ERROR')
        message = error_response.get('message', 'An unknown error occurred')
        description = error_response.get('description', '')
        title = error_response.get('title', package_title if package_title else 'Unknown Package')
        
        # Create user-friendly message with detailed information
        user_message = f"❌ PURCHASE_FAILED\n"
        user_message += f"🏷️ Package: {package_title if package_title else 'Unknown Package'}\n"
        user_message += f"💰 Price: Rp {price:,}\n"
        user_message += f"💳 Payment Method: {payment_method}\n"
        user_message += f"⚠️ Error Code: {code}\n"
        user_message += f"📝 Error Message: {message}\n"
        if description:
            user_message += f"📋 Details: {description}\n"
        user_message += f"🕒 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        return user_message
    else:
        # Handle string errors
        return f"❌ PURCHASE_FAILED\n\n" \
               f"🏷️ Package: {package_title if package_title else 'Unknown Package'}\n" \
               f"💰 Price: Rp {price:,}\n" \
               f"💳 Payment Method: {payment_method}\n" \
               f"⚠️ Error: {str(error_response)}\n" \
               f"🕒 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n" \
               f"💡 Please try again later."


# Bot functions
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /start is issued."""
    user = update.effective_user
    
    message = f"👋 Hi {user.first_name}! Welcome to DoyDor XL Bot.\n\n"
    message += "I can help you manage your XL account right from Telegram!\n\n"
    
    # Check if user is already logged in
    active_user = auth_instance.get_active_user(context)
    if active_user:
        message += f"✅ You're already logged in as `{active_user['number']}`\n\n"
        await show_main_menu(update, context)
        return
    else:
        message += "Use /login to start using the bot."
        
        keyboard = [
            [KeyboardButton("📱 Login")],
            [KeyboardButton("🌐 Buy VPN"), KeyboardButton("💝 Donate")],
            [KeyboardButton("ℹ️ Help")]
        ]
        reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
        
        await update.message.reply_text(message, reply_markup=reply_markup)

async def login_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Start the login process."""
    # Save user ID to database when they initiate login
    user = update.effective_user
    is_new_user = False
    
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        # Check if user already exists
        c.execute("SELECT user_id FROM users WHERE user_id = ?", (user.id,))
        existing_user = c.fetchone()
        
        # Insert user if not exists
        c.execute("INSERT OR IGNORE INTO users (user_id) VALUES (?)", (user.id,))
        conn.commit()
        
        # Check if user was newly added
        if existing_user is None:
            is_new_user = True
            
        conn.close()
    except Exception as e:
        logger.error("Error saving user ID to database: %s", e)
    
    # Send notification to group if it's a new user
    if is_new_user:
        try:
            log_message = (
                f"🆕 *NEW_USER_LOGIN_ATTEMPT*\n"
                f"👤 User: {user.first_name} (@{user.username or 'N/A'})\n"
                f"🆔 User ID: `{user.id}`\n"
                f"🕒 Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
            )
            await send_log_to_group(log_message)
        except Exception as e:
            logger.error("Error sending new user notification to group: %s", e)
    
    await update.message.reply_text(
        "📞 Please enter your XL number (e.g., 6281234567890):"
    )
    return PHONE

async def phone_received(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle phone number input."""
    phone_number = update.message.text
    
    if not phone_number.startswith("628") or len(phone_number) < 10 or len(phone_number) > 14:
        await update.message.reply_text(
            "❌ Invalid number format. Please enter a valid XL number (e.g., 6281234567890):"
        )
        return PHONE
    
    # Store phone number in context
    context.user_data['phone_number'] = phone_number
    
    # Request OTP
    try:
        subscriber_id = get_otp(phone_number)
        if not subscriber_id:
            await update.message.reply_text("❌ Failed to request OTP. Please try again later.")
            return ConversationHandler.END
            
        await update.message.reply_text("📤 OTP has been sent to your phone. Please enter the 6-digit OTP:")
        return OTP
    except ValueError as e:
        # Handle specific error messages
        error_msg = str(e)
        if "reach limit" in error_msg.lower() or "too many requests" in error_msg.lower():
            await update.message.reply_text("⏰ OTP request limit reached. Please wait a few minutes before requesting another OTP.")
        else:
            await update.message.reply_text(f"❌ {error_msg}")
        return ConversationHandler.END
    except requests.RequestException as e:
        # Handle HTTP errors like 429 specifically
        error_msg = str(e)
        if "429" in error_msg or "too many requests" in error_msg.lower():
            await update.message.reply_text("⏰ Too many requests. Please wait a moment and try again.")
        else:
            logger.error("Network error requesting OTP: %s", e, exc_info=True)
            await update.message.reply_text("❌ Network error while requesting OTP. Please check your connection and try again.")
        return ConversationHandler.END
    except Exception as e:
        logger.error("Error requesting OTP: %s", e, exc_info=True)
        await update.message.reply_text("❌ Error requesting OTP. Please check your connection and try again.")
        return ConversationHandler.END

async def otp_received(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle OTP input."""
    otp = update.message.text
    phone_number = context.user_data.get('phone_number')
    global api_key
    
    if not otp.isdigit() or len(otp) != 6:
        await update.message.reply_text("❌ Invalid OTP format. Please enter a 6-digit OTP:")
        return OTP
    
    try:
        tokens = submit_otp(api_key, phone_number, otp)
        if not tokens:
            await update.message.reply_text("❌ Failed to login. Please check your OTP and try again.")
            return ConversationHandler.END
            
        # Save tokens
        auth_instance.add_refresh_token(int(phone_number), tokens["refresh_token"])
        auth_instance.set_active_user(context, int(phone_number))
        
        # Log successful login
        user = update.effective_user
        log_message = (
            f"🔐 *NEW_LOGIN*\n"
            f"👤 User: {user.first_name} (@{user.username or 'N/A'})\n"
            f"🆔 User ID: `{user.id}`\n"
            f"📱 XL Number: `{phone_number}`\n"
            f"🕒 Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )
        user_logger.info(f"LOGIN - User: {user.id} ({user.username or 'N/A'}), XL Number: {phone_number}")
        await send_log_to_group(log_message)
        
        await update.message.reply_text("✅ Login Successful! Fetching Account...")
        
        # Show main menu
        await show_main_menu(update, context)
        return ConversationHandler.END
    except requests.RequestException as e:
        # Handle HTTP errors like 429 specifically
        error_msg = str(e)
        if "429" in error_msg or "too many requests" in error_msg.lower():
            await update.message.reply_text("⏰ Too many requests. Please wait a moment and try again.")
        else:
            logger.error("Network error submitting OTP: %s", e, exc_info=True)
            await update.message.reply_text("❌ Network error during login. Please try again.")
        return ConversationHandler.END
    except ValueError as e:
        # Handle specific value errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            await update.message.reply_text("⏰ Too many requests. Please wait a moment and try again.")
        else:
            logger.error("Value error submitting OTP: %s", e, exc_info=True)
            await update.message.reply_text("❌ Error during login. Please try again.")
        return ConversationHandler.END
    except Exception as e:
        logger.error("Error submitting OTP: %s", e)
        await update.message.reply_text("❌ Error during login. Please try again.")
        return ConversationHandler.END

async def show_main_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Display main menu."""
    keyboard = [
        [KeyboardButton("💰 Account Info")],
        [KeyboardButton("📦 My Packages")],
        [KeyboardButton("🛒 Buy Packages")],
        [KeyboardButton("🌐 Buy VPN"), KeyboardButton("💝 Donate")],
        [KeyboardButton("🚪 Logout"), KeyboardButton("🚪 Pilih Nomor")]
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    
    # Get user info
    user = auth_instance.get_active_user(context)
    if user:
        try:
            global api_key
            balance_data = get_balance(api_key, user["tokens"]["id_token"])
            if balance_data:
                balance_remaining = balance_data.get("remaining", "N/A")
                balance_expired_at = balance_data.get("expired_at", "N/A")
                
                # Convert timestamp to readable date format
                if isinstance(balance_expired_at, (int, float)) and balance_expired_at != "N/A":
                    try:
                        from datetime import datetime
                        expired_at_dt = datetime.fromtimestamp(balance_expired_at).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        expired_at_dt = str(balance_expired_at)
                else:
                    expired_at_dt = str(balance_expired_at)
                
                message = "📱 *Account Information*\n"
                message += f"🔢 Number: `{user['number']}`\n"
                message += f"💸 Balance: `Rp {balance_remaining:,}`\n"
                message += f"📅 Active Until: `{expired_at_dt}`\n\n"
                message += "📋 *Please select an option:*"
            else:
                # Even if balance data is not available, still show the menu
                message = f"📱 *Account Information*\n"
                message += f"✅ Logged in as: `{user['number']}`\n"
                message += "⚠️ Unable to fetch balance information. Please try again later.\n\n"
                message += "📋 *Please select an option:*"
        except ValueError as e:
            # Handle rate limit errors specifically
            error_msg = str(e)
            if "too many requests" in error_msg.lower():
                message = f"📱 *Account Information*\n"
                message += f"✅ Logged in as: `{user['number']}`\n"
                message += "⏰ Rate limit reached. Please wait a moment and try again.\n\n"
                message += "📋 *Please select an option:*"
            else:
                message = f"📱 *Account Information*\n"
                message += f"✅ Logged in as: `{user['number']}`\n"
                message += "⚠️ Error fetching account information\n\n"
                message += "📋 *Please select an option:*"
        except Exception as e:
            logger.error("Error fetching account info: %s", e, exc_info=True)
            message = f"📱 *Account Information*\n"
            message += f"✅ Logged in as: `{user['number']}`\n"
            message += "⚠️ Error fetching account information\n\n"
            message += "📋 *Please select an option:*"
    else:
        message = "📋 *Please select an option:*"
    
    await update.message.reply_text(message, reply_markup=reply_markup, parse_mode='Markdown')

async def handle_menu_selection(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle menu selections."""
    text = update.message.text
    
    # Check if we're waiting for a family code input
    if context.user_data.get('awaiting_family_code'):
        family_code = text.strip()
        # Clear the awaiting flag
        context.user_data['awaiting_family_code'] = False
        # Get enterprise mode
        is_enterprise = context.user_data.get('is_enterprise', False)
        # Clear the enterprise flag
        if 'is_enterprise' in context.user_data:
            del context.user_data['is_enterprise']
        # Show packages for the provided family code
        # We need to simulate a callback query here
        class MockQuery:
            def __init__(self, message):
                self.message = message
                
        mock_query = MockQuery(update.message)
        if is_enterprise:
            await show_enterprise_family_packages(update, context, mock_query, family_code)
        else:
            await show_family_packages(update, context, mock_query, family_code)
        return
    
    # Check if we're waiting for value input for a family package
    pending_payment = context.user_data.get('pending_payment')
    if pending_payment and pending_payment.get('awaiting_value_input'):
        try:
            value_input = int(text.strip())
            original_price = pending_payment['original_price']
            
            # Clear the awaiting flag
            del context.user_data['pending_payment']
            
            # Use the input value or original price
            amount = value_input if value_input > 0 else original_price
            
            # Process the payment with the specified amount
            await process_family_payment(update, context, pending_payment['package'], 
                                        pending_payment['payment_method'], amount)
            return
        except ValueError:
            await update.message.reply_text("❌ Invalid input. Please enter a valid number.")
            return
            
    elif text == "🚪 Pilih Nomor":
        await show_account_management(update, context)
    if text == "💰 Account Info":
        await show_account_info(update, context)
    elif text == "📦 My Packages":
        await show_my_packages(update, context)
    elif text == "🛒 Buy Packages":
        await show_buy_packages_menu(update, context)
    elif text == "🌐 Buy VPN":
        await show_vpn_info(update, context)
    elif text == "💝 Donate":
        await show_donation_info(update, context)
    elif text == "🚪 Logout":
        await logout(update, context)
    elif text == "📱 Login":
        await login_start(update, context)
    elif text == "ℹ️ Help":
        await help_command(update, context)
    else:
        await update.message.reply_text("❓ Unknown option. Please use the menu buttons.")


    async def show_account_management(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user = auth_instance.get_active_user(context)
        
        if not saved_accounts:
            await update.callback_query.edit_message_text("❌ Tidak ada akun tersimpan")
            return

        keyboard = []
        for i, account in enumerate(saved_accounts, 1):
            is_active = USER_TOKENS.get(user_id, {}).get('phone_number') == account['phone_number']
            status = " ✅" if is_active else ""
            keyboard.append([InlineKeyboardButton(f"{i}. {account['phone_number']}{status}", callback_data=f"manage_account_{i}")])
        
        keyboard.append([InlineKeyboardButton("🔙 Kembali", callback_data="settings_back")])
        
        await update.callback_query.edit_message_text(
            "👥 Akun Tersimpan:",
            reply_markup=InlineKeyboardMarkup(keyboard)

async def show_account_info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show account information."""
    global api_key
    user = auth_instance.get_active_user(context)
    if not user:
        await update.message.reply_text("❌ No active user found. Please login first.")
        return
        
    try:
        balance_data = get_balance(api_key, user["tokens"]["id_token"])
        if balance_data:
            balance_remaining = balance_data.get("remaining", "N/A")
            balance_expired_at = balance_data.get("expired_at", "N/A")
            
            # Convert timestamp to readable date format
            if isinstance(balance_expired_at, (int, float)) and balance_expired_at != "N/A":
                try:
                    from datetime import datetime
                    expired_at_dt = datetime.fromtimestamp(balance_expired_at).strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    expired_at_dt = str(balance_expired_at)
            else:
                expired_at_dt = str(balance_expired_at)
            
            message = "📱 *Account Information*\n"
            message += f"🔢 Number: `{user['number']}`\n"
            message += f"💸 Balance: `Rp {balance_remaining:,}`\n"
            message += f"📅 Active Until: `{expired_at_dt}`"
        else:
            message = f"📱 *Account Information*\n🔢 Number: `{user['number']}`\n⚠️ Unable to fetch balance information. Please try again later."
            
        await update.message.reply_text(message, parse_mode='Markdown')
    except ValueError as e:
        # Handle rate limit errors specifically
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            await update.message.reply_text("⏰ Rate limit reached. Please wait a moment and try again.")
        else:
            logger.error("Error fetching account info: %s", e, exc_info=True)
            await update.message.reply_text("❌ Error fetching account information.")
    except Exception as e:
        logger.error("Error fetching account info: %s", e, exc_info=True)
        await update.message.reply_text("❌ Error fetching account information.")

async def show_my_packages(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show user's packages."""
    global api_key
    user = auth_instance.get_active_user(context)
    if not user:
        await update.message.reply_text("❌ No active user found. Please login first.")
        return
    
    try:
        quotas = fetch_my_packages(api_key, user["tokens"])
        if not quotas:
            await update.message.reply_text("❌ Failed to fetch your packages.")
            return
            
        message = "📦 *My Packages*\n\n"
        
        num = 1
        for quota in quotas:
            quota_code = quota["quota_code"]
            name = quota["name"]
            
            # Get package details
            try:
                package_details = get_package(api_key, user["tokens"], quota_code)
                if package_details:
                    # Extract package information
                    name1 = package_details.get("package_family", {}).get("name", "")
                    name2 = package_details.get("package_detail_variant", {}).get("name", "")
                    name3 = package_details.get("package_option", {}).get("name", "")
                    
                    full_name = f"{name1} {name2} {name3}".strip()
                    if full_name:
                        name = full_name
                        
                    # Get validity
                    validity = package_details["package_option"].get("validity", "N/A")
                    
                    # Format benefits
                    benefits_text = ""
                    benefits = package_details["package_option"].get("benefits", [])
                    if benefits and isinstance(benefits, list):
                        for benefit in benefits:
                            benefit_name = benefit.get('name', 'Unknown')
                            benefit_total = benefit.get('total', 0)
                            
                            if "Call" in benefit_name:
                                minutes = benefit_total / 60
                                benefits_text += f"📞 {benefit_name}: {minutes:.0f} minutes\n"
                            else:
                                if benefit_total > 0:
                                    if benefit_total >= 1_000_000_000:
                                        quota_gb = benefit_total / (1024 ** 3)
                                        benefits_text += f"📊 {benefit_name}: {quota_gb:.2f} GB\n"
                                    elif benefit_total >= 1_000_000:
                                        quota_mb = benefit_total / (1024 ** 2)
                                        benefits_text += f"📊 {benefit_name}: {quota_mb:.2f} MB\n"
                                    elif benefit_total >= 1_000:
                                        quota_kb = benefit_total / 1024
                                        benefits_text += f"📊 {benefit_name}: {quota_kb:.2f} KB\n"
                                    else:
                                        benefits_text += f"📊 {benefit_name}: {benefit_total}\n"
                    
                    message += f"*Package {num}*\n"
                    message += f"🏷️ Name: `{name}`\n"
                    message += f"📅 Validity: `{validity}`\n"
                    if benefits_text:
                        message += f"🎁 Benefits:\n{benefits_text}"
                    message += "➖➖➖➖➖\n"
                else:
                    message += f"*Package {num}*\n"
                    message += f"🏷️ Name: `{name}`\n"
                    message += "➖➖➖➖➖\n"
            except ValueError as e:
                # Handle rate limit errors
                error_msg = str(e)
                if "too many requests" in error_msg.lower():
                    await update.message.reply_text("⏰ Too many requests. Please wait a moment and try again.")
                    return
                else:
                    logger.error("Error fetching package details: %s", e, exc_info=True)
                    message += f"*Package {num}*\n"
                    message += f"🏷️ Name: `{name}`\n"
                    message += "➖➖➖➖➖\n"
            except Exception as e:
                logger.error("Error fetching package details: %s", e, exc_info=True)
                message += f"*Package {num}*\n"
                message += f"🏷️ Name: `{name}`\n"
                message += "➖➖➖➖➖\n"
            
            num += 1
        
        await update.message.reply_text(message, parse_mode='Markdown')
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            await update.message.reply_text("⏰ Too many requests. Please wait a moment and try again.")
        else:
            logger.error("Error fetching my packages: %s", e, exc_info=True)
            await update.message.reply_text("❌ Error fetching your packages.")
    except Exception as e:
        logger.error("Error fetching my packages: %s", e, exc_info=True)
        await update.message.reply_text("❌ Error fetching your packages.")

async def show_buy_packages_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show buy packages menu."""
    # Check if user is logged in
    user = auth_instance.get_active_user(context)
    if not user:
        await update.message.reply_text("❌ Please login first to buy packages.")
        return
    
    keyboard = [
        [InlineKeyboardButton("🔥 XUT Packages", callback_data="buy_xut")],
        [InlineKeyboardButton("👨‍👩‍👧‍👦 Buy by Family Code (YTTA)", callback_data="buy_family_code")],
        [InlineKeyboardButton("🏢 Buy by Family Code (Enterprise)", callback_data="buy_family_code_enterprise")],
        [InlineKeyboardButton("🔙 Back", callback_data="main_menu")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    message = "🛒 *Buy Packages*\n\n"
    message += "Please select a package category:"
    
    await update.message.reply_text(message, reply_markup=reply_markup, parse_mode='Markdown')

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle button presses."""
    query = update.callback_query
    await query.answer()
    
    if query.data == "buy_xut":
        await show_xut_packages(update, context, query)
    elif query.data == "buy_family_code":
        # Ask user for family code
        await query.message.reply_text("👨‍👩‍👧‍👦 Please enter the Family Code:")
        # Set state to expect family code input
        context.user_data['awaiting_family_code'] = True
        # Set enterprise mode to False
        context.user_data['is_enterprise'] = False
    elif query.data == "buy_family_code_enterprise":
        # Ask user for family code for enterprise packages
        await query.message.reply_text("🏢 Please enter the Enterprise Family Code:")
        # Set state to expect family code input
        context.user_data['awaiting_family_code'] = True
        # Set enterprise mode to True
        context.user_data['is_enterprise'] = True
    elif query.data.startswith("pkg_"):
        # Handle package selection with index-based approach
        try:
            # Extract package index
            package_index = int(query.data[4:])  # Remove "pkg_" prefix
            # Get package from cache
            if package_index in xut_packages_cache:
                package = xut_packages_cache[package_index]
                await show_package_details(update, context, query, package)
            else:
                await query.message.reply_text("❌ Package not found. Please try again.")
        except Exception as e:
            logger.error("Error handling package selection: %s", e, exc_info=True)
            await query.message.reply_text("❌ Error handling package selection. Please try again.")
    elif query.data.startswith("family_pkg_"):
        # Handle family package selection
        try:
            # Extract package index
            package_index = int(query.data[11:])  # Remove "family_pkg_" prefix
            # Get package from cache
            if package_index in family_packages_cache:
                package = family_packages_cache[package_index]
                await show_package_details(update, context, query, package)
            else:
                await query.message.reply_text("❌ Package not found. Please try again.")
        except requests.RequestException as e:
            logger.error("Network error handling family package selection: %s", e, exc_info=True)
            await query.message.reply_text("❌ Network error. Please check your connection and try again.")
        except Exception as e:
            logger.error("Error handling family package selection: %s", e, exc_info=True)
            await query.message.reply_text("❌ Error handling family package selection. Please try again.")
    elif query.data.startswith("pay_"):
        # Handle payment method selection
        try:
            parts = query.data.split("_")
            payment_method = parts[1]
            package_index = int(parts[2])  # Get package index
            # Get package from cache
            package = None
            if package_index in xut_packages_cache:
                package = xut_packages_cache[package_index]
            elif package_index in family_packages_cache:
                package = family_packages_cache[package_index]
            
            if package:
                await process_payment(update, context, query, payment_method, package)
            else:
                await query.message.reply_text("❌ Package not found. Please try again.")
        except Exception as e:
            logger.error("Error handling payment selection: %s", e, exc_info=True)
            await query.message.reply_text("❌ Error handling payment selection. Please try again.")
    elif query.data == "main_menu":
        # Show main menu
        await show_main_menu_query(update, context, query)

async def show_main_menu_query(update: Update, context: ContextTypes.DEFAULT_TYPE, query) -> None:
    """Display main menu from a callback query."""
    keyboard = [
        [KeyboardButton("💰 Account Info")],
        [KeyboardButton("📦 My Packages")],
        [KeyboardButton("🛒 Buy Packages")],
        [KeyboardButton("🌐 Buy VPN"), KeyboardButton("💝 Donate")],
        [KeyboardButton("🚪 Logout"), KeyboardButton("🚪 Pilih Nomor")]]
    
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    
    # Get user info
    user = auth_instance.get_active_user(context)
    if user:
        try:
            global api_key
            balance_data = get_balance(api_key, user["tokens"]["id_token"])
            if balance_data:
                balance_remaining = balance_data.get("remaining", "N/A")
                balance_expired_at = balance_data.get("expired_at", "N/A")
                
                # Convert timestamp to readable date format
                if isinstance(balance_expired_at, (int, float)) and balance_expired_at != "N/A":
                    try:
                        from datetime import datetime
                        expired_at_dt = datetime.fromtimestamp(balance_expired_at).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        expired_at_dt = str(balance_expired_at)
                else:
                    expired_at_dt = str(balance_expired_at)
                
                message = "📱 *Account Information*\n"
                message += f"🔢 Number: `{user['number']}`\n"
                message += f"💸 Balance: `Rp {balance_remaining:,}`\n"
                message += f"📅 Active Until: `{expired_at_dt}`\n\n"
                message += "📋 *Please select an option:*"
            else:
                message = "📋 *Please select an option:*"
        except Exception as e:
            logger.error("Error fetching account info: %s", e)
            message = "❌ Error fetching account information.\n\n📋 *Please select an option:*"
    else:
        message = "📋 *Please select an option:*"
    
    await query.message.reply_text(message, reply_markup=reply_markup, parse_mode='Markdown')

def get_package_xut_for_user(context: ContextTypes.DEFAULT_TYPE):
    """Get XUT packages for the current user"""
    global api_key
    user = auth_instance.get_active_user(context)
    if not user:
        print("No active user found.")
        return None
    
    tokens = user["tokens"]
    packages = []
    
    try:
        data = get_family(api_key, tokens, PACKAGE_FAMILY_CODE)
        if not data:
            return None
            
        package_variants = data["package_variants"]
        start_number = 1
        for variant in package_variants:
            for option in variant["package_options"]:
                friendly_name = option["name"]
                
                if friendly_name.lower() == "vidio":
                    friendly_name = "🔥 HOT! Unli Turbo Vidio"
                if friendly_name.lower() == "iflix":
                    friendly_name = "🔥 HOT! Unli Turbo Iflix"
                    
                packages.append({
                    "number": start_number,
                    "name": friendly_name,
                    "price": option["price"],
                    "code": option["package_option_code"]
                })
                
                start_number += 1
        return packages
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            print("Rate limit exceeded when fetching XUT packages")
            raise ValueError("Too many requests. Please wait before trying again.")
        else:
            logger.error("Error fetching XUT packages: %s", e, exc_info=True)
            return None
    except Exception as e:
        logger.error("Error fetching XUT packages: %s", e, exc_info=True)
        return None

def get_packages_by_family_code_for_user(context: ContextTypes.DEFAULT_TYPE, family_code: str, is_enterprise: bool = False):
    """Get packages for the current user by family code"""
    global api_key
    user = auth_instance.get_active_user(context)
    if not user:
        print("No active user found.")
        return None
    
    tokens = user["tokens"]
    packages = []
    
    try:
        # Modify the get_family call to support is_enterprise parameter
        print("Fetching package family...")
        path = "api/v8/xl-stores/options/list"
        id_token = tokens.get("id_token")
        payload_dict = {
            "is_show_tagging_tab": True,
            "is_dedicated_event": True,
            "is_transaction_routine": False,
            "migration_type": "NONE",
            "package_family_code": family_code,
            "is_autobuy": False,
            "is_enterprise": is_enterprise,  # Use the is_enterprise parameter
            "is_pdlp": True,
            "referral_code": "",
            "is_migration": False,
            "lang": "en"
        }
        
        res = send_api_request(api_key, path, payload_dict, id_token, "POST")
        if res.get("status") != "SUCCESS":
            print(f"Failed to get family {family_code}")
            print(json.dumps(res, indent=2))
            return None
            
        data = res["data"]
        
        if not data:
            print(f"Failed to fetch family data for code: {family_code}")
            return None
            
        package_variants = data["package_variants"]
        start_number = 1
        for variant in package_variants:
            for option in variant["package_options"]:
                friendly_name = option["name"]
                    
                packages.append({
                    "number": start_number,
                    "name": friendly_name,
                    "price": option["price"],
                    "code": option["package_option_code"]
                })
                
                start_number += 1
        return packages
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            print("Rate limit exceeded when fetching family packages")
            raise ValueError("Too many requests. Please wait before trying again.")
        else:
            logger.error("Error fetching packages by family code: %s", e, exc_info=True)
            print(f"Error fetching packages for family code {family_code}: {str(e)}")
            return None
    except Exception as e:
        logger.error("Error fetching packages by family code: %s", e, exc_info=True)
        print(f"Error fetching packages for family code {family_code}: {str(e)}")
        return None

async def show_xut_packages(update: Update, context: ContextTypes.DEFAULT_TYPE, query) -> None:
    """Show XUT packages."""
    user = auth_instance.get_active_user(context)
    if not user:
        await query.message.reply_text("❌ No active user found. Please login first.")
        return
        
    try:
        packages = get_package_xut_for_user(context)
        if not packages:
            await query.message.reply_text("❌ Failed to fetch XUT packages.")
            return
            
        # Clear and update package cache
        global xut_packages_cache
        xut_packages_cache.clear()
        
        keyboard = []
        for i, pkg in enumerate(packages):
            # Store package in cache with index as key
            xut_packages_cache[i] = pkg
            
            # Use shorter callback data with index
            button = InlineKeyboardButton(
                f"{pkg['name']} - Rp {pkg['price']:,}", 
                callback_data=f"pkg_{i}"
            )
            keyboard.append([button])
        
        # Add back button
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="main_menu")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        message = "🔥 *XUT Packages*\n\n"
        message += "Please select a package to purchase:"
        
        await query.message.reply_text(message, reply_markup=reply_markup, parse_mode='Markdown')
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            await query.message.reply_text("⏰ Too many requests. Please wait a moment and try again.")
        else:
            logger.error("Error fetching XUT packages: %s", e, exc_info=True)
            await query.message.reply_text("❌ Error fetching XUT packages.")
    except Exception as e:
        logger.error("Error fetching XUT packages: %s", e, exc_info=True)
        await query.message.reply_text("❌ Error fetching XUT packages.")

async def show_family_packages(update: Update, context: ContextTypes.DEFAULT_TYPE, query, family_code: str) -> None:
    """Show packages by family code."""
    user = auth_instance.get_active_user(context)
    if not user:
        await query.message.reply_text("❌ No active user found. Please login first.")
        return
        
    try:
        packages = get_packages_by_family_code_for_user(context, family_code)
        if not packages:
            await query.message.reply_text("❌ Failed to fetch packages for the provided family code.\n\n"
                                         "Possible reasons:\n"
                                         "• Invalid family code\n"
                                         "• Family code has expired\n"
                                         "• Network connectivity issues\n"
                                         "• Server maintenance\n\n"
                                         "Please verify your family code and try again.")
            return
            
        # Clear and update package cache
        global family_packages_cache
        family_packages_cache.clear()
        
        keyboard = []
        for i, pkg in enumerate(packages):
            # Store package in cache with index as key
            family_packages_cache[i] = pkg
            
            # Use shorter callback data with index
            button = InlineKeyboardButton(
                f"{pkg['name']} - Rp {pkg['price']:,}", 
                callback_data=f"family_pkg_{i}"
            )
            keyboard.append([button])
        
        # Add back button
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="main_menu")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        message = "👨‍👩‍👧‍👦 *Family Packages*\n\n"
        message += "Please select a package to purchase:"
        
        await query.message.reply_text(message, reply_markup=reply_markup, parse_mode='Markdown')
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            await query.message.reply_text("⏰ Too many requests. Please wait a moment and try again.")
        else:
            logger.error("Error fetching family packages: %s", e, exc_info=True)
            await query.message.reply_text("❌ Error fetching family packages.\n\n")
    except Exception as e:
        logger.error("Error fetching family packages: %s", e, exc_info=True)
        await query.message.reply_text("❌ Error fetching family packages.\n\n")

async def show_enterprise_family_packages(update: Update, context: ContextTypes.DEFAULT_TYPE, query, family_code: str) -> None:
    """Show enterprise packages by family code."""
    user = auth_instance.get_active_user(context)
    if not user:
        await query.message.reply_text("❌ No active user found. Please login first.")
        return
        
    try:
        # Use the is_enterprise parameter
        packages = get_packages_by_family_code_for_user(context, family_code, is_enterprise=True)
        if not packages:
            await query.message.reply_text("❌ Failed to fetch enterprise packages for the provided family code.\n\n"
            )
            return
            
        # Clear and update package cache
        global family_packages_cache
        family_packages_cache.clear()
        
        keyboard = []
        for i, pkg in enumerate(packages):
            # Store package in cache with index as key
            family_packages_cache[i] = pkg
            
            # Use shorter callback data with index
            button = InlineKeyboardButton(
                f"{pkg['name']} - Rp {pkg['price']:,}", 
                callback_data=f"family_pkg_{i}"
            )
            keyboard.append([button])
        
        # Add back button
        keyboard.append([InlineKeyboardButton("🔙 Back", callback_data="main_menu")])
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        message = "🏢 *Enterprise Family Packages*\n\n"
        message += "Please select a package to purchase:"
        
        await query.message.reply_text(message, reply_markup=reply_markup, parse_mode='Markdown')
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            await query.message.reply_text("⏰ Too many requests. Please wait a moment and try again.")
        else:
            logger.error("Error fetching enterprise family packages: %s", e, exc_info=True)
            await query.message.reply_text("❌ Error fetching enterprise family packages.\n\n")
    except Exception as e:
        logger.error("Error fetching enterprise family packages: %s", e, exc_info=True)
        await query.message.reply_text("❌ Error fetching enterprise family packages.\n\n")

async def show_package_details(update: Update, context: ContextTypes.DEFAULT_TYPE, query, package) -> None:
    """Show package details with T&C."""
    user = auth_instance.get_active_user(context)
    if not user:
        await query.message.reply_text("❌ No active user found. Please login first.")
        return
    
    try:
        package_code = package["code"]
        global api_key
        package_details = get_package(api_key, user["tokens"], package_code)
        if not package_details:
            await query.message.reply_text("❌ Failed to load package details.")
            return
            
        # Extract package information
        name1 = package_details.get("package_family", {}).get("name", "")  # Unlimited Turbo
        name2 = package_details.get("package_detail_variant", {}).get("name", "")  # For Xtra Combo
        name3 = package_details.get("package_option", {}).get("name", "")  # Vidio
        
        title = f"{name1} {name2} {name3}".strip()
        price = package_details["package_option"]["price"]
        validity = package_details["package_option"]["validity"]
        token_confirmation = package_details["token_confirmation"]
        tnc = package_details["package_option"].get("tnc", "No terms and conditions available")
        
        # Clean up HTML in T&C
        import re
        clean_tnc = re.sub('<[^<]+?>', '', tnc).strip()
        if len(clean_tnc) > 500:  # Limit T&C length for readability
            clean_tnc = clean_tnc[:500] + "..."
        
        # Find package index in cache
        global xut_packages_cache, family_packages_cache
        package_index = None
        # Check in XUT packages cache first
        for idx, pkg in xut_packages_cache.items():
            if pkg["code"] == package_code:
                package_index = idx
                break
        
        # If not found, check in family packages cache
        if package_index is None:
            for idx, pkg in family_packages_cache.items():
                if pkg["code"] == package_code:
                    package_index = idx
                    break
        
        if package_index is None:
            await query.message.reply_text("❌ Package not found in cache.")
            return
        
        # Store package info in context
        context.user_data['current_package'] = {
            'index': package_index,
            'code': package_code,
            'title': title,
            'price': price,
            'validity': validity,
            'token_confirmation': token_confirmation
        }
        
        # Format benefits
        benefits_text = ""
        benefits = package_details["package_option"].get("benefits", [])
        if benefits and isinstance(benefits, list):
            benefits_text = "\n🎁 *Package Benefits:*\n"
            for benefit in benefits:
                benefit_name = benefit.get('name', 'Unknown')
                benefit_total = benefit.get('total', 0)
                
                if "Call" in benefit_name:
                    minutes = benefit_total / 60
                    benefits_text += f"📞 {benefit_name}: {minutes:.0f} minutes\n"
                else:
                    if benefit_total > 0:
                        if benefit_total >= 1_000_000_000:
                            quota_gb = benefit_total / (1024 ** 3)
                            benefits_text += f"📊 {benefit_name}: {quota_gb:.2f} GB\n"
                        elif benefit_total >= 1_000_000:
                            quota_mb = benefit_total / (1024 ** 2)
                            benefits_text += f"📊 {benefit_name}: {quota_mb:.2f} MB\n"
                        elif benefit_total >= 1_000:
                            quota_kb = benefit_total / 1024
                            benefits_text += f"📊 {benefit_name}: {quota_kb:.2f} KB\n"
                        else:
                            benefits_text += f"📊 {benefit_name}: {benefit_total}\n"
        
        # Create payment buttons with package index
        keyboard = [
            [InlineKeyboardButton("💳 Pay with Balance", callback_data=f"pay_BALANCE_{package_index}")],
            [InlineKeyboardButton("📱 Pay with QRIS", callback_data=f"pay_QRIS_{package_index}")],
            [InlineKeyboardButton("🔙 Back", callback_data="buy_xut")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        message = f"📦 *Package Details*\n\n"
        message += f"🏷️ Name: `{title}`\n"
        message += f"💰 Price: `Rp {price:,}`\n"
        message += f"⏰ Validity: `{validity}`\n"
        message += benefits_text
        message += f"\n📜 *Terms & Conditions:*\n{clean_tnc}\n"
        message += "\n\n💳 *Select Payment Method:*"
        
        await query.message.reply_text(message, reply_markup=reply_markup, parse_mode='Markdown')
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            await query.message.reply_text("⏰ Too many requests. Please wait a moment and try again.")
        else:
            logger.error("Error fetching package details: %s", e, exc_info=True)
            await query.message.reply_text("❌ Error fetching package details.")
    except Exception as e:
        logger.error("Error fetching package details: %s", e, exc_info=True)
        await query.message.reply_text("❌ Error fetching package details.")

async def process_payment(update: Update, context: ContextTypes.DEFAULT_TYPE, query, payment_method, package) -> None:
    """Process package payment."""
    user = auth_instance.get_active_user(context)
    if not user:
        await query.message.reply_text("❌ No active user found. Please login first.")
        return
    
    try:
        package_code = package["code"]
        title = package["name"]
        price = package["price"]
        
        # Get token confirmation from package details
        global api_key
        package_details = get_package(api_key, user["tokens"], package_code)
        if not package_details:
            await query.message.reply_text("❌ Failed to load package details.\n\n"
                                         "Possible reasons:\n"
                                         "• Package no longer available\n"
                                         "• Network connectivity issues\n"
                                         "• Invalid package code\n"
                                         "• Server maintenance\n\n"
                                         "Please try again later or select a different package.")
            return
            
        token_confirmation = package_details["token_confirmation"]
        
        if payment_method == "BALANCE":
            # Check if this is a family package and ask for value input
            if is_family_package(package_code):
                # Ask user for value input
                await query.message.reply_text(f"👨‍👩‍👧‍👦 Family Package detected.\n\nPackage price is Rp {price:,}.\nPlease enter the value you want to pay (or press 0 to use the original price):")
                # Store package info and payment method in context for later use
                context.user_data['pending_payment'] = {
                    'package': package,
                    'payment_method': payment_method,
                    'original_price': price,
                    'awaiting_value_input': True
                }
                return
            
            await query.message.reply_text("💳 Processing payment with balance...")
            
            # Actually process the payment
            result = purchase_package_with_balance(
                api_key, 
                user["tokens"], 
                package_code
            )
            
            # Log purchase attempt
            tg_user = update.effective_user
            if result["success"]:
                log_message = (
                    f"✅ *PURCHASE_SUCCESS*\n"
                    f"👤 User: {tg_user.first_name} (@{tg_user.username or 'N/A'})\n"
                    f"🆔 User ID: `{tg_user.id}`\n"
                    f"📱 XL Number: `{user['number']}`\n"
                    f"🏷️ Package: `{package_title if package_title else 'Unknown Package'}`\n"
                    f"💰 Price: `Rp {price:,}`\n"
                    f"💳 Method: `Balance`\n"
                    f"🕒 Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
                )
                user_logger.info(f"PURCHASE_SUCCESS - User: {tg_user.id} ({tg_user.username or 'N/A'}), "
                               f"XL Number: {user['number']}, Package: {title}, Price: Rp {price:,}, "
                               f"Method: BALANCE")
                
                message = f"✅ Successfully purchased package!\n\n"
                message += f"🏷️ Package: `{title}`\n"
                message += f"💰 Price: `Rp {price:,}`\n"
                message += f"💳 Payment Method: Balance\n\n"
                message += "📲 Please check your XL app for confirmation."
            else:
                log_message = (
                    f"❌ *PURCHASE_FAILED*\n"
                    f"👤 User: {tg_user.first_name} (@{tg_user.username or 'N/A'})\n"
                    f"🆔 User ID: `{tg_user.id}`\n"
                    f"📱 XL Number: `{user['number']}`\n"
                    f"🏷️ Package: `{package_title if package_title else 'Unknown Package'}`\n"
                    f"💰 Price: `Rp {price:,}`\n"
                    f"💳 Method: `Balance`\n"
                    f"⚠️ Error: `{result.get('error', 'Unknown error')}`\n"
                    f"🕒 Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
                )
                # Extract just the error message for logging
                error_msg = result.get('error', 'Unknown error')
                if error_msg.startswith('❌ Purchase failed'):
                    # Extract the core error details for logging
                    lines = error_msg.split('\n')
                    if len(lines) > 2:
                        core_error = lines[0]  # First line contains the main error
                    else:
                        core_error = error_msg
                else:
                    core_error = error_msg
                user_logger.info(f"PURCHASE_FAILED - User: {tg_user.id} ({tg_user.username or 'N/A'}), "
                               f"XL Number: {user['number']}, Package: {title}, Price: Rp {price:,}, "
                               f"Method: BALANCE, Error: {core_error}")
                
                # Format error message with detailed information using format_api_error
                error_content = result.get('error', 'Unknown error')
                # If the error is already formatted, use it as is
                if error_content.startswith("❌ PURCHASE_FAILED"):
                    message = error_content
                else:
                    # Otherwise format it with our enhanced format
                    message = format_api_error(error_content, title, price, "Balance")
            
            # Send log to Telegram group
            await send_log_to_group(log_message)
            
            # Add back button
            keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await query.message.reply_text(message, reply_markup=reply_markup, parse_mode='Markdown')
        elif payment_method == "QRIS":
            # Check if this is a family package and ask for value input
            if is_family_package(package_code):
                # Ask user for value input
                await query.message.reply_text(f"👨‍👩‍👧‍👦 Family Package detected.\n\nPackage price is Rp {price:,}.\nPlease enter the value you want to pay (or press 0 to use the original price):")
                # Store package info and payment method in context for later use
                context.user_data['pending_payment'] = {
                    'package': package,
                    'payment_method': payment_method,
                    'original_price': price,
                    'awaiting_value_input': True
                }
                return
            
            await query.message.reply_text("📱 Generating QRIS payment code...")
            
            # Get payment methods
            payment_methods_data = get_payment_methods(
                api_key, 
                user["tokens"], 
                token_confirmation, 
                package_code
            )
            
            if not payment_methods_data:
                await query.message.reply_text("❌ Failed to fetch payment methods.\n\n"
                                             "Possible reasons:\n"
                                             "• Network connectivity issues\n"
                                             "• Package no longer available\n"
                                             "• Server maintenance\n"
                                             "• Invalid package code\n\n"
                                             "Please try again later or select a different package.")
                return
                
            token_payment = payment_methods_data["token_payment"]
            ts_to_sign = payment_methods_data["timestamp"]
            
            # Process QRIS payment
            transaction_id = settlement_qris(
                api_key,
                user["tokens"],
                token_payment,
                ts_to_sign,
                package_code,
                price,
                title
            )
            
            if not transaction_id:
                error_message = "Failed to create QRIS transaction"
                message = format_api_error(error_message, title, price, "QRIS")
                await query.message.reply_text(message)
                return
                
            # Get QRIS code
            qris_code = get_qris_code(api_key, user["tokens"], transaction_id)
            if not qris_code:
                error_message = "Failed to get QRIS code"
                message = format_api_error(error_message, title, price, "QRIS")
                await query.message.reply_text(message)
                return
                message += f"💡 Please try again later or use a different payment method."
                await query.message.reply_text(message)
                return
                
            # Create QR code image
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(qris_code)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Save to bytes
            bio = BytesIO()
            img.save(bio, format='PNG')
            bio.seek(0)
            
            # Send QR code image
            await update.effective_message.reply_photo(photo=bio, filename='qris_payment.png')
            
            # Send payment details with expiration notice
            current_time = datetime.now().strftime("%H:%M:%S")
            expiration_time = (datetime.now() + timedelta(minutes=5)).strftime("%H:%M:%S")
            
            message = f"📱 *QRIS Payment*\n\n"
            message += f"🏷️ Package: `{title}`\n"
            message += f"💰 Price: `Rp {price:,}`\n"
            message += f"🕒 Generated at: `{current_time}`\n"
            message += f"⚠️ Expires at: `{expiration_time}` (5 minutes from now)\n\n"
            message += "Scan the QR code above with your e-wallet app to complete the payment.\n\n"
            message += "⚠️ This payment method requires you to complete the transaction within 5 minutes."
            
            # Log QRIS payment generation
            tg_user = update.effective_user
            log_message = (
                f"📱 *QRIS_GENERATED*\n"
                f"👤 User: {tg_user.first_name} (@{tg_user.username or 'N/A'})\n"
                f"🆔 User ID: `{tg_user.id}`\n"
                f"📱 XL Number: `{user['number']}`\n"
                f"🏷️ Package: `{title}`\n"
                f"💰 Price: `Rp {price:,}`\n"
                f"🕒 Generated: `{current_time}`\n"
                f"⏰ Expires: `{expiration_time}`"
            )
            user_logger.info(f"QRIS_GENERATED - User: {tg_user.id} ({tg_user.username or 'N/A'}), "
                           f"XL Number: {user['number']}, Package: {title}, Price: Rp {price:,}")
            
            # Send log to Telegram group
            await send_log_to_group(log_message)
            
            # Add back button
            keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await query.message.reply_text(message, reply_markup=reply_markup, parse_mode='Markdown')
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            await query.message.reply_text("⏰ Too many requests. Please wait a moment and try again.")
        else:
            logger.error("Error processing payment: %s", e, exc_info=True)
            await query.message.reply_text("❌ Error processing payment.\n\n")
    except Exception as e:
        logger.error("Error processing payment: %s", e, exc_info=True)
        await query.message.reply_text("❌ Error processing payment.\n\n")

async def process_family_payment(update: Update, context: ContextTypes.DEFAULT_TYPE, package, payment_method, amount: int) -> None:
    """Process family package payment with custom amount."""
    user = auth_instance.get_active_user(context)
    if not user:
        await update.message.reply_text("❌ No active user found. Please login first.")
        return
    
    try:
        package_code = package["code"]
        title = package["name"]
        original_price = package["price"]
        
        # Get token confirmation from package details
        global api_key
        package_details = get_package(api_key, user["tokens"], package_code)
        if not package_details:
            await update.message.reply_text("❌ Failed to load package details.\n\n"
                                         "Possible reasons:\n"
                                         "• Package no longer available\n"
                                         "• Network connectivity issues\n"
                                         "• Invalid package code\n"
                                         "• Server maintenance\n\n"
                                         "Please try again later or select a different package.")
            return
            
        token_confirmation = package_details["token_confirmation"]
        
        if payment_method == "BALANCE":
            await update.message.reply_text("💳 Processing payment with balance...")
            
            # Actually process the payment with custom amount
            result = purchase_package_with_balance_custom_amount(
                api_key, 
                user["tokens"], 
                package_code,
                amount
            )
            
            # Log purchase attempt
            tg_user = update.effective_user
            if result["success"]:
                log_message = (
                    f"✅ *PURCHASE_SUCCESS*\n"
                    f"👤 User: {tg_user.first_name} (@{tg_user.username or 'N/A'})\n"
                    f"🆔 User ID: `{tg_user.id}`\n"
                    f"📱 XL Number: `{user['number']}`\n"
                    f"🏷️ Package: `{title}`\n"
                    f"💰 Price: `Rp {original_price:,}`\n"
                    f"💵 Paid: `Rp {amount:,}`\n"
                    f"💳 Method: `Balance`\n"
                    f"🕒 Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
                )
                user_logger.info(f"PURCHASE_SUCCESS - User: {tg_user.id} ({tg_user.username or 'N/A'}), "
                               f"XL Number: {user['number']}, Package: {title}, Original Price: Rp {original_price:,}, "
                               f"Paid: Rp {amount:,}, Method: BALANCE")
                
                message = f"✅ Successfully purchased package!\n\n"
                message += f"🏷️ Package: `{title}`\n"
                message += f"💰 Original Price: `Rp {original_price:,}`\n"
                message += f"💵 Paid: `Rp {amount:,}`\n"
                message += f"💳 Payment Method: Balance\n\n"
                message += "📲 Please check your XL app for confirmation."
            else:
                log_message = (
                    f"❌ *PURCHASE_FAILED*\n"
                    f"👤 User: {tg_user.first_name} (@{tg_user.username or 'N/A'})\n"
                    f"🆔 User ID: `{tg_user.id}`\n"
                    f"📱 XL Number: `{user['number']}`\n"
                    f"🏷️ Package: `{package_title if package_title else 'Unknown Package'}`\n"
                    f"💰 Original Price: `Rp {original_price:,}`\n"
                    f"💵 Paid: `Rp {amount:,}`\n"
                    f"💳 Method: `Balance`\n"
                    f"⚠️ Error: `{result.get('error', 'Unknown error')}`\n"
                    f"🕒 Time: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
                )
                # Extract just the error message for logging
                error_msg = result.get('error', 'Unknown error')
                if error_msg.startswith('❌ Purchase failed'):
                    # Extract the core error details for logging
                    lines = error_msg.split('\n')
                    if len(lines) > 2:
                        core_error = lines[0]  # First line contains the main error
                    else:
                        core_error = error_msg
                else:
                    core_error = error_msg
                user_logger.info(f"PURCHASE_FAILED - User: {tg_user.id} ({tg_user.username or 'N/A'}), "
                               f"XL Number: {user['number']}, Package: {title}, Original Price: Rp {original_price:,}, "
                               f"Paid: Rp {amount:,}, Method: BALANCE, Error: {core_error}")
                
                # Format error message with detailed information using format_api_error
                error_content = result.get('error', 'Unknown error')
                # If the error is already formatted, use it as is
                if error_content.startswith("❌ PURCHASE_FAILED"):
                    message = error_content
                else:
                    # Otherwise format it with our enhanced format
                    message = format_api_error(error_content, title, original_price, "Balance")
                message += f"🕒 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            # Send log to Telegram group
            await send_log_to_group(log_message)
            
            # Add back button
            keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await update.message.reply_text(message, reply_markup=reply_markup, parse_mode='Markdown')
        elif payment_method == "QRIS":
            await update.message.reply_text("📱 Generating QRIS payment code...")
            
            # Get payment methods
            payment_methods_data = get_payment_methods(
                api_key, 
                user["tokens"], 
                token_confirmation, 
                package_code
            )
            
            if not payment_methods_data:
                error_message = "Failed to fetch payment methods"
                message = format_api_error(error_message, title, original_price, "QRIS")
                await update.message.reply_text(message)
                return
                
            token_payment = payment_methods_data["token_payment"]
            ts_to_sign = payment_methods_data["timestamp"]
            
            # Process QRIS payment with custom amount
            transaction_id = settlement_qris(
                api_key,
                user["tokens"],
                token_payment,
                ts_to_sign,
                package_code,
                amount,  # Use custom amount
                title
            )
            
            if not transaction_id:
                error_message = "Failed to generate QRIS payment"
                message = format_api_error(error_message, title, amount, "QRIS")
                await update.message.reply_text(message)
                return
                
            # Get QRIS code
            qris_code = get_qris_code(api_key, user["tokens"], transaction_id)
            if not qris_code:
                error_message = "Failed to fetch QRIS code"
                message = format_api_error(error_message, title, amount, "QRIS")
                await update.message.reply_text(message)
                return
            
            # Create QR code image
            qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
            qr.add_data(qris_code)
            qr.make(fit=True)
            
            # Save QR code to BytesIO
            qr_img = qr.make_image(fill_color="black", back_color="white")
            img_buffer = BytesIO()
            qr_img.save(img_buffer, format='PNG')
            img_buffer.seek(0)
            
            # Send QR code image
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            expiration_time = (datetime.now() + timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            
            caption = f"📱 *QRIS Payment*\n\n"
            caption += f"🏷️ Package: `{title}`\n"
            caption += f"💰 Original Price: `Rp {original_price:,}`\n"
            caption += f"💵 To Pay: `Rp {amount:,}`\n"
            caption += f"🕒 Generated: `{current_time}`\n"
            caption += f"⏰ Expires: `{expiration_time}`\n\n"
            caption += "Scan the QR code with your e-wallet app to complete the payment.\n"
            
            await update.message.reply_photo(photo=img_buffer, caption=caption, parse_mode='Markdown')
            
            # Log QRIS generation
            tg_user = update.effective_user
            log_message = (
                f"📱 *QRIS_GENERATED*\n"
                f"👤 User: {tg_user.first_name} (@{tg_user.username or 'N/A'})\n"
                f"🆔 User ID: `{tg_user.id}`\n"
                f"📱 XL Number: `{user['number']}`\n"
                f"🏷️ Package: `{title}`\n"
                f"💰 Original Price: `Rp {original_price:,}`\n"
                f"💵 To Pay: `Rp {amount:,}`\n"
                f"🕒 Generated: `{current_time}`\n"
                f"⏰ Expires: `{expiration_time}`"
            )
            user_logger.info(f"QRIS_GENERATED - User: {tg_user.id} ({tg_user.username or 'N/A'}), "
                           f"XL Number: {user['number']}, Package: {title}, Original Price: Rp {original_price:,}, "
                           f"To Pay: Rp {amount:,}")
            
            # Send log to Telegram group
            await send_log_to_group(log_message)
            
            # Add back button
            keyboard = [[InlineKeyboardButton("🔙 Back to Menu", callback_data="main_menu")]]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await update.message.reply_text("Please scan the QR code to complete your payment.", reply_markup=reply_markup)
    except ValueError as e:
        # Handle rate limit errors
        error_msg = str(e)
        if "too many requests" in error_msg.lower():
            await update.message.reply_text("⏰ Too many requests. Please wait a moment and try again.")
        else:
            logger.error("Error processing family payment: %s", e, exc_info=True)
            await update.message.reply_text("❌ Error processing family payment.\n\n")
    except Exception as e:
        logger.error("Error processing family payment: %s", e, exc_info=True)
        await update.message.reply_text("❌ Error processing family payment.\n\n")

async def logout(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle logout."""
    user = auth_instance.get_active_user(context)
    if user:
        auth_instance.remove_active_user(context)
        await update.message.reply_text("✅ You have been logged out.")
    else:
        await update.message.reply_text("❌ You are not logged in.")
    
    # Show login option
    keyboard = [[KeyboardButton("📱 Login")]]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    await update.message.reply_text("Use the login button to log in again.", reply_markup=reply_markup)

async def show_vpn_info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show VPN information and purchase options."""
    try:
        # VPN information directly in code instead of reading from vpn.md
        message = "🌐 *WINTUNELING VPN*\n\n"
        message += "*purchasing premium VPN at @WINTUNELING_VPN_BOT*\n\n"
        message += "*Available:*\n\n"
        message += "Premium VPN for SSH/VMESS/VLESS/TROJAN protocols\n\n"
        message += "*Servers:*\n\n"
        message += "🇮🇩 ID Aren - Rp 8,000\n"
        message += "🇸🇬 SG Tencent - Rp 6,000\n"
        message += "🇸🇬 SG Digital Ocean - Rp 8,000\n\n"
        message += "*Note:*\n\n"
        message += "STB-specific servers is not allowed ‼️\n\n"
        message += "💰 *Topup Via Saldo Qris\n\n"
        message += "To purchase a Premium VPN, please contact: @WINTUNELINGVPNN"
        
        await update.message.reply_text(message, parse_mode='Markdown')
    except Exception as e:
        logger.error("Error showing VPN info: %s", e)
        await update.message.reply_text("❌ Error fetching VPN information.")

async def show_donation_info(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show donation information with QRIS image."""
    try:
        message = "💝 *Donation*\n\n"
        message += "Thank you for supporting the development of this bot!\n\n"
        message += "Scan the QRIS code below to make a donation:"
        
        # Send the QRIS image
        await update.message.reply_photo(
            photo="https://i.imgur.com/CftHGbi.jpeg",
            caption="Terima kasih sudah berdonasi untuk pengembangan bot! 🙏"
        )
    except Exception as e:
        logger.error("Error showing donation info: %s", e)
        await update.message.reply_text("❌ Error showing donation information.\n\nTerima kasih sudah berdonasi untuk pengembangan bot! 🙏")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /help is issued."""
    message = "ℹ️ *DoyDor XL Bot Help*\n\n"
    message += "I can help you manage your XL account directly from Telegram!\n\n"
    message += "📱 *Available Commands:*\n"
    message += "/start - Start the bot\n"
    message += "/login - Login to your XL account\n"
    message += "/help - Show this help message\n\n"
    message += "💡 *How to Use:*\n"
    message += "1. Click '📱 Login' or use /login\n"
    message += "2. Enter your XL number\n"
    message += "3. Enter the OTP sent to your phone\n"
    message += "4. Use the menu buttons to navigate\n\n"
    message += "💳 *Features:*\n"
    message += "• Check account balance\n"
    message += "• View package information\n"
    message += "• Buy packages with QRIS or balance\n"
    message += "• Logout when finished\n\n"
    message += "🔒 *Security:*\n"
    message += "Your credentials are stored securely on your device."
    
    # Add admin commands if user is admin
    admin_id = os.getenv("ADMIN_ID")
    if admin_id and str(update.effective_user.id) == admin_id:
        message += "\n\n🛠️ *Admin Commands:*\n"
        message += "/post <message> - Send message to all users\n"
        message += "/users - Show user statistics\n"
        message += "/test_error - Test error reporting"
    
    await update.message.reply_text(message, parse_mode='Markdown')

async def post_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Admin-only command to send messages to all subscribers."""
    # Check if user is admin
    admin_id = os.getenv("ADMIN_ID")
    if not admin_id or str(update.effective_user.id) != admin_id:
        await update.message.reply_text("❌ You don't have permission to use this command. Please contact Admin.")
        return
    
    # Check if message text is provided
    if not context.args:
        await update.message.reply_text("❌ Please provide a message to send. Usage: /post <message>")
        return
    
    # Get message from arguments
    message = "📢 *ADMIN ANNOUNCEMENT*\n\n" + " ".join(context.args)
    
    # Read user IDs from database
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT user_id FROM users")
        user_ids = [row[0] for row in c.fetchall()]
        conn.close()
        
        if not user_ids:
            await update.message.reply_text("❌ No subscribers found.")
            return
        
        # Send message to all subscribers
        success_count = 0
        failed_count = 0
        
        await update.message.reply_text(f"🔄 Sending message to {len(user_ids)} users...")
        
        for user_id in user_ids:
            try:
                await application_instance.bot.send_message(
                    chat_id=user_id,
                    text=message,
                    parse_mode='Markdown'
                )
                success_count += 1
                logger.info(f"Successfully sent message to user {user_id}")
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Failed to send message to user {user_id}: {error_msg}")
                # Check for specific Telegram errors
                if "Forbidden" in error_msg or "bot was blocked by the user" in error_msg:
                    logger.info(f"User {user_id} has blocked the bot or hasn't started a conversation")
                elif "Chat not found" in error_msg:
                    logger.info(f"Chat with user {user_id} not found")
                failed_count += 1
        
        await update.message.reply_text(
            f"✅ Message sent to {success_count} users.\n"
            f"❌ Failed to send to {failed_count} users.\n\n"
            f"Note: Users must have started a conversation with the bot before they can receive messages."
        )
    except Exception as e:
        logger.error(f"Error sending admin message: {e}")
        await update.message.reply_text("❌ Error sending message to subscribers.")

async def users_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Admin-only command to check the number of registered users."""
    # Check if user is admin
    admin_id = os.getenv("ADMIN_ID")
    if not admin_id or str(update.effective_user.id) != admin_id:
        await update.message.reply_text("❌ You don't have permission to use this command.")
        return
    
    # Get user count from database
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        user_count = c.fetchone()[0]
        conn.close()
        
        await update.message.reply_text(
            f"📊 *User Statistics*\n\n"
            f"Total registered users: `{user_count}`"
        )
    except Exception as e:
        logger.error(f"Error fetching user count: {e}", exc_info=True)
        await update.message.reply_text("❌ Error fetching user count.")

async def test_error_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Admin-only command to test error reporting."""
    # Check if user is admin
    admin_id = os.getenv("ADMIN_ID")
    if not admin_id or str(update.effective_user.id) != admin_id:
        await update.message.reply_text("❌ You don't have permission to use this command.")
        return
    
    # Test error reporting
    try:
        await update.message.reply_text("Testing error reporting...")
        # Intentionally raise an exception to test error handling
        raise Exception("This is a test error for verification purposes")
    except Exception as e:
        logger.error("Test error for verification: %s", e, exc_info=True)
        await update.message.reply_text("✅ Test error reported. Check admin notifications.")

def main() -> None:
    """Start the bot."""
    # Initialize database
    init_db()
    
    # Create the Application and pass it your bot's token
    global application_instance
    application_instance = Application.builder().token(os.getenv("TELEGRAM_BOT_TOKEN")).build()

    # Patch the error handler to work with the application instance
    async def send_error_to_admin_async(message):
        """Send error message to admin user"""
        admin_id = os.getenv("ADMIN_ID")
        if application_instance and admin_id:
            try:
                await application_instance.bot.send_message(
                    chat_id=admin_id,
                    text=message,
                    parse_mode='Markdown'
                )
            except Exception as e:
                # Log to console as we can't send to Telegram
                print(f"Failed to send error to admin: {e}")

    # Add conversation handler for login
    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("login", login_start), 
                      MessageHandler(filters.Regex("^📱 Login$"), login_start)],
        states={
            PHONE: [MessageHandler(filters.TEXT & ~filters.COMMAND, phone_received)],
            OTP: [MessageHandler(filters.TEXT & ~filters.COMMAND, otp_received)],
        },
        fallbacks=[CommandHandler("start", start)],
    )

    # Add handlers
    application_instance.add_handler(CommandHandler("start", start))
    application_instance.add_handler(CommandHandler("help", help_command))
    application_instance.add_handler(CommandHandler("post", post_command))
    application_instance.add_handler(CommandHandler("users", users_command))
    application_instance.add_handler(CommandHandler("test_error", test_error_command))
    application_instance.add_handler(conv_handler)
    application_instance.add_handler(CallbackQueryHandler(button_handler))
    application_instance.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_menu_selection))

    # Run the bot until the user presses Ctrl-C
    application_instance.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    # Start the bot
    main()




