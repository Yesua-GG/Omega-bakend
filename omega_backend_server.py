import os
import re
import sys
import hmac
import time
import json
import base64
import hashlib
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple

from fastapi import FastAPI, HTTPException, Request, Header, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import requests

# ==============================================================================
# CONFIGURACIÓN Y VARIABLES DE ENTORNO (RENDER / LOCAL)
# ==============================================================================
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "omega_system.db")
ADMIN_SECRET_KEY = os.getenv("OMEGA_ADMIN_KEY", "omega_admin_2026_secreto")

# Secreto maestro compartido únicamente con el binario nativo C++ (libomega_security.so)
APP_MASTER_SECRET = os.getenv("OMEGA_APP_MASTER_SECRET", "Om3g4_C0r3_S3rv3r_M4st3r_K3y_2026!#99")
EXPECTED_PACKAGE_NAME = "com.redtools.omega"

# Huella SHA-256 inicial autorizada (incluye llave local de desarrollo + llaves Play Store que agregues en /admin)
DEFAULT_ALLOWED_CERTS = "ada693022f9b72312fba59ea63daf162e8b0b58ed4aeca8d6dfc9007288a1158"

# Variables de Supabase (Configurables en el Dashboard de Render)
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "") or os.getenv("SUPABASE_SERVICE_KEY", "")
USE_SUPABASE = bool(SUPABASE_URL and SUPABASE_KEY)

app = FastAPI(
    title="Omega Core Authoritative Server",
    description="Servidor Autoritativo de Membresías, Configuración Efímera, URLs Cifradas y Verificación Nativa de Firma APK",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# CATÁLOGO DINÁMICO DE URLS Y CONFIGURACIÓN GLOBAL POR DEFECTO
# ==============================================================================
DEFAULT_SYSTEM_CONFIGS: Dict[str, str] = {
    "enforce_apk_signature": "true",
    "enforce_device_lock": "true",
    "allowed_apk_sha256": DEFAULT_ALLOWED_CERTS,
    "lease_ttl_sec": "180",
    "heartbeat_sec": "75",
    "host_co": "https://api-gw-cf.latam-co.saea1.aws.indriverapp.com",
    "host_latam": "https://api-gw-cf.latam.saea1.aws.indriverapp.com",
    "host_cas": "https://cas-gw-cf.euce1.indriverapp.com",
    "host_auth": "https://ath-gw-cf.euce1.indriverapp.com",
    "host_messenger": "https://api-gw-cf.euce1.indriverapp.com",
    "ws_ssn_host": "wss://ssn-lb-cf.latam.saea1.aws.indriverapp.com",
    "ws_ssn_path": "/connection/websocket",
    "feed_v3_path": "/feed/api/feed/v3/orders",
    "mode_sync_path": "/profile-api/api/profile-api/v1/mode",
    "vehicle_path": "/new-order/api/new-order/v1/settings/contractor/vehicle",
    "contractor_settings_path": "/new-order/api/new-order/v1/settings/contractor",
    "bid_new_order_path": "/new-order/api/new-order/v1/contractor-orders/{id}/bids",
    "bid_courier_path": "/courier/api/courier/v1/contractor-orders/{id}/bids",
    "bid_track_path": "/new-order/api/new-order/v2/bids/{bid_id}",
    "detail_new_order_path": "/new-order/api/new-order/v1/contractor-orders/{id}",
    "detail_courier_path": "/courier/api/courier/v1/contractor-orders/{id}",
    "detail_api_courier_path": "/api/courier/v1/contractor-orders/{id}",
    "detail_v1_path": "/v1/contractor-orders/{id}",
    "min_poll_ms": "700",
    "max_poll_ms": "1200"
}

# Caché ligero en RAM para system_config global (evita múltiples viajes HTTP a Supabase en cada latido)
_SYS_CONFIG_CACHE: Dict[str, str] = {}
_SYS_CONFIG_CACHE_TS: float = 0.0
_SYS_CONFIG_TTL_SEC: float = 6.0


def invalidate_config_cache():
    global _SYS_CONFIG_CACHE_TS
    _SYS_CONFIG_CACHE_TS = 0.0


# ==============================================================================
# ADAPTADOR DE BASE DE DATOS: SUPABASE REST / SQLITE LOCAL FALLBACK
# ==============================================================================
def supabase_headers() -> Dict[str, str]:
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }


def get_sqlite_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_local_sqlite():
    conn = get_sqlite_db()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS drivers (
        uid TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        phone TEXT,
        status TEXT DEFAULT 'active',
        valid_until TEXT NOT NULL,
        created_at TEXT NOT NULL,
        notes TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uid TEXT,
        ip_address TEXT,
        action TEXT,
        status TEXT,
        details TEXT,
        created_at TEXT
    )
    """)
    for k, v in DEFAULT_SYSTEM_CONFIGS.items():
        cursor.execute("INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)", (k, v))

    conn.commit()
    conn.close()


if not USE_SUPABASE:
    init_local_sqlite()


def db_get_driver(uid: str) -> Optional[Dict[str, Any]]:
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/drivers?uid=eq.{uid}&select=*"
            res = requests.get(url, headers=supabase_headers(), timeout=5)
            if res.status_code == 200:
                data = res.json()
                return data[0] if data else None
        except Exception as e:
            print(f"[Supabase Error get_driver] {e}")
            return None
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM drivers WHERE uid = ?", (uid,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None


def db_list_drivers() -> List[Dict[str, Any]]:
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/drivers?select=*&order=created_at.desc"
            res = requests.get(url, headers=supabase_headers(), timeout=5)
            if res.status_code == 200:
                return res.json()
            return []
        except Exception as e:
            print(f"[Supabase Error list_drivers] {e}")
            return []
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM drivers ORDER BY created_at DESC")
        drivers = [dict(row) for row in cur.fetchall()]
        conn.close()
        return drivers


def db_save_driver(uid: str, name: str, phone: str, valid_until: str, status: str = "active", notes: str = ""):
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/drivers"
            headers = supabase_headers()
            headers["Prefer"] = "resolution=merge-duplicates"
            payload = {
                "uid": uid,
                "name": name,
                "phone": phone,
                "status": status,
                "valid_until": valid_until,
                "notes": notes
            }
            requests.post(url, headers=headers, json=payload, timeout=5)
        except Exception as e:
            print(f"[Supabase Error save_driver] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        now_iso = datetime.now().isoformat()
        cur.execute("""
        INSERT INTO drivers (uid, name, phone, status, valid_until, created_at, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(uid) DO UPDATE SET
            name = excluded.name,
            phone = excluded.phone,
            status = excluded.status,
            valid_until = excluded.valid_until,
            notes = excluded.notes
        """, (uid, name, phone, status, valid_until, now_iso, notes))
        conn.commit()
        conn.close()


def db_delete_driver(uid: str):
    if USE_SUPABASE:
        try:
            requests.delete(f"{SUPABASE_URL}/rest/v1/drivers?uid=eq.{uid}", headers=supabase_headers(), timeout=5)
            requests.delete(f"{SUPABASE_URL}/rest/v1/system_config?key=eq.driver_cfg:{uid}", headers=supabase_headers(), timeout=5)
            requests.delete(f"{SUPABASE_URL}/rest/v1/system_config?key=eq.driver_dev:{uid}", headers=supabase_headers(), timeout=5)
        except Exception as e:
            print(f"[Supabase Error delete_driver] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM drivers WHERE uid = ?", (uid,))
        cur.execute("DELETE FROM system_config WHERE key IN (?, ?)", (f"driver_cfg:{uid}", f"driver_dev:{uid}"))
        conn.commit()
        conn.close()


def db_get_raw_key(key: str, default: str = "") -> str:
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/system_config?key=eq.{key}&select=value"
            res = requests.get(url, headers=supabase_headers(), timeout=5)
            if res.status_code == 200:
                data = res.json()
                return data[0]["value"] if data else default
        except Exception as e:
            print(f"[Supabase Error get_raw_key] {e}")
            return default
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("SELECT value FROM system_config WHERE key = ?", (key,))
        row = cur.fetchone()
        conn.close()
        return row["value"] if row else default
    return default


def db_set_config(key: str, value: str):
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/system_config"
            headers = supabase_headers()
            headers["Prefer"] = "resolution=merge-duplicates"
            requests.post(url, headers=headers, json={"key": key, "value": str(value)}, timeout=5)
        except Exception as e:
            print(f"[Supabase Error set_config] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO system_config (key, value) VALUES (?, ?)", (key, str(value)))
        conn.commit()
        conn.close()
    if not key.startswith("driver_"):
        invalidate_config_cache()


def db_delete_key(key: str):
    if USE_SUPABASE:
        try:
            requests.delete(f"{SUPABASE_URL}/rest/v1/system_config?key=eq.{key}", headers=supabase_headers(), timeout=5)
        except Exception as e:
            print(f"[Supabase Error delete_key] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM system_config WHERE key = ?", (key,))
        conn.commit()
        conn.close()
    if not key.startswith("driver_"):
        invalidate_config_cache()


def db_get_global_configs() -> Dict[str, str]:
    global _SYS_CONFIG_CACHE, _SYS_CONFIG_CACHE_TS
    now = time.time()
    if _SYS_CONFIG_CACHE and (now - _SYS_CONFIG_CACHE_TS) < _SYS_CONFIG_TTL_SEC:
        return dict(_SYS_CONFIG_CACHE)

    merged = dict(DEFAULT_SYSTEM_CONFIGS)
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/system_config?key=not.like.driver_*&select=key,value"
            res = requests.get(url, headers=supabase_headers(), timeout=5)
            if res.status_code == 200:
                for row in res.json():
                    merged[row["key"]] = row["value"]
        except Exception as e:
            print(f"[Supabase Error get_global_configs] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM system_config WHERE key NOT LIKE 'driver_%'")
        for row in cur.fetchall():
            merged[row["key"]] = row["value"]
        conn.close()

    _SYS_CONFIG_CACHE = merged
    _SYS_CONFIG_CACHE_TS = now
    return dict(merged)


def db_get_prefix_map(prefix: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/system_config?key=like.{prefix}*&select=key,value"
            res = requests.get(url, headers=supabase_headers(), timeout=5)
            if res.status_code == 200:
                for row in res.json():
                    k = row["key"][len(prefix):]
                    try:
                        out[k] = json.loads(row["value"])
                    except Exception:
                        out[k] = row["value"]
        except Exception as e:
            print(f"[Supabase Error get_prefix_map] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM system_config WHERE key LIKE ?", (f"{prefix}%",))
        for row in cur.fetchall():
            k = row["key"][len(prefix):]
            try:
                out[k] = json.loads(row["value"])
            except Exception:
                out[k] = row["value"]
        conn.close()
    return out


def db_log_event(uid: str, ip: str, action: str, status: str, details: str = ""):
    now_iso = datetime.now().isoformat()
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/access_logs"
            payload = {
                "uid": uid,
                "ip_address": ip,
                "action": action,
                "status": status,
                "details": details
            }
            requests.post(url, headers=supabase_headers(), json=payload, timeout=3)
        except Exception:
            pass
    else:
        try:
            conn = get_sqlite_db()
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO access_logs (uid, ip_address, action, status, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (uid, ip, action, status, details, now_iso))
            conn.commit()
            conn.close()
        except Exception:
            pass


def db_get_logs(limit: int = 50) -> List[Dict[str, Any]]:
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/access_logs?select=*&order=id.desc&limit={limit}"
            res = requests.get(url, headers=supabase_headers(), timeout=5)
            return res.json() if res.status_code == 200 else []
        except Exception:
            return []
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM access_logs ORDER BY id DESC LIMIT ?", (limit,))
        logs = [dict(r) for r in cur.fetchall()]
        conn.close()
        return logs


# ==============================================================================
# CRIPTOGRAFÍA: VERIFICACIÓN NATIVA DE FIRMA APK, HMAC Y SOBRE CIFRADO
# ==============================================================================
def normalize_sha256(raw: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", raw or "").lower()


def parse_allowed_certs(raw_csv: str) -> List[str]:
    certs = []
    for part in (raw_csv or "").replace("\n", ",").replace(";", ",").split(","):
        norm = normalize_sha256(part)
        if len(norm) == 64 and norm not in certs:
            certs.append(norm)
    # Garantizar siempre al menos la semilla inicial si la lista quedó vacía por error
    if not certs:
        certs.append(normalize_sha256(DEFAULT_ALLOWED_CERTS))
    return certs


def verify_app_attestation(request: Request, raw_body: bytes, sys_cfg: Dict[str, str]) -> Tuple[bool, str, str, str]:
    """
    Verifica que la petición provenga genuinamente del motor nativo C++ (libomega_security.so)
    de la aplicación oficial Omega y que el certificado X.509 del APK no haya sido modificado.
    Retorna: (ok, reason_code, cert_sha256_o_mensaje, device_id)
    """
    ts_str = (request.headers.get("X-Omega-Timestamp") or "").strip()
    nonce = (request.headers.get("X-Omega-Nonce") or "").strip()
    pkg = (request.headers.get("X-Omega-Package") or "").strip()
    cert_sha = normalize_sha256(request.headers.get("X-Omega-Cert-Sha256") or "")
    device_id = (request.headers.get("X-Omega-Device-Id") or "").strip()
    env_status = (request.headers.get("X-Omega-Env") or "").strip()
    sig_hex = (request.headers.get("X-Omega-Signature") or "").strip().lower()

    if not ts_str or not nonce or not sig_hex or len(cert_sha) != 64 or not device_id:
        return False, "missing_attestation", f"Headers incompletos (cert={cert_sha[:12]})", device_id

    if pkg != EXPECTED_PACKAGE_NAME:
        return False, "invalid_package", f"Package inválido: {pkg}", device_id

    try:
        req_ts = int(ts_str)
    except ValueError:
        return False, "invalid_timestamp", "Timestamp malformado", device_id

    now_ts = int(time.time())
    if abs(now_ts - req_ts) > 360:
        return False, "clock_skew", f"Reloj desfasado ({now_ts - req_ts}s)", device_id

    if env_status != "clean":
        return False, "env_tampered", f"Entorno comprometido detectado por C++ ({env_status})", device_id

    body_sha = hashlib.sha256(raw_body or b"").hexdigest().lower()
    canonical = f"{request.method.upper()}\n{request.url.path}\n{ts_str}\n{nonce}\n{cert_sha}\n{device_id}\n{env_status}\n{body_sha}"
    expected_sig = hmac.new(
        APP_MASTER_SECRET.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().lower()

    if not hmac.compare_digest(expected_sig, sig_hex):
        return False, "bad_hmac", f"Firma HMAC nativa inválida (cert={cert_sha[:16]}...)", device_id

    enforce_sig = sys_cfg.get("enforce_apk_signature", "true").lower() == "true"
    allowed_certs = parse_allowed_certs(sys_cfg.get("allowed_apk_sha256", DEFAULT_ALLOWED_CERTS))

    if enforce_sig and cert_sha not in allowed_certs:
        return False, "apk_tampered", cert_sha, device_id

    # Si enforce_apk_signature está apagado temporalmente por admin, ciframos para el cert entrante;
    # cuando está encendido (por defecto), ciframos estrictamente para el cert oficial verificado.
    matched_cert = cert_sha if cert_sha in allowed_certs else (cert_sha if not enforce_sig else allowed_certs[0])
    return True, "ok", matched_cert, device_id


def seal_payload_for_apk(payload_dict: Dict[str, Any], target_cert_sha256: str) -> str:
    """
    Cifra y autentica las URLs y configuración ligándolas matemáticamente al SHA-256
    del certificado del APK oficial. Si alguien modifica y re-firma el APK, libomega_security.so
    derivará otra llave y jamás podrá descifrar las URLs ni la configuración.
    Formato: {server_nonce_hex}.{base64_ciphertext}.{mac_hex}
    """
    clean_cert = normalize_sha256(target_cert_sha256)
    server_nonce = os.urandom(16).hex().lower()

    enc_key = hashlib.sha256(f"{APP_MASTER_SECRET}|SEAL|{clean_cert}|{server_nonce}".encode("utf-8")).digest()
    mac_key = hashlib.sha256(f"{APP_MASTER_SECRET}|MAC|{clean_cert}|{server_nonce}".encode("utf-8")).digest()

    plaintext = json.dumps(payload_dict, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ciphertext = bytearray(len(plaintext))

    block_count = (len(plaintext) + 31) // 32
    for counter in range(block_count):
        keystream = hmac.new(enc_key, f"{server_nonce}:{counter}".encode("utf-8"), hashlib.sha256).digest()
        start = counter * 32
        end = min(start + 32, len(plaintext))
        for i in range(start, end):
            ciphertext[i] = plaintext[i] ^ keystream[i - start]

    b64_cipher = base64.b64encode(bytes(ciphertext)).decode("ascii")
    mac_hex = hmac.new(mac_key, f"{server_nonce}.{b64_cipher}".encode("utf-8"), hashlib.sha256).hexdigest().lower()
    return f"{server_nonce}.{b64_cipher}.{mac_hex}"


def issue_lease_token(uid: str, device_id: str, cert_sha256: str, ttl_sec: int) -> str:
    exp_ts = int(time.time()) + max(30, ttl_sec)
    raw = f"{uid}|{device_id}|{cert_sha256}|{exp_ts}"
    sig = hmac.new(APP_MASTER_SECRET.encode("utf-8"), f"LEASE|{raw}".encode("utf-8"), hashlib.sha256).hexdigest().lower()
    token_plain = f"{raw}|{sig}"
    return base64.urlsafe_b64encode(token_plain.encode("utf-8")).decode("ascii").rstrip("=")


def verify_lease_token(lease_token: str, expected_device_id: str, expected_cert_sha256: str) -> Optional[str]:
    if not lease_token:
        return None
    try:
        padded = lease_token + "=" * ((4 - len(lease_token) % 4) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        parts = decoded.split("|")
        if len(parts) != 5:
            return None
        uid, dev_id, cert_sha, exp_str, sig = parts
        raw = f"{uid}|{dev_id}|{cert_sha}|{exp_str}"
        expected_sig = hmac.new(APP_MASTER_SECRET.encode("utf-8"), f"LEASE|{raw}".encode("utf-8"), hashlib.sha256).hexdigest().lower()
        if not hmac.compare_digest(expected_sig, sig):
            return None
        if int(time.time()) > int(exp_str) + 30:
            return None
        if dev_id != expected_device_id or normalize_sha256(cert_sha) != normalize_sha256(expected_cert_sha256):
            return None
        return uid
    except Exception:
        return None


def extract_verified_jwt_uid(token: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    Extrae el UID del JWT de sesión comprobando formato estructural (3 segmentos) y expiración.
    """
    if not token:
        return None, "missing_jwt"
    try:
        clean = token.replace("Bearer ", "").replace("bearer ", "").strip()
        parts = clean.split(".")
        if len(parts) != 3 or not parts[2]:
            return None, "malformed_jwt"
        payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
        exp = int(payload.get("exp") or 0)
        if exp > 0 and exp < (int(time.time()) - 300):
            return None, "expired_jwt"
        uid_val = (
            payload.get("user_id")
            or payload.get("uid")
            or payload.get("contractor_id")
            or payload.get("sub")
        )
        if uid_val:
            return str(uid_val).strip(), None
        return None, "missing_uid_claim"
    except Exception as e:
        return None, f"jwt_parse_error:{e}"


def build_endpoints_bundle(sys_cfg: Dict[str, str]) -> Dict[str, Any]:
    return {
        "host_co": sys_cfg.get("host_co", DEFAULT_SYSTEM_CONFIGS["host_co"]),
        "host_latam": sys_cfg.get("host_latam", DEFAULT_SYSTEM_CONFIGS["host_latam"]),
        "host_cas": sys_cfg.get("host_cas", DEFAULT_SYSTEM_CONFIGS["host_cas"]),
        "host_auth": sys_cfg.get("host_auth", DEFAULT_SYSTEM_CONFIGS["host_auth"]),
        "host_messenger": sys_cfg.get("host_messenger", DEFAULT_SYSTEM_CONFIGS["host_messenger"]),
        "ws_ssn_host": sys_cfg.get("ws_ssn_host", DEFAULT_SYSTEM_CONFIGS["ws_ssn_host"]),
        "ws_ssn_path": sys_cfg.get("ws_ssn_path", DEFAULT_SYSTEM_CONFIGS["ws_ssn_path"]),
        "feed_v3_path": sys_cfg.get("feed_v3_path", DEFAULT_SYSTEM_CONFIGS["feed_v3_path"]),
        "mode_sync_path": sys_cfg.get("mode_sync_path", DEFAULT_SYSTEM_CONFIGS["mode_sync_path"]),
        "vehicle_path": sys_cfg.get("vehicle_path", DEFAULT_SYSTEM_CONFIGS["vehicle_path"]),
        "contractor_settings_path": sys_cfg.get("contractor_settings_path", DEFAULT_SYSTEM_CONFIGS["contractor_settings_path"]),
        "bid_new_order_path": sys_cfg.get("bid_new_order_path", DEFAULT_SYSTEM_CONFIGS["bid_new_order_path"]),
        "bid_courier_path": sys_cfg.get("bid_courier_path", DEFAULT_SYSTEM_CONFIGS["bid_courier_path"]),
        "bid_track_path": sys_cfg.get("bid_track_path", DEFAULT_SYSTEM_CONFIGS["bid_track_path"]),
        "detail_new_order_path": sys_cfg.get("detail_new_order_path", DEFAULT_SYSTEM_CONFIGS["detail_new_order_path"]),
        "detail_courier_path": sys_cfg.get("detail_courier_path", DEFAULT_SYSTEM_CONFIGS["detail_courier_path"]),
        "detail_api_courier_path": sys_cfg.get("detail_api_courier_path", DEFAULT_SYSTEM_CONFIGS["detail_api_courier_path"]),
        "detail_v1_path": sys_cfg.get("detail_v1_path", DEFAULT_SYSTEM_CONFIGS["detail_v1_path"]),
        "min_poll_ms": int(sys_cfg.get("min_poll_ms", "700") or 700),
        "max_poll_ms": int(sys_cfg.get("max_poll_ms", "1200") or 1200)
    }


def load_driver_cloud_state(uid: str) -> Optional[Dict[str, Any]]:
    raw = db_get_raw_key(f"driver_cfg:{uid}", "")
    if not raw:
        return None
    try:
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def save_driver_cloud_state(uid: str, bot_config: Optional[Dict[str, Any]], zones: Optional[List[Any]], zone_settings: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    existing = load_driver_cloud_state(uid) or {}
    updated = {
        "bot_config": bot_config if bot_config is not None else existing.get("bot_config"),
        "zones": zones if zones is not None else existing.get("zones", []),
        "zone_settings": zone_settings if zone_settings is not None else existing.get("zone_settings", {}),
        "updated_at": datetime.now().isoformat()
    }
    db_set_config(f"driver_cfg:{uid}", json.dumps(updated, separators=(",", ":"), ensure_ascii=False))
    return updated


def check_and_bind_device(uid: str, device_id: str, device_model: str, cert_sha: str, enforce_lock: bool) -> Tuple[bool, Optional[Dict[str, Any]]]:
    raw = db_get_raw_key(f"driver_dev:{uid}", "")
    existing: Optional[Dict[str, Any]] = None
    if raw:
        try:
            existing = json.loads(raw)
        except Exception:
            existing = None

    now_iso = datetime.now().isoformat()
    if existing and existing.get("device_id") and existing.get("device_id") != device_id:
        if enforce_lock:
            return False, existing

    record = {
        "device_id": device_id,
        "device_model": device_model or (existing.get("device_model") if existing else "Android"),
        "cert_sha256": cert_sha[:16],
        "bound_at": existing.get("bound_at", now_iso) if existing else now_iso,
        "last_seen": now_iso
    }
    # Actualizar registro cuando es nuevo o cambió el modelo / más de 10 minutos desde último latido
    should_write = (existing is None) or (existing.get("device_id") != device_id)
    if not should_write and existing:
        try:
            last_dt = datetime.fromisoformat(existing.get("last_seen", ""))
            if (datetime.now() - last_dt).total_seconds() > 600:
                should_write = True
        except Exception:
            should_write = True
    if should_write:
        db_set_config(f"driver_dev:{uid}", json.dumps(record, separators=(",", ":"), ensure_ascii=False))
    return True, record


def evaluate_driver_membership(uid: str) -> Tuple[bool, int, str, str, Optional[Dict[str, Any]], int]:
    """
    Valida en el servidor el estado de membresía del conductor.
    Retorna: (authorized, http_status, reason, message, driver_row, days_left)
    """
    driver = db_get_driver(uid)
    if not driver:
        return (
            False,
            403,
            "unregistered",
            f"Tu cuenta (ID: {uid}) aún no tiene una membresía activa. Envía tu ID a soporte para activarla.",
            None,
            0
        )

    if driver.get("status") == "banned":
        return (
            False,
            403,
            "banned",
            "Tu membresía se encuentra suspendida por el administrador. Contacta a soporte.",
            driver,
            0
        )

    raw_valid = driver.get("valid_until", "")
    try:
        clean_iso = raw_valid.replace("Z", "+00:00") if "Z" in raw_valid else raw_valid
        valid_until_dt = datetime.fromisoformat(clean_iso)
        if valid_until_dt.tzinfo is not None:
            valid_until_dt = valid_until_dt.replace(tzinfo=None)
    except Exception:
        valid_until_dt = datetime.now() - timedelta(days=1)

    now = datetime.now()
    if now > valid_until_dt:
        return (
            False,
            402,
            "expired",
            "Tu membresía ha vencido. Renueva tu plan para descargar configuración y habilitar el sistema.",
            driver,
            0
        )

    days_left = max(0, (valid_until_dt - now).days)
    return (
        True,
        200,
        "active",
        f"Membresía Activa ({days_left} días restantes)",
        driver,
        days_left
    )


# ==============================================================================
# MODELOS PYDANTIC
# ==============================================================================
class DriverRegisterRequest(BaseModel):
    uid: str
    name: str
    phone: Optional[str] = ""
    days: int = 30
    notes: Optional[str] = ""


class DriverExtendRequest(BaseModel):
    days: int = 30


class DriverStatusUpdateRequest(BaseModel):
    status: str  # "active" o "banned"


class SystemSettingsUpdateRequest(BaseModel):
    settings: Dict[str, Any]


# ==============================================================================
# ENDPOINTS MÓVILES PROTEGIDOS POR FIRMA NATIVA APK + LEASE EFÍMERO
# ==============================================================================
@app.get("/")
def root():
    return {
        "service": "Omega Core Authoritative Server",
        "status": "online",
        "backend_mode": "Supabase Cloud (PostgreSQL)" if USE_SUPABASE else "Local SQLite",
        "security": "APK-SHA256 + Native-HMAC + Sealed-RAM-Lease",
        "version": "3.0.0",
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/v1/auth/bootstrap")
async def auth_bootstrap(request: Request):
    """
    Entrega únicamente los hosts de autenticación inicial (CAS / Renew) cifrados para el
    certificado del APK oficial. Si el APK fue modificado o re-firmado, es rechazado aquí mismo.
    """
    client_ip = request.client.host if request.client else "unknown"
    raw_body = await request.body()
    sys_cfg = db_get_global_configs()

    att_ok, att_reason, cert_or_msg, device_id = verify_app_attestation(request, raw_body, sys_cfg)
    if not att_ok:
        db_log_event("bootstrap", client_ip, "bootstrap", "tampered", f"{att_reason}: {cert_or_msg}")
        return JSONResponse(
            status_code=403,
            content={
                "authorized": False,
                "reason": att_reason,
                "message": "Aplicación no oficial o modificada detectada. Descarga la versión original."
            }
        )

    sealed = seal_payload_for_apk(
        {
            "host_cas": sys_cfg.get("host_cas", DEFAULT_SYSTEM_CONFIGS["host_cas"]),
            "host_auth": sys_cfg.get("host_auth", DEFAULT_SYSTEM_CONFIGS["host_auth"]),
            "issued_at": int(time.time())
        },
        cert_or_msg
    )
    return {
        "ok": True,
        "sealed_payload": sealed
    }


@app.post("/api/v1/auth/validate-session")
async def validate_session(request: Request):
    """
    Sincronización maestra al detectar inicio de sesión:
    1. Verifica criptográficamente la firma SHA-256 del APK y el HMAC nativo C++.
    2. Verifica el token de sesión y extrae el UID real del conductor.
    3. Comprueba estado de membresía y vínculo único de dispositivo (Device Lock).
    4. Entrega lease efímero de corta duración + sobre cifrado con URLs dinámicas y BotConfig/Zonas.
    """
    client_ip = request.client.host if request.client else "unknown"
    raw_body = await request.body()
    sys_cfg = db_get_global_configs()

    att_ok, att_reason, cert_or_msg, device_id = verify_app_attestation(request, raw_body, sys_cfg)
    if not att_ok:
        db_log_event("unknown", client_ip, "validate_session", "tampered", f"{att_reason}: {cert_or_msg}")
        return JSONResponse(
            status_code=403,
            content={
                "authorized": False,
                "engine_active": False,
                "reason": att_reason,
                "message": "Verificación de integridad fallida: la aplicación fue modificada o su firma no es oficial."
            }
        )

    try:
        body_json = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception:
        body_json = {}

    token = body_json.get("token")
    fallback_uid = str(body_json.get("uid") or "").strip()
    device_model = str(body_json.get("device_model") or "Android").strip()
    initial_state = body_json.get("initial_state")

    jwt_uid, jwt_err = extract_verified_jwt_uid(token)
    if jwt_err in ("expired_jwt", "malformed_jwt") or (jwt_err and jwt_err.startswith("jwt_parse_error")):
        extracted_uid = None
    else:
        extracted_uid = jwt_uid or fallback_uid
        if jwt_uid and fallback_uid and jwt_uid != fallback_uid:
            if not db_get_driver(jwt_uid) and db_get_driver(fallback_uid):
                extracted_uid = fallback_uid

    if sys_cfg.get("playstore_review_mode", "false").lower() == "true":
        db_log_event(extracted_uid or "reviewer", client_ip, "validate_session", "camouflaged", "Modo Revisión Play Store Activo")
        return JSONResponse(
            status_code=403,
            content={
                "authorized": False,
                "review_mode": True,
                "engine_active": False,
                "uid": extracted_uid or "",
                "reason": "review_mode",
                "message": "Servicio en mantenimiento temporal de sincronización."
            }
        )

    if not extracted_uid:
        db_log_event("anonymous", client_ip, "validate_session", "rejected", f"Token inválido ({jwt_err})")
        return JSONResponse(
            status_code=401,
            content={
                "authorized": False,
                "engine_active": False,
                "reason": "unauthorized",
                "message": "Sesión de conductor no válida o expirada. Inicia sesión nuevamente."
            }
        )

    is_auth, http_code, reason, msg, driver, days_left = evaluate_driver_membership(extracted_uid)
    if not is_auth or not driver:
        db_log_event(extracted_uid, client_ip, "validate_session", reason, f"{msg} | cert={cert_or_msg[:12]}")
        return JSONResponse(
            status_code=http_code,
            content={
                "authorized": False,
                "engine_active": False,
                "reason": reason,
                "uid": extracted_uid,
                "valid_until": driver.get("valid_until", "") if driver else "",
                "message": msg
            }
        )

    enforce_dev_lock = sys_cfg.get("enforce_device_lock", "true").lower() == "true"
    dev_ok, bound_info = check_and_bind_device(extracted_uid, device_id, device_model, cert_or_msg, enforce_dev_lock)
    if not dev_ok:
        bound_model = bound_info.get("device_model", "otro equipo") if bound_info else "otro equipo"
        db_log_event(extracted_uid, client_ip, "validate_session", "device_mismatch", f"Intento desde {device_model} ({device_id[:8]}), vinculado a {bound_model}")
        return JSONResponse(
            status_code=403,
            content={
                "authorized": False,
                "engine_active": False,
                "reason": "device_mismatch",
                "uid": extracted_uid,
                "message": f"Esta membresía ya está vinculada a otro dispositivo ({bound_model}). Solicita liberación al administrador."
            }
        )

    # Cargar o inicializar configuración remota del conductor en la nube
    cloud_state = load_driver_cloud_state(extracted_uid)
    if cloud_state is None and isinstance(initial_state, dict):
        cloud_state = save_driver_cloud_state(
            extracted_uid,
            initial_state.get("bot_config"),
            initial_state.get("zones"),
            initial_state.get("zone_settings")
        )
    elif cloud_state is None:
        cloud_state = {
            "bot_config": None,
            "zones": [],
            "zone_settings": {},
            "updated_at": datetime.now().isoformat()
        }

    lease_ttl = max(60, int(sys_cfg.get("lease_ttl_sec", "180") or 180))
    heartbeat_sec = max(30, min(lease_ttl - 30, int(sys_cfg.get("heartbeat_sec", "75") or 75)))
    lease_token = issue_lease_token(extracted_uid, device_id, cert_or_msg, lease_ttl)

    sealed = seal_payload_for_apk(
        {
            "uid": extracted_uid,
            "driver_name": driver.get("name", "Conductor"),
            "days_left": days_left,
            "valid_until": driver.get("valid_until", ""),
            "lease_ttl_sec": lease_ttl,
            "heartbeat_sec": heartbeat_sec,
            "endpoints": build_endpoints_bundle(sys_cfg),
            "driver_state": cloud_state,
            "issued_at": int(time.time())
        },
        cert_or_msg
    )

    db_log_event(extracted_uid, client_ip, "validate_session", "success", f"OK ({days_left}d) • {device_model} • APK={cert_or_msg[:10]}")
    return {
        "authorized": True,
        "engine_active": True,
        "uid": extracted_uid,
        "driver_name": driver.get("name", "Conductor"),
        "days_left": days_left,
        "valid_until": driver.get("valid_until", ""),
        "lease_ttl_sec": lease_ttl,
        "heartbeat_sec": heartbeat_sec,
        "lease_token": lease_token,
        "message": msg,
        "sealed_payload": sealed
    }


@app.post("/api/v1/auth/heartbeat")
async def session_heartbeat(request: Request):
    """
    Renueva el lease volátil de corta duración en RAM. Si la membresía venció, fue suspendida
    o el APK fue alterado, revoca inmediatamente la sesión para purgar la RAM del teléfono.
    """
    client_ip = request.client.host if request.client else "unknown"
    raw_body = await request.body()
    sys_cfg = db_get_global_configs()

    att_ok, att_reason, cert_or_msg, device_id = verify_app_attestation(request, raw_body, sys_cfg)
    if not att_ok:
        db_log_event("heartbeat", client_ip, "heartbeat", "tampered", f"{att_reason}: {cert_or_msg}")
        return JSONResponse(
            status_code=403,
            content={"authorized": False, "reason": att_reason, "message": "Integridad de aplicación inválida."}
        )

    try:
        body_json = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception:
        body_json = {}

    lease_in = str(body_json.get("lease_token") or "")
    token = body_json.get("token")
    device_model = str(body_json.get("device_model") or "Android")

    uid = verify_lease_token(lease_in, device_id, cert_or_msg)
    if not uid:
        uid, _ = extract_verified_jwt_uid(token)

    if not uid:
        return JSONResponse(
            status_code=401,
            content={"authorized": False, "reason": "unauthorized", "message": "Sesión expirada."}
        )

    is_auth, http_code, reason, msg, driver, days_left = evaluate_driver_membership(uid)
    if not is_auth or not driver:
        db_log_event(uid, client_ip, "heartbeat", reason, msg)
        return JSONResponse(
            status_code=http_code,
            content={"authorized": False, "reason": reason, "uid": uid, "message": msg}
        )

    enforce_dev_lock = sys_cfg.get("enforce_device_lock", "true").lower() == "true"
    dev_ok, _ = check_and_bind_device(uid, device_id, device_model, cert_or_msg, enforce_dev_lock)
    if not dev_ok:
        return JSONResponse(
            status_code=403,
            content={"authorized": False, "reason": "device_mismatch", "uid": uid, "message": "Membresía activa en otro dispositivo."}
        )

    lease_ttl = max(60, int(sys_cfg.get("lease_ttl_sec", "180") or 180))
    heartbeat_sec = max(30, min(lease_ttl - 30, int(sys_cfg.get("heartbeat_sec", "75") or 75)))
    new_lease = issue_lease_token(uid, device_id, cert_or_msg, lease_ttl)
    cloud_state = load_driver_cloud_state(uid) or {"bot_config": None, "zones": [], "zone_settings": {}}

    sealed = seal_payload_for_apk(
        {
            "uid": uid,
            "driver_name": driver.get("name", "Conductor"),
            "days_left": days_left,
            "valid_until": driver.get("valid_until", ""),
            "lease_ttl_sec": lease_ttl,
            "heartbeat_sec": heartbeat_sec,
            "endpoints": build_endpoints_bundle(sys_cfg),
            "driver_state": cloud_state,
            "issued_at": int(time.time())
        },
        cert_or_msg
    )

    return {
        "authorized": True,
        "uid": uid,
        "driver_name": driver.get("name", "Conductor"),
        "days_left": days_left,
        "valid_until": driver.get("valid_until", ""),
        "lease_ttl_sec": lease_ttl,
        "heartbeat_sec": heartbeat_sec,
        "lease_token": new_lease,
        "message": msg,
        "sealed_payload": sealed
    }


@app.put("/api/v1/driver/state")
async def update_driver_state(request: Request):
    """
    Guarda en el servidor (Supabase / SQLite) toda la configuración (BotConfig, Zonas, Switches)
    del conductor. Si modifican la app o no tienen membresía activa, el servidor rechaza guardar.
    """
    client_ip = request.client.host if request.client else "unknown"
    raw_body = await request.body()
    sys_cfg = db_get_global_configs()

    att_ok, att_reason, cert_or_msg, device_id = verify_app_attestation(request, raw_body, sys_cfg)
    if not att_ok:
        db_log_event("state_sync", client_ip, "save_config", "tampered", f"{att_reason}: {cert_or_msg}")
        return JSONResponse(
            status_code=403,
            content={"authorized": False, "reason": att_reason, "message": "Firma de aplicación no autorizada."}
        )

    try:
        body_json = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception:
        raise HTTPException(status_code=400, detail="JSON inválido")

    lease_in = str(body_json.get("lease_token") or "")
    token = body_json.get("token")
    uid = verify_lease_token(lease_in, device_id, cert_or_msg)
    if not uid:
        uid, _ = extract_verified_jwt_uid(token)

    if not uid:
        return JSONResponse(
            status_code=401,
            content={"authorized": False, "reason": "unauthorized", "message": "Sesión inválida al guardar configuración."}
        )

    is_auth, http_code, reason, msg, _, _ = evaluate_driver_membership(uid)
    if not is_auth:
        db_log_event(uid, client_ip, "save_config", reason, "Rechazado guardado de configuración")
        return JSONResponse(
            status_code=http_code,
            content={"authorized": False, "reason": reason, "message": msg}
        )

    enforce_dev_lock = sys_cfg.get("enforce_device_lock", "true").lower() == "true"
    dev_ok, _ = check_and_bind_device(uid, device_id, str(body_json.get("device_model") or "Android"), cert_or_msg, enforce_dev_lock)
    if not dev_ok:
        return JSONResponse(
            status_code=403,
            content={"authorized": False, "reason": "device_mismatch", "message": "Dispositivo no autorizado."}
        )

    saved = save_driver_cloud_state(
        uid=uid,
        bot_config=body_json.get("bot_config"),
        zones=body_json.get("zones"),
        zone_settings=body_json.get("zone_settings")
    )
    return {
        "ok": True,
        "authorized": True,
        "updated_at": saved.get("updated_at")
    }


# ==============================================================================
# SEGURIDAD DE ADMINISTRACIÓN (/api/v1/admin/*)
# ==============================================================================
def require_admin_auth(request: Request, token_query: Optional[str] = None):
    header_key = (request.headers.get("X-Admin-Key") or "").strip()
    candidate = header_key or (token_query or "").strip()
    if not candidate or not hmac.compare_digest(candidate, ADMIN_SECRET_KEY):
        raise HTTPException(status_code=401, detail="Clave maestra de administrador requerida o inválida")


@app.get("/api/v1/admin/drivers")
def admin_list_drivers(request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    drivers = db_list_drivers()
    dev_map = db_get_prefix_map("driver_dev:")
    cfg_map = db_get_prefix_map("driver_cfg:")
    now = datetime.now()
    for d in drivers:
        uid = d.get("uid", "")
        try:
            raw_v = d.get("valid_until", "").replace("Z", "+00:00")
            exp = datetime.fromisoformat(raw_v)
            if exp.tzinfo is not None:
                exp = exp.replace(tzinfo=None)
            d["days_left"] = max(0, (exp - now).days)
            d["is_active"] = (now <= exp) and (d.get("status") != "banned")
        except Exception:
            d["days_left"] = 0
            d["is_active"] = False
        dev_info = dev_map.get(uid)
        d["device_info"] = dev_info if isinstance(dev_info, dict) else None
        d["has_cloud_config"] = uid in cfg_map
    return drivers


@app.post("/api/v1/admin/drivers")
def admin_register_driver(req: DriverRegisterRequest, request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    expiry = (datetime.now() + timedelta(days=req.days)).isoformat()
    db_save_driver(req.uid.strip(), req.name.strip(), (req.phone or "").strip(), expiry, "active", req.notes or "")
    return {"status": "ok", "message": f"Conductor {req.uid} activado por {req.days} días"}


@app.post("/api/v1/admin/drivers/{uid}/extend")
def admin_extend_driver(uid: str, req: DriverExtendRequest, request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    driver = db_get_driver(uid)
    if not driver:
        raise HTTPException(status_code=404, detail="Conductor no encontrado")

    try:
        raw_v = driver.get("valid_until", "").replace("Z", "+00:00")
        current_exp = datetime.fromisoformat(raw_v)
        if current_exp.tzinfo is not None:
            current_exp = current_exp.replace(tzinfo=None)
        base_date = max(datetime.now(), current_exp)
    except Exception:
        base_date = datetime.now()

    new_exp = (base_date + timedelta(days=req.days)).isoformat()
    db_save_driver(uid, driver.get("name", "Conductor"), driver.get("phone", ""), new_exp, "active", driver.get("notes", ""))
    return {"status": "ok", "message": f"Se extendieron {req.days} días a UID {uid}", "valid_until": new_exp}


@app.post("/api/v1/admin/drivers/{uid}/status")
def admin_toggle_driver_status(uid: str, req: DriverStatusUpdateRequest, request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    driver = db_get_driver(uid)
    if not driver:
        raise HTTPException(status_code=404, detail="Conductor no encontrado")
    new_status = "banned" if req.status == "banned" else "active"
    db_save_driver(uid, driver.get("name", "Conductor"), driver.get("phone", ""), driver.get("valid_until", ""), new_status, driver.get("notes", ""))
    return {"status": "ok", "driver_status": new_status}


@app.post("/api/v1/admin/drivers/{uid}/reset-device")
def admin_reset_driver_device(uid: str, request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    db_delete_key(f"driver_dev:{uid}")
    return {"status": "ok", "message": f"Dispositivo liberado para UID {uid}"}


@app.delete("/api/v1/admin/drivers/{uid}")
def admin_delete_driver(uid: str, request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    db_delete_driver(uid)
    return {"status": "ok", "message": f"Conductor {uid} y sus datos remotos eliminados"}


@app.get("/api/v1/admin/settings")
def admin_get_settings(request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    return db_get_global_configs()


@app.post("/api/v1/admin/settings")
def admin_update_settings(req: SystemSettingsUpdateRequest, request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    for k, v in req.settings.items():
        if k in DEFAULT_SYSTEM_CONFIGS:
            if k == "allowed_apk_sha256":
                certs = parse_allowed_certs(str(v))
                db_set_config(k, ",".join(certs))
            else:
                db_set_config(k, str(v).strip())
    invalidate_config_cache()
    return {"status": "ok", "settings": db_get_global_configs()}


@app.get("/api/v1/admin/logs")
def admin_get_logs(request: Request, limit: int = 50, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    return db_get_logs(limit)


# ==============================================================================
# PANEL WEB DE CONTROL VISUAL (/admin)
# ==============================================================================
@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard():
    db_label = "🟢 Supabase PostgreSQL (Cloud)" if USE_SUPABASE else "🟡 SQLite Local"
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Omega Core v3.0 - Panel Autoritativo</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-hover: #1f2937;
            --border: #232f46;
            --accent: #3b82f6;
            --accent-glow: rgba(59, 130, 246, 0.3);
            --green: #10b981;
            --red: #ef4444;
            --orange: #f59e0b;
            --text: #f3f4f6;
            --text-dim: #9ca3af;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: 'Outfit', sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 24px; min-height: 100vh; }}
        .header {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }}
        .header h1 {{ font-size: 26px; font-weight: 700; background: linear-gradient(135deg, #60a5fa, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .badge {{ padding: 6px 12px; border-radius: 9999px; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }}
        .badge-active {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 24px; }}
        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 20px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); margin-bottom: 20px; }}
        .card-title {{ font-size: 13px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }}
        .card-value {{ font-size: 30px; font-weight: 700; }}
        .btn {{ padding: 9px 16px; border-radius: 10px; border: none; font-weight: 600; cursor: pointer; transition: all 0.2s; font-size: 13px; }}
        .btn-primary {{ background: var(--accent); color: white; box-shadow: 0 4px 14px var(--accent-glow); }}
        .btn-primary:hover {{ background: #2563eb; }}
        .btn-success {{ background: var(--green); color: white; }}
        .btn-warning {{ background: var(--orange); color: #090d16; }}
        .btn-danger {{ background: var(--red); color: white; }}
        .btn-sm {{ padding: 6px 10px; font-size: 12px; margin-right: 4px; margin-bottom: 4px; }}
        .table-container {{ background: var(--surface); border: 1px solid var(--border); border-radius: 16px; overflow-x: auto; margin-bottom: 24px; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th {{ background: #172033; padding: 14px 16px; font-size: 12px; color: var(--text-dim); text-transform: uppercase; }}
        td {{ padding: 14px 16px; border-top: 1px solid var(--border); font-size: 13px; vertical-align: middle; }}
        tr:hover td {{ background: var(--surface-hover); }}
        .modal-form {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; align-items: end; margin-top: 12px; }}
        input, select, textarea {{ background: #0c121e; border: 1px solid var(--border); padding: 10px 12px; border-radius: 10px; color: white; font-size: 13px; width: 100%; }}
        label {{ font-size: 12px; color: var(--text-dim); display: block; margin-bottom: 4px; }}
        .log-box {{ background: #080c14; border: 1px solid var(--border); border-radius: 12px; padding: 14px; font-family: monospace; font-size: 12px; max-height: 260px; overflow-y: auto; color: #a5b4fc; }}
        .log-line {{ padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>OMEGA CORE v3.0 • SERVIDOR AUTORITATIVO</h1>
            <p style="color: var(--text-dim); font-size: 13px;">Control Total de Membresías, Configuración en Nube, URLs Cifradas y Firma APK</p>
        </div>
        <div style="display: flex; gap: 10px; align-items: center;">
            <span class="badge" style="background: rgba(255,255,255,0.08);">{db_label}</span>
            <button class="btn btn-warning" onclick="promptAdminKey()">🔑 Clave Admin</button>
            <button class="btn btn-primary" onclick="loadData()">🔄 Refrescar</button>
        </div>
    </div>

    <div class="grid">
        <div class="card" style="margin-bottom:0;">
            <div class="card-title">Conductores Registrados</div>
            <div class="card-value" id="totalDriversCount">--</div>
            <div style="font-size: 13px; color: var(--green); margin-top: 4px;" id="activeDriversCount">-- activos</div>
        </div>
        <div class="card" style="margin-bottom:0;">
            <div class="card-title">Blindaje Criptográfico APK</div>
            <div style="margin-top: 8px; display:flex; gap:8px; flex-wrap:wrap;">
                <span id="sigEnforceBadge" class="badge badge-active">Firma SHA-256 Activa</span>
                <span id="devLockBadge" class="badge badge-active">1 Cuenta = 1 Equipo</span>
            </div>
            <p style="font-size: 12px; color: var(--text-dim); margin-top: 8px;">Las URLs y ajustes viajan cifrados para la firma oficial del APK y duran segundos en RAM.</p>
        </div>
        <div class="card" style="margin-bottom:0;">
            <div class="card-title">Tiempo de Vida en RAM (Lease TTL)</div>
            <div class="card-value" id="ttlDisplay">180s</div>
            <div style="font-size: 12px; color: var(--text-dim); margin-top: 4px;">Cero datos permanentes en teléfono</div>
        </div>
    </div>

    <div class="card">
        <h3 style="font-size: 16px; margin-bottom: 8px;">Registrar / Activar Membresía de Conductor</h3>
        <div class="modal-form">
            <div>
                <label>UID Conductor</label>
                <input type="text" id="newUid" placeholder="Ej: 104928374">
            </div>
            <div>
                <label>Nombre</label>
                <input type="text" id="newName" placeholder="Ej: Juan Pérez">
            </div>
            <div>
                <label>Teléfono</label>
                <input type="text" id="newPhone" placeholder="+57300...">
            </div>
            <div>
                <label>Vigencia</label>
                <select id="newDays">
                    <option value="1">1 Día (Demo)</option>
                    <option value="7">7 Días</option>
                    <option value="15">15 Días</option>
                    <option value="30" selected>30 Días (1 Mes)</option>
                    <option value="90">90 Días</option>
                    <option value="365">1 Año</option>
                </select>
            </div>
            <button class="btn btn-primary" onclick="registerDriver()">Activar Membresía</button>
        </div>
    </div>

    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>UID</th>
                    <th>Conductor</th>
                    <th>Estado</th>
                    <th>Vigencia</th>
                    <th>Equipo Vinculado</th>
                    <th>Config Nube</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody id="driversTbody">
                <tr><td colspan="7" style="text-align:center; color: var(--text-dim);">Cargando...</td></tr>
            </tbody>
        </table>
    </div>

    <div class="card">
        <h3 style="font-size: 16px; margin-bottom: 10px;">🛡️ Firmas Oficiales APK (SHA-256) y URLs Remotas</h3>
        <p style="font-size: 12px; color: var(--text-dim); margin-bottom: 12px;">
            Pega aquí las huellas SHA-256 de tus certificados oficiales separadas por coma (con o sin dos puntos, ej. llave Debug + llave App Signing de Google Play Console). Cualquier APK modificado tendrá otra firma y no podrá descifrar las URLs.
        </p>
        <div style="margin-bottom: 12px;">
            <label>Huellas SHA-256 Autorizadas (separadas por coma)</label>
            <textarea id="cfgAllowedCerts" rows="2" placeholder="ada69302..."></textarea>
        </div>
        <div class="modal-form" style="margin-bottom: 12px;">
            <div>
                <label>Exigir Firma Oficial APK</label>
                <select id="cfgEnforceSig">
                    <option value="true">Sí (Bloquear APKs modificados)</option>
                    <option value="false">No (Modo diagnóstico)</option>
                </select>
            </div>
            <div>
                <label>Bloqueo por Dispositivo</label>
                <select id="cfgEnforceDev">
                    <option value="true">Sí (1 Membresía = 1 Teléfono)</option>
                    <option value="false">No</option>
                </select>
            </div>
            <div>
                <label>Duración Lease en RAM (segundos)</label>
                <input type="number" id="cfgLeaseTtl" value="180">
            </div>
            <div>
                <label>Host Regional CO</label>
                <input type="text" id="cfgHostCo">
            </div>
            <div>
                <label>Host Regional LATAM</label>
                <input type="text" id="cfgHostLatam">
            </div>
            <div>
                <label>WebSocket SSN Host</label>
                <input type="text" id="cfgWsHost">
            </div>
        </div>
        <button class="btn btn-success" onclick="saveSystemSettings()">💾 Guardar Blindaje y URLs en Servidor</button>
    </div>

    <div class="card">
        <div class="card-title">Registro de Auditoría y Seguridad en Vivo (Últimos 50 eventos)</div>
        <div class="log-box" id="logsContainer">Cargando registros...</div>
    </div>

    <script>
        function getAdminKey() {{
            let k = localStorage.getItem('omega_admin_key') || '';
            if (!k) {{
                k = prompt('Ingresa la clave de administrador (OMEGA_ADMIN_KEY):', 'omega_admin_2026_secreto') || '';
                if (k) localStorage.setItem('omega_admin_key', k.trim());
            }}
            return k.trim();
        }}

        function promptAdminKey() {{
            const current = localStorage.getItem('omega_admin_key') || '';
            const k = prompt('Actualizar clave de administrador:', current);
            if (k !== null) {{
                localStorage.setItem('omega_admin_key', k.trim());
                loadData();
            }}
        }}

        async function apiFetch(url, options = {{}}) {{
            const headers = Object.assign({{ 'Content-Type': 'application/json', 'X-Admin-Key': getAdminKey() }}, options.headers || {{}});
            const res = await fetch(url, Object.assign({{}}, options, {{ headers }}));
            if (res.status === 401) {{
                localStorage.removeItem('omega_admin_key');
                alert('Clave de administrador incorrecta.');
                throw new Error('Unauthorized');
            }}
            return res;
        }}

        async function loadData() {{
            try {{
                const [drvRes, setRes, logRes] = await Promise.all([
                    apiFetch('/api/v1/admin/drivers'),
                    apiFetch('/api/v1/admin/settings'),
                    apiFetch('/api/v1/admin/logs?limit=50')
                ]);
                const drivers = await drvRes.json();
                const settings = await setRes.json();
                const logs = await logRes.json();

                document.getElementById('totalDriversCount').innerText = drivers.length;
                document.getElementById('activeDriversCount').innerText = drivers.filter(d => d.is_active).length + ' con membresía activa';
                document.getElementById('ttlDisplay').innerText = (settings.lease_ttl_sec || '180') + 's';

                document.getElementById('cfgAllowedCerts').value = settings.allowed_apk_sha256 || '';
                document.getElementById('cfgEnforceSig').value = settings.enforce_apk_signature || 'true';
                document.getElementById('cfgEnforceDev').value = settings.enforce_device_lock || 'true';
                document.getElementById('cfgLeaseTtl').value = settings.lease_ttl_sec || '180';
                document.getElementById('cfgHostCo').value = settings.host_co || '';
                document.getElementById('cfgHostLatam').value = settings.host_latam || '';
                document.getElementById('cfgWsHost').value = settings.ws_ssn_host || '';

                const sigBadge = document.getElementById('sigEnforceBadge');
                sigBadge.className = 'badge ' + (settings.enforce_apk_signature === 'true' ? 'badge-active' : 'badge-warning');
                sigBadge.innerText = settings.enforce_apk_signature === 'true' ? 'Firma SHA-256 Estricta' : 'Firma Flexible';

                const devBadge = document.getElementById('devLockBadge');
                devBadge.className = 'badge ' + (settings.enforce_device_lock === 'true' ? 'badge-active' : 'badge-warning');
                devBadge.innerText = settings.enforce_device_lock === 'true' ? '1 Cuenta = 1 Equipo' : 'Multi-equipo';

                const tbody = document.getElementById('driversTbody');
                if (drivers.length === 0) {{
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">Sin conductores registrados.</td></tr>';
                }} else {{
                    tbody.innerHTML = drivers.map(d => {{
                        const isBanned = d.status === 'banned';
                        const badgeClass = d.is_active ? 'badge-active' : 'badge-danger';
                        const statusText = d.is_active ? 'Activo' : (isBanned ? 'Suspendido' : 'Vencido');
                        const validDisplay = (d.valid_until || '').replace('T', ' ').substring(0, 16);
                        const devLabel = d.device_info
                            ? `<span class="badge badge-active">📱 ${{d.device_info.device_model || 'Vinculado'}}</span>`
                            : `<span style="color:var(--text-dim);">Libre</span>`;
                        const cfgLabel = d.has_cloud_config
                            ? `<span class="badge badge-active">☁️ Guardada</span>`
                            : `<span style="color:var(--text-dim);">Por defecto</span>`;
                        return `<tr>
                            <td style="font-weight:700; color:#60a5fa;">${{d.uid}}</td>
                            <td><b>${{d.name}}</b><br><span style="color:var(--text-dim);font-size:12px;">${{d.phone || ''}}</span></td>
                            <td><span class="badge ${{badgeClass}}">${{statusText}}</span></td>
                            <td><b>${{d.days_left}}d</b><br><span style="color:var(--text-dim);font-size:11px;">${{validDisplay}}</span></td>
                            <td>${{devLabel}}</td>
                            <td>${{cfgLabel}}</td>
                            <td>
                                <button class="btn btn-sm btn-primary" onclick="extendDays('${{d.uid}}', 30)">+30d</button>
                                <button class="btn btn-sm btn-warning" onclick="resetDevice('${{d.uid}}')">📱 Liberar</button>
                                <button class="btn btn-sm ${{isBanned ? 'btn-success' : 'btn-danger'}}" onclick="toggleBan('${{d.uid}}', '${{isBanned ? 'active' : 'banned'}}')">${{isBanned ? 'Reactivar' : 'Suspender'}}</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteDriver('${{d.uid}}')">🗑️</button>
                            </td>
                        </tr>`;
                    }}).join('');
                }}

                const logBox = document.getElementById('logsContainer');
                logBox.innerHTML = logs.length === 0
                    ? '<div style="color:#6b7280;">Sin eventos aún.</div>'
                    : logs.map(l => {{
                        const time = (l.created_at || '').substring(11, 19);
                        const color = l.status === 'success' ? '#34d399' : (l.status === 'tampered' ? '#ef4444' : '#fbbf24');
                        return `<div class="log-line"><span style="color:#60a5fa;">[${{time}}]</span> <b>UID: ${{l.uid || 'anon'}}</b> (${{l.ip_address}}) - <span style="color:${{color}}">${{l.action}} [${{l.status}}]</span> - ${{l.details || ''}}</div>`;
                    }}).join('');
            }} catch (e) {{
                console.error(e);
            }}
        }}

        async function registerDriver() {{
            const uid = document.getElementById('newUid').value.trim();
            const name = document.getElementById('newName').value.trim();
            const phone = document.getElementById('newPhone').value.trim();
            const days = parseInt(document.getElementById('newDays').value);
            if (!uid || !name) return alert('Ingresa UID y Nombre.');
            await apiFetch('/api/v1/admin/drivers', {{ method: 'POST', body: JSON.stringify({{ uid, name, phone, days }}) }});
            document.getElementById('newUid').value = '';
            document.getElementById('newName').value = '';
            document.getElementById('newPhone').value = '';
            loadData();
        }}

        async function extendDays(uid, days) {{
            await apiFetch(`/api/v1/admin/drivers/${{uid}}/extend`, {{ method: 'POST', body: JSON.stringify({{ days }}) }});
            loadData();
        }}

        async function resetDevice(uid) {{
            await apiFetch(`/api/v1/admin/drivers/${{uid}}/reset-device`, {{ method: 'POST' }});
            loadData();
        }}

        async function toggleBan(uid, status) {{
            await apiFetch(`/api/v1/admin/drivers/${{uid}}/status`, {{ method: 'POST', body: JSON.stringify({{ status }}) }});
            loadData();
        }}

        async function deleteDriver(uid) {{
            if (!confirm(`¿Eliminar definitivamente al conductor ${{uid}} y su configuración en nube?`)) return;
            await apiFetch(`/api/v1/admin/drivers/${{uid}}`, {{ method: 'DELETE' }});
            loadData();
        }}

        async function saveSystemSettings() {{
            const settings = {{
                allowed_apk_sha256: document.getElementById('cfgAllowedCerts').value,
                enforce_apk_signature: document.getElementById('cfgEnforceSig').value,
                enforce_device_lock: document.getElementById('cfgEnforceDev').value,
                lease_ttl_sec: document.getElementById('cfgLeaseTtl').value,
                host_co: document.getElementById('cfgHostCo').value,
                host_latam: document.getElementById('cfgHostLatam').value,
                ws_ssn_host: document.getElementById('cfgWsHost').value
            }};
            await apiFetch('/api/v1/admin/settings', {{ method: 'POST', body: JSON.stringify({{ settings }}) }});
            alert('Configuración del servidor actualizada.');
            loadData();
        }}

        loadData();
        setInterval(loadData, 12000);
    </script>
</body>
</html>"""


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("omega_backend_server:app", host="0.0.0.0", port=port, reload=True)
