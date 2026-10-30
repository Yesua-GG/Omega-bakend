import os
import re
import sys
import math
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
    description="Servidor Autoritativo v3.1: Membresías, Equipos y Configs Separados + URLs Multipaís Cifradas + Firma Nativa APK",
    version="3.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# CONFIGURACIÓN GLOBAL DEL SISTEMA Y SEMILLA MULTIPAÍS POR DEFECTO
# ==============================================================================
DEFAULT_SYSTEM_CONFIGS: Dict[str, str] = {
    "playstore_review_mode": "false",
    "auto_trial_enabled": "true",
    "auto_trial_days": "3",
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

DEFAULT_COUNTRY_ENDPOINTS: List[Dict[str, Any]] = [
    {
        "country_code": "DO",
        "country_name": "República Dominicana",
        "api_host": "https://api-gw-cf.latam.saea1.aws.indriverapp.com",
        "ws_host": "wss://ssn-lb-cf.latam.saea1.aws.indriverapp.com",
        "messenger_host": "https://api-gw-cf.euce1.indriverapp.com",
        "auth_host": "",
        "cas_host": "",
        "currency_code": "DOP",
        "currency_symbol": "RD$",
        "min_lat": 17.40,
        "max_lat": 20.10,
        "min_lon": -72.10,
        "max_lon": -68.20,
        "priority": 5,
        "is_active": True
    },
    {
        "country_code": "PA",
        "country_name": "Panamá",
        "api_host": "https://api-gw-cf.latam.saea1.aws.indriverapp.com",
        "ws_host": "wss://ssn-lb-cf.latam.saea1.aws.indriverapp.com",
        "messenger_host": "https://api-gw-cf.euce1.indriverapp.com",
        "auth_host": "",
        "cas_host": "",
        "currency_code": "USD",
        "currency_symbol": "$",
        "min_lat": 7.20,
        "max_lat": 9.70,
        "min_lon": -83.10,
        "max_lon": -77.40,
        "priority": 6,
        "is_active": True
    },
    {
        "country_code": "EC",
        "country_name": "Ecuador",
        "api_host": "https://api-gw-cf.latam.saea1.aws.indriverapp.com",
        "ws_host": "wss://ssn-lb-cf.latam.saea1.aws.indriverapp.com",
        "messenger_host": "https://api-gw-cf.euce1.indriverapp.com",
        "auth_host": "",
        "cas_host": "",
        "currency_code": "USD",
        "currency_symbol": "$",
        "min_lat": -5.00,
        "max_lat": 0.78,
        "min_lon": -81.20,
        "max_lon": -75.20,
        "priority": 7,
        "is_active": True
    },
    {
        "country_code": "CO",
        "country_name": "Colombia",
        "api_host": "https://api-gw-cf.latam-co.saea1.aws.indriverapp.com",
        "ws_host": "wss://ssn-lb-cf.latam.saea1.aws.indriverapp.com",
        "messenger_host": "https://api-gw-cf.euce1.indriverapp.com",
        "auth_host": "",
        "cas_host": "",
        "currency_code": "COP",
        "currency_symbol": "$",
        "min_lat": -4.30,
        "max_lat": 13.50,
        "min_lon": -82.00,
        "max_lon": -66.80,
        "priority": 10,
        "is_active": True
    },
    {
        "country_code": "PE",
        "country_name": "Perú",
        "api_host": "https://api-gw-cf.latam-pe.saea1.aws.indriverapp.com",
        "ws_host": "wss://ssn-lb-cf.latam.saea1.aws.indriverapp.com",
        "messenger_host": "https://api-gw-cf.euce1.indriverapp.com",
        "auth_host": "",
        "cas_host": "",
        "currency_code": "PEN",
        "currency_symbol": "S/",
        "min_lat": -18.40,
        "max_lat": -0.05,
        "min_lon": -81.40,
        "max_lon": -68.60,
        "priority": 12,
        "is_active": True
    },
    {
        "country_code": "MX",
        "country_name": "México",
        "api_host": "https://api-gw-cf.latam-mx.usea1.aws.indriverapp.com",
        "ws_host": "wss://ssn-lb-cf.latam.saea1.aws.indriverapp.com",
        "messenger_host": "https://api-gw-cf.euce1.indriverapp.com",
        "auth_host": "",
        "cas_host": "",
        "currency_code": "MXN",
        "currency_symbol": "$",
        "min_lat": 14.50,
        "max_lat": 32.80,
        "min_lon": -118.50,
        "max_lon": -86.50,
        "priority": 12,
        "is_active": True
    },
    {
        "country_code": "CL",
        "country_name": "Chile",
        "api_host": "https://api-gw-cf.latam.saea1.aws.indriverapp.com",
        "ws_host": "wss://ssn-lb-cf.latam.saea1.aws.indriverapp.com",
        "messenger_host": "https://api-gw-cf.euce1.indriverapp.com",
        "auth_host": "",
        "cas_host": "",
        "currency_code": "CLP",
        "currency_symbol": "$",
        "min_lat": -56.00,
        "max_lat": -17.50,
        "min_lon": -76.00,
        "max_lon": -66.40,
        "priority": 12,
        "is_active": True
    },
    {
        "country_code": "BR",
        "country_name": "Brasil",
        "api_host": "https://api-gw-cf.latam-br.saea1.aws.indriverapp.com",
        "ws_host": "wss://ssn-lb-cf.latam.saea1.aws.indriverapp.com",
        "messenger_host": "https://api-gw-cf.euce1.indriverapp.com",
        "auth_host": "",
        "cas_host": "",
        "currency_code": "BRL",
        "currency_symbol": "R$",
        "min_lat": -33.80,
        "max_lat": 5.30,
        "min_lon": -74.00,
        "max_lon": -34.70,
        "priority": 15,
        "is_active": True
    },
    {
        "country_code": "LATAM",
        "country_name": "Latinoamérica (General)",
        "api_host": "https://api-gw-cf.latam.saea1.aws.indriverapp.com",
        "ws_host": "wss://ssn-lb-cf.latam.saea1.aws.indriverapp.com",
        "messenger_host": "https://api-gw-cf.euce1.indriverapp.com",
        "auth_host": "",
        "cas_host": "",
        "currency_code": "USD",
        "currency_symbol": "$",
        "min_lat": -60.00,
        "max_lat": 35.00,
        "min_lon": -120.00,
        "max_lon": -30.00,
        "priority": 999,
        "is_active": True
    }
]

# Cachés ligeros en RAM para evitar viajes HTTP redundantes a Supabase en cada latido
_SYS_CONFIG_CACHE: Dict[str, str] = {}
_SYS_CONFIG_CACHE_TS: float = 0.0
_COUNTRIES_CACHE: List[Dict[str, Any]] = []
_COUNTRIES_CACHE_TS: float = 0.0
_CACHE_TTL_SEC: float = 6.0


def invalidate_config_cache():
    global _SYS_CONFIG_CACHE_TS, _COUNTRIES_CACHE_TS
    _SYS_CONFIG_CACHE_TS = 0.0
    _COUNTRIES_CACHE_TS = 0.0


# ==============================================================================
# ADAPTADOR DE BASE DE DATOS NORMALIZADO: SUPABASE POSTGRESQL / SQLITE LOCAL
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

    # Bloque A: Usuarios, Membresías, Equipos, Configs y Logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS drivers (
        uid TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        phone TEXT DEFAULT '',
        status TEXT DEFAULT 'active',
        valid_until TEXT NOT NULL,
        created_at TEXT NOT NULL,
        notes TEXT DEFAULT '',
        country_code TEXT DEFAULT 'CO',
        plan_type TEXT DEFAULT 'trial',
        updated_at TEXT DEFAULT ''
    )
    """)
    for col_sql in [
        "ALTER TABLE drivers ADD COLUMN country_code TEXT DEFAULT 'CO'",
        "ALTER TABLE drivers ADD COLUMN plan_type TEXT DEFAULT 'trial'",
        "ALTER TABLE drivers ADD COLUMN updated_at TEXT DEFAULT ''"
    ]:
        try:
            cursor.execute(col_sql)
        except Exception:
            pass

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS driver_devices (
        uid TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        device_model TEXT DEFAULT 'Android',
        cert_sha256 TEXT DEFAULT '',
        bound_at TEXT NOT NULL,
        last_seen TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS driver_configs (
        uid TEXT PRIMARY KEY,
        bot_config TEXT,
        zones TEXT DEFAULT '[]',
        zone_settings TEXT DEFAULT '{}',
        updated_at TEXT NOT NULL
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

    # Bloque B: Configuración del Sistema y Catálogo Multipaís de URLs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS country_endpoints (
        country_code TEXT PRIMARY KEY,
        country_name TEXT NOT NULL,
        api_host TEXT NOT NULL,
        ws_host TEXT DEFAULT '',
        messenger_host TEXT DEFAULT '',
        auth_host TEXT DEFAULT '',
        cas_host TEXT DEFAULT '',
        currency_code TEXT DEFAULT 'USD',
        currency_symbol TEXT DEFAULT '$',
        min_lat REAL,
        max_lat REAL,
        min_lon REAL,
        max_lon REAL,
        priority INTEGER DEFAULT 10,
        is_active INTEGER DEFAULT 1,
        updated_at TEXT DEFAULT ''
    )
    """)

    for k, v in DEFAULT_SYSTEM_CONFIGS.items():
        cursor.execute("INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)", (k, v))

    now_iso = datetime.now().isoformat()
    for c in DEFAULT_COUNTRY_ENDPOINTS:
        cursor.execute("""
        INSERT INTO country_endpoints (
            country_code, country_name, api_host, ws_host, messenger_host, auth_host, cas_host,
            currency_code, currency_symbol, min_lat, max_lat, min_lon, max_lon, priority, is_active, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(country_code) DO UPDATE SET
            api_host = excluded.api_host,
            ws_host = excluded.ws_host,
            messenger_host = excluded.messenger_host,
            currency_code = excluded.currency_code,
            currency_symbol = excluded.currency_symbol,
            updated_at = excluded.updated_at
        """, (
            c["country_code"], c["country_name"], c["api_host"], c["ws_host"], c["messenger_host"],
            c["auth_host"], c["cas_host"], c["currency_code"], c["currency_symbol"],
            c["min_lat"], c["max_lat"], c["min_lon"], c["max_lon"], c["priority"],
            1 if c["is_active"] else 0, now_iso
        ))

    conn.commit()
    conn.close()


if not USE_SUPABASE:
    init_local_sqlite()


# ------------------------------------------------------------------------------
# BLOQUE A.1: USUARIOS Y MEMBRESÍAS (tabla `drivers`)
# ------------------------------------------------------------------------------
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
    return None


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


def db_save_driver(
    uid: str,
    name: str,
    phone: str,
    valid_until: str,
    status: str = "active",
    notes: str = "",
    country_code: str = "CO",
    plan_type: str = "paid"
):
    clean_cc = (country_code or "CO").strip().upper()
    now_iso = datetime.now().isoformat()
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/drivers"
            headers = supabase_headers()
            headers["Prefer"] = "resolution=merge-duplicates"
            full_payload = {
                "uid": uid,
                "name": name,
                "phone": phone,
                "status": status,
                "valid_until": valid_until,
                "notes": notes,
                "country_code": clean_cc,
                "plan_type": plan_type,
                "updated_at": now_iso
            }
            res = requests.post(url, headers=headers, json=full_payload, timeout=5)
            if res.status_code >= 400:
                # Respaldo compatible si aún no ejecutaron ALTER TABLE en drivers
                base_payload = {
                    "uid": uid,
                    "name": name,
                    "phone": phone,
                    "status": status,
                    "valid_until": valid_until,
                    "notes": notes
                }
                requests.post(url, headers=headers, json=base_payload, timeout=5)
        except Exception as e:
            print(f"[Supabase Error save_driver] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO drivers (uid, name, phone, status, valid_until, created_at, notes, country_code, plan_type, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(uid) DO UPDATE SET
            name = excluded.name,
            phone = excluded.phone,
            status = excluded.status,
            valid_until = excluded.valid_until,
            notes = excluded.notes,
            country_code = excluded.country_code,
            plan_type = excluded.plan_type,
            updated_at = excluded.updated_at
        """, (uid, name, phone, status, valid_until, now_iso, notes, clean_cc, plan_type, now_iso))
        conn.commit()
        conn.close()


def db_update_driver_country(uid: str, country_code: str):
    clean_cc = (country_code or "").strip().upper()
    if not clean_cc or len(clean_cc) > 8:
        return
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/drivers?uid=eq.{uid}"
            requests.patch(
                url,
                headers=supabase_headers(),
                json={"country_code": clean_cc, "updated_at": datetime.now().isoformat()},
                timeout=4
            )
        except Exception:
            pass
    else:
        try:
            conn = get_sqlite_db()
            cur = conn.cursor()
            cur.execute("UPDATE drivers SET country_code = ?, updated_at = ? WHERE uid = ?", (clean_cc, datetime.now().isoformat(), uid))
            conn.commit()
            conn.close()
        except Exception:
            pass


def db_insert_driver_if_new(
    uid: str,
    name: str,
    phone: str,
    valid_until: str,
    notes: str = "",
    country_code: str = "CO"
) -> Dict[str, Any]:
    """
    Inserta un nuevo conductor únicamente si su UID no existe aún (atómico contra condiciones de carrera
    para que nunca se sobrescriba una membresía vencida o suspendida).
    """
    clean_cc = (country_code or "CO").strip().upper()
    now_iso = datetime.now().isoformat()
    record = {
        "uid": uid,
        "name": name,
        "phone": phone,
        "status": "active",
        "valid_until": valid_until,
        "notes": notes,
        "country_code": clean_cc,
        "plan_type": "trial",
        "updated_at": now_iso
    }
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/drivers?on_conflict=uid"
            headers = supabase_headers()
            headers["Prefer"] = "resolution=ignore-duplicates,return=representation"
            res = requests.post(url, headers=headers, json=record, timeout=6)
            if res.status_code >= 400:
                base_rec = {
                    "uid": uid,
                    "name": name,
                    "phone": phone,
                    "status": "active",
                    "valid_until": valid_until,
                    "notes": notes
                }
                res = requests.post(url, headers=headers, json=base_rec, timeout=6)
            if res.status_code in (200, 201):
                rows = res.json() if res.text else []
                if isinstance(rows, list) and rows:
                    return rows[0]
        except Exception as e:
            print(f"[Supabase Error insert_driver_if_new] {e}")
        return db_get_driver(uid) or record
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("""
        INSERT OR IGNORE INTO drivers (uid, name, phone, status, valid_until, created_at, notes, country_code, plan_type, updated_at)
        VALUES (?, ?, ?, 'active', ?, ?, ?, ?, 'trial', ?)
        """, (uid, name, phone, valid_until, now_iso, notes, clean_cc, now_iso))
        conn.commit()
        conn.close()
        return db_get_driver(uid) or record


def db_delete_driver(uid: str):
    if USE_SUPABASE:
        try:
            # ON DELETE CASCADE en driver_devices y driver_configs limpia automáticamente sus hijos
            requests.delete(f"{SUPABASE_URL}/rest/v1/driver_devices?uid=eq.{uid}", headers=supabase_headers(), timeout=4)
            requests.delete(f"{SUPABASE_URL}/rest/v1/driver_configs?uid=eq.{uid}", headers=supabase_headers(), timeout=4)
            requests.delete(f"{SUPABASE_URL}/rest/v1/drivers?uid=eq.{uid}", headers=supabase_headers(), timeout=5)
            requests.delete(f"{SUPABASE_URL}/rest/v1/system_config?key=in.(driver_cfg:{uid},driver_dev:{uid})", headers=supabase_headers(), timeout=4)
        except Exception as e:
            print(f"[Supabase Error delete_driver] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM driver_devices WHERE uid = ?", (uid,))
        cur.execute("DELETE FROM driver_configs WHERE uid = ?", (uid,))
        cur.execute("DELETE FROM drivers WHERE uid = ?", (uid,))
        cur.execute("DELETE FROM system_config WHERE key IN (?, ?)", (f"driver_cfg:{uid}", f"driver_dev:{uid}"))
        conn.commit()
        conn.close()


# ------------------------------------------------------------------------------
# BLOQUE A.2: EQUIPOS VINCULADOS POR USUARIO (tabla `driver_devices`)
# ------------------------------------------------------------------------------
def db_get_driver_device(uid: str) -> Optional[Dict[str, Any]]:
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/driver_devices?uid=eq.{uid}&select=*"
            res = requests.get(url, headers=supabase_headers(), timeout=5)
            if res.status_code == 200:
                rows = res.json()
                return rows[0] if rows else None
            if res.status_code == 404:
                # Respaldo temporal si la tabla aún no fue creada
                raw = db_get_raw_key(f"driver_dev:{uid}", "")
                return json.loads(raw) if raw else None
        except Exception as e:
            print(f"[Supabase Error get_driver_device] {e}")
        return None
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM driver_devices WHERE uid = ?", (uid,))
        row = cur.fetchone()
        conn.close()
        return dict(row) if row else None


def db_upsert_driver_device(uid: str, device_id: str, device_model: str, cert_sha256: str, bound_at: str, last_seen: str):
    payload = {
        "uid": uid,
        "device_id": device_id,
        "device_model": device_model,
        "cert_sha256": cert_sha256,
        "bound_at": bound_at,
        "last_seen": last_seen
    }
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/driver_devices"
            headers = supabase_headers()
            headers["Prefer"] = "resolution=merge-duplicates"
            res = requests.post(url, headers=headers, json=payload, timeout=5)
            if res.status_code == 404:
                db_set_config(f"driver_dev:{uid}", json.dumps(payload, separators=(",", ":")))
        except Exception as e:
            print(f"[Supabase Error upsert_driver_device] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO driver_devices (uid, device_id, device_model, cert_sha256, bound_at, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(uid) DO UPDATE SET
            device_id = excluded.device_id,
            device_model = excluded.device_model,
            cert_sha256 = excluded.cert_sha256,
            bound_at = excluded.bound_at,
            last_seen = excluded.last_seen
        """, (uid, device_id, device_model, cert_sha256, bound_at, last_seen))
        conn.commit()
        conn.close()


def db_delete_driver_device(uid: str):
    if USE_SUPABASE:
        try:
            requests.delete(f"{SUPABASE_URL}/rest/v1/driver_devices?uid=eq.{uid}", headers=supabase_headers(), timeout=5)
            requests.delete(f"{SUPABASE_URL}/rest/v1/system_config?key=eq.driver_dev:{uid}", headers=supabase_headers(), timeout=4)
        except Exception as e:
            print(f"[Supabase Error delete_driver_device] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM driver_devices WHERE uid = ?", (uid,))
        cur.execute("DELETE FROM system_config WHERE key = ?", (f"driver_dev:{uid}",))
        conn.commit()
        conn.close()


def db_map_driver_devices() -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if USE_SUPABASE:
        try:
            res = requests.get(f"{SUPABASE_URL}/rest/v1/driver_devices?select=*", headers=supabase_headers(), timeout=5)
            if res.status_code == 200:
                for row in res.json():
                    if row.get("uid"):
                        out[row["uid"]] = row
                return out
        except Exception as e:
            print(f"[Supabase Error map_driver_devices] {e}")
        return out
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM driver_devices")
        for row in cur.fetchall():
            d = dict(row)
            out[d["uid"]] = d
        conn.close()
        return out


# ------------------------------------------------------------------------------
# BLOQUE A.3: CONFIGURACIÓN PERSONAL Y ZONAS POR USUARIO (tabla `driver_configs`)
# ------------------------------------------------------------------------------
def load_driver_cloud_state(uid: str) -> Optional[Dict[str, Any]]:
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/driver_configs?uid=eq.{uid}&select=*"
            res = requests.get(url, headers=supabase_headers(), timeout=5)
            if res.status_code == 200:
                rows = res.json()
                if rows:
                    row = rows[0]
                    return {
                        "bot_config": row.get("bot_config"),
                        "zones": row.get("zones") if isinstance(row.get("zones"), list) else [],
                        "zone_settings": row.get("zone_settings") if isinstance(row.get("zone_settings"), dict) else {},
                        "updated_at": row.get("updated_at", "")
                    }
                return None
            if res.status_code == 404:
                raw = db_get_raw_key(f"driver_cfg:{uid}", "")
                return json.loads(raw) if raw else None
        except Exception as e:
            print(f"[Supabase Error load_driver_cloud_state] {e}")
        return None
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM driver_configs WHERE uid = ?", (uid,))
        row = cur.fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        try:
            bot_cfg = json.loads(d["bot_config"]) if d.get("bot_config") else None
        except Exception:
            bot_cfg = None
        try:
            zones = json.loads(d["zones"]) if d.get("zones") else []
        except Exception:
            zones = []
        try:
            zs = json.loads(d["zone_settings"]) if d.get("zone_settings") else {}
        except Exception:
            zs = {}
        return {
            "bot_config": bot_cfg,
            "zones": zones if isinstance(zones, list) else [],
            "zone_settings": zs if isinstance(zs, dict) else {},
            "updated_at": d.get("updated_at", "")
        }


def save_driver_cloud_state(
    uid: str,
    bot_config: Optional[Dict[str, Any]],
    zones: Optional[List[Any]],
    zone_settings: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    existing = load_driver_cloud_state(uid) or {}
    now_iso = datetime.now().isoformat()
    final_bot = bot_config if bot_config is not None else existing.get("bot_config")
    final_zones = zones if zones is not None else existing.get("zones", [])
    final_zs = zone_settings if zone_settings is not None else existing.get("zone_settings", {})

    updated = {
        "bot_config": final_bot,
        "zones": final_zones,
        "zone_settings": final_zs,
        "updated_at": now_iso
    }

    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/driver_configs"
            headers = supabase_headers()
            headers["Prefer"] = "resolution=merge-duplicates"
            payload = {
                "uid": uid,
                "bot_config": final_bot,
                "zones": final_zones,
                "zone_settings": final_zs,
                "updated_at": now_iso
            }
            res = requests.post(url, headers=headers, json=payload, timeout=5)
            if res.status_code == 404:
                db_set_config(f"driver_cfg:{uid}", json.dumps(updated, separators=(",", ":"), ensure_ascii=False))
        except Exception as e:
            print(f"[Supabase Error save_driver_cloud_state] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO driver_configs (uid, bot_config, zones, zone_settings, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(uid) DO UPDATE SET
            bot_config = excluded.bot_config,
            zones = excluded.zones,
            zone_settings = excluded.zone_settings,
            updated_at = excluded.updated_at
        """, (
            uid,
            json.dumps(final_bot, separators=(",", ":"), ensure_ascii=False) if final_bot is not None else None,
            json.dumps(final_zones, separators=(",", ":"), ensure_ascii=False),
            json.dumps(final_zs, separators=(",", ":"), ensure_ascii=False),
            now_iso
        ))
        conn.commit()
        conn.close()

    return updated


def db_set_of_configured_uids() -> set:
    if USE_SUPABASE:
        try:
            res = requests.get(f"{SUPABASE_URL}/rest/v1/driver_configs?select=uid", headers=supabase_headers(), timeout=5)
            if res.status_code == 200:
                return {r.get("uid") for r in res.json() if r.get("uid")}
        except Exception:
            pass
        return set()
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("SELECT uid FROM driver_configs")
        uids = {r["uid"] for r in cur.fetchall()}
        conn.close()
        return uids


# ------------------------------------------------------------------------------
# BLOQUE A.4: AUDITORÍA DE ACCESOS (tabla `access_logs`)
# ------------------------------------------------------------------------------
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


# ------------------------------------------------------------------------------
# BLOQUE B.1: CONFIGURACIÓN DEL SISTEMA Y SHA-256 (tabla `system_config`)
# ------------------------------------------------------------------------------
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


def db_get_global_configs() -> Dict[str, str]:
    global _SYS_CONFIG_CACHE, _SYS_CONFIG_CACHE_TS
    now = time.time()
    if _SYS_CONFIG_CACHE and (now - _SYS_CONFIG_CACHE_TS) < _CACHE_TTL_SEC:
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


# ------------------------------------------------------------------------------
# BLOQUE B.2: CATÁLOGO MULTIPAÍS DE URLS REGIONALES (tabla `country_endpoints`)
# ------------------------------------------------------------------------------
def _normalize_country_row(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "country_code": str(row.get("country_code") or "").strip().upper(),
        "country_name": str(row.get("country_name") or "").strip(),
        "api_host": str(row.get("api_host") or "").strip().rstrip("/"),
        "ws_host": str(row.get("ws_host") or "").strip().rstrip("/"),
        "messenger_host": str(row.get("messenger_host") or "").strip().rstrip("/"),
        "auth_host": str(row.get("auth_host") or "").strip().rstrip("/"),
        "cas_host": str(row.get("cas_host") or "").strip().rstrip("/"),
        "currency_code": str(row.get("currency_code") or "USD").strip().upper(),
        "currency_symbol": str(row.get("currency_symbol") or "$").strip(),
        "min_lat": float(row["min_lat"]) if row.get("min_lat") is not None else None,
        "max_lat": float(row["max_lat"]) if row.get("max_lat") is not None else None,
        "min_lon": float(row["min_lon"]) if row.get("min_lon") is not None else None,
        "max_lon": float(row["max_lon"]) if row.get("max_lon") is not None else None,
        "priority": int(row.get("priority") if row.get("priority") is not None else 10),
        "is_active": bool(row.get("is_active", True))
    }


def db_list_countries(only_active: bool = False) -> List[Dict[str, Any]]:
    global _COUNTRIES_CACHE, _COUNTRIES_CACHE_TS
    now = time.time()
    if _COUNTRIES_CACHE and (now - _COUNTRIES_CACHE_TS) < _CACHE_TTL_SEC:
        rows = list(_COUNTRIES_CACHE)
        return [r for r in rows if r["is_active"]] if only_active else rows

    loaded: List[Dict[str, Any]] = []
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/country_endpoints?select=*&order=priority.asc,country_code.asc"
            res = requests.get(url, headers=supabase_headers(), timeout=5)
            if res.status_code == 200:
                loaded = [_normalize_country_row(r) for r in res.json() if r.get("country_code")]
            elif res.status_code == 404:
                # Si la tabla aún no fue creada en Supabase, usar semilla por defecto
                loaded = [_normalize_country_row(c) for c in DEFAULT_COUNTRY_ENDPOINTS]
        except Exception as e:
            print(f"[Supabase Error list_countries] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM country_endpoints ORDER BY priority ASC, country_code ASC")
        loaded = [_normalize_country_row(dict(r)) for r in cur.fetchall()]
        conn.close()

    if not loaded:
        loaded = [_normalize_country_row(c) for c in DEFAULT_COUNTRY_ENDPOINTS]

    _COUNTRIES_CACHE = loaded
    _COUNTRIES_CACHE_TS = now
    return [r for r in loaded if r["is_active"]] if only_active else list(loaded)


def db_upsert_country(country: Dict[str, Any]) -> Dict[str, Any]:
    norm = _normalize_country_row(country)
    if not norm["country_code"] or not norm["country_name"] or not norm["api_host"]:
        raise HTTPException(status_code=400, detail="Código de país, nombre y URL API principal son obligatorios")

    now_iso = datetime.now().isoformat()
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/country_endpoints"
            headers = supabase_headers()
            headers["Prefer"] = "resolution=merge-duplicates,return=representation"
            payload = dict(norm)
            payload["updated_at"] = now_iso
            res = requests.post(url, headers=headers, json=payload, timeout=6)
            if res.status_code == 404:
                raise HTTPException(
                    status_code=500,
                    detail="La tabla country_endpoints aún no existe en Supabase. Ejecuta primero el SQL de migración v3.1."
                )
        except HTTPException:
            raise
        except Exception as e:
            print(f"[Supabase Error upsert_country] {e}")
            raise HTTPException(status_code=500, detail=f"Error guardando país en Supabase: {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO country_endpoints (
            country_code, country_name, api_host, ws_host, messenger_host, auth_host, cas_host,
            currency_code, currency_symbol, min_lat, max_lat, min_lon, max_lon, priority, is_active, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(country_code) DO UPDATE SET
            country_name = excluded.country_name,
            api_host = excluded.api_host,
            ws_host = excluded.ws_host,
            messenger_host = excluded.messenger_host,
            auth_host = excluded.auth_host,
            cas_host = excluded.cas_host,
            currency_code = excluded.currency_code,
            currency_symbol = excluded.currency_symbol,
            min_lat = excluded.min_lat,
            max_lat = excluded.max_lat,
            min_lon = excluded.min_lon,
            max_lon = excluded.max_lon,
            priority = excluded.priority,
            is_active = excluded.is_active,
            updated_at = excluded.updated_at
        """, (
            norm["country_code"], norm["country_name"], norm["api_host"], norm["ws_host"],
            norm["messenger_host"], norm["auth_host"], norm["cas_host"], norm["currency_code"],
            norm["currency_symbol"], norm["min_lat"], norm["max_lat"], norm["min_lon"],
            norm["max_lon"], norm["priority"], 1 if norm["is_active"] else 0, now_iso
        ))
        conn.commit()
        conn.close()

    # Sincronizar llaves globales de respaldo si se actualiza CO o LATAM
    if norm["country_code"] == "CO" and norm["is_active"]:
        db_set_config("host_co", norm["api_host"])
    elif norm["country_code"] == "LATAM" and norm["is_active"]:
        db_set_config("host_latam", norm["api_host"])

    invalidate_config_cache()
    return norm


def db_delete_country(country_code: str):
    clean = (country_code or "").strip().upper()
    if clean == "LATAM":
        raise HTTPException(status_code=400, detail="El perfil base LATAM sirve de respaldo general; puedes editar su URL pero no eliminarlo.")
    if USE_SUPABASE:
        try:
            requests.delete(f"{SUPABASE_URL}/rest/v1/country_endpoints?country_code=eq.{clean}", headers=supabase_headers(), timeout=5)
        except Exception as e:
            print(f"[Supabase Error delete_country] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM country_endpoints WHERE country_code = ?", (clean,))
        conn.commit()
        conn.close()
    invalidate_config_cache()


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

    matched_cert = cert_sha if cert_sha in allowed_certs else (cert_sha if not enforce_sig else allowed_certs[0])
    return True, "ok", matched_cert, device_id


def seal_payload_for_apk(payload_dict: Dict[str, Any], target_cert_sha256: str) -> str:
    """
    Cifra y autentica las URLs multipaís y configuración ligándolas matemáticamente al SHA-256
    del certificado del APK oficial.
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
    active_countries = db_list_countries(only_active=True)
    co_row = next((c for c in active_countries if c["country_code"] == "CO"), None)
    latam_row = next((c for c in active_countries if c["country_code"] == "LATAM"), None)

    host_co = (co_row["api_host"] if co_row and co_row.get("api_host") else sys_cfg.get("host_co", DEFAULT_SYSTEM_CONFIGS["host_co"]))
    host_latam = (latam_row["api_host"] if latam_row and latam_row.get("api_host") else sys_cfg.get("host_latam", DEFAULT_SYSTEM_CONFIGS["host_latam"]))

    return {
        "host_co": host_co,
        "host_latam": host_latam,
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
        "max_poll_ms": int(sys_cfg.get("max_poll_ms", "1200") or 1200),
        "countries": active_countries
    }


def check_and_bind_device(
    uid: str,
    device_id: str,
    device_model: str,
    cert_sha: str,
    enforce_lock: bool
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    existing = db_get_driver_device(uid)
    now_iso = datetime.now().isoformat()

    if existing and existing.get("device_id") and existing.get("device_id") != device_id:
        if enforce_lock:
            return False, existing

    bound_at = existing.get("bound_at", now_iso) if existing else now_iso
    final_model = device_model or (existing.get("device_model") if existing else "Android")

    should_write = (existing is None) or (existing.get("device_id") != device_id)
    if not should_write and existing:
        try:
            raw_last = str(existing.get("last_seen") or "").replace("Z", "+00:00")
            last_dt = datetime.fromisoformat(raw_last)
            if last_dt.tzinfo is not None:
                last_dt = last_dt.replace(tzinfo=None)
            if (datetime.now() - last_dt).total_seconds() > 600:
                should_write = True
        except Exception:
            should_write = True

    if should_write:
        db_upsert_driver_device(
            uid=uid,
            device_id=device_id,
            device_model=final_model,
            cert_sha256=cert_sha[:16],
            bound_at=bound_at,
            last_seen=now_iso
        )

    return True, {
        "uid": uid,
        "device_id": device_id,
        "device_model": final_model,
        "cert_sha256": cert_sha[:16],
        "bound_at": bound_at,
        "last_seen": now_iso
    }


def evaluate_driver_membership(uid: str) -> Tuple[bool, int, str, str, Optional[Dict[str, Any]], int]:
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
            "Tu membresía o prueba gratuita ha vencido. Renueva tu plan para descargar configuración y habilitar el sistema.",
            driver,
            0
        )

    rem_sec = max(0.0, (valid_until_dt - now).total_seconds())
    days_left = max(1, int(math.ceil(rem_sec / 86400.0)))
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
    country_code: Optional[str] = "CO"
    plan_type: Optional[str] = "paid"
    notes: Optional[str] = ""


class DriverExtendRequest(BaseModel):
    days: int = 30


class DriverStatusUpdateRequest(BaseModel):
    status: str  # "active" o "banned"


class SystemSettingsUpdateRequest(BaseModel):
    settings: Dict[str, Any]


class CountryEndpointRequest(BaseModel):
    country_code: str
    country_name: str
    api_host: str
    ws_host: Optional[str] = ""
    messenger_host: Optional[str] = ""
    auth_host: Optional[str] = ""
    cas_host: Optional[str] = ""
    currency_code: Optional[str] = "USD"
    currency_symbol: Optional[str] = "$"
    min_lat: Optional[float] = None
    max_lat: Optional[float] = None
    min_lon: Optional[float] = None
    max_lon: Optional[float] = None
    priority: int = 10
    is_active: bool = True


# ==============================================================================
# ENDPOINTS MÓVILES PROTEGIDOS POR FIRMA NATIVA APK + LEASE EFÍMERO
# ==============================================================================
@app.get("/")
def root():
    return {
        "service": "Omega Core Authoritative Server",
        "status": "online",
        "backend_mode": "Supabase Cloud (Normalized PostgreSQL)" if USE_SUPABASE else "Local SQLite (Normalized)",
        "security": "APK-SHA256 + Native-HMAC + Sealed-RAM-Lease + Multi-Country-URLs",
        "version": "3.1.0",
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/v1/auth/bootstrap")
async def auth_bootstrap(request: Request):
    """
    Entrega los hosts de autenticación inicial (CAS / Auth) cifrados para el certificado oficial del APK.
    Soporta resolución opcional por país si ese país define cas_host / auth_host propios.
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

    try:
        req_json = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except Exception:
        req_json = {}

    req_cc = str(req_json.get("country_code") or "").strip().upper()
    cas_host = sys_cfg.get("host_cas", DEFAULT_SYSTEM_CONFIGS["host_cas"])
    auth_host = sys_cfg.get("host_auth", DEFAULT_SYSTEM_CONFIGS["host_auth"])

    if req_cc:
        matched_country = next((c for c in db_list_countries(only_active=True) if c["country_code"] == req_cc), None)
        if matched_country:
            if matched_country.get("cas_host"):
                cas_host = matched_country["cas_host"]
            if matched_country.get("auth_host"):
                auth_host = matched_country["auth_host"]

    sealed = seal_payload_for_apk(
        {
            "host_cas": cas_host,
            "host_auth": auth_host,
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
    2. Verifica el token de sesión y extrae el UID real del conductor (auto-registrando 3 días gratis si es nuevo).
    3. Comprueba estado de membresía (`drivers`) y vínculo de equipo (`driver_devices`).
    4. Entrega lease efímero + sobre cifrado con URLs multipaís (`country_endpoints`) y config (`driver_configs`).
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
    req_driver_name = str(body_json.get("driver_name") or "").strip()
    req_driver_phone = str(body_json.get("driver_phone") or "").strip()
    req_country_code = str(body_json.get("country_code") or "").strip().upper()
    device_model = str(body_json.get("device_model") or "Android").strip()
    initial_state = body_json.get("initial_state")

    jwt_uid, jwt_err = extract_verified_jwt_uid(token)
    if jwt_err in ("expired_jwt", "malformed_jwt") or (jwt_err and jwt_err.startswith("jwt_parse_error")):
        extracted_uid = None
    else:
        if jwt_uid and fallback_uid and jwt_uid != fallback_uid:
            if db_get_driver(jwt_uid):
                extracted_uid = jwt_uid
            elif db_get_driver(fallback_uid):
                extracted_uid = fallback_uid
            else:
                extracted_uid = fallback_uid if fallback_uid.isdigit() else jwt_uid
        else:
            extracted_uid = jwt_uid or fallback_uid

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

    # Auto-registro automático de nuevos conductores con 3 días gratis (configurable en /admin)
    if reason == "unregistered" and driver is None:
        auto_trial_enabled = sys_cfg.get("auto_trial_enabled", "true").lower() == "true"
        try:
            trial_days = max(0, int(sys_cfg.get("auto_trial_days", "3") or 3))
        except Exception:
            trial_days = 3

        if auto_trial_enabled and trial_days > 0:
            clean_name = req_driver_name or f"Conductor {extracted_uid}"
            clean_phone = req_driver_phone
            trial_until = (datetime.now() + timedelta(days=trial_days)).isoformat()
            trial_notes = f"Prueba gratis automática ({trial_days} días) • {device_model}"
            created_driver = db_insert_driver_if_new(
                uid=extracted_uid,
                name=clean_name,
                phone=clean_phone,
                valid_until=trial_until,
                notes=trial_notes,
                country_code=req_country_code or "CO"
            )
            db_log_event(
                extracted_uid,
                client_ip,
                "auto_register_trial",
                "success",
                f"Nuevo usuario registrado automáticamente con {trial_days}d gratis ({clean_name}) [{req_country_code or 'CO'}] • {device_model}"
            )
            is_auth, http_code, reason, msg, driver, days_left = evaluate_driver_membership(extracted_uid)
            if not driver and created_driver:
                driver = created_driver
                is_auth = True
                http_code = 200
                reason = "active"
                days_left = trial_days
                msg = f"¡Bienvenido! Tienes {trial_days} días de prueba gratuita activa."

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

    # Si el teléfono detectó su país por GPS y cambió respecto al registrado, actualizarlo en `drivers`
    if req_country_code and req_country_code != (driver.get("country_code") or ""):
        db_update_driver_country(extracted_uid, req_country_code)

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

    # Cargar o inicializar configuración remota del conductor en `driver_configs`
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
    req_country_code = str(body_json.get("country_code") or "").strip().upper()

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

    if req_country_code and req_country_code != (driver.get("country_code") or ""):
        db_update_driver_country(uid, req_country_code)

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
    Guarda en `driver_configs` (Supabase / SQLite) toda la configuración (BotConfig, Zonas, Switches)
    del conductor, completamente separada de `system_config`.
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
    dev_map = db_map_driver_devices()
    cfg_uids = db_set_of_configured_uids()
    now = datetime.now()
    for d in drivers:
        uid = d.get("uid", "")
        try:
            raw_v = d.get("valid_until", "").replace("Z", "+00:00")
            exp = datetime.fromisoformat(raw_v)
            if exp.tzinfo is not None:
                exp = exp.replace(tzinfo=None)
            rem_s = (exp - now).total_seconds()
            d["days_left"] = max(1, int(math.ceil(rem_s / 86400.0))) if rem_s > 0 else 0
            d["is_active"] = (now <= exp) and (d.get("status") != "banned")
        except Exception:
            d["days_left"] = 0
            d["is_active"] = False
        dev_info = dev_map.get(uid)
        d["device_info"] = dev_info if isinstance(dev_info, dict) else None
        d["has_cloud_config"] = uid in cfg_uids
    return drivers


@app.post("/api/v1/admin/drivers")
def admin_register_driver(req: DriverRegisterRequest, request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    expiry = (datetime.now() + timedelta(days=req.days)).isoformat()
    db_save_driver(
        uid=req.uid.strip(),
        name=req.name.strip(),
        phone=(req.phone or "").strip(),
        valid_until=expiry,
        status="active",
        notes=req.notes or "",
        country_code=req.country_code or "CO",
        plan_type=req.plan_type or "paid"
    )
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
    db_save_driver(
        uid=uid,
        name=driver.get("name", "Conductor"),
        phone=driver.get("phone", ""),
        valid_until=new_exp,
        status="active",
        notes=driver.get("notes", ""),
        country_code=driver.get("country_code", "CO"),
        plan_type="paid"
    )
    return {"status": "ok", "message": f"Se extendieron {req.days} días a UID {uid}", "valid_until": new_exp}


@app.post("/api/v1/admin/drivers/{uid}/status")
def admin_toggle_driver_status(uid: str, req: DriverStatusUpdateRequest, request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    driver = db_get_driver(uid)
    if not driver:
        raise HTTPException(status_code=404, detail="Conductor no encontrado")
    new_status = "banned" if req.status == "banned" else "active"
    db_save_driver(
        uid=uid,
        name=driver.get("name", "Conductor"),
        phone=driver.get("phone", ""),
        valid_until=driver.get("valid_until", ""),
        status=new_status,
        notes=driver.get("notes", ""),
        country_code=driver.get("country_code", "CO"),
        plan_type=driver.get("plan_type", "paid")
    )
    return {"status": "ok", "driver_status": new_status}


@app.post("/api/v1/admin/drivers/{uid}/reset-device")
def admin_reset_driver_device(uid: str, request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    db_delete_driver_device(uid)
    return {"status": "ok", "message": f"Dispositivo liberado para UID {uid}"}


@app.delete("/api/v1/admin/drivers/{uid}")
def admin_delete_driver(uid: str, request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    db_delete_driver(uid)
    return {"status": "ok", "message": f"Conductor {uid} y sus datos remotos eliminados"}


# --- GESTIÓN DE PAÍSES Y URLS REGIONALES (`country_endpoints`) ---
@app.get("/api/v1/admin/countries")
def admin_get_countries(request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    return db_list_countries(only_active=False)


@app.post("/api/v1/admin/countries")
def admin_upsert_country(req: CountryEndpointRequest, request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    saved = db_upsert_country(req.dict())
    return {"status": "ok", "country": saved}


@app.delete("/api/v1/admin/countries/{country_code}")
def admin_remove_country(country_code: str, request: Request, token: Optional[str] = Query(None)):
    require_admin_auth(request, token)
    db_delete_country(country_code)
    return {"status": "ok", "message": f"País {country_code.upper()} eliminado"}


# --- GESTIÓN DE PARÁMETROS DEL SISTEMA (`system_config`) ---
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
# PANEL WEB DE CONTROL VISUAL (/admin) - SEPARADO EN USUARIOS / PAÍSES / SISTEMA
# ==============================================================================
@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard():
    db_label = "🟢 Supabase PostgreSQL Normalizado" if USE_SUPABASE else "🟡 SQLite Local Normalizado"
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Omega Core v3.1 - Panel Autoritativo</title>
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
            --purple: #8b5cf6;
            --text: #f3f4f6;
            --text-dim: #9ca3af;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: 'Outfit', sans-serif; }}
        body {{ background: var(--bg); color: var(--text); padding: 24px; min-height: 100vh; }}
        .header {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }}
        .header h1 {{ font-size: 26px; font-weight: 700; background: linear-gradient(135deg, #60a5fa, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .badge {{ padding: 5px 11px; border-radius: 9999px; font-size: 12px; font-weight: 600; display: inline-flex; align-items: center; gap: 5px; }}
        .badge-active {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
        .badge-info {{ background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 18px; margin-bottom: 24px; }}
        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 20px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); margin-bottom: 22px; }}
        .card-title {{ font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }}
        .card-value {{ font-size: 28px; font-weight: 700; }}
        .section-tag {{ font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #60a5fa; margin-bottom: 6px; display: block; }}
        .btn {{ padding: 9px 16px; border-radius: 10px; border: none; font-weight: 600; cursor: pointer; transition: all 0.2s; font-size: 13px; }}
        .btn-primary {{ background: var(--accent); color: white; box-shadow: 0 4px 14px var(--accent-glow); }}
        .btn-primary:hover {{ background: #2563eb; }}
        .btn-success {{ background: var(--green); color: white; }}
        .btn-warning {{ background: var(--orange); color: #090d16; }}
        .btn-danger {{ background: var(--red); color: white; }}
        .btn-sm {{ padding: 5px 10px; font-size: 12px; margin-right: 4px; margin-bottom: 4px; }}
        .table-container {{ background: var(--surface); border: 1px solid var(--border); border-radius: 16px; overflow-x: auto; margin-bottom: 24px; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th {{ background: #172033; padding: 13px 15px; font-size: 12px; color: var(--text-dim); text-transform: uppercase; }}
        td {{ padding: 12px 15px; border-top: 1px solid var(--border); font-size: 13px; vertical-align: middle; }}
        tr:hover td {{ background: var(--surface-hover); }}
        .modal-form {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(175px, 1fr)); gap: 12px; align-items: end; margin-top: 12px; }}
        input, select, textarea {{ background: #0c121e; border: 1px solid var(--border); padding: 10px 12px; border-radius: 10px; color: white; font-size: 13px; width: 100%; }}
        label {{ font-size: 12px; color: var(--text-dim); display: block; margin-bottom: 4px; }}
        .log-box {{ background: #080c14; border: 1px solid var(--border); border-radius: 12px; padding: 14px; font-family: monospace; font-size: 12px; max-height: 260px; overflow-y: auto; color: #a5b4fc; }}
        .log-line {{ padding: 5px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }}
        .mono {{ font-family: monospace; font-size: 12px; color: #93c5fd; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>OMEGA CORE v3.1 • ARQUITECTURA NORMALIZADA</h1>
            <p style="color: var(--text-dim); font-size: 13px;">Membresías y Usuarios separados de Seguridad SHA-256 y Catálogo Multipaís de URLs</p>
        </div>
        <div style="display: flex; gap: 10px; align-items: center;">
            <span class="badge" style="background: rgba(255,255,255,0.08);">{db_label}</span>
            <button class="btn btn-warning" onclick="promptAdminKey()">🔑 Clave Admin</button>
            <button class="btn btn-primary" onclick="loadData()">🔄 Refrescar</button>
        </div>
    </div>

    <div class="grid">
        <div class="card" style="margin-bottom:0;">
            <div class="card-title">Conductores (drivers)</div>
            <div class="card-value" id="totalDriversCount">--</div>
            <div style="font-size: 13px; color: var(--green); margin-top: 4px;" id="activeDriversCount">-- activos</div>
        </div>
        <div class="card" style="margin-bottom:0;">
            <div class="card-title">Países Configurados (country_endpoints)</div>
            <div class="card-value" id="countriesCount">--</div>
            <div style="font-size: 13px; color: #60a5fa; margin-top: 4px;">Resolución automática por GPS</div>
        </div>
        <div class="card" style="margin-bottom:0;">
            <div class="card-title">Blindaje Criptográfico (system_config)</div>
            <div style="margin-top: 8px; display:flex; gap:8px; flex-wrap:wrap;">
                <span id="sigEnforceBadge" class="badge badge-active">Firma SHA-256</span>
                <span id="devLockBadge" class="badge badge-active">1 Equipo</span>
            </div>
            <div style="font-size: 12px; color: var(--text-dim); margin-top: 8px;">RAM Lease TTL: <b id="ttlDisplay">180s</b></div>
        </div>
    </div>

    <!-- ===================================================================== -->
    <!-- SECCIÓN 1: MEMBRESÍAS, INFORMACIÓN DE USUARIOS Y EQUIPOS              -->
    <!-- ===================================================================== -->
    <div class="card">
        <span class="section-tag">Bloque 1 • Usuarios y Membresías (drivers / driver_devices / driver_configs)</span>
        <h3 style="font-size: 17px; margin-bottom: 8px;">👥 Registrar o Activar Membresía de Conductor</h3>
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
                <label>País Inicial</label>
                <input type="text" id="newCountry" value="CO" placeholder="CO, DO, PE, MX...">
            </div>
            <div>
                <label>Vigencia</label>
                <select id="newDays">
                    <option value="3">3 Días (Prueba)</option>
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
                    <th>País / Plan</th>
                    <th>Estado</th>
                    <th>Vigencia</th>
                    <th>Equipo (driver_devices)</th>
                    <th>Config (driver_configs)</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody id="driversTbody">
                <tr><td colspan="8" style="text-align:center; color: var(--text-dim);">Cargando...</td></tr>
            </tbody>
        </table>
    </div>

    <!-- ===================================================================== -->
    <!-- SECCIÓN 2: URLS MULTIPAÍS (country_endpoints)                         -->
    <!-- ===================================================================== -->
    <div class="card">
        <span class="section-tag">Bloque 2 • Enrutamiento Multipaís (country_endpoints)</span>
        <h3 style="font-size: 17px; margin-bottom: 6px;">🌎 URLs Regionales por País</h3>
        <p style="font-size: 12px; color: var(--text-dim); margin-bottom: 12px;">
            Agrega o edita las URLs específicas de cada país. La app detecta el país automáticamente por coordenadas GPS y descifra su URL correspondiente en RAM sin necesidad de actualizar el APK.
        </p>
        <div class="modal-form">
            <div>
                <label>Código ISO País</label>
                <input type="text" id="ctCode" placeholder="Ej: CO, DO, PE, MX, AR">
            </div>
            <div>
                <label>Nombre del País</label>
                <input type="text" id="ctName" placeholder="Ej: Perú">
            </div>
            <div style="grid-column: span 2;">
                <label>URL Principal API (api_host) *</label>
                <input type="text" id="ctApiHost" placeholder="https://api-gw-cf.latam.saea1.aws.indriverapp.com">
            </div>
            <div>
                <label>URL WebSocket (Opcional)</label>
                <input type="text" id="ctWsHost" placeholder="Vacío = usa global">
            </div>
            <div>
                <label>URL Chat/VoIP (Opcional)</label>
                <input type="text" id="ctMsgHost" placeholder="Vacío = usa global">
            </div>
            <div>
                <label>Moneda (ISO / Símbolo)</label>
                <div style="display:flex; gap:6px;">
                    <input type="text" id="ctCurrCode" placeholder="PEN" value="USD">
                    <input type="text" id="ctCurrSym" placeholder="S/" value="$">
                </div>
            </div>
            <div>
                <label>Latitud Mín / Máx (GPS)</label>
                <div style="display:flex; gap:6px;">
                    <input type="number" step="0.01" id="ctMinLat" placeholder="-18.4">
                    <input type="number" step="0.01" id="ctMaxLat" placeholder="-0.05">
                </div>
            </div>
            <div>
                <label>Longitud Mín / Máx (GPS)</label>
                <div style="display:flex; gap:6px;">
                    <input type="number" step="0.01" id="ctMinLon" placeholder="-81.4">
                    <input type="number" step="0.01" id="ctMaxLon" placeholder="-68.6">
                </div>
            </div>
            <div>
                <label>Prioridad / Estado</label>
                <div style="display:flex; gap:6px;">
                    <input type="number" id="ctPriority" value="10" title="Menor número se evalúa primero">
                    <select id="ctActive">
                        <option value="true">Activo</option>
                        <option value="false">Inactivo</option>
                    </select>
                </div>
            </div>
            <button class="btn btn-success" onclick="saveCountry()">💾 Guardar País</button>
        </div>
    </div>

    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>País</th>
                    <th>URL Principal API (api_host)</th>
                    <th>Overrides (WS / Chat)</th>
                    <th>Moneda</th>
                    <th>Cuadrante GPS (Lat / Lon)</th>
                    <th>Prioridad</th>
                    <th>Estado</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody id="countriesTbody">
                <tr><td colspan="8" style="text-align:center; color: var(--text-dim);">Cargando países...</td></tr>
            </tbody>
        </table>
    </div>

    <!-- ===================================================================== -->
    <!-- SECCIÓN 3: CONFIGURACIÓN DEL SISTEMA Y CLAVES SHA-256 (system_config) -->
    <!-- ===================================================================== -->
    <div class="card">
        <span class="section-tag">Bloque 3 • Parámetros Globales del Sistema (system_config)</span>
        <h3 style="font-size: 17px; margin-bottom: 10px;">🛡️ Claves SHA-256 del APK, Prueba Gratis y Hosts Centrales</h3>
        <div style="margin-bottom: 12px;">
            <label>Huellas SHA-256 Autorizadas del Certificado APK (separadas por coma)</label>
            <textarea id="cfgAllowedCerts" rows="2" placeholder="ada69302..."></textarea>
        </div>
        <div class="modal-form" style="margin-bottom: 14px;">
            <div>
                <label>Auto-Registro Gratis</label>
                <select id="cfgAutoTrial">
                    <option value="true">Sí (Automático al entrar)</option>
                    <option value="false">No (Solo manual)</option>
                </select>
            </div>
            <div>
                <label>Días Gratis Iniciales</label>
                <input type="number" id="cfgTrialDays" value="3" min="1" max="365">
            </div>
            <div>
                <label>Exigir Firma Oficial APK</label>
                <select id="cfgEnforceSig">
                    <option value="true">Sí (Bloquear modificados)</option>
                    <option value="false">No (Diagnóstico)</option>
                </select>
            </div>
            <div>
                <label>Bloqueo por Dispositivo</label>
                <select id="cfgEnforceDev">
                    <option value="true">Sí (1 Cuenta = 1 Equipo)</option>
                    <option value="false">No</option>
                </select>
            </div>
            <div>
                <label>Lease en RAM (segundos)</label>
                <input type="number" id="cfgLeaseTtl" value="180">
            </div>
            <div>
                <label>Host Central Auth (OAuth)</label>
                <input type="text" id="cfgHostAuth">
            </div>
            <div>
                <label>Host Central CAS (Login)</label>
                <input type="text" id="cfgHostCas">
            </div>
            <div>
                <label>Host Central Messenger</label>
                <input type="text" id="cfgHostMessenger">
            </div>
            <div>
                <label>WebSocket SSN Global</label>
                <input type="text" id="cfgWsHost">
            </div>
        </div>
        <button class="btn btn-success" onclick="saveSystemSettings()">💾 Guardar Configuración del Sistema</button>
    </div>

    <div class="card">
        <div class="card-title">Registro de Auditoría y Seguridad en Vivo (access_logs)</div>
        <div class="log-box" id="logsContainer">Cargando registros...</div>
    </div>

    <script>
        let cachedCountries = [];

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
                const [drvRes, ctRes, setRes, logRes] = await Promise.all([
                    apiFetch('/api/v1/admin/drivers'),
                    apiFetch('/api/v1/admin/countries'),
                    apiFetch('/api/v1/admin/settings'),
                    apiFetch('/api/v1/admin/logs?limit=50')
                ]);
                const drivers = await drvRes.json();
                const countries = await ctRes.json();
                const settings = await setRes.json();
                const logs = await logRes.json();
                cachedCountries = countries;

                document.getElementById('totalDriversCount').innerText = drivers.length;
                document.getElementById('activeDriversCount').innerText = drivers.filter(d => d.is_active).length + ' con membresía activa';
                document.getElementById('countriesCount').innerText = countries.filter(c => c.is_active).length + ' activos / ' + countries.length + ' total';
                document.getElementById('ttlDisplay').innerText = (settings.lease_ttl_sec || '180') + 's';

                document.getElementById('cfgAllowedCerts').value = settings.allowed_apk_sha256 || '';
                document.getElementById('cfgAutoTrial').value = settings.auto_trial_enabled || 'true';
                document.getElementById('cfgTrialDays').value = settings.auto_trial_days || '3';
                document.getElementById('cfgEnforceSig').value = settings.enforce_apk_signature || 'true';
                document.getElementById('cfgEnforceDev').value = settings.enforce_device_lock || 'true';
                document.getElementById('cfgLeaseTtl').value = settings.lease_ttl_sec || '180';
                document.getElementById('cfgHostAuth').value = settings.host_auth || '';
                document.getElementById('cfgHostCas').value = settings.host_cas || '';
                document.getElementById('cfgHostMessenger').value = settings.host_messenger || '';
                document.getElementById('cfgWsHost').value = settings.ws_ssn_host || '';

                const sigBadge = document.getElementById('sigEnforceBadge');
                sigBadge.className = 'badge ' + (settings.enforce_apk_signature === 'true' ? 'badge-active' : 'badge-warning');
                sigBadge.innerText = settings.enforce_apk_signature === 'true' ? 'Firma SHA-256 Estricta' : 'Firma Flexible';

                const devBadge = document.getElementById('devLockBadge');
                devBadge.className = 'badge ' + (settings.enforce_device_lock === 'true' ? 'badge-active' : 'badge-warning');
                devBadge.innerText = settings.enforce_device_lock === 'true' ? '1 Cuenta = 1 Equipo' : 'Multi-equipo';

                // Renderizar Conductores
                const tbody = document.getElementById('driversTbody');
                if (drivers.length === 0) {{
                    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;">Sin conductores registrados.</td></tr>';
                }} else {{
                    tbody.innerHTML = drivers.map(d => {{
                        const isBanned = d.status === 'banned';
                        const badgeClass = d.is_active ? 'badge-active' : 'badge-danger';
                        const statusText = d.is_active ? 'Activo' : (isBanned ? 'Suspendido' : 'Vencido');
                        const validDisplay = (d.valid_until || '').replace('T', ' ').substring(0, 16);
                        const cc = d.country_code || 'CO';
                        const plan = (d.plan_type || 'trial') === 'trial' ? 'Prueba' : 'Plan Pago';
                        const devLabel = d.device_info
                            ? `<span class="badge badge-active">📱 ${{d.device_info.device_model || 'Vinculado'}}</span>`
                            : `<span style="color:var(--text-dim);">Libre</span>`;
                        const cfgLabel = d.has_cloud_config
                            ? `<span class="badge badge-info">☁️ Guardada</span>`
                            : `<span style="color:var(--text-dim);">Por defecto</span>`;
                        return `<tr>
                            <td style="font-weight:700; color:#60a5fa;">${{d.uid}}</td>
                            <td><b>${{d.name}}</b><br><span style="color:var(--text-dim);font-size:12px;">${{d.phone || ''}}</span></td>
                            <td><span class="badge badge-info">${{cc}}</span> <span style="font-size:12px;color:var(--text-dim);">${{plan}}</span></td>
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

                // Renderizar Países
                const ctBody = document.getElementById('countriesTbody');
                ctBody.innerHTML = countries.map(c => {{
                    const boxStr = (c.min_lat !== null && c.max_lat !== null)
                        ? `Lat [${{c.min_lat}} .. ${{c.max_lat}}]<br>Lon [${{c.min_lon}} .. ${{c.max_lon}}]`
                        : `<span style="color:var(--text-dim);">Sin filtro GPS</span>`;
                    const overrides = [];
                    if (c.ws_host) overrides.push('WS propio');
                    if (c.messenger_host) overrides.push('Chat propio');
                    const ovStr = overrides.length ? overrides.join(', ') : '<span style="color:var(--text-dim);">Global</span>';
                    const delBtn = c.country_code === 'LATAM'
                        ? ''
                        : `<button class="btn btn-sm btn-danger" onclick="deleteCountry('${{c.country_code}}')">🗑️</button>`;
                    return `<tr>
                        <td><span class="badge badge-info">${{c.country_code}}</span> <b>${{c.country_name}}</b></td>
                        <td class="mono">${{c.api_host}}</td>
                        <td style="font-size:12px;">${{ovStr}}</td>
                        <td><b>${{c.currency_code}}</b> (${{c.currency_symbol}})</td>
                        <td style="font-size:11px; color:var(--text-dim);">${{boxStr}}</td>
                        <td>${{c.priority}}</td>
                        <td><span class="badge ${{c.is_active ? 'badge-active' : 'badge-danger'}}">${{c.is_active ? 'Activo' : 'Inactivo'}}</span></td>
                        <td>
                            <button class="btn btn-sm btn-primary" onclick="editCountry('${{c.country_code}}')">✏️ Editar</button>
                            ${{delBtn}}
                        </td>
                    </tr>`;
                }}).join('');

                // Renderizar Logs
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
            const country_code = document.getElementById('newCountry').value.trim().toUpperCase() || 'CO';
            const days = parseInt(document.getElementById('newDays').value);
            if (!uid || !name) return alert('Ingresa UID y Nombre.');
            await apiFetch('/api/v1/admin/drivers', {{ method: 'POST', body: JSON.stringify({{ uid, name, phone, days, country_code, plan_type: 'paid' }}) }});
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
            if (!confirm(`¿Eliminar definitivamente al conductor ${{uid}}, su equipo y su configuración en nube?`)) return;
            await apiFetch(`/api/v1/admin/drivers/${{uid}}`, {{ method: 'DELETE' }});
            loadData();
        }}

        function editCountry(code) {{
            const c = cachedCountries.find(x => x.country_code === code);
            if (!c) return;
            document.getElementById('ctCode').value = c.country_code;
            document.getElementById('ctName').value = c.country_name;
            document.getElementById('ctApiHost').value = c.api_host;
            document.getElementById('ctWsHost').value = c.ws_host || '';
            document.getElementById('ctMsgHost').value = c.messenger_host || '';
            document.getElementById('ctCurrCode').value = c.currency_code || 'USD';
            document.getElementById('ctCurrSym').value = c.currency_symbol || '$';
            document.getElementById('ctMinLat').value = c.min_lat !== null ? c.min_lat : '';
            document.getElementById('ctMaxLat').value = c.max_lat !== null ? c.max_lat : '';
            document.getElementById('ctMinLon').value = c.min_lon !== null ? c.min_lon : '';
            document.getElementById('ctMaxLon').value = c.max_lon !== null ? c.max_lon : '';
            document.getElementById('ctPriority').value = c.priority;
            document.getElementById('ctActive').value = c.is_active ? 'true' : 'false';
            document.getElementById('ctCode').scrollIntoView({{ behavior: 'smooth', block: 'center' }});
        }}

        async function saveCountry() {{
            const parseOptFloat = (id) => {{
                const v = document.getElementById(id).value.trim();
                return v === '' ? null : parseFloat(v);
            }};
            const payload = {{
                country_code: document.getElementById('ctCode').value.trim().toUpperCase(),
                country_name: document.getElementById('ctName').value.trim(),
                api_host: document.getElementById('ctApiHost').value.trim(),
                ws_host: document.getElementById('ctWsHost').value.trim(),
                messenger_host: document.getElementById('ctMsgHost').value.trim(),
                currency_code: document.getElementById('ctCurrCode').value.trim().toUpperCase() || 'USD',
                currency_symbol: document.getElementById('ctCurrSym').value.trim() || '$',
                min_lat: parseOptFloat('ctMinLat'),
                max_lat: parseOptFloat('ctMaxLat'),
                min_lon: parseOptFloat('ctMinLon'),
                max_lon: parseOptFloat('ctMaxLon'),
                priority: parseInt(document.getElementById('ctPriority').value || '10'),
                is_active: document.getElementById('ctActive').value === 'true'
            }};
            if (!payload.country_code || !payload.country_name || !payload.api_host) {{
                return alert('Completa Código ISO, Nombre del País y URL Principal API.');
            }}
            const res = await apiFetch('/api/v1/admin/countries', {{ method: 'POST', body: JSON.stringify(payload) }});
            if (!res.ok) {{
                const err = await res.json();
                return alert(err.detail || 'Error guardando país');
            }}
            alert(`País ${{payload.country_code}} guardado correctamente.`);
            loadData();
        }}

        async function deleteCountry(code) {{
            if (!confirm(`¿Eliminar el perfil de URLs del país ${{code}}?`)) return;
            await apiFetch(`/api/v1/admin/countries/${{code}}`, {{ method: 'DELETE' }});
            loadData();
        }}

        async function saveSystemSettings() {{
            const settings = {{
                allowed_apk_sha256: document.getElementById('cfgAllowedCerts').value,
                auto_trial_enabled: document.getElementById('cfgAutoTrial').value,
                auto_trial_days: document.getElementById('cfgTrialDays').value,
                enforce_apk_signature: document.getElementById('cfgEnforceSig').value,
                enforce_device_lock: document.getElementById('cfgEnforceDev').value,
                lease_ttl_sec: document.getElementById('cfgLeaseTtl').value,
                host_auth: document.getElementById('cfgHostAuth').value,
                host_cas: document.getElementById('cfgHostCas').value,
                host_messenger: document.getElementById('cfgHostMessenger').value,
                ws_ssn_host: document.getElementById('cfgWsHost').value
            }};
            await apiFetch('/api/v1/admin/settings', {{ method: 'POST', body: JSON.stringify({{ settings }}) }});
            alert('Configuración del sistema actualizada.');
            loadData();
        }}

        loadData();
        setInterval(loadData, 15000);
    </script>
</body>
</html>"""


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("omega_backend_server:app", host="0.0.0.0", port=port, reload=True)
