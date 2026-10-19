import os
import sys
import json
import base64
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

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

# Variables de Supabase (Configurables en el Dashboard de Render)
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "") or os.getenv("SUPABASE_SERVICE_KEY", "")

USE_SUPABASE = bool(SUPABASE_URL and SUPABASE_KEY)

app = FastAPI(
    title="Omega Fleet Sync Server (Supabase + Render)",
    description="Servidor de Gestión de Licencias Dinámicas y Modo Camuflaje Play Store para Omega",
    version="2.1.0"
)

# Permitir CORS para peticiones desde app móvil o navegador
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================================================================
# ADAPTADOR DE BASE DE DATOS: SUPABASE REST / SQLITE LOCAL FALLBACK
# ==============================================================================
def supabase_headers():
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
    default_configs = {
        "playstore_review_mode": "false",
        "host_co": "https://api-gw-cf.latam-co.saea1.aws.indriverapp.com",
        "host_latam": "https://api-gw-cf.latam.saea1.aws.indriverapp.com",
        "feed_path": "/new-order/api/new-order/v1/contractor-orders",
        "bid_path": "/api/v2/orders/{id}/bid",
        "min_poll_ms": "700",
        "max_poll_ms": "1200"
    }
    for k, v in default_configs.items():
        cursor.execute("INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)", (k, v))
        
    cursor.execute("SELECT COUNT(*) as count FROM drivers")
    if cursor.fetchone()["count"] == 0:
        demo_expiry = (datetime.now() + timedelta(days=365)).isoformat()
        cursor.execute("""
        INSERT INTO drivers (uid, name, phone, status, valid_until, created_at, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            "1000001",
            "Conductor VIP Demo",
            "+573001234567",
            "active",
            demo_expiry,
            datetime.now().isoformat(),
            "Cuenta inicial de prueba"
        ))
    conn.commit()
    conn.close()

if not USE_SUPABASE:
    init_local_sqlite()

# ------------------------------------------------------------------------------
# OPERACIONES CRUD UNIFICADAS (DETECTA SUPABASE AUTOMÁTICAMENTE)
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
            url = f"{SUPABASE_URL}/rest/v1/drivers?uid=eq.{uid}"
            requests.delete(url, headers=supabase_headers(), timeout=5)
        except Exception as e:
            print(f"[Supabase Error delete_driver] {e}")
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM drivers WHERE uid = ?", (uid,))
        conn.commit()
        conn.close()

def db_get_config(key: str, default: str = "") -> str:
    if USE_SUPABASE:
        try:
            url = f"{SUPABASE_URL}/rest/v1/system_config?key=eq.{key}&select=value"
            res = requests.get(url, headers=supabase_headers(), timeout=5)
            if res.status_code == 200:
                data = res.json()
                return data[0]["value"] if data else default
        except Exception as e:
            print(f"[Supabase Error get_config] {e}")
            return default
    else:
        conn = get_sqlite_db()
        cur = conn.cursor()
        cur.execute("SELECT value FROM system_config WHERE key = ?", (key,))
        row = cur.fetchone()
        conn.close()
        return row["value"] if row else default

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
# HELPERS DE TOKEN JWT
# ==============================================================================
def decode_jwt_payload_unverified(token: str) -> Optional[Dict[str, Any]]:
    try:
        clean = token.replace("Bearer ", "").strip()
        parts = clean.split(".")
        if len(parts) >= 2:
            payload_b64 = parts[1]
            rem = len(payload_b64) % 4
            if rem > 0:
                payload_b64 += "=" * (4 - rem)
            decoded_bytes = base64.urlsafe_b64decode(payload_b64)
            return json.loads(decoded_bytes.decode("utf-8"))
    except Exception as e:
        print(f"[Error JWT Decode] {e}")
    return None

# ==============================================================================
# MODELOS PYDANTIC
# ==============================================================================
class ValidateSessionRequest(BaseModel):
    token: Optional[str] = None
    uid: Optional[str] = None
    app_version: Optional[str] = "1.0.0"
    device_model: Optional[str] = None

class DriverRegisterRequest(BaseModel):
    uid: str
    name: str
    phone: Optional[str] = ""
    days: int = 30
    notes: Optional[str] = ""

class DriverExtendRequest(BaseModel):
    days: int = 30

class ToggleReviewModeRequest(BaseModel):
    enabled: bool

# ==============================================================================
# ENDPOINT PRINCIPAL: VALIDACIÓN DE SESIÓN (CONSUMIDO POR APP OMEGA)
# ==============================================================================
@app.get("/")
def root():
    return {
        "service": "Fleet Sync Driver Assistant Core",
        "status": "online",
        "backend_mode": "Supabase Cloud (PostgreSQL)" if USE_SUPABASE else "Local SQLite",
        "version": "2.1.0",
        "timestamp": datetime.now().isoformat()
    }

@app.post("/api/v1/auth/validate-session")
def validate_session(req: ValidateSessionRequest, request: Request):
    """
    Endpoint consumido por Omega al iniciar sesión o cada cierto intervalo.
    1. Si Modo Revisión Play Store está ACTIVO -> Apaga el motor bot (devuelve camuflaje).
    2. Extrae el UID del conductor (del JWT o directo).
    3. Verifica si tiene licencia activa y cuántos días le restan en Supabase.
    4. Si está autorizado -> Devuelve las URLs dinámicas de inDriver y la configuración remota.
    """
    client_ip = request.client.host if request.client else "unknown"
    extracted_uid = req.uid
    
    # 1. Intentar extraer UID del JWT de inDriver si viene token
    if req.token:
        payload = decode_jwt_payload_unverified(req.token)
        if payload:
            extracted_uid = str(
                payload.get("user_id") or 
                payload.get("uid") or 
                payload.get("sub") or 
                payload.get("contractor_id") or 
                extracted_uid
            )

    # 2. Verificar si está activo el "Modo Revisión Play Store"
    review_mode_active = db_get_config("playstore_review_mode", "false").lower() == "true"
    if review_mode_active:
        db_log_event(extracted_uid or "reviewer", client_ip, "validate_session", "camouflaged", "Modo Revisión Activo")
        return {
            "authorized": True,
            "review_mode": True,
            "engine_active": False,
            "days_left": 999,
            "message": "Bienvenido al Asistente de Conducción y Consumo",
            "driver_name": "Conductor",
            "config": {
                "display_mode": "standard_driver_tool",
                "features_enabled": ["fuel_calculator", "mileage_tracker"]
            }
        }

    # Si no hay UID identificado
    if not extracted_uid:
        db_log_event("anonymous", client_ip, "validate_session", "rejected", "No UID or JWT provided")
        return JSONResponse(
            status_code=401,
            content={
                "authorized": False,
                "review_mode": False,
                "engine_active": False,
                "reason": "unauthorized",
                "message": "Sesión inválida. Inicie sesión en su cuenta de conductor."
            }
        )

    # 3. Consultar base de datos (Supabase o SQLite)
    driver = db_get_driver(extracted_uid)

    # Si el conductor no está registrado en la base de datos
    if not driver:
        db_log_event(extracted_uid, client_ip, "validate_session", "unregistered", f"UID {extracted_uid} no registrado")
        return JSONResponse(
            status_code=403,
            content={
                "authorized": False,
                "review_mode": False,
                "engine_active": False,
                "reason": "unregistered",
                "uid": extracted_uid,
                "message": f"Dispositivo no registrado (ID: {extracted_uid}). Contacte a soporte para activar su suscripción."
            }
        )

    # Si está suspendido o bloqueado manualmente
    if driver.get("status") == "banned":
        db_log_event(extracted_uid, client_ip, "validate_session", "banned", "Conductor suspendido")
        return JSONResponse(
            status_code=403,
            content={
                "authorized": False,
                "review_mode": False,
                "engine_active": False,
                "reason": "banned",
                "message": "Su cuenta ha sido suspendida. Contacte a soporte."
            }
        )

    # 4. Verificar fecha de expiración
    raw_valid = driver.get("valid_until", "")
    try:
        # Manejar ISO strings con 'Z' o zona horaria
        clean_iso = raw_valid.replace("Z", "+00:00") if "Z" in raw_valid else raw_valid
        valid_until_dt = datetime.fromisoformat(clean_iso)
        # Normalizar tz-naive vs tz-aware si aplica
        if valid_until_dt.tzinfo is not None:
            valid_until_dt = valid_until_dt.replace(tzinfo=None)
    except Exception:
        valid_until_dt = datetime.now() - timedelta(days=1)

    now = datetime.now()
    if now > valid_until_dt:
        db_log_event(extracted_uid, client_ip, "validate_session", "expired", f"Venció el {raw_valid}")
        return JSONResponse(
            status_code=402,
            content={
                "authorized": False,
                "review_mode": False,
                "engine_active": False,
                "reason": "expired",
                "uid": extracted_uid,
                "valid_until": raw_valid,
                "message": "Su suscripción ha vencido. Renueve su plan para continuar usando el asistente automático."
            }
        )

    # 5. Conductor AUTORIZADO y ACTIVO
    days_left = max(0, (valid_until_dt - now).days)
    db_log_event(extracted_uid, client_ip, "validate_session", "success", f"OK - {days_left} días restantes")

    # Entrega dinámica de configuración remota
    return {
        "authorized": True,
        "review_mode": False,
        "engine_active": True,
        "driver_name": driver.get("name", "Conductor"),
        "uid": extracted_uid,
        "days_left": days_left,
        "valid_until": raw_valid,
        "message": f"Licencia Activa ({days_left} días)",
        "config": {
            "host_co": db_get_config("host_co", "https://api-gw-cf.latam-co.saea1.aws.indriverapp.com"),
            "host_latam": db_get_config("host_latam", "https://api-gw-cf.latam.saea1.aws.indriverapp.com"),
            "feed_path": db_get_config("feed_path", "/new-order/api/new-order/v1/contractor-orders"),
            "bid_path": db_get_config("bid_path", "/api/v2/orders/{id}/bid"),
            "min_poll_ms": int(db_get_config("min_poll_ms", "700")),
            "max_poll_ms": int(db_get_config("max_poll_ms", "1200"))
        }
    }

# ==============================================================================
# API DE ADMINISTRACIÓN
# ==============================================================================
@app.get("/api/v1/admin/drivers")
def admin_list_drivers(token: Optional[str] = Query(None)):
    if token and token != ADMIN_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Clave de admin inválida")
    drivers = db_list_drivers()
    now = datetime.now()
    for d in drivers:
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
    return drivers

@app.post("/api/v1/admin/drivers")
def admin_register_driver(req: DriverRegisterRequest):
    expiry = (datetime.now() + timedelta(days=req.days)).isoformat()
    db_save_driver(req.uid.strip(), req.name.strip(), req.phone.strip(), expiry, "active", req.notes)
    return {"status": "ok", "message": f"Conductor {req.uid} activado por {req.days} días"}

@app.post("/api/v1/admin/drivers/{uid}/extend")
def admin_extend_driver(uid: str, req: DriverExtendRequest):
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

@app.delete("/api/v1/admin/drivers/{uid}")
def admin_delete_driver(uid: str):
    db_delete_driver(uid)
    return {"status": "ok", "message": f"Conductor {uid} eliminado"}

@app.post("/api/v1/admin/toggle-review-mode")
def admin_toggle_review_mode(req: ToggleReviewModeRequest):
    val = "true" if req.enabled else "false"
    db_set_config("playstore_review_mode", val)
    return {
        "status": "ok",
        "playstore_review_mode": req.enabled,
        "message": "Modo Revisión Play Store " + ("ACTIVADO (Camuflaje ON)" if req.enabled else "DESACTIVADO (Omega Normal)")
    }

@app.get("/api/v1/admin/logs")
def admin_get_logs(limit: int = 50):
    return db_get_logs(limit)

# ==============================================================================
# PANEL WEB DE CONTROL VISUAL (/admin)
# ==============================================================================
@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard():
    review_mode = db_get_config("playstore_review_mode", "false").lower() == "true"
    db_label = "🟢 Supabase PostgreSQL (Cloud)" if USE_SUPABASE else "🟡 SQLite Local"
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Omega Core - Panel de Control</title>
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
        .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }}
        .header h1 {{ font-size: 26px; font-weight: 700; background: linear-gradient(135deg, #60a5fa, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .badge {{ padding: 6px 14px; border-radius: 9999px; font-size: 13px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }}
        .badge-active {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-danger {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
        
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-bottom: 28px; }}
        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 20px; box-shadow: 0 8px 24px rgba(0,0,0,0.4); }}
        .card-title {{ font-size: 14px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }}
        .card-value {{ font-size: 32px; font-weight: 700; }}
        
        .switch-container {{ display: flex; align-items: center; justify-content: space-between; margin-top: 10px; }}
        .btn {{ padding: 10px 18px; border-radius: 10px; border: none; font-weight: 600; cursor: pointer; transition: all 0.2s; font-size: 14px; }}
        .btn-primary {{ background: var(--accent); color: white; box-shadow: 0 4px 14px var(--accent-glow); }}
        .btn-primary:hover {{ background: #2563eb; transform: translateY(-1px); }}
        .btn-success {{ background: var(--green); color: white; }}
        .btn-danger {{ background: var(--red); color: white; }}
        .btn-sm {{ padding: 6px 12px; font-size: 12px; }}

        .table-container {{ background: var(--surface); border: 1px solid var(--border); border-radius: 16px; overflow: hidden; margin-bottom: 28px; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th {{ background: #172033; padding: 14px 18px; font-size: 13px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }}
        td {{ padding: 16px 18px; border-top: 1px solid var(--border); font-size: 14px; }}
        tr:hover td {{ background: var(--surface-hover); }}

        .modal-form {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)) 120px; gap: 12px; align-items: end; margin-top: 12px; }}
        input, select {{ background: #0c121e; border: 1px solid var(--border); padding: 10px 14px; border-radius: 10px; color: white; font-size: 14px; width: 100%; }}
        input:focus {{ outline: none; border-color: var(--accent); }}
        label {{ font-size: 12px; color: var(--text-dim); display: block; margin-bottom: 4px; }}
        
        .log-box {{ background: #080c14; border: 1px solid var(--border); border-radius: 12px; padding: 14px; font-family: monospace; font-size: 12px; max-height: 220px; overflow-y: auto; color: #a5b4fc; }}
        .log-line {{ padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.05); }}
    </style>
</head>
<body>

    <div class="header">
        <div>
            <h1>OMEGA CORE SERVER</h1>
            <p style="color: var(--text-dim); font-size: 14px;">Gestor Remoto de Licencias y Camuflaje Play Store</p>
        </div>
        <div style="display: flex; gap: 12px; align-items: center;">
            <span class="badge" style="background: rgba(255,255,255,0.08);">{db_label}</span>
            <button class="btn btn-primary" onclick="loadData()">Refrescar</button>
        </div>
    </div>

    <!-- METRICAS & SWITCH DE CAMUFLAJE -->
    <div class="grid">
        <div class="card">
            <div class="card-title">Modo Revisión Play Store (Camuflaje)</div>
            <div class="switch-container">
                <div>
                    <span id="reviewBadge" class="badge {'badge-danger' if review_mode else 'badge-active'}">
                        {'CAMUFLAJE ACTIVO (Play Store)' if review_mode else 'OMEGA NORMAL (Activo)'}
                    </span>
                    <p style="font-size: 12px; color: var(--text-dim); margin-top: 6px;">
                        {'Los evaluadores de Google ven una app inocua' if review_mode else 'Los conductores autorizados reciben pedidos'}
                    </p>
                </div>
                <button id="btnToggleReview" class="btn {'btn-success' if review_mode else 'btn-danger'}" onclick="toggleReviewMode()">
                    {'Desactivar Camuflaje' if review_mode else 'Activar Camuflaje'}
                </button>
            </div>
        </div>

        <div class="card">
            <div class="card-title">Conductores Totales</div>
            <div class="card-value" id="totalDriversCount">--</div>
            <div style="font-size: 13px; color: var(--green); margin-top: 4px;" id="activeDriversCount">-- activos</div>
        </div>

        <div class="card">
            <div class="card-title">Base de Datos</div>
            <div class="card-value" style="font-size: 20px; color: #60a5fa; margin-top: 6px;">{db_label}</div>
            <div style="font-size: 12px; color: var(--text-dim); margin-top: 4px;">Render + Supabase Cloud Engine</div>
        </div>
    </div>

    <!-- AGREGAR CONDUCTOR RAPIDO -->
    <div class="card" style="margin-bottom: 24px;">
        <h3 style="font-size: 16px; margin-bottom: 8px;">Registrar / Activar Conductor</h3>
        <p style="font-size: 13px; color: var(--text-dim); margin-bottom: 12px;">Ingresa el UID de inDriver del conductor (o cópialo del log de peticiones cuando intente ingresar).</p>
        <div class="modal-form">
            <div>
                <label>UID inDriver (ID de Contratista)</label>
                <input type="text" id="newUid" placeholder="Ej: 104928374">
            </div>
            <div>
                <label>Nombre del Conductor</label>
                <input type="text" id="newName" placeholder="Ej: Juan Pérez">
            </div>
            <div>
                <label>Teléfono (Opcional)</label>
                <input type="text" id="newPhone" placeholder="+57300...">
            </div>
            <div>
                <label>Días de Licencia</label>
                <select id="newDays">
                    <option value="7">7 Días (Prueba)</option>
                    <option value="15">15 Días</option>
                    <option value="30" selected>30 Días (1 Mes)</option>
                    <option value="90">90 Días (3 Meses)</option>
                    <option value="365">1 Año</option>
                </select>
            </div>
            <button class="btn btn-primary" onclick="registerDriver()">Activar</button>
        </div>
    </div>

    <!-- TABLA DE CONDUCTORES -->
    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>UID inDriver</th>
                    <th>Conductor</th>
                    <th>Teléfono</th>
                    <th>Estado</th>
                    <th>Días Restantes</th>
                    <th>Vence El</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody id="driversTbody">
                <tr><td colspan="7" style="text-align: center; color: var(--text-dim);">Cargando conductores...</td></tr>
            </tbody>
        </table>
    </div>

    <!-- LOGS EN VIVO -->
    <div class="card">
        <div class="card-title">Registro de Peticiones y Validaciones (Últimas 50)</div>
        <div class="log-box" id="logsContainer">Cargando registros...</div>
    </div>

    <script>
        let currentReviewMode = {str(review_mode).lower()};

        async function loadData() {{
            try {{
                const res = await fetch('/api/v1/admin/drivers');
                const drivers = await res.json();
                
                document.getElementById('totalDriversCount').innerText = drivers.length;
                const active = drivers.filter(d => d.is_active).length;
                document.getElementById('activeDriversCount').innerText = active + " con suscripción activa";

                const tbody = document.getElementById('driversTbody');
                if (drivers.length === 0) {{
                    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;">No hay conductores registrados.</td></tr>';
                }} else {{
                    tbody.innerHTML = drivers.map(d => {{
                        const badgeClass = d.is_active ? 'badge-active' : 'badge-danger';
                        const statusText = d.is_active ? 'Activo' : (d.status === 'banned' ? 'Bloqueado' : 'Vencido');
                        const validDisplay = (d.valid_until || '').replace('T', ' ').substring(0, 16);
                        return `
                        <tr>
                            <td style="font-weight: 700; color: #60a5fa;">${{d.uid}}</td>
                            <td>${{d.name}}</td>
                            <td>${{d.phone || '-'}}</td>
                            <td><span class="badge ${{badgeClass}}">${{statusText}}</span></td>
                            <td style="font-weight: 600;">${{d.days_left}} días</td>
                            <td style="color: var(--text-dim); font-size: 13px;">${{validDisplay}}</td>
                            <td>
                                <button class="btn btn-sm btn-primary" onclick="extendDays('${{d.uid}}', 30)">+30 Días</button>
                                <button class="btn btn-sm btn-danger" onclick="deleteDriver('${{d.uid}}')">Borrar</button>
                            </td>
                        </tr>
                        `;
                    }}).join('');
                }}

                // Cargar Logs
                const logRes = await fetch('/api/v1/admin/logs?limit=40');
                const logs = await logRes.json();
                const logBox = document.getElementById('logsContainer');
                if (logs.length === 0) {{
                    logBox.innerHTML = '<div style="color: #6b7280;">Sin actividad registrada aún.</div>';
                }} else {{
                    logBox.innerHTML = logs.map(l => {{
                        const time = (l.created_at || '').substring(11, 19);
                        return `<div class="log-line"><span style="color:#60a5fa;">[${{time}}]</span> <b>UID: ${{l.uid || 'anon'}}</b> - IP: ${{l.ip_address}} - <span style="color:${{l.status === 'success' ? '#34d399' : '#f87171'}}">${{l.action}} (${{l.status}})</span> - ${{l.details || ''}}</div>`;
                    }}).join('');
                }}

            }} catch (err) {{
                console.error("Error cargando datos:", err);
            }}
        }}

        async function toggleReviewMode() {{
            const nextMode = !currentReviewMode;
            const res = await fetch('/api/v1/admin/toggle-review-mode', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ enabled: nextMode }})
            }});
            const data = await res.json();
            currentReviewMode = data.playstore_review_mode;
            
            const badge = document.getElementById('reviewBadge');
            const btn = document.getElementById('btnToggleReview');
            if (currentReviewMode) {{
                badge.className = 'badge badge-danger';
                badge.innerText = 'CAMUFLAJE ACTIVO (Play Store)';
                btn.className = 'btn btn-success';
                btn.innerText = 'Desactivar Camuflaje';
            }} else {{
                badge.className = 'badge badge-active';
                badge.innerText = 'OMEGA NORMAL (Activo)';
                btn.className = 'btn btn-danger';
                btn.innerText = 'Activar Camuflaje';
            }}
            loadData();
        }}

        async function registerDriver() {{
            const uid = document.getElementById('newUid').value.trim();
            const name = document.getElementById('newName').value.trim();
            const phone = document.getElementById('newPhone').value.trim();
            const days = parseInt(document.getElementById('newDays').value);

            if (!uid || !name) {{
                alert("Por favor ingresa el UID y el Nombre del conductor.");
                return;
            }}

            await fetch('/api/v1/admin/drivers', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ uid, name, phone, days }})
            }});

            document.getElementById('newUid').value = '';
            document.getElementById('newName').value = '';
            document.getElementById('newPhone').value = '';
            loadData();
        }}

        async function extendDays(uid, days) {{
            await fetch(`/api/v1/admin/drivers/${{uid}}/extend`, {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ days }})
            }});
            loadData();
        }}

        async function deleteDriver(uid) {{
            if (!confirm(`¿Eliminar al conductor con UID ${{uid}}?`)) return;
            await fetch(`/api/v1/admin/drivers/${{uid}}`, {{ method: 'DELETE' }});
            loadData();
        }}

        loadData();
        setInterval(loadData, 10000);
    </script>
</body>
</html>
    """

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"\n========================================================")
    print(f"🚀 INICIANDO OMEGA FLEET SERVER ({'SUPABASE' if USE_SUPABASE else 'SQLITE LOCAL'})")
    print(f"🖥️  PANEL DE CONTROL WEB EN: http://localhost:{port}/admin")
    print(f"📖 SWAGGER DOCS EN:          http://localhost:{port}/docs")
    print(f"========================================================\n")
    uvicorn.run("omega_backend_server:app", host="0.0.0.0", port=port, reload=True)
