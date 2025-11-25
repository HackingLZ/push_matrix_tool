import base64
import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterable, Tuple

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from pywebpush import webpush, WebPushException
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("PUSH_DEMO_DB", BASE_DIR / "push_demo.db"))
CONFIG_PATH = Path(os.getenv("PUSH_DEMO_CONFIG", BASE_DIR / "config.json"))
VAPID_PRIVATE_PATH = Path(os.getenv("PUSH_DEMO_VAPID_PRIVATE", BASE_DIR / "vapid_private.pem"))
VAPID_PUBLIC_PATH = Path(os.getenv("PUSH_DEMO_VAPID_PUBLIC", BASE_DIR / "vapid_public.pem"))

# Admin password - generated at startup or loaded from config
ADMIN_PASSWORD = None
ADMIN_USERNAME = "admin"

# Protected routes that require authentication
PROTECTED_ROUTES = {"/register", "/dashboard", "/debug", "/admin", "/templates"}

# Protected API endpoints (require auth)
PROTECTED_API_ROUTES = {
    "/api/admin",
    "/api/clients",
    "/api/send",
    "/api/schedule",
    "/api/scheduled",
    "/api/history",
    "/api/templates",
    "/api/cleanup",
    "/api/validate-all",
    "/api/debug",
    "/api/export",
    "/api/webhook",
}

# Public API endpoints (no auth required for client registration)
PUBLIC_API_ROUTES = {
    "/api/subscribe",
    "/api/heartbeat",
    "/api/telemetry",
}


def load_config() -> dict:
    """Load configuration from config.json."""
    if CONFIG_PATH.exists():
        try:
            return json.loads(CONFIG_PATH.read_text())
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def save_config(config: dict) -> None:
    """Save configuration to config.json."""
    CONFIG_PATH.write_text(json.dumps(config, indent=2))


def get_or_create_password() -> str:
    """Get existing password from config or generate a new one."""
    config = load_config()
    if "admin_password" in config:
        return config["admin_password"]

    # Generate new password
    password = secrets.token_urlsafe(16)
    config["admin_password"] = password
    save_config(config)
    return password


class BasicAuthMiddleware(BaseHTTPMiddleware):
    """HTTP Basic Auth middleware for protected routes."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Check if route is protected (pages)
        is_protected_page = any(path.startswith(route) for route in PROTECTED_ROUTES)

        # Check if API route is protected
        is_protected_api = any(path.startswith(route) for route in PROTECTED_API_ROUTES)

        # Check if API route is public (registration endpoints)
        is_public_api = any(path.startswith(route) for route in PUBLIC_API_ROUTES)

        # Allow public API routes without auth
        if is_public_api:
            return await call_next(request)

        # If not protected, allow through
        if not is_protected_page and not is_protected_api:
            return await call_next(request)

        # Check for valid auth header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Basic "):
            try:
                credentials = base64.b64decode(auth_header[6:]).decode("utf-8")
                username, password = credentials.split(":", 1)
                # Use constant-time comparison to prevent timing attacks
                if username == ADMIN_USERNAME and secrets.compare_digest(password, ADMIN_PASSWORD):
                    return await call_next(request)
            except (ValueError, UnicodeDecodeError):
                pass

        # Return 401 with WWW-Authenticate header
        return Response(
            content="Unauthorized",
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": 'Basic realm="Push Demo Admin"'},
        )


def ensure_vapid_keys() -> None:
    """Create a VAPID keypair if missing."""
    if VAPID_PRIVATE_PATH.exists() and VAPID_PUBLIC_PATH.exists():
        return

    private_key = ec.generate_private_key(ec.SECP256R1())
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    VAPID_PRIVATE_PATH.write_bytes(private_bytes)
    VAPID_PUBLIC_PATH.write_bytes(public_bytes)


def load_public_key_b64() -> str:
    ensure_vapid_keys()
    raw = VAPID_PUBLIC_PATH.read_bytes()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def init_db(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id TEXT UNIQUE,
            endpoint TEXT,
            keys TEXT,
            user_agent TEXT,
            ip TEXT,
            created_at TEXT,
            last_seen TEXT,
            clicks INTEGER DEFAULT 0,
            device_info TEXT
        )
        """
    )
    # Scheduled notifications table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scheduled_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT,
            url TEXT,
            icon TEXT,
            target TEXT DEFAULT 'all',
            selected_clients TEXT,
            scheduled_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            sent_at TEXT,
            result TEXT
        )
        """
    )
    # Notification history table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS notification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            body TEXT,
            url TEXT,
            icon TEXT,
            target TEXT,
            sent_at TEXT NOT NULL,
            total_clients INTEGER DEFAULT 0,
            successful INTEGER DEFAULT 0,
            failed INTEGER DEFAULT 0,
            errors TEXT
        )
        """
    )
    # Custom templates table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            category TEXT DEFAULT 'Custom',
            title TEXT NOT NULL,
            body TEXT,
            url TEXT,
            icon_default TEXT,
            icon_windows TEXT,
            icon_macos TEXT,
            icon_linux TEXT,
            icon_android TEXT,
            icon_ios TEXT,
            badge TEXT,
            tag TEXT,
            color_accent TEXT,
            color_bg TEXT,
            require_interaction INTEGER DEFAULT 0,
            silent INTEGER DEFAULT 0,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    # Migration: add new columns if they don't exist
    try:
        cur.execute("ALTER TABLE clients ADD COLUMN client_id TEXT")
    except sqlite3.OperationalError:
        pass
    try:
        cur.execute("ALTER TABLE clients ADD COLUMN device_info TEXT")
    except sqlite3.OperationalError:
        pass
    # Create index on client_id for fast lookups
    cur.execute("CREATE INDEX IF NOT EXISTS idx_client_id ON clients(client_id)")
    conn.commit()
    return conn


app = FastAPI()

# Initialize password on module load
ADMIN_PASSWORD = get_or_create_password()

# Add authentication middleware
app.add_middleware(BasicAuthMiddleware)

templates = Jinja2Templates(directory=BASE_DIR / "static")
app.state.db = init_db(DB_PATH)
PUBLIC_VAPID_KEY = load_public_key_b64()


def get_db():
    return app.state.db


def fetch_clients(db) -> Iterable[Tuple]:
    cur = db.cursor()
    cur.execute(
        "SELECT id, client_id, endpoint, keys, user_agent, ip, created_at, last_seen, clicks, device_info "
        "FROM clients ORDER BY last_seen DESC"
    )
    rows = cur.fetchall()
    result = []
    for r in rows:
        device_info = {}
        if r["device_info"]:
            try:
                device_info = json.loads(r["device_info"])
            except json.JSONDecodeError:
                pass
        result.append({
            "id": r["id"],
            "client_id": r["client_id"],
            "endpoint": r["endpoint"],
            "keys": r["keys"],
            "user_agent": r["user_agent"],
            "ip": r["ip"],
            "created_at": r["created_at"],
            "last_seen": r["last_seen"],
            "clicks": r["clicks"],
            "device_info": device_info,
        })
    return result


@app.get("/sw.js")
async def service_worker() -> FileResponse:
    return FileResponse(BASE_DIR / "sw.js", media_type="application/javascript")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    config = load_config()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "public_key": PUBLIC_VAPID_KEY,
            "redirect_url": config.get("redirect_url", ""),
        },
    )


@app.get("/register", response_class=HTMLResponse)
async def register(request: Request):
    return templates.TemplateResponse(
        "register.html",
        {
            "request": request,
            "public_key": PUBLIC_VAPID_KEY,
        },
    )


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db=Depends(get_db)):
    clients = fetch_clients(db)
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "clients": clients,
            "public_key": PUBLIC_VAPID_KEY,
        },
    )


@app.get("/debug", response_class=HTMLResponse)
async def debug_tools(request: Request):
    return templates.TemplateResponse(
        "debug.html",
        {
            "request": request,
            "public_key": PUBLIC_VAPID_KEY,
        },
    )


@app.get("/test_harness", response_class=HTMLResponse)
async def test_harness(request: Request):
    return templates.TemplateResponse(
        "test_harness.html",
        {
            "request": request,
            "public_key": PUBLIC_VAPID_KEY,
        },
    )


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    config = load_config()
    return templates.TemplateResponse(
        "admin.html",
        {
            "request": request,
            "config": config,
            "public_key": PUBLIC_VAPID_KEY,
        },
    )


@app.get("/templates", response_class=HTMLResponse)
async def templates_page(request: Request, db=Depends(get_db)):
    cur = db.cursor()
    custom_templates = cur.execute(
        "SELECT * FROM templates ORDER BY category, name"
    ).fetchall()
    return templates.TemplateResponse(
        "templates.html",
        {
            "request": request,
            "templates": [dict(t) for t in custom_templates],
        },
    )


@app.post("/api/admin/config")
async def save_admin_config(request: Request):
    """Save SSL/domain configuration. Requires server restart to take effect."""
    data = await request.json()
    config = load_config()

    # Update SSL settings
    if "ssl_enabled" in data:
        config["ssl_enabled"] = data["ssl_enabled"]
    if "domain" in data:
        config["domain"] = data["domain"]
    if "email" in data:
        config["email"] = data["email"]
    if "ssl_cert" in data:
        config["ssl_cert"] = data["ssl_cert"]
    if "ssl_key" in data:
        config["ssl_key"] = data["ssl_key"]
    if "port" in data:
        config["port"] = data["port"]

    # Redirect settings
    if "redirect_url" in data:
        config["redirect_url"] = data["redirect_url"]

    # Webhook settings
    if "webhook_url" in data:
        config["webhook_url"] = data["webhook_url"]

    # Test mode settings
    if "test_client_id" in data:
        config["test_client_id"] = data["test_client_id"]

    save_config(config)
    return {"ok": True, "message": "Configuration saved. Restart server to apply changes."}


@app.get("/api/admin/config")
async def get_admin_config():
    """Get current configuration."""
    config = load_config()
    # Don't expose password
    safe_config = {k: v for k, v in config.items() if k != "admin_password"}
    return safe_config


@app.post("/api/admin/password")
async def change_password(request: Request):
    """Change the admin password."""
    global ADMIN_PASSWORD
    data = await request.json()
    new_password = data.get("password")

    if not new_password or len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    config = load_config()
    config["admin_password"] = new_password
    save_config(config)
    ADMIN_PASSWORD = new_password

    return {"ok": True, "message": "Password changed successfully"}


@app.post("/api/admin/restart")
async def request_restart():
    """Signal that a restart is needed. Returns instructions."""
    return {
        "ok": True,
        "message": "Please restart the server manually to apply SSL changes.",
        "hint": "Run: python server.py (with your desired flags)"
    }


@app.post("/api/admin/vapid")
async def save_vapid_config(request: Request):
    """Save VAPID configuration or regenerate keys."""
    data = await request.json()
    regenerate = data.get("regenerate", False)
    private_path = data.get("private_path", "")

    config = load_config()

    if regenerate:
        # Delete existing keys to force regeneration on restart
        try:
            if VAPID_PRIVATE_PATH.exists():
                VAPID_PRIVATE_PATH.unlink()
            if VAPID_PUBLIC_PATH.exists():
                VAPID_PUBLIC_PATH.unlink()
            # Regenerate immediately
            ensure_vapid_keys()
            return {
                "ok": True,
                "message": "VAPID keys regenerated. All existing subscriptions are now invalid. Restart server to apply."
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to regenerate keys: {e}")

    if private_path:
        config["vapid_private_path"] = private_path
        save_config(config)

    return {"ok": True, "message": "VAPID configuration saved."}


@app.post("/api/subscribe")
async def subscribe(request: Request, db=Depends(get_db)):
    data = await request.json()
    sub = data.get("subscription")
    client_id = data.get("clientId")  # Fingerprint from browser
    device_info = data.get("deviceInfo", {})

    if not sub or "endpoint" not in sub:
        raise HTTPException(status_code=400, detail="subscription missing endpoint")

    now = datetime.utcnow().isoformat()
    cur = db.cursor()

    if client_id:
        # Check if this client_id already exists
        existing = cur.execute(
            "SELECT id, endpoint FROM clients WHERE client_id = ?", (client_id,)
        ).fetchone()

        if existing:
            # Update existing client with new endpoint
            cur.execute(
                """
                UPDATE clients SET
                    endpoint = ?,
                    keys = ?,
                    user_agent = ?,
                    ip = ?,
                    last_seen = ?,
                    device_info = ?
                WHERE client_id = ?
                """,
                (
                    sub["endpoint"],
                    json.dumps(sub.get("keys", {})),
                    request.headers.get("user-agent", ""),
                    request.client.host if request.client else "",
                    now,
                    json.dumps(device_info),
                    client_id,
                ),
            )
            db.commit()
            print(f"[subscribe] updated client {client_id[:16]}... with new endpoint")
            return {"ok": True, "id": existing["id"], "clientId": client_id, "updated": True}

    # New client - generate client_id if not provided
    if not client_id:
        import hashlib
        # Fallback: hash endpoint + user agent as pseudo-fingerprint
        client_id = hashlib.sha256(
            f"{sub['endpoint']}{request.headers.get('user-agent', '')}".encode()
        ).hexdigest()[:32]

    cur.execute(
        """
        INSERT INTO clients (client_id, endpoint, keys, user_agent, ip, created_at, last_seen, device_info)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            client_id,
            sub["endpoint"],
            json.dumps(sub.get("keys", {})),
            request.headers.get("user-agent", ""),
            request.client.host if request.client else "",
            now,
            now,
            json.dumps(device_info),
        ),
    )
    db.commit()
    row_id = cur.lastrowid
    print(f"[subscribe] new client {client_id[:16]}... as id {row_id}")

    # Trigger webhook for new registration
    import asyncio
    asyncio.create_task(trigger_webhook("client.registered", {
        "id": row_id,
        "client_id": client_id,
        "device_info": device_info,
        "ip": request.client.host if request.client else "",
    }))

    return {"ok": True, "id": row_id, "clientId": client_id, "updated": False}


@app.post("/api/send")
async def send_notification(
    title: str = Form(""),
    body: str = Form(""),
    url: str = Form(""),
    icon: str = Form(""),
    target: str = Form("all"),
    selected_clients: str = Form(""),
    db=Depends(get_db),
):
    if not title:
        raise HTTPException(status_code=400, detail="title required")

    # Use the shared send function
    result = send_push_to_clients(
        db,
        title=title,
        body=body,
        url=url,
        icon=icon,
        target=target,
        selected_clients=selected_clients,
    )

    if result["total"] == 0:
        raise HTTPException(status_code=400, detail="no registered clients")

    # Log to history
    now = datetime.utcnow().isoformat()
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO notification_history
        (title, body, url, icon, target, sent_at, total_clients, successful, failed, errors)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            title,
            body,
            url,
            icon,
            target if target != "selected" else f"selected:{selected_clients}",
            now,
            result["total"],
            result["sent"],
            len(result["errors"]),
            json.dumps(result["errors"][:10]),
        ),
    )
    db.commit()

    if result["sent"] == 0 and result["errors"]:
        raise HTTPException(status_code=400, detail=f"push failed: {result['errors'][0]}")

    print(f"[push] attempted {result['total']} sends, successes={result['sent']}, errors={len(result['errors'])}")
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/api/telemetry")
async def telemetry(request: Request, db=Depends(get_db)):
    data = await request.json()
    endpoint = data.get("endpoint")
    if not endpoint:
        raise HTTPException(status_code=400, detail="missing endpoint")

    cur = db.cursor()
    cur.execute(
        "UPDATE clients SET clicks = clicks + 1, last_seen=? WHERE endpoint=?",
        (datetime.utcnow().isoformat(), endpoint),
    )
    db.commit()
    return {"ok": True}


@app.get("/api/clients")
async def list_clients(db=Depends(get_db)):
    rows = fetch_clients(db)
    return [
        {
            "id": r["id"],
            "endpoint": r["endpoint"],
            "last_seen": r["last_seen"],
            "ip": r["ip"],
            "clicks": r["clicks"],
        }
        for r in rows
    ]


@app.get("/health")
async def healthcheck():
    return {"status": "ok"}


@app.post("/api/heartbeat")
async def heartbeat(request: Request, db=Depends(get_db)):
    """Update last_seen for a client (called periodically by browser)."""
    data = await request.json()
    client_id = data.get("clientId")
    device_info = data.get("deviceInfo")

    if not client_id:
        raise HTTPException(status_code=400, detail="missing clientId")

    now = datetime.utcnow().isoformat()
    cur = db.cursor()

    # Update last_seen and optionally device_info
    if device_info:
        cur.execute(
            "UPDATE clients SET last_seen = ?, device_info = ? WHERE client_id = ?",
            (now, json.dumps(device_info), client_id),
        )
    else:
        cur.execute(
            "UPDATE clients SET last_seen = ? WHERE client_id = ?",
            (now, client_id),
        )
    db.commit()
    return {"ok": True}


@app.get("/api/clients/status")
async def clients_status(db=Depends(get_db)):
    """Get online/offline status for all clients based on last_seen.

    Note: 'Online' means the registration page is open and sending heartbeats.
    Push notifications can still be delivered to 'offline' clients via service workers.
    """
    from datetime import timedelta

    now = datetime.utcnow()
    # Online = heartbeat within last 2 minutes (heartbeats sent every 30s)
    online_threshold = (now - timedelta(seconds=120)).isoformat()
    # Recent = seen within last hour
    recent_threshold = (now - timedelta(hours=1)).isoformat()

    cur = db.cursor()
    rows = cur.execute(
        "SELECT id, client_id, last_seen FROM clients"
    ).fetchall()

    statuses = {}
    for r in rows:
        key = r["client_id"] or str(r["id"])
        last_seen = r["last_seen"]

        if last_seen and last_seen >= online_threshold:
            status = "online"
        elif last_seen and last_seen >= recent_threshold:
            status = "recent"
        else:
            status = "offline"

        statuses[key] = {
            "status": status,
            "online": status == "online",  # backwards compat
            "lastSeen": last_seen,
        }
    return statuses


@app.post("/api/cleanup")
async def cleanup_stale_subscriptions(db=Depends(get_db)):
    """Remove subscriptions that haven't been seen in over 30 days."""
    from datetime import timedelta

    cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) FROM clients WHERE last_seen < ?", (cutoff,))
    count = cur.fetchone()[0]

    if count > 0:
        cur.execute("DELETE FROM clients WHERE last_seen < ?", (cutoff,))
        db.commit()

    print(f"[cleanup] removed {count} stale subscription(s) older than 30 days")
    return {"removed": count}


@app.post("/api/validate-all")
async def validate_all_subscriptions(db=Depends(get_db)):
    """Test all subscriptions and remove invalid ones. Use sparingly."""
    cur = db.cursor()
    rows = list(cur.execute("SELECT id, endpoint, keys FROM clients"))

    results = {"total": len(rows), "valid": 0, "invalid": 0, "removed": []}

    for client_id, endpoint, keys_json in rows:
        try:
            # Send a test push (will show as notification)
            webpush(
                subscription_info={"endpoint": endpoint, "keys": json.loads(keys_json)},
                data=json.dumps({"title": "Subscription Valid", "body": "Your push subscription is working.", "url": "/"}),
                vapid_private_key=str(VAPID_PRIVATE_PATH),
                vapid_claims={"sub": "mailto:demo@example.com"},
            )
            results["valid"] += 1
        except WebPushException as exc:
            status_code = getattr(exc.response, "status_code", None) if hasattr(exc, "response") else None
            if status_code in (404, 410):
                cur.execute("DELETE FROM clients WHERE id = ?", (client_id,))
                results["removed"].append(client_id)
                results["invalid"] += 1
            else:
                # Other errors (e.g., rate limit) - don't remove
                results["valid"] += 1
        except Exception:
            results["valid"] += 1  # Don't remove on unknown errors

    if results["removed"]:
        db.commit()

    print(f"[validate-all] checked {results['total']}, valid={results['valid']}, removed={len(results['removed'])}")
    return results


@app.get("/api/debug/subscription/{client_id}")
async def debug_subscription(client_id: int, db=Depends(get_db)):
    """Check if a subscription is still valid by sending a test push."""
    cur = db.cursor()
    row = cur.execute(
        "SELECT endpoint, keys FROM clients WHERE id = ?", (client_id,)
    ).fetchone()

    if not row:
        return {"valid": False, "error": "Client not found"}

    endpoint, keys_json = row["endpoint"], row["keys"]

    # Try to send a silent/test push
    try:
        webpush(
            subscription_info={"endpoint": endpoint, "keys": json.loads(keys_json)},
            data=json.dumps({"title": "Connection Test", "body": "If you see this, push is working!"}),
            vapid_private_key=str(VAPID_PRIVATE_PATH),
            vapid_claims={"sub": "mailto:demo@example.com"},
        )
        return {
            "valid": True,
            "endpoint_domain": endpoint.split("/")[2] if "/" in endpoint else "unknown",
            "message": "Push sent successfully"
        }
    except WebPushException as e:
        # 410 Gone = subscription expired/invalid
        # 404 = endpoint not found
        status_code = getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
        return {
            "valid": False,
            "status_code": status_code,
            "error": str(e),
            "hint": "410 = subscription expired, 404 = invalid endpoint"
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ============ Scheduled Notifications ============

def send_push_to_clients(db, title: str, body: str, url: str, icon: str = "", target: str = "all", selected_clients: str = "") -> dict:
    """
    Internal function to send push notifications.
    Returns dict with sent, errors, expired counts.
    """
    cur = db.cursor()
    query = "SELECT id, endpoint, keys FROM clients"
    params = ()

    if target == "selected" and selected_clients:
        client_ids = [int(x) for x in selected_clients.split(",") if x.strip().isdigit()]
        if client_ids:
            placeholders = ",".join("?" * len(client_ids))
            query += f" WHERE id IN ({placeholders})"
            params = tuple(client_ids)
    elif target != "all":
        query += " WHERE id = ?"
        params = (target,)

    rows = list(cur.execute(query, params))
    result = {"total": len(rows), "sent": 0, "errors": [], "expired": []}

    for row in rows:
        client_id_int, endpoint, keys_json = row[0], row[1], row[2]
        try:
            payload = {"title": title, "body": body, "url": url}
            if icon:
                payload["icon"] = icon
            webpush(
                subscription_info={"endpoint": endpoint, "keys": json.loads(keys_json)},
                data=json.dumps(payload),
                vapid_private_key=str(VAPID_PRIVATE_PATH),
                vapid_claims={"sub": "mailto:demo@example.com"},
            )
            result["sent"] += 1
        except WebPushException as exc:
            status_code = getattr(exc.response, "status_code", None) if hasattr(exc, "response") else None
            result["errors"].append(str(exc))
            if status_code in (404, 410):
                result["expired"].append(endpoint)
        except Exception as exc:
            result["errors"].append(str(exc))

    # Clean up expired subscriptions
    if result["expired"]:
        for ep in result["expired"]:
            cur.execute("DELETE FROM clients WHERE endpoint = ?", (ep,))
        db.commit()

    return result


@app.post("/api/schedule")
async def schedule_notification(request: Request, db=Depends(get_db)):
    """Schedule a notification to be sent at a specific time."""
    data = await request.json()
    title = data.get("title", "").strip()
    body = data.get("body", "")
    url = data.get("url", "")
    icon = data.get("icon", "")
    target = data.get("target", "all")
    selected_clients = data.get("selected_clients", "")
    scheduled_at = data.get("scheduled_at")

    if not title:
        raise HTTPException(status_code=400, detail="title required")
    if not scheduled_at:
        raise HTTPException(status_code=400, detail="scheduled_at required")

    now = datetime.utcnow().isoformat()
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO scheduled_notifications
        (title, body, url, icon, target, selected_clients, scheduled_at, created_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        """,
        (title, body, url, icon, target, selected_clients, scheduled_at, now),
    )
    db.commit()
    return {"ok": True, "id": cur.lastrowid, "scheduled_at": scheduled_at}


@app.get("/api/scheduled")
async def list_scheduled(db=Depends(get_db)):
    """List all scheduled notifications."""
    cur = db.cursor()
    rows = cur.execute(
        "SELECT * FROM scheduled_notifications ORDER BY scheduled_at ASC"
    ).fetchall()
    return [dict(r) for r in rows]


@app.delete("/api/scheduled/{job_id}")
async def cancel_scheduled(job_id: int, db=Depends(get_db)):
    """Cancel a scheduled notification."""
    cur = db.cursor()
    cur.execute("DELETE FROM scheduled_notifications WHERE id = ? AND status = 'pending'", (job_id,))
    db.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Scheduled notification not found or already sent")
    return {"ok": True, "deleted": job_id}


@app.post("/api/scheduled/process")
async def process_scheduled(db=Depends(get_db)):
    """Process any due scheduled notifications. Call this periodically."""
    now = datetime.utcnow().isoformat()
    cur = db.cursor()

    # Find pending notifications that are due
    due = cur.execute(
        "SELECT * FROM scheduled_notifications WHERE status = 'pending' AND scheduled_at <= ?",
        (now,)
    ).fetchall()

    results = []
    for job in due:
        job_dict = dict(job)
        # Send the notification
        send_result = send_push_to_clients(
            db,
            title=job_dict["title"],
            body=job_dict["body"] or "",
            url=job_dict["url"] or "",
            icon=job_dict["icon"] or "",
            target=job_dict["target"] or "all",
            selected_clients=job_dict["selected_clients"] or "",
        )

        # Update job status
        cur.execute(
            "UPDATE scheduled_notifications SET status = 'sent', sent_at = ?, result = ? WHERE id = ?",
            (now, json.dumps(send_result), job_dict["id"]),
        )

        # Log to history
        cur.execute(
            """
            INSERT INTO notification_history
            (title, body, url, icon, target, sent_at, total_clients, successful, failed, errors)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_dict["title"],
                job_dict["body"],
                job_dict["url"],
                job_dict["icon"],
                job_dict["target"],
                now,
                send_result["total"],
                send_result["sent"],
                len(send_result["errors"]),
                json.dumps(send_result["errors"][:10]),  # Store first 10 errors
            ),
        )

        results.append({"id": job_dict["id"], "result": send_result})

    db.commit()
    return {"processed": len(results), "results": results}


# ============ Notification History ============

@app.get("/api/history")
async def get_notification_history(limit: int = 50, db=Depends(get_db)):
    """Get notification history."""
    cur = db.cursor()
    rows = cur.execute(
        "SELECT * FROM notification_history ORDER BY sent_at DESC LIMIT ?",
        (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


@app.delete("/api/history")
async def clear_history(db=Depends(get_db)):
    """Clear notification history."""
    cur = db.cursor()
    cur.execute("DELETE FROM notification_history")
    db.commit()
    return {"ok": True, "message": "History cleared"}


# ============ Client Management ============

@app.delete("/api/clients/{client_id}")
async def delete_client(client_id: int, db=Depends(get_db)):
    """Delete a specific client."""
    cur = db.cursor()
    cur.execute("DELETE FROM clients WHERE id = ?", (client_id,))
    db.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Client not found")
    return {"ok": True, "deleted": client_id}


@app.delete("/api/clients")
async def delete_selected_clients(request: Request, db=Depends(get_db)):
    """Delete multiple clients by ID."""
    data = await request.json()
    client_ids = data.get("ids", [])
    if not client_ids:
        raise HTTPException(status_code=400, detail="No client IDs provided")

    cur = db.cursor()
    placeholders = ",".join("?" * len(client_ids))
    cur.execute(f"DELETE FROM clients WHERE id IN ({placeholders})", tuple(client_ids))
    db.commit()
    return {"ok": True, "deleted": cur.rowcount}


# ============ Export ============

@app.get("/api/export/clients")
async def export_clients(format: str = "json", db=Depends(get_db)):
    """Export clients as JSON or CSV."""
    clients = fetch_clients(db)

    if format.lower() == "csv":
        import csv
        import io
        output = io.StringIO()
        if clients:
            fieldnames = ["id", "client_id", "endpoint", "user_agent", "ip", "created_at", "last_seen", "clicks", "device_type", "os", "browser"]
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for cl in clients:
                di = cl.get("device_info", {}) or {}
                writer.writerow({
                    "id": cl["id"],
                    "client_id": cl["client_id"],
                    "endpoint": cl["endpoint"],
                    "user_agent": cl["user_agent"],
                    "ip": cl["ip"],
                    "created_at": cl["created_at"],
                    "last_seen": cl["last_seen"],
                    "clicks": cl["clicks"],
                    "device_type": di.get("deviceType", ""),
                    "os": di.get("os", ""),
                    "browser": di.get("browser", ""),
                })
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=clients.csv"}
        )

    # Default: JSON
    return Response(
        content=json.dumps(clients, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=clients.json"}
    )


# ============ Webhook on Registration ============

def is_safe_webhook_url(url: str) -> tuple:
    """
    Validate webhook URL to prevent SSRF attacks.
    Returns (is_safe, error_message).
    """
    from urllib.parse import urlparse
    import ipaddress
    import socket

    try:
        parsed = urlparse(url)

        # Only allow http/https
        if parsed.scheme not in ('http', 'https'):
            return False, "Only http/https URLs are allowed"

        if not parsed.hostname:
            return False, "Invalid URL: no hostname"

        # Block common internal/metadata endpoints
        blocked_hosts = {
            'localhost', '127.0.0.1', '0.0.0.0', '::1',
            'metadata.google.internal', '169.254.169.254',
            'metadata.aws.internal',
        }
        if parsed.hostname.lower() in blocked_hosts:
            return False, f"Blocked hostname: {parsed.hostname}"

        # Try to resolve hostname and check if it's a private IP
        try:
            # Get all IPs for the hostname
            infos = socket.getaddrinfo(parsed.hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for info in infos:
                ip_str = info[4][0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                        return False, f"URL resolves to private/internal IP: {ip_str}"
                except ValueError:
                    pass
        except socket.gaierror:
            # Can't resolve - might be okay, let it through but log
            print(f"[webhook] Warning: Could not resolve hostname {parsed.hostname}")

        return True, None

    except Exception as e:
        return False, f"URL validation error: {str(e)}"


async def trigger_webhook(event: str, data: dict):
    """Fire webhook if configured."""
    config = load_config()
    webhook_url = config.get("webhook_url")
    if not webhook_url:
        return

    # Validate URL for SSRF
    is_safe, error = is_safe_webhook_url(webhook_url)
    if not is_safe:
        print(f"[webhook] Blocked unsafe URL: {error}")
        return

    import httpx
    payload = {
        "event": event,
        "timestamp": datetime.utcnow().isoformat(),
        "data": data,
    }
    try:
        async with httpx.AsyncClient() as client:
            await client.post(webhook_url, json=payload, timeout=10.0)
        print(f"[webhook] Sent {event} to {webhook_url}")
    except Exception as e:
        print(f"[webhook] Failed to send {event}: {e}")


# ============ Template Management ============

@app.get("/api/templates")
async def list_templates(db=Depends(get_db)):
    """List all custom templates."""
    cur = db.cursor()
    rows = cur.execute("SELECT * FROM templates ORDER BY category, name").fetchall()
    return [dict(r) for r in rows]


@app.get("/api/templates/{template_id}")
async def get_template(template_id: int, db=Depends(get_db)):
    """Get a specific template."""
    cur = db.cursor()
    row = cur.execute("SELECT * FROM templates WHERE id = ?", (template_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Template not found")
    return dict(row)


@app.post("/api/templates")
async def create_template(request: Request, db=Depends(get_db)):
    """Create a new template."""
    data = await request.json()
    now = datetime.utcnow().isoformat()

    required = ["name", "title"]
    for field in required:
        if not data.get(field):
            raise HTTPException(status_code=400, detail=f"{field} is required")

    cur = db.cursor()
    try:
        cur.execute(
            """
            INSERT INTO templates (
                name, category, title, body, url,
                icon_default, icon_windows, icon_macos, icon_linux, icon_android, icon_ios,
                badge, tag, color_accent, color_bg,
                require_interaction, silent, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data.get("name"),
                data.get("category", "Custom"),
                data.get("title"),
                data.get("body", ""),
                data.get("url", ""),
                data.get("icon_default", ""),
                data.get("icon_windows", ""),
                data.get("icon_macos", ""),
                data.get("icon_linux", ""),
                data.get("icon_android", ""),
                data.get("icon_ios", ""),
                data.get("badge", ""),
                data.get("tag", ""),
                data.get("color_accent", ""),
                data.get("color_bg", ""),
                1 if data.get("require_interaction") else 0,
                1 if data.get("silent") else 0,
                now,
                now,
            ),
        )
        db.commit()
        return {"ok": True, "id": cur.lastrowid}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Template name already exists")


@app.put("/api/templates/{template_id}")
async def update_template(template_id: int, request: Request, db=Depends(get_db)):
    """Update an existing template."""
    data = await request.json()
    now = datetime.utcnow().isoformat()

    cur = db.cursor()
    existing = cur.execute("SELECT id FROM templates WHERE id = ?", (template_id,)).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Template not found")

    try:
        cur.execute(
            """
            UPDATE templates SET
                name = ?, category = ?, title = ?, body = ?, url = ?,
                icon_default = ?, icon_windows = ?, icon_macos = ?, icon_linux = ?, icon_android = ?, icon_ios = ?,
                badge = ?, tag = ?, color_accent = ?, color_bg = ?,
                require_interaction = ?, silent = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                data.get("name"),
                data.get("category", "Custom"),
                data.get("title"),
                data.get("body", ""),
                data.get("url", ""),
                data.get("icon_default", ""),
                data.get("icon_windows", ""),
                data.get("icon_macos", ""),
                data.get("icon_linux", ""),
                data.get("icon_android", ""),
                data.get("icon_ios", ""),
                data.get("badge", ""),
                data.get("tag", ""),
                data.get("color_accent", ""),
                data.get("color_bg", ""),
                1 if data.get("require_interaction") else 0,
                1 if data.get("silent") else 0,
                now,
                template_id,
            ),
        )
        db.commit()
        return {"ok": True}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Template name already exists")


@app.delete("/api/templates/{template_id}")
async def delete_template(template_id: int, db=Depends(get_db)):
    """Delete a template."""
    cur = db.cursor()
    cur.execute("DELETE FROM templates WHERE id = ?", (template_id,))
    db.commit()
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Template not found")
    return {"ok": True}


@app.post("/api/templates/{template_id}/duplicate")
async def duplicate_template(template_id: int, db=Depends(get_db)):
    """Duplicate a template."""
    cur = db.cursor()
    row = cur.execute("SELECT * FROM templates WHERE id = ?", (template_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Template not found")

    template = dict(row)
    now = datetime.utcnow().isoformat()

    # Generate unique name
    base_name = template["name"] + " (Copy)"
    name = base_name
    counter = 1
    while True:
        existing = cur.execute("SELECT id FROM templates WHERE name = ?", (name,)).fetchone()
        if not existing:
            break
        counter += 1
        name = f"{base_name} {counter}"

    cur.execute(
        """
        INSERT INTO templates (
            name, category, title, body, url,
            icon_default, icon_windows, icon_macos, icon_linux, icon_android, icon_ios,
            badge, tag, color_accent, color_bg,
            require_interaction, silent, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            name,
            template["category"],
            template["title"],
            template["body"],
            template["url"],
            template["icon_default"],
            template["icon_windows"],
            template["icon_macos"],
            template["icon_linux"],
            template["icon_android"],
            template["icon_ios"],
            template["badge"],
            template["tag"],
            template["color_accent"],
            template["color_bg"],
            template["require_interaction"],
            template["silent"],
            now,
            now,
        ),
    )
    db.commit()
    return {"ok": True, "id": cur.lastrowid, "name": name}


@app.post("/api/webhook/test")
async def test_webhook(request: Request):
    """Send a test webhook to the specified URL."""
    data = await request.json()
    url = data.get("url")

    if not url:
        raise HTTPException(status_code=400, detail="URL required")

    # Validate URL for SSRF
    is_safe, error = is_safe_webhook_url(url)
    if not is_safe:
        return {"ok": False, "error": f"Blocked: {error}"}

    import httpx
    payload = {
        "event": "test",
        "timestamp": datetime.utcnow().isoformat(),
        "data": {"message": "This is a test webhook from Push Demo"},
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=payload, timeout=10.0)
            return {"ok": True, "status_code": response.status_code}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def get_certbot_cert(domain: str, email: str = None, staging: bool = False) -> tuple:
    """
    Obtain SSL certificate using certbot standalone mode.
    Returns (cert_path, key_path) or raises an exception.
    """
    import subprocess
    import shutil

    if not shutil.which("certbot"):
        raise RuntimeError(
            "certbot not found. Install it with:\n"
            "  macOS: brew install certbot\n"
            "  Ubuntu/Debian: sudo apt install certbot\n"
            "  RHEL/CentOS: sudo yum install certbot"
        )

    cert_dir = Path(f"/etc/letsencrypt/live/{domain}")
    cert_path = cert_dir / "fullchain.pem"
    key_path = cert_dir / "privkey.pem"

    # Check if certs already exist and are valid
    if cert_path.exists() and key_path.exists():
        print(f"[ssl] Found existing certificates for {domain}")
        # Try to renew if needed
        renew_cmd = ["certbot", "renew", "--non-interactive"]
        subprocess.run(renew_cmd, capture_output=True)
        return str(cert_path), str(key_path)

    # Request new certificate
    print(f"[ssl] Requesting new certificate for {domain}...")
    cmd = [
        "certbot", "certonly",
        "--standalone",
        "--non-interactive",
        "--agree-tos",
        "-d", domain,
    ]

    if email:
        cmd.extend(["-m", email])
    else:
        cmd.append("--register-unsafely-without-email")

    if staging:
        cmd.append("--staging")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(
            f"certbot failed:\n{result.stderr}\n\n"
            "Make sure:\n"
            "  1. Port 80 is available (certbot needs it for verification)\n"
            "  2. Domain DNS points to this server\n"
            "  3. Running with sudo/root permissions"
        )

    if not cert_path.exists():
        raise RuntimeError(f"Certificate not found at {cert_path} after certbot ran")

    print(f"[ssl] Certificate obtained successfully!")
    return str(cert_path), str(key_path)


def main():
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="Push Demo Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")

    # SSL options
    ssl_group = parser.add_argument_group("SSL/TLS options")
    ssl_group.add_argument("--ssl", action="store_true", help="Enable SSL/TLS")
    ssl_group.add_argument("--ssl-cert", help="Path to SSL certificate file (fullchain.pem)")
    ssl_group.add_argument("--ssl-key", help="Path to SSL private key file (privkey.pem)")

    # Let's Encrypt / certbot options
    certbot_group = parser.add_argument_group("Let's Encrypt options")
    certbot_group.add_argument("--domain", help="Domain for Let's Encrypt certificate (auto-obtains via certbot)")
    certbot_group.add_argument("--email", help="Email for Let's Encrypt registration")
    certbot_group.add_argument("--staging", action="store_true", help="Use Let's Encrypt staging server (for testing)")

    args = parser.parse_args()

    ssl_certfile = None
    ssl_keyfile = None

    # Handle SSL configuration
    if args.domain:
        # Use certbot to get/renew certificate
        try:
            ssl_certfile, ssl_keyfile = get_certbot_cert(
                domain=args.domain,
                email=args.email,
                staging=args.staging
            )
            args.ssl = True
            if args.port == 8000:
                args.port = 443  # Default to 443 for HTTPS
        except RuntimeError as e:
            print(f"[ssl] Error: {e}")
            return 1

    elif args.ssl:
        # Manual SSL cert paths
        if not args.ssl_cert or not args.ssl_key:
            print("[ssl] Error: --ssl requires --ssl-cert and --ssl-key, or use --domain for auto-cert")
            return 1
        if not Path(args.ssl_cert).exists():
            print(f"[ssl] Error: Certificate file not found: {args.ssl_cert}")
            return 1
        if not Path(args.ssl_key).exists():
            print(f"[ssl] Error: Key file not found: {args.ssl_key}")
            return 1
        ssl_certfile = args.ssl_cert
        ssl_keyfile = args.ssl_key

    # Build uvicorn config
    protocol = "https" if args.ssl else "http"
    host_display = "localhost" if args.host == "0.0.0.0" else args.host
    base_url = f"{protocol}://{host_display}:{args.port}"

    print(f"\nStarting Push Demo")
    print(f"{'=' * 40}")
    print(f"  Home:      {base_url}/")
    print(f"  Register:  {base_url}/register  [protected]")
    print(f"  Dashboard: {base_url}/dashboard [protected]")
    print(f"  Templates: {base_url}/templates [protected]")
    print(f"  Debug:     {base_url}/debug     [protected]")
    print(f"  Admin:     {base_url}/admin     [protected]")
    print(f"{'=' * 40}")
    print(f"\n  Auth:  admin / {ADMIN_PASSWORD}")
    print(f"{'=' * 40}\n")

    if args.ssl:
        print(f"[ssl] Using certificate: {ssl_certfile}")
        print(f"[ssl] Using key: {ssl_keyfile}")

    uvicorn.run(
        "server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        ssl_certfile=ssl_certfile,
        ssl_keyfile=ssl_keyfile,
    )
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main() or 0)
