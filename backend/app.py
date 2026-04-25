"""
app.py – LinkGuardian Pro Flask Backend
Handles: Auth, Links CRUD, Manual checks, Cron endpoint, Rate limiting
"""

import os
import uuid
import hashlib
import hmac
import datetime
import logging
from functools import wraps
from typing import Optional

from flask import (Flask, request, jsonify, session,
                   send_from_directory, g)
from flask_cors import CORS
from dotenv import load_dotenv
from supabase import create_client, Client

from monitor import check_link
from alerts import dispatch_alert, build_plan_expiry_message, send_telegram_message

# ── Bootstrap ──────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder="../frontend", static_url_path="")
app.secret_key = os.environ["FLASK_SECRET_KEY"]

# CORS – allow frontend origin
CORS(app, supports_credentials=True,
     origins=[os.getenv("FRONTEND_URL", "*")])

# ── Supabase ───────────────────────────────────────────────────────────────────
supabase: Client = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_SERVICE_KEY"],   # service role – backend only
)

# ── Plan limits ────────────────────────────────────────────────────────────────
PLAN_LIMITS = {
    "free":     5,
    "pro":      20,
    "business": 100,
    "agency":   500,
}

FREE_CHECKER_LIMIT = int(os.getenv("FREE_CHECKER_LIMIT", 10))
CRON_API_KEY = os.getenv("CRON_API_KEY", "")

# ─────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    """SHA-256 password hash (use bcrypt in production if you prefer)."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    return hmac.compare_digest(hash_password(password), hashed)


def get_client_ip() -> str:
    return (request.headers.get("X-Forwarded-For") or
            request.remote_addr or "unknown")


def is_plan_active(user: dict) -> bool:
    """Returns True if plan is free (no expiry) or expiry is in the future."""
    if user.get("plan") == "free":
        return True
    expiry = user.get("plan_expiry")
    if not expiry:
        return True
    if isinstance(expiry, str):
        expiry = datetime.datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    return expiry > datetime.datetime.now(datetime.timezone.utc)


def days_until_expiry(user: dict) -> Optional[int]:
    expiry = user.get("plan_expiry")
    if not expiry:
        return None
    if isinstance(expiry, str):
        expiry = datetime.datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    delta = expiry - datetime.datetime.now(datetime.timezone.utc)
    return delta.days


# ─────────────────────────────────────────────────────────────────────────────
# Auth middleware
# ─────────────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401
        # Load user from DB
        res = (supabase.table("users")
               .select("*").eq("id", user_id).single().execute())
        if not res.data:
            session.clear()
            return jsonify({"error": "User not found"}), 401
        g.user = res.data
        return f(*args, **kwargs)
    return decorated


def cron_auth_required(f):
    """Protect cron endpoint with API key header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-Cron-Key") or request.args.get("api_key")
        if not CRON_API_KEY or not hmac.compare_digest(key or "", CRON_API_KEY):
            return jsonify({"error": "Unauthorized"}), 403
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiter (IP-based, in-memory fallback + DB)
# ─────────────────────────────────────────────────────────────────────────────
_rate_cache: dict = {}   # ip -> {count, window_start}

def is_rate_limited(ip: str, limit: int = FREE_CHECKER_LIMIT) -> bool:
    now = datetime.datetime.utcnow()
    window_start_cutoff = now - datetime.timedelta(hours=1)

    entry = _rate_cache.get(ip)
    if entry and entry["window_start"] > window_start_cutoff:
        if entry["count"] >= limit:
            return True
        entry["count"] += 1
    else:
        _rate_cache[ip] = {"count": 1, "window_start": now}
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Static file routes (serve frontend)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/dashboard")
def dashboard():
    return send_from_directory(app.static_folder, "dashboard.html")

@app.route("/login")
def login_page():
    return send_from_directory(app.static_folder, "login.html")

@app.route("/signup")
def signup_page():
    return send_from_directory(app.static_folder, "signup.html")

@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)


# ─────────────────────────────────────────────────────────────────────────────
# Auth API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    full_name = (data.get("full_name") or "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    # Check if email already exists
    existing = (supabase.table("users")
                .select("id").eq("email", email).execute())
    if existing.data:
        return jsonify({"error": "Email already registered"}), 409

    new_user = {
        "id":            str(uuid.uuid4()),
        "email":         email,
        "full_name":     full_name,
        "password_hash": hash_password(password),
        "plan":          "free",
        "join_date":     datetime.datetime.utcnow().isoformat(),
    }
    res = supabase.table("users").insert(new_user).execute()
    if not res.data:
        return jsonify({"error": "Registration failed"}), 500

    session["user_id"] = new_user["id"]
    return jsonify({"message": "Account created", "user_id": new_user["id"]}), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    res = (supabase.table("users")
           .select("*").eq("email", email).single().execute())
    user = res.data
    if not user or not verify_password(password, user.get("password_hash", "")):
        return jsonify({"error": "Invalid email or password"}), 401

    # Update last_login
    supabase.table("users").update(
        {"last_login": datetime.datetime.utcnow().isoformat()}
    ).eq("id", user["id"]).execute()

    session["user_id"] = user["id"]
    return jsonify({
        "message":  "Logged in",
        "user_id":  user["id"],
        "email":    user["email"],
        "full_name": user.get("full_name"),
        "plan":     user.get("plan"),
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"message": "Logged out"})


# ─── FORGOT PASSWORD ENDPOINT (ADDED) ─────────────────────────────────────────
@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Email required"}), 400

    # Use fallback method because supabase-py version may be old
    try:
        import requests as req
        supabase_url = os.environ["SUPABASE_URL"]
        anon_key = os.environ["SUPABASE_KEY"]
        headers = {
            "apikey": anon_key,
            "Content-Type": "application/json"
        }
        body = {"email": email}
        resp = req.post(f"{supabase_url}/auth/v1/recover", json=body, headers=headers)
        if resp.status_code == 200:
            return jsonify({"message": "Reset email sent"}), 200
        else:
            return jsonify({"error": "Failed to send reset email"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/user", methods=["GET"])
@login_required
def api_user():
    user = g.user
    days_left = days_until_expiry(user)
    return jsonify({
        "id":         user["id"],
        "email":      user["email"],
        "full_name":  user.get("full_name"),
        "plan":       user.get("plan"),
        "plan_expiry": user.get("plan_expiry"),
        "days_left":  days_left,
        "plan_active": is_plan_active(user),
        "telegram_chat_id": user.get("telegram_chat_id"),
        "max_links":  PLAN_LIMITS.get(user.get("plan", "free"), 5),
    })


@app.route("/api/user/settings", methods=["PATCH"])
@login_required
def api_update_settings():
    data = request.get_json(silent=True) or {}
    allowed = {"full_name", "telegram_chat_id", "whatsapp_number"}
    update = {k: v for k, v in data.items() if k in allowed}
    if not update:
        return jsonify({"error": "No valid fields to update"}), 400
    supabase.table("users").update(update).eq("id", g.user["id"]).execute()
    return jsonify({"message": "Settings updated"})


# ─────────────────────────────────────────────────────────────────────────────
# Free single-check API (no login required)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/check-single", methods=["POST"])
def api_check_single():
    ip = get_client_ip()
    if is_rate_limited(ip, FREE_CHECKER_LIMIT):
        return jsonify({
            "error": f"Rate limit exceeded. Max {FREE_CHECKER_LIMIT} checks/hour."
        }), 429

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    platform = (data.get("platform") or "generic").strip().lower()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    result = check_link(url, platform)
    return jsonify({
        "url":           url,
        "status":        result["status"],
        "response_time": result.get("response_time"),
        "layer_used":    result.get("layer_used"),
        "error":         result.get("error"),
    })


# ─────────────────────────────────────────────────────────────────────────────
# Links API (protected)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/links", methods=["GET"])
@login_required
def api_get_links():
    res = (supabase.table("links")
           .select("*")
           .eq("user_id", g.user["id"])
           .eq("is_active", True)
           .order("created_at", desc=True)
           .execute())
    return jsonify(res.data or [])


@app.route("/api/links", methods=["POST"])
@login_required
def api_add_link():
    user = g.user

    # Plan limit check
    max_links = PLAN_LIMITS.get(user.get("plan", "free"), 5)
    existing = (supabase.table("links")
                .select("id", count="exact")
                .eq("user_id", user["id"])
                .eq("is_active", True)
                .execute())
    count = existing.count or len(existing.data or [])
    if count >= max_links:
        return jsonify({
            "error": f"Plan limit reached ({max_links} links). Upgrade to add more."
        }), 403

    # Plan active check
    if not is_plan_active(user) and user.get("plan") != "free":
        return jsonify({"error": "Your plan has expired. Please renew."}), 403

    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    name = (data.get("name") or url[:60]).strip()
    platform = (data.get("platform") or "generic").lower()
    frequency = (data.get("frequency") or "twice_daily")

    if not url:
        return jsonify({"error": "URL is required"}), 400

    new_link = {
        "id":        str(uuid.uuid4()),
        "user_id":   user["id"],
        "name":      name,
        "url":       url,
        "platform":  platform,
        "frequency": frequency,
        "status":    "pending",
        "is_active": True,
        "created_at": datetime.datetime.utcnow().isoformat(),
    }
    res = supabase.table("links").insert(new_link).execute()
    if not res.data:
        return jsonify({"error": "Failed to add link"}), 500
    return jsonify(res.data[0]), 201


@app.route("/api/links/<link_id>", methods=["DELETE"])
@login_required
def api_delete_link(link_id):
    # Soft delete
    supabase.table("links").update({"is_active": False}).eq(
        "id", link_id).eq("user_id", g.user["id"]).execute()
    return jsonify({"message": "Link removed"})


@app.route("/api/links/<link_id>/check", methods=["POST"])
@login_required
def api_check_link(link_id):
    res = (supabase.table("links")
           .select("*").eq("id", link_id)
           .eq("user_id", g.user["id"])
           .single().execute())
    link = res.data
    if not link:
        return jsonify({"error": "Link not found"}), 404

    result = check_link(link["url"], link.get("platform", "generic"))
    now = datetime.datetime.utcnow().isoformat()

    supabase.table("links").update({
        "status":       result["status"],
        "last_checked": now,
        "response_time": result.get("response_time"),
        "layer_used":   result.get("layer_used"),
        "error_message": result.get("error"),
    }).eq("id", link_id).execute()

    # Log to history
    supabase.table("check_history").insert({
        "id":            str(uuid.uuid4()),
        "link_id":       link_id,
        "user_id":       g.user["id"],
        "status":        result["status"],
        "response_time": result.get("response_time"),
        "layer_used":    result.get("layer_used"),
        "error_message": result.get("error"),
        "checked_at":    now,
    }).execute()

    return jsonify({
        "link_id":      link_id,
        "status":       result["status"],
        "response_time": result.get("response_time"),
        "layer_used":   result.get("layer_used"),
        "error":        result.get("error"),
    })


@app.route("/api/links/<link_id>/history", methods=["GET"])
@login_required
def api_link_history(link_id):
    res = (supabase.table("check_history")
           .select("*")
           .eq("link_id", link_id)
           .eq("user_id", g.user["id"])
           .order("checked_at", desc=True)
           .limit(50)
           .execute())
    return jsonify(res.data or [])


# ─────────────────────────────────────────────────────────────────────────────
# Cron endpoint (called by GitHub Actions)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/cron/daily-check", methods=["POST"])
@cron_auth_required
def api_cron_daily_check():
    """
    - Check all active links for active-plan users
    - Send alerts on status change
    - Send plan expiry warnings
    """
    logger.info("=== Cron: daily-check started ===")
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now_utc.isoformat()
    checked = 0
    alerts_sent = 0

    # ── 1. Check all active links ──────────────────────────────────────────
    links_res = (supabase.table("links")
                 .select("*, users(*)")
                 .eq("is_active", True)
                 .execute())
    all_links = links_res.data or []

    for link in all_links:
        user = link.get("users") or {}
        if not user:
            continue

        # Skip if plan expired
        if not is_plan_active(user) and user.get("plan") != "free":
            continue

        old_status = link.get("status", "pending")
        result = check_link(link["url"], link.get("platform", "generic"))
        new_status = result["status"]
        checked += 1

        update_data = {
            "status":       new_status,
            "last_checked": now_iso,
            "response_time": result.get("response_time"),
            "layer_used":   result.get("layer_used"),
            "error_message": result.get("error"),
        }

        # Detect status change
        status_changed = old_status != new_status
        if status_changed:
            update_data["last_status_change"] = now_iso
            update_data["alert_sent"] = False  # reset alert flag on new change

        # Send alert only once per change (alert_sent flag)
        should_alert = (
            new_status != "active" and
            not link.get("alert_sent", False) and
            status_changed
        )

        if should_alert:
            res = dispatch_alert(user, link, new_status,
                                 result.get("layer_used", ""),
                                 result.get("error"))
            if any(res.values()):
                update_data["alert_sent"] = True
                alerts_sent += 1
                # Log alert
                supabase.table("alerts").insert({
                    "id":         str(uuid.uuid4()),
                    "user_id":    user["id"],
                    "link_id":    link["id"],
                    "alert_type": new_status,
                    "channel":    "telegram",
                    "message":    f"Status changed to {new_status}",
                    "sent_at":    now_iso,
                    "success":    True,
                }).execute()

        supabase.table("links").update(update_data).eq("id", link["id"]).execute()

        # Log history
        supabase.table("check_history").insert({
            "id":            str(uuid.uuid4()),
            "link_id":       link["id"],
            "user_id":       user["id"],
            "status":        new_status,
            "response_time": result.get("response_time"),
            "layer_used":    result.get("layer_used"),
            "error_message": result.get("error"),
            "checked_at":    now_iso,
        }).execute()

    # ── 2. Plan expiry alerts ─────────────────────────────────────────────
    users_res = supabase.table("users").select("*").neq("plan", "free").execute()
    for user in (users_res.data or []):
        days_left = days_until_expiry(user)
        if days_left is None:
            continue
        # Alert at 7, 3, 1 days and on expiry day
        if days_left in (7, 3, 1, 0):
            msg = build_plan_expiry_message(
                user.get("full_name", ""), user.get("plan", ""),
                days_left
            )
            chat_id = user.get("telegram_chat_id")
            if chat_id:
                ok = send_telegram_message(chat_id, msg)
                if ok:
                    supabase.table("alerts").insert({
                        "id":         str(uuid.uuid4()),
                        "user_id":    user["id"],
                        "alert_type": "plan_expiry" if days_left > 0 else "plan_expired",
                        "channel":    "telegram",
                        "message":    msg,
                        "sent_at":    now_iso,
                        "success":    True,
                    }).execute()

    logger.info(f"=== Cron done: {checked} links checked, {alerts_sent} alerts sent ===")
    return jsonify({
        "message":      "Daily check complete",
        "links_checked": checked,
        "alerts_sent":  alerts_sent,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Health check
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "LinkGuardian Pro"})


# ─────────────────────────────────────────────────────────────────────────────
# Run
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)