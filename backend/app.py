"""
app.py – LinkGuardian Pro Flask Backend
Deploy target: Koyeb (free tier, 512 MB RAM)
Frontend:      Vercel (static)
Database:      Supabase (PostgreSQL)
"""

import os
import uuid
import random
import string
import hashlib
import hmac
import secrets
import datetime
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from typing import Optional

import bcrypt
from flask import Flask, request, jsonify, session, send_from_directory, g
from flask_cors import CORS
from dotenv import load_dotenv
from supabase import create_client, Client

from monitor import check_link
from alerts import dispatch_alert, build_plan_expiry_message, send_telegram_message

# ── Bootstrap ─────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Flask app ──────────────────────────────────────────────────────────────────
# Koyeb mein backend alag service hai; frontend Vercel pe hai.
# isliye static_folder yahan zaruri nahi — sirf API endpoints serve karenge.
# Agar kabhi same-origin pe serve karna ho toh "../frontend" rakh sakte ho.
app = Flask(__name__, static_folder="../frontend", static_url_path="")

_secret = os.environ.get("FLASK_SECRET_KEY")
if not _secret:
    raise RuntimeError("FLASK_SECRET_KEY env variable is not set!")
app.secret_key = _secret

# ── Session cookie hardening ───────────────────────────────────────────────────
_is_prod = os.getenv("FLASK_ENV", "production") != "development"
app.config.update(
    SESSION_COOKIE_HTTPONLY    = True,
    SESSION_COOKIE_SECURE      = _is_prod,        # HTTPS only in prod (Koyeb has HTTPS)
    SESSION_COOKIE_SAMESITE    = "None" if _is_prod else "Lax",
    # SameSite=None required when frontend (Vercel) and backend (Koyeb) are on
    # different origins — browsers block cross-site cookies otherwise.
    # Requires Secure=True (HTTPS), which Koyeb provides automatically.
    SESSION_COOKIE_NAME        = "lg_session",
    PERMANENT_SESSION_LIFETIME = datetime.timedelta(days=30),
)

# ── CORS ───────────────────────────────────────────────────────────────────────
# Frontend (Vercel) aur backend (Koyeb) alag domains hain.
# FRONTEND_URL must be set in Koyeb env vars, e.g. https://linkguardian.vercel.app
_frontend_url = os.getenv("FRONTEND_URL", "").rstrip("/")
if _is_prod and not _frontend_url:
    logger.warning("FRONTEND_URL not set – CORS will block all cross-origin requests!")

_cors_origins = [_frontend_url] if _frontend_url else (["*"] if not _is_prod else [])
CORS(
    app,
    supports_credentials=True,
    origins=_cors_origins,
    allow_headers=["Content-Type", "X-Cron-Key"],
    methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
)

# ── Supabase ───────────────────────────────────────────────────────────────────
supabase: Client = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_SERVICE_KEY"],   # service role key – never expose to frontend
)

# ── Plan limits ────────────────────────────────────────────────────────────────
FREE_PLANS = {"free", "hobby"}   # plans that never expire

PLAN_LIMITS: dict[str, int] = {
    "free":     5,
    "hobby":    5,
    "pro_lite": 20,
    "popular":  30,
    "business": 100,
    # legacy names kept for backward compat
    "pro":      20,
    "agency":   500,
}

PLAN_HISTORY_DAYS: dict[str, int] = {
    "free":     7,
    "hobby":    7,
    "pro_lite": 90,
    "popular":  90,
    "business": 90,
    "pro":      90,
    "agency":   90,
}

FREE_CHECKER_LIMIT = int(os.getenv("FREE_CHECKER_LIMIT", "10"))
CRON_API_KEY       = os.getenv("CRON_API_KEY", "")


# ─────────────────────────────────────────────────────────────────────────────
# Email (password reset)
# ─────────────────────────────────────────────────────────────────────────────

def send_email(to_email: str, subject: str, html_body: str) -> bool:
    smtp_host  = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port  = int(os.getenv("SMTP_PORT", "587"))
    smtp_user  = os.getenv("SMTP_USER", "")
    smtp_pass  = os.getenv("SMTP_PASS", "")
    from_email = os.getenv("FROM_EMAIL", smtp_user)

    if not smtp_user or not smtp_pass:
        logger.warning("SMTP credentials not set — password-reset email skipped")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = from_email
    msg["To"]      = to_email
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(smtp_user, smtp_pass)
            srv.sendmail(from_email, to_email, msg.as_string())
        return True
    except Exception as exc:
        logger.error(f"Email send failed: {exc}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────────────────────

def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def verify_password(pw: str, stored: str) -> bool:
    """Supports bcrypt (new) and legacy SHA-256 (old users, auto-upgraded on login)."""
    if stored.startswith(("$2b$", "$2a$")):
        return bcrypt.checkpw(pw.encode(), stored.encode())
    return hmac.compare_digest(
        hashlib.sha256(pw.encode()).hexdigest(), stored
    )


def get_client_ip() -> str:
    """
    Return real client IP.
    X-Forwarded-For: client, proxy1, proxy2  — Koyeb/Vercel append on the RIGHT.
    Take the RIGHTMOST entry to prevent client spoofing.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[-1].strip()
    return request.remote_addr or "unknown"


def is_plan_active(user: dict) -> bool:
    if user.get("plan") in FREE_PLANS:
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
    return (expiry - datetime.datetime.now(datetime.timezone.utc)).days


def _make_referral_code(base_name: str) -> str:
    """Generate a unique referral code with collision retry."""
    base = (base_name or "USER").replace(" ", "").upper()[:8]
    for _ in range(8):
        candidate = base + "".join(random.choices(string.digits, k=4))
        res = supabase.table("users").select("id") \
              .eq("referral_code", candidate).execute()
        if not res.data:
            return candidate
    # Extreme fallback (virtually impossible to reach)
    return base + "".join(random.choices(string.digits, k=6))


# ─────────────────────────────────────────────────────────────────────────────
# Auth decorators
# ─────────────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "Authentication required"}), 401
        res = supabase.table("users").select("*").eq("id", user_id).single().execute()
        if not res.data:
            session.clear()
            return jsonify({"error": "User not found"}), 401
        g.user = res.data
        return f(*args, **kwargs)
    return decorated


def cron_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-Cron-Key") or request.args.get("api_key", "")
        if not CRON_API_KEY or not hmac.compare_digest(key, CRON_API_KEY):
            return jsonify({"error": "Unauthorized"}), 403
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────────────────────
# Rate limiter (in-memory, per-worker)
# Koyeb free tier = 1 gunicorn worker, so in-memory is sufficient.
# ─────────────────────────────────────────────────────────────────────────────
_rate_cache: dict = {}


def is_rate_limited(ip: str, limit: int = FREE_CHECKER_LIMIT) -> bool:
    now     = datetime.datetime.utcnow()
    cutoff  = now - datetime.timedelta(hours=1)
    entry   = _rate_cache.get(ip)
    if entry and entry["window_start"] > cutoff:
        if entry["count"] >= limit:
            return True
        entry["count"] += 1
    else:
        _rate_cache[ip] = {"count": 1, "window_start": now}
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Static file serving
# NOTE: In production, frontend is on Vercel — Flask only serves API.
# These routes are kept for local development convenience.
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

@app.route("/forgot-password")
def forgot_password_page():
    return send_from_directory(app.static_folder, "forgot-password.html")

@app.route("/reset-password")
def reset_password_page():
    return send_from_directory(app.static_folder, "reset-password.html")

@app.route("/<path:filename>")
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)


# ─────────────────────────────────────────────────────────────────────────────
# Auth API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/signup", methods=["POST"])
def api_signup():
    data      = request.get_json(silent=True) or {}
    email     = (data.get("email") or "").strip().lower()
    password  = data.get("password") or ""
    full_name = (data.get("full_name") or "").strip()
    ref_code  = (data.get("referral_code") or "").strip().upper()

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    existing = supabase.table("users").select("id").eq("email", email).execute()
    if existing.data:
        return jsonify({"error": "Email already registered"}), 409

    # Referral resolution
    referred_by_id = None
    if ref_code:
        ref_res = supabase.table("users").select("id") \
                  .eq("referral_code", ref_code).execute()
        if ref_res.data:
            referred_by_id = ref_res.data[0]["id"]

    new_user = {
        "id":                   str(uuid.uuid4()),
        "email":                email,
        "full_name":            full_name,
        "password_hash":        hash_password(password),
        "plan":                 "free",
        "join_date":            datetime.datetime.utcnow().isoformat(),
        "referral_code":        _make_referral_code(full_name or email.split("@")[0]),
        "referred_by":          referred_by_id,
        "total_referrals":      0,
        "free_months_earned":   0,
        "free_months_remaining": 0,
    }
    res = supabase.table("users").insert(new_user).execute()
    if not res.data:
        return jsonify({"error": "Registration failed"}), 500

    session.permanent = True
    session["user_id"] = new_user["id"]
    return jsonify({"message": "Account created", "user_id": new_user["id"]}), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    data     = request.get_json(silent=True) or {}
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    try:
        res = supabase.table("users").select("*").eq("email", email).single().execute()
        user = res.data
    except Exception:
        user = None

    if not user or not verify_password(password, user.get("password_hash", "")):
        return jsonify({"error": "Invalid email or password"}), 401

    # Auto-upgrade legacy SHA-256 → bcrypt
    stored = user.get("password_hash", "")
    if not stored.startswith(("$2b$", "$2a$")):
        supabase.table("users").update(
            {"password_hash": hash_password(password)}
        ).eq("id", user["id"]).execute()
        logger.info(f"Upgraded password hash for user {user['id']}")

    supabase.table("users").update(
        {"last_login": datetime.datetime.utcnow().isoformat()}
    ).eq("id", user["id"]).execute()

    session.permanent = True
    session["user_id"] = user["id"]
    return jsonify({
        "message":   "Logged in",
        "user_id":   user["id"],
        "email":     user["email"],
        "full_name": user.get("full_name"),
        "plan":      user.get("plan"),
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"message": "Logged out"})


@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Email required"}), 400

    ok_msg = {"message": "If that email is registered, a reset link has been sent."}
    try:
        res = supabase.table("users").select("id, full_name") \
              .eq("email", email).execute()
        if not res.data:
            return jsonify(ok_msg), 200

        user        = res.data[0]
        raw_token   = secrets.token_urlsafe(32)
        token_hash  = hashlib.sha256(raw_token.encode()).hexdigest()
        expiry      = (datetime.datetime.now(datetime.timezone.utc)
                       + datetime.timedelta(hours=1)).isoformat()

        supabase.table("users").update({
            "reset_token":        token_hash,
            "reset_token_expiry": expiry,
        }).eq("id", user["id"]).execute()

        frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5000")
        reset_link   = f"{frontend_url}/reset-password?token={raw_token}"
        name         = user.get("full_name") or "there"

        html_body = f"""
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;">
          <h2 style="color:#00E5FF;">LinkGuardian Pro</h2>
          <p>Hi {name},</p>
          <p>We received a password reset request for your account.</p>
          <p>
            <a href="{reset_link}"
               style="background:#00E5FF;color:#000;padding:12px 24px;
                      border-radius:8px;text-decoration:none;font-weight:700;
                      display:inline-block;">
              Reset My Password
            </a>
          </p>
          <p style="color:#666;font-size:0.85rem;">
            This link expires in <strong>1 hour</strong>.<br>
            If you did not request this, you can safely ignore this email.
          </p>
          <p style="color:#999;font-size:0.8rem;">Or copy: {reset_link}</p>
        </div>
        """
        send_email(email, "Reset your LinkGuardian Pro password", html_body)
        return jsonify(ok_msg), 200

    except Exception as exc:
        logger.error(f"forgot-password error: {exc}")
        return jsonify(ok_msg), 200


@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    data         = request.get_json(silent=True) or {}
    raw_token    = (data.get("token") or "").strip()
    new_password = data.get("password") or ""

    if not raw_token or not new_password:
        return jsonify({"error": "Token and new password are required"}), 400
    if len(new_password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    try:
        res = supabase.table("users").select("id, reset_token_expiry") \
              .eq("reset_token", token_hash).execute()
        if not res.data:
            return jsonify({"error": "Invalid or expired reset link"}), 400

        user       = res.data[0]
        expiry_str = user.get("reset_token_expiry")
        if not expiry_str:
            return jsonify({"error": "Invalid or expired reset link"}), 400

        expiry = datetime.datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
        if expiry < datetime.datetime.now(datetime.timezone.utc):
            return jsonify({"error": "Reset link has expired. Please request a new one."}), 400

        supabase.table("users").update({
            "password_hash":      hash_password(new_password),
            "reset_token":        None,
            "reset_token_expiry": None,
        }).eq("id", user["id"]).execute()

        return jsonify({"message": "Password reset successful. You can now log in."}), 200

    except Exception as exc:
        logger.error(f"reset-password error: {exc}")
        return jsonify({"error": "Something went wrong. Please try again."}), 500


@app.route("/api/user", methods=["GET"])
@login_required
def api_user():
    user         = g.user
    days_left    = days_until_expiry(user)
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5000")
    ref_code     = user.get("referral_code") or ""
    return jsonify({
        "id":                   user["id"],
        "email":                user["email"],
        "full_name":            user.get("full_name"),
        "plan":                 user.get("plan"),
        "plan_expiry":          user.get("plan_expiry"),
        "days_left":            days_left,
        "plan_active":          is_plan_active(user),
        "telegram_chat_id":     user.get("telegram_chat_id"),
        "max_links":            PLAN_LIMITS.get(user.get("plan", "free"), 5),
        "referral_code":        ref_code,
        "referral_link":        f"{frontend_url}/signup?ref={ref_code}" if ref_code else "",
        "total_referrals":      user.get("total_referrals", 0),
        "free_months_earned":   user.get("free_months_earned", 0),
        "free_months_remaining": user.get("free_months_remaining", 0),
    })


@app.route("/api/user/settings", methods=["PATCH"])
@login_required
def api_update_settings():
    data    = request.get_json(silent=True) or {}
    allowed = {"full_name", "telegram_chat_id", "whatsapp_number"}
    update  = {k: v for k, v in data.items() if k in allowed}
    if not update:
        return jsonify({"error": "No valid fields to update"}), 400
    supabase.table("users").update(update).eq("id", g.user["id"]).execute()
    return jsonify({"message": "Settings updated"})


# ─────────────────────────────────────────────────────────────────────────────
# Free single-check (public, rate-limited)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/check-single", methods=["POST"])
def api_check_single():
    ip = get_client_ip()
    if is_rate_limited(ip, FREE_CHECKER_LIMIT):
        return jsonify({
            "error": f"Rate limit exceeded. Max {FREE_CHECKER_LIMIT} checks/hour."
        }), 429

    data     = request.get_json(silent=True) or {}
    url      = (data.get("url") or "").strip()
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
    res = supabase.table("links") \
        .select("*") \
        .eq("user_id", g.user["id"]) \
        .eq("is_active", True) \
        .order("created_at", desc=True) \
        .execute()
    return jsonify(res.data or [])


@app.route("/api/links", methods=["POST"])
@login_required
def api_add_link():
    user = g.user

    # Plan limit check
    max_links = PLAN_LIMITS.get(user.get("plan", "free"), 5)
    existing  = supabase.table("links") \
        .select("id", count="exact") \
        .eq("user_id", user["id"]) \
        .eq("is_active", True) \
        .execute()
    count = existing.count or len(existing.data or [])
    if count >= max_links:
        return jsonify({
            "error": f"Plan limit reached ({max_links} links). Upgrade to add more."
        }), 403

    # Plan active check (free/hobby never expire)
    if user.get("plan") not in FREE_PLANS and not is_plan_active(user):
        return jsonify({"error": "Your plan has expired. Please renew."}), 403

    data      = request.get_json(silent=True) or {}
    url       = (data.get("url") or "").strip()
    name      = (data.get("name") or url[:60]).strip()
    platform  = (data.get("platform") or "generic").lower()
    frequency = data.get("frequency") or "twice_daily"

    if not url:
        return jsonify({"error": "URL is required"}), 400

    new_link = {
        "id":         str(uuid.uuid4()),
        "user_id":    user["id"],
        "name":       name,
        "url":        url,
        "platform":   platform,
        "frequency":  frequency,
        "status":     "pending",
        "is_active":  True,
        "created_at": datetime.datetime.utcnow().isoformat(),
    }
    res = supabase.table("links").insert(new_link).execute()
    if not res.data:
        return jsonify({"error": "Failed to add link"}), 500
    return jsonify(res.data[0]), 201


@app.route("/api/links/<link_id>", methods=["DELETE"])
@login_required
def api_delete_link(link_id):
    supabase.table("links").update({"is_active": False}) \
        .eq("id", link_id).eq("user_id", g.user["id"]).execute()
    return jsonify({"message": "Link removed"})


@app.route("/api/links/<link_id>/check", methods=["POST"])
@login_required
def api_check_link(link_id):
    try:
        res = supabase.table("links").select("*") \
              .eq("id", link_id).eq("user_id", g.user["id"]).single().execute()
        link = res.data
    except Exception:
        link = None
    if not link:
        return jsonify({"error": "Link not found"}), 404

    result = check_link(link["url"], link.get("platform", "generic"))
    now    = datetime.datetime.utcnow().isoformat()

    supabase.table("links").update({
        "status":        result["status"],
        "last_checked":  now,
        "response_time": result.get("response_time"),
        "layer_used":    result.get("layer_used"),
        "error_message": result.get("error"),
    }).eq("id", link_id).execute()

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
        "link_id":       link_id,
        "status":        result["status"],
        "response_time": result.get("response_time"),
        "layer_used":    result.get("layer_used"),
        "error":         result.get("error"),
    })


@app.route("/api/links/<link_id>/history", methods=["GET"])
@login_required
def api_link_history(link_id):
    res = supabase.table("check_history") \
        .select("*") \
        .eq("link_id", link_id) \
        .eq("user_id", g.user["id"]) \
        .order("checked_at", desc=True) \
        .limit(50) \
        .execute()
    return jsonify(res.data or [])


# ─────────────────────────────────────────────────────────────────────────────
# Cron endpoint – called by cron-job.org (free external cron)
# Schedule: every hour  →  https://your-app.koyeb.app/api/cron/daily-check
# Header:   X-Cron-Key: <CRON_API_KEY>
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/cron/daily-check", methods=["POST"])
@cron_auth_required
def api_cron_daily_check():
    logger.info("=== Cron: daily-check started ===")
    now_utc     = datetime.datetime.now(datetime.timezone.utc)
    now_iso     = now_utc.isoformat()
    current_hr  = now_utc.hour
    checked     = 0
    alerts_sent = 0

    def should_run(frequency: str) -> bool:
        """Decide if this link should be checked at the current hour."""
        f = (frequency or "twice_daily").lower()
        if f == "hourly":
            return True
        if f == "two_hourly":
            return current_hr % 2 == 0
        if f == "six_hourly":
            return current_hr % 6 == 0
        # twice_daily / daily / default: 6 AM and 6 PM UTC
        return current_hr in (6, 18)

    # ── Fetch all active links with their owner ───────────────────────────
    links_res = supabase.table("links") \
        .select("*, users(*)") \
        .eq("is_active", True) \
        .execute()
    all_links = links_res.data or []

    for link in all_links:
        user = link.get("users") or {}
        if not user:
            continue

        # Skip expired paid plans
        if user.get("plan") not in FREE_PLANS and not is_plan_active(user):
            continue

        # Respect frequency
        if not should_run(link.get("frequency", "twice_daily")):
            continue

        old_status = link.get("status", "pending")
        result     = check_link(link["url"], link.get("platform", "generic"))
        new_status = result["status"]
        checked   += 1

        update_data = {
            "status":        new_status,
            "last_checked":  now_iso,
            "response_time": result.get("response_time"),
            "layer_used":    result.get("layer_used"),
            "error_message": result.get("error"),
        }

        status_changed = old_status != new_status
        if status_changed:
            update_data["last_status_change"] = now_iso
            update_data["alert_sent"] = False

        should_alert = (
            new_status != "active"
            and not link.get("alert_sent", False)
            and status_changed
        )
        if should_alert:
            res = dispatch_alert(user, link, new_status,
                                 result.get("layer_used", ""),
                                 result.get("error"))
            if any(res.values()):
                update_data["alert_sent"] = True
                alerts_sent += 1
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

    # ── Plan expiry alerts ─────────────────────────────────────────────────
    paid_users_res = supabase.table("users").select("*") \
        .not_.in_("plan", list(FREE_PLANS)).execute()
    for u in (paid_users_res.data or []):
        dl = days_until_expiry(u)
        if dl is None:
            continue
        if dl in (7, 3, 1, 0):
            msg     = build_plan_expiry_message(u.get("full_name", ""), u.get("plan", ""), dl)
            chat_id = u.get("telegram_chat_id")
            if chat_id:
                ok = send_telegram_message(chat_id, msg)
                if ok:
                    supabase.table("alerts").insert({
                        "id":         str(uuid.uuid4()),
                        "user_id":    u["id"],
                        "link_id":    None,
                        "alert_type": "plan_expiry" if dl > 0 else "plan_expired",
                        "channel":    "telegram",
                        "message":    msg,
                        "sent_at":    now_iso,
                        "success":    True,
                    }).execute()

    # ── Auto-cleanup: delete check_history older than 90 days ─────────────
    cutoff_90 = (now_utc - datetime.timedelta(days=90)).isoformat()
    try:
        supabase.table("check_history").delete() \
            .lt("checked_at", cutoff_90).execute()
        logger.info("Cleaned check_history older than 90 days")
    except Exception as exc:
        logger.warning(f"History cleanup failed: {exc}")

    logger.info(f"=== Cron done: checked={checked}, alerts={alerts_sent} ===")
    return jsonify({
        "message":       "Daily check complete",
        "links_checked": checked,
        "alerts_sent":   alerts_sent,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Feedback API (public)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/feedback", methods=["POST"])
def api_submit_feedback():
    data    = request.get_json(silent=True) or {}
    name    = (data.get("name") or "").strip()[:100]
    email   = (data.get("email") or "").strip().lower()[:200]
    message = (data.get("message") or "").strip()
    rating  = data.get("rating")

    if not message:
        return jsonify({"error": "Message is required"}), 400
    if rating is not None:
        try:
            rating = int(rating)
            if not 1 <= rating <= 5:
                return jsonify({"error": "Rating must be 1–5"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid rating"}), 400

    supabase.table("feedback").insert({
        "id":         str(uuid.uuid4()),
        "name":       name or None,
        "email":      email or None,
        "message":    message,
        "rating":     rating,
        "created_at": datetime.datetime.utcnow().isoformat(),
    }).execute()
    return jsonify({"message": "Thank you for your feedback!"}), 201


# ─────────────────────────────────────────────────────────────────────────────
# Referral API
# ─────────────────────────────────────────────────────────────────────────────

def _apply_referral_reward(referrer_id: str) -> None:
    """Called when a referred user subscribes to a paid plan."""
    try:
        res = supabase.table("users").select("*") \
              .eq("id", referrer_id).single().execute()
        if not res.data:
            return
    except Exception:
        return

    referrer  = res.data
    total     = (referrer.get("total_referrals") or 0) + 1
    earned    = referrer.get("free_months_earned") or 0
    remaining = referrer.get("free_months_remaining") or 0

    new_earned = total // 5          # 1 month per 5 paid referrals
    new_months = new_earned - earned
    if new_months > 0:
        earned    += new_months
        remaining += new_months
        now_utc    = datetime.datetime.now(datetime.timezone.utc)
        expiry     = referrer.get("plan_expiry")
        if expiry:
            if isinstance(expiry, str):
                expiry = datetime.datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            base = max(expiry, now_utc)
        else:
            base = now_utc
        new_expiry = (base + datetime.timedelta(days=30 * new_months)).isoformat()
        update = {
            "total_referrals":       total,
            "free_months_earned":    earned,
            "free_months_remaining": remaining,
            "plan_expiry":           new_expiry,
            "plan": "popular" if referrer.get("plan") in FREE_PLANS else referrer.get("plan"),
        }
        logger.info(f"Referral reward: {referrer_id} +{new_months} month(s)")
    else:
        update = {"total_referrals": total}

    supabase.table("users").update(update).eq("id", referrer_id).execute()


@app.route("/api/referral/stats", methods=["GET"])
@login_required
def api_referral_stats():
    user         = g.user
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5000")
    ref_code     = user.get("referral_code") or ""
    return jsonify({
        "referral_code":         ref_code,
        "referral_link":         f"{frontend_url}/signup?ref={ref_code}",
        "total_referrals":       user.get("total_referrals", 0),
        "free_months_earned":    user.get("free_months_earned", 0),
        "free_months_remaining": user.get("free_months_remaining", 0),
    })


@app.route("/api/admin/referral/trigger", methods=["POST"])
def api_admin_trigger_referral():
    """Manual test: simulate a paid referral. Protected by ADMIN_SECRET."""
    data         = request.get_json(silent=True) or {}
    admin_secret = os.getenv("ADMIN_SECRET", "")
    if not admin_secret or data.get("admin_secret") != admin_secret:
        return jsonify({"error": "Unauthorized"}), 403
    referrer_id = (data.get("referrer_id") or "").strip()
    if not referrer_id:
        return jsonify({"error": "referrer_id required"}), 400
    _apply_referral_reward(referrer_id)
    return jsonify({"message": f"Referral reward applied for {referrer_id}"}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Health check  (Koyeb uses this for uptime monitoring)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "LinkGuardian Pro"}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Entry point (local dev only; Koyeb uses gunicorn via Procfile)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port  = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
