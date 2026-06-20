"""
app.py – AffiGuard Flask Backend
Deploy target: Render (free tier, 512 MB RAM)
Frontend:      Vercel (static)
Database:      Supabase (PostgreSQL)
"""

import os
import uuid
import random
import string
import hashlib
import hmac
import html
import secrets
import datetime
import logging
import smtplib
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from functools import wraps
from typing import Optional

import bcrypt
from flask import Flask, request, jsonify, session, send_from_directory, g
from flask_cors import CORS
from dotenv import load_dotenv
from supabase import create_client, Client

from monitor import check_link, is_safe_url, check_tag_guard, crawl_affiliate_links
from alerts import dispatch_alert, build_plan_expiry_message, send_telegram_message

# ── Bootstrap ─────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── Flask app ──────────────────────────────────────────────────────────────────
# Render mein backend alag service hai; frontend Vercel pe hai.
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
    SESSION_COOKIE_SECURE      = _is_prod,        # HTTPS only in prod (Render has HTTPS)
    SESSION_COOKIE_SAMESITE    = "None" if _is_prod else "Lax",
    # SameSite=None required when frontend (Vercel) and backend (Render) are on
    # different origins — browsers block cross-site cookies otherwise.
    # Requires Secure=True (HTTPS), which Render provides automatically.
    SESSION_COOKIE_NAME        = "lg_session",
    PERMANENT_SESSION_LIFETIME = datetime.timedelta(days=30),
)

# ── CORS ───────────────────────────────────────────────────────────────────────
# Frontend (Vercel) aur backend (Render) alag domains hain.
# FRONTEND_URL must be set in Render env vars, e.g. https://affiguard.vercel.app
_frontend_url = os.getenv("FRONTEND_URL", "").rstrip("/")
if _is_prod and not _frontend_url:
    logger.warning("FRONTEND_URL not set – CORS will block all cross-origin requests!")

_cors_origins = [_frontend_url] if _frontend_url else (["*"] if not _is_prod else [])
CORS(
    app,
    supports_credentials=True,
    origins=_cors_origins,
    allow_headers=["Content-Type", "X-Cron-Key", "X-Admin-Secret"],
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
    X-Forwarded-For: client, proxy1, proxy2
    Render puts the real client IP as the LEFTMOST entry.
    Take index [0] — do NOT use [-1] (that would be Render's internal proxy IP,
    which would break rate limiting: either everyone gets blocked or no one does).
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
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
# ── Rate limiter (Supabase-backed, survives restarts) ─────────────────────────
# MIN-03 FIX: Replaced in-memory dict with Supabase rate_limits table.
# In-memory cache reset on every Render deploy, letting abusers bypass the limit.
# Supabase persists across restarts. Falls back to in-memory if DB call fails
# so a Supabase blip never breaks the free checker entirely.
# ─────────────────────────────────────────────────────────────────────────────
_rate_cache_fallback: dict = {}  # fallback only — used when Supabase unreachable


def is_rate_limited(ip: str, limit: int = FREE_CHECKER_LIMIT) -> bool:
    """
    Returns True if this IP has exceeded `limit` requests in the last hour.
    Uses Supabase atomic increment_rate_limit RPC. Falls back to in-memory on error.
    """
    try:
        res = supabase.rpc("increment_rate_limit", {"ip": ip, "limit_hour": limit}).execute()
        return bool(res.data)
    except Exception as exc:
        logger.warning(f"Rate limit RPC failed, using fallback: {exc}")
        now    = datetime.datetime.now(datetime.timezone.utc)
        cutoff = now - datetime.timedelta(hours=1)
        entry  = _rate_cache_fallback.get(ip)
        if entry and entry["window_start"] > cutoff:
            if entry["count"] >= limit:
                return True
            entry["count"] += 1
        else:
            _rate_cache_fallback[ip] = {"count": 1, "window_start": now}
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
        "join_date":            datetime.datetime.now(datetime.timezone.utc).isoformat(),
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
        {"last_login": datetime.datetime.now(datetime.timezone.utc).isoformat()}
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
        name         = html.escape(user.get("full_name") or "there")

        html_body = f"""
        <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;">
          <h2 style="color:#00E5FF;">AffiGuard</h2>
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
        send_email(email, "Reset your AffiGuard password", html_body)
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

    safe, reason = is_safe_url(url)
    if not safe:
        return jsonify({"error": f"Invalid URL: {reason}"}), 400

    result = check_link(url, platform)
    return jsonify({
        "url":           url,
        "status":        result["status"],
        "response_time": result.get("response_time"),
        "layer_used":    result.get("layer_used"),
        "error":         result.get("error"),
    })


# ── Tag Guard ─────────────────────────────────────────────────────────────────

@app.route("/api/tag-guard", methods=["POST"])
@login_required
def api_tag_guard():
    user = g.user
    data = request.get_json(silent=True) or {}

    if data.get("check_all"):
        links_res = supabase.table("links") \
            .select("id, url, name, platform") \
            .eq("user_id", user["id"]).eq("is_active", True).execute()
        results = []
        for link in (links_res.data or []):
            safe, _ = is_safe_url(link["url"])
            if not safe: continue
            tg = check_tag_guard(link["url"], link.get("platform", "generic"))
            results.append({"link_id": link["id"], "link_name": link["name"],
                "url": link["url"], "platform": link.get("platform"),
                "tag_present": tg["tag_present"], "tag_found": tg["tag_found"],
                "final_url": tg["final_url"], "error": tg["error"]})
        warnings = [r for r in results if r["tag_present"] is False]
        return jsonify({"results": results, "total_checked": len(results),
            "warnings": len(warnings),
            "message": f"⚠️ {len(warnings)} link(s) have missing affiliate tags!"
                       if warnings else "✅ All affiliate tags are present."}), 200

    url      = (data.get("url") or "").strip()
    platform = (data.get("platform") or "generic").strip().lower()
    if not url: return jsonify({"error": "URL is required"}), 400
    safe, reason = is_safe_url(url)
    if not safe: return jsonify({"error": f"Invalid URL: {reason}"}), 400
    return jsonify(check_tag_guard(url, platform)), 200


# ── Smart Auto-Crawl ──────────────────────────────────────────────────────────

@app.route("/api/crawl-links", methods=["POST"])
@login_required
def api_crawl_links():
    user = g.user
    data = request.get_json(silent=True) or {}
    page_url = (data.get("page_url") or "").strip()
    if not page_url: return jsonify({"error": "page_url is required"}), 400
    safe, reason = is_safe_url(page_url)
    if not safe: return jsonify({"error": f"Invalid URL: {reason}"}), 400

    crawl_result = crawl_affiliate_links(page_url, max_links=200)
    if crawl_result["error"] and not crawl_result["found"]:
        return jsonify({"error": crawl_result["error"]}), 400

    existing_res  = supabase.table("links").select("url").eq("user_id", user["id"]).execute()
    existing_urls = {r["url"] for r in (existing_res.data or [])}
    for item in crawl_result["found"]:
        item["already_added"] = item["url"] in existing_urls

    return jsonify({
        "found":         crawl_result["found"],
        "total_on_page": crawl_result["total_on_page"],
        "already_added": [r["url"] for r in crawl_result["found"] if r["already_added"]],
        "page_url":      page_url,
        "error":         crawl_result["error"],
    }), 200


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

    safe, reason = is_safe_url(url)
    if not safe:
        return jsonify({"error": f"Invalid URL: {reason}"}), 400

    new_link = {
        "id":         str(uuid.uuid4()),
        "user_id":    user["id"],
        "name":       name,
        "url":        url,
        "platform":   platform,
        "frequency":  frequency,
        "status":     "pending",
        "is_active":  True,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
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
    now    = datetime.datetime.now(datetime.timezone.utc).isoformat()

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
# Schedule: every hour  →  https://your-app.onrender.com/api/cron/daily-check
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

    # Filter to only links that should run this hour
    due_links = []
    for link in all_links:
        user = link.get("users") or {}
        if not user:
            continue
        if user.get("plan") not in FREE_PLANS and not is_plan_active(user):
            continue
        if not should_run(link.get("frequency", "twice_daily")):
            continue
        due_links.append(link)

    def _process_link(link: dict) -> dict:
        """Check one link and return update payload. Thread-safe — no shared state."""
        user       = link.get("users") or {}
        old_status = link.get("status", "pending")
        result     = check_link(link["url"], link.get("platform", "generic"))
        return {
            "link":       link,
            "user":       user,
            "old_status": old_status,
            "result":     result,
        }

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_process_link, lnk): lnk for lnk in due_links}
        for future in as_completed(futures):
            try:
                payload    = future.result()
            except Exception as exc:
                logger.error(f"Link check thread error: {exc}")
                continue

            link       = payload["link"]
            user       = payload["user"]
            old_status = payload["old_status"]
            result     = payload["result"]
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
            # Dedup: skip if a plan_expiry alert was already sent today
            today_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
            existing_alert = supabase.table("alerts") \
                .select("id") \
                .eq("user_id", u["id"]) \
                .in_("alert_type", ["plan_expiry", "plan_expired"]) \
                .gte("sent_at", today_start) \
                .execute()
            if existing_alert.data:
                continue
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
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }).execute()
    return jsonify({"message": "Thank you for your feedback!"}), 201


# ─────────────────────────────────────────────────────────────────────────────
# Referral API
# ─────────────────────────────────────────────────────────────────────────────

def _apply_referral_reward(referrer_id: str) -> None:
    """Called when a referred user subscribes to a paid plan. Uses atomic DB function."""
    try:
        supabase.rpc("increment_referral_and_award", {"user_id": referrer_id}).execute()
        logger.info(f"Referral reward applied atomically for {referrer_id}")
    except Exception as exc:
        logger.error(f"_apply_referral_reward RPC failed for {referrer_id}: {exc}")


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


@app.route("/api/user/redeem-coupon", methods=["POST"])
@login_required
def api_redeem_coupon():
    """
    User redeems a coupon code from dashboard.
    Body: { "code": "SUMMER50" }
    """
    user = g.user
    data = request.get_json(silent=True) or {}
    code = (data.get("code") or "").strip().upper()

    if not code:
        return jsonify({"error": "Coupon code is required"}), 400

    now_utc = datetime.datetime.now(datetime.timezone.utc)

    # Fetch coupon
    try:
        res = supabase.table("coupons").select("*").eq("code", code).eq("is_active", True).single().execute()
    except Exception:
        return jsonify({"error": "Invalid or expired coupon code"}), 400

    coupon = res.data
    if not coupon:
        return jsonify({"error": "Invalid or expired coupon code"}), 400

    # Check expiry
    if coupon.get("expires_at"):
        try:
            exp = datetime.datetime.fromisoformat(coupon["expires_at"].replace("Z", "+00:00"))
            if now_utc > exp:
                return jsonify({"error": "This coupon has expired"}), 400
        except Exception:
            pass

    # Check max uses
    if coupon.get("max_uses") is not None and coupon.get("uses", 0) >= coupon["max_uses"]:
        return jsonify({"error": "This coupon has reached its usage limit"}), 400

    # Apply coupon
    update: dict = {}
    coupon_type = coupon.get("type", "free_months")
    value       = coupon.get("value", 1)
    msg         = ""

    if coupon_type == "free_months":
        # Extend plan expiry
        expiry = user.get("plan_expiry")
        if expiry:
            try:
                base = datetime.datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                base = max(base, now_utc)
            except Exception:
                base = now_utc
        else:
            base = now_utc
        update["plan_expiry"] = (base + datetime.timedelta(days=30 * value)).isoformat()
        if user.get("plan") in FREE_PLANS:
            update["plan"] = coupon.get("plan_grant") or "popular"
        msg = f"{value} free month(s) added to your plan!"

    elif coupon_type == "plan_upgrade":
        plan_grant = coupon.get("plan_grant") or "popular"
        update["plan"] = plan_grant
        if not user.get("plan_expiry") or user.get("plan") in FREE_PLANS:
            update["plan_expiry"] = (now_utc + datetime.timedelta(days=30)).isoformat()
        msg = f"Plan upgraded to {plan_grant.title()}!"

    elif coupon_type == "percent_off":
        # Percent-off coupons are informational only (applied at payment time)
        # For now just acknowledge — payment integration handles the discount
        msg = f"{value}% discount coupon noted. Apply at checkout."

    # Save user update
    if update:
        supabase.table("users").update(update).eq("id", user["id"]).execute()

    # Increment coupon uses
    supabase.table("coupons").update({"uses": (coupon.get("uses") or 0) + 1}) \
            .eq("id", coupon["id"]).execute()

    # Deactivate if single-use
    if coupon.get("max_uses") == 1:
        supabase.table("coupons").update({"is_active": False}).eq("id", coupon["id"]).execute()

    return jsonify({"message": msg, "updated": update}), 200


# ── Admin: Feedback viewer ────────────────────────────────────────────────────

@app.route("/api/admin/feedback", methods=["GET"])
def api_admin_list_feedback():
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403

    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(50, int(request.args.get("per_page", 20)))
    offset   = (page - 1) * per_page

    res   = supabase.table("feedback").select("*", count="exact") \
                .order("created_at", desc=True).range(offset, offset + per_page - 1).execute()
    total = res.count or 0

    return jsonify({
        "feedback":    res.data or [],
        "total":       total,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }), 200



def api_admin_trigger_referral():
    """Manual test: simulate a paid referral. Protected by ADMIN_SECRET."""
    data         = request.get_json(silent=True) or {}
    admin_secret = os.getenv("ADMIN_SECRET", "")
    provided     = request.headers.get("X-Admin-Secret", "")
    if not admin_secret or not provided or not hmac.compare_digest(provided, admin_secret):
        return jsonify({"error": "Unauthorized"}), 403
    referrer_id = (data.get("referrer_id") or "").strip()
    if not referrer_id:
        return jsonify({"error": "referrer_id required"}), 400
    _apply_referral_reward(referrer_id)
    return jsonify({"message": f"Referral reward applied for {referrer_id}"}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Admin Panel API  (all routes protected by X-Admin-Secret header)
# ─────────────────────────────────────────────────────────────────────────────

def _admin_auth() -> bool:
    """Return True if request carries a valid ADMIN_SECRET header."""
    secret   = os.getenv("ADMIN_SECRET", "")
    provided = request.headers.get("X-Admin-Secret", "")
    return bool(secret and provided and hmac.compare_digest(provided, secret))


# ── Dashboard stats ───────────────────────────────────────────────────────────

@app.route("/api/admin/stats", methods=["GET"])
def api_admin_stats():
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403

    now_utc = datetime.datetime.now(datetime.timezone.utc)

    # Total users
    total_users = supabase.table("users").select("id", count="exact").execute().count or 0

    # Users joined today
    today_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    new_today   = supabase.table("users").select("id", count="exact") \
                    .gte("join_date", today_start).execute().count or 0

    # Paid users
    paid_users = supabase.table("users").select("id", count="exact") \
                    .not_.in_("plan", list(FREE_PLANS)).execute().count or 0

    # Total links monitored
    total_links = supabase.table("links").select("id", count="exact") \
                    .eq("is_active", True).execute().count or 0

    # Alerts sent last 7 days
    week_ago = (now_utc - datetime.timedelta(days=7)).isoformat()
    alerts_7d = supabase.table("alerts").select("id", count="exact") \
                    .gte("sent_at", week_ago).execute().count or 0

    # Plan breakdown
    users_res = supabase.table("users").select("plan").execute()
    plan_counts: dict = {}
    for u in (users_res.data or []):
        p = u.get("plan", "free")
        plan_counts[p] = plan_counts.get(p, 0) + 1

    return jsonify({
        "total_users":  total_users,
        "new_today":    new_today,
        "paid_users":   paid_users,
        "free_users":   total_users - paid_users,
        "total_links":  total_links,
        "alerts_7d":    alerts_7d,
        "plan_counts":  plan_counts,
    }), 200


# ── List users (paginated) ────────────────────────────────────────────────────

@app.route("/api/admin/users", methods=["GET"])
def api_admin_list_users():
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403

    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(50, int(request.args.get("per_page", 20)))
    search   = (request.args.get("search") or "").strip()
    plan_f   = (request.args.get("plan")   or "").strip()

    offset = (page - 1) * per_page
    query  = supabase.table("users").select(
        "id, email, full_name, plan, plan_expiry, join_date, last_login, "
        "telegram_chat_id, total_referrals, referral_code",
        count="exact"
    )

    if search:
        query = query.ilike("email", f"%{search}%")
    if plan_f:
        query = query.eq("plan", plan_f)

    res   = query.order("join_date", desc=True).range(offset, offset + per_page - 1).execute()
    total = res.count or 0

    return jsonify({
        "users":      res.data or [],
        "total":      total,
        "page":       page,
        "per_page":   per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }), 200


# ── Single user detail ────────────────────────────────────────────────────────

@app.route("/api/admin/users/<user_id>", methods=["GET"])
def api_admin_get_user(user_id):
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403

    user_res = supabase.table("users").select("*").eq("id", user_id).single().execute()
    if not user_res.data:
        return jsonify({"error": "User not found"}), 404

    links_res = supabase.table("links").select("*") \
                    .eq("user_id", user_id).order("created_at", desc=True).execute()

    return jsonify({
        "user":  user_res.data,
        "links": links_res.data or [],
    }), 200


# ── Update user plan (grant access / change plan / extend expiry) ─────────────

@app.route("/api/admin/users/<user_id>/plan", methods=["POST"])
def api_admin_update_plan(user_id):
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403

    data       = request.get_json(silent=True) or {}
    new_plan   = (data.get("plan")   or "").strip().lower()
    free_months = int(data.get("free_months", 0))   # grant N free months
    note       = (data.get("note")   or "").strip()  # internal note (optional)

    valid_plans = list(PLAN_LIMITS.keys())
    if new_plan and new_plan not in valid_plans:
        return jsonify({"error": f"Invalid plan. Valid: {valid_plans}"}), 400

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    update  = {}

    if new_plan:
        update["plan"] = new_plan

    if free_months > 0:
        # Extend expiry from today (or from current expiry if in future)
        user_res = supabase.table("users").select("plan_expiry").eq("id", user_id).single().execute()
        if user_res.data and user_res.data.get("plan_expiry"):
            try:
                current_expiry = datetime.datetime.fromisoformat(
                    user_res.data["plan_expiry"].replace("Z", "+00:00")
                )
                base = max(current_expiry, now_utc)
            except Exception:
                base = now_utc
        else:
            base = now_utc
        update["plan_expiry"] = (base + datetime.timedelta(days=30 * free_months)).isoformat()

    if not update:
        return jsonify({"error": "Nothing to update. Provide plan or free_months."}), 400

    supabase.table("users").update(update).eq("id", user_id).execute()

    logger.info(f"ADMIN: Updated user {user_id} → {update} | note: {note}")
    return jsonify({"message": "User plan updated", "updated": update}), 200


# ── Suspend / unsuspend user ──────────────────────────────────────────────────

@app.route("/api/admin/users/<user_id>/suspend", methods=["POST"])
def api_admin_suspend_user(user_id):
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403

    data    = request.get_json(silent=True) or {}
    suspend = bool(data.get("suspend", True))

    # Suspending = demote to free + deactivate all links
    if suspend:
        supabase.table("users").update({"plan": "free", "plan_expiry": None}) \
                .eq("id", user_id).execute()
        supabase.table("links").update({"is_active": False}) \
                .eq("user_id", user_id).execute()
        msg = f"User {user_id} suspended — plan reset to free, links deactivated"
    else:
        # Unsuspend — reactivate links only (plan restore is separate)
        supabase.table("links").update({"is_active": True}) \
                .eq("user_id", user_id).execute()
        msg = f"User {user_id} unsuspended — links reactivated"

    logger.info(f"ADMIN: {msg}")
    return jsonify({"message": msg}), 200


# ── Delete user ───────────────────────────────────────────────────────────────

@app.route("/api/admin/users/<user_id>", methods=["DELETE"])
def api_admin_delete_user(user_id):
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403

    supabase.table("users").delete().eq("id", user_id).execute()
    logger.info(f"ADMIN: Deleted user {user_id}")
    return jsonify({"message": f"User {user_id} deleted"}), 200


# ── Send manual Telegram message to a user ────────────────────────────────────

@app.route("/api/admin/users/<user_id>/message", methods=["POST"])
def api_admin_message_user(user_id):
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403

    data    = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "message is required"}), 400

    user_res = supabase.table("users").select("telegram_chat_id, email") \
                    .eq("id", user_id).single().execute()
    if not user_res.data:
        return jsonify({"error": "User not found"}), 404

    chat_id = user_res.data.get("telegram_chat_id")
    if not chat_id:
        return jsonify({"error": "User has no Telegram chat ID configured"}), 400

    ok = send_telegram_message(chat_id, f"📢 <b>Message from AffiGuard</b>\n\n{html.escape(message)}")
    return jsonify({"sent": ok}), 200 if ok else 500


# ── Broadcast Telegram message to all users (or paid-only) ───────────────────

@app.route("/api/admin/broadcast", methods=["POST"])
def api_admin_broadcast():
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403

    data      = request.get_json(silent=True) or {}
    message   = (data.get("message") or "").strip()
    paid_only = bool(data.get("paid_only", False))

    if not message:
        return jsonify({"error": "message is required"}), 400

    query = supabase.table("users").select("telegram_chat_id, email")
    if paid_only:
        query = query.not_.in_("plan", list(FREE_PLANS))
    users_res = query.execute()

    sent = failed = skipped = 0
    for u in (users_res.data or []):
        chat_id = u.get("telegram_chat_id")
        if not chat_id:
            skipped += 1
            continue
        ok = send_telegram_message(chat_id, f"📢 <b>AffiGuard Update</b>\n\n{html.escape(message)}")
        if ok: sent += 1
        else:  failed += 1

    return jsonify({
        "sent":    sent,
        "failed":  failed,
        "skipped": skipped,
        "total":   sent + failed + skipped,
    }), 200


# ── All links overview ────────────────────────────────────────────────────────

@app.route("/api/admin/links", methods=["GET"])
def api_admin_list_links():
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403

    status_f = (request.args.get("status") or "").strip()
    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(100, int(request.args.get("per_page", 50)))
    offset   = (page - 1) * per_page

    query = supabase.table("links").select("*, users(email, plan)", count="exact")
    if status_f:
        query = query.eq("status", status_f)

    res   = query.order("last_checked", desc=True).range(offset, offset + per_page - 1).execute()
    total = res.count or 0

    return jsonify({
        "links":       res.data or [],
        "total":       total,
        "page":        page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }), 200





# ─────────────────────────────────────────────────────────────────────────────
# Health check  (Render uses this for uptime monitoring)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/admin")
def admin_panel():
    """Serve the admin panel HTML."""
    return app.send_static_file("admin.html")


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "AffiGuard"}), 200


# ─────────────────────────────────────────────────────────────────────────────
# Entry point (local dev only; Render uses gunicorn via Procfile)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port  = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_ENV", "production") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)

# ── Admin: Recent signups ─────────────────────────────────────────────────────

@app.route("/api/admin/recent-signups", methods=["GET"])
def api_admin_recent_signups():
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403
    limit = min(50, int(request.args.get("limit", 20)))
    res = supabase.table("users") \
        .select("id, email, full_name, plan, join_date, telegram_chat_id") \
        .order("join_date", desc=True).limit(limit).execute()
    return jsonify({"signups": res.data or []}), 200


# ── Admin: Payments list ──────────────────────────────────────────────────────

@app.route("/api/admin/payments", methods=["GET"])
def api_admin_payments():
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403
    page     = max(1, int(request.args.get("page", 1)))
    per_page = min(100, int(request.args.get("per_page", 50)))
    offset   = (page - 1) * per_page
    res = supabase.table("payments") \
        .select("*, users(email)", count="exact") \
        .order("created_at", desc=True) \
        .range(offset, offset + per_page - 1).execute()
    total = res.count or 0
    # Revenue summary
    all_paid = supabase.table("payments") \
        .select("amount, currency") \
        .eq("status", "paid").execute()
    total_inr = sum(
        float(p.get("amount") or 0)
        for p in (all_paid.data or [])
        if (p.get("currency") or "").upper() == "INR"
    )
    total_usd = sum(
        float(p.get("amount") or 0)
        for p in (all_paid.data or [])
        if (p.get("currency") or "").upper() == "USD"
    )
    return jsonify({
        "payments":    res.data or [],
        "total":       total,
        "page":        page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
        "revenue_inr": round(total_inr, 2),
        "revenue_usd": round(total_usd, 2),
    }), 200


# ── Admin: Record manual payment ──────────────────────────────────────────────

@app.route("/api/admin/payments", methods=["POST"])
def api_admin_record_payment():
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403
    data     = request.get_json(silent=True) or {}
    email    = (data.get("email")    or "").strip()
    amount   = float(data.get("amount", 0))
    currency = (data.get("currency") or "USD").upper().strip()
    plan     = (data.get("plan")     or "").strip().lower()
    months   = int(data.get("months", 1))
    gateway  = (data.get("gateway")  or "manual").strip()
    note     = (data.get("note")     or "").strip()

    if not email or not plan or amount <= 0:
        return jsonify({"error": "email, plan, and amount are required"}), 400

    # Find user
    user_res = supabase.table("users").select("id, plan_expiry") \
        .eq("email", email).single().execute()
    if not user_res.data:
        return jsonify({"error": "User not found"}), 404
    user_id = user_res.data["id"]

    # Record payment
    supabase.table("payments").insert({
        "id":         str(uuid.uuid4()),
        "user_id":    user_id,
        "amount":     amount,
        "currency":   currency,
        "plan":       plan,
        "status":     "paid",
        "gateway":    gateway,
        "gateway_id": note or f"manual-{uuid.uuid4().hex[:8]}",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }).execute()

    # Update user plan + expiry
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    expiry  = user_res.data.get("plan_expiry")
    if expiry:
        try:
            base = datetime.datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            base = max(base, now_utc)
        except Exception:
            base = now_utc
    else:
        base = now_utc
    new_expiry = (base + datetime.timedelta(days=30 * months)).isoformat()
    supabase.table("users").update({"plan": plan, "plan_expiry": new_expiry}) \
        .eq("id", user_id).execute()

    logger.info(f"ADMIN: Manual payment recorded for {email} — {amount} {currency}, plan={plan}")
    return jsonify({"message": "Payment recorded and plan updated", "new_expiry": new_expiry}), 200


# ── Admin: Coupons ────────────────────────────────────────────────────────────

@app.route("/api/admin/coupons", methods=["GET"])
def api_admin_list_coupons():
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403
    res = supabase.table("coupons").select("*").order("created_at", desc=True).execute()
    return jsonify({"coupons": res.data or []}), 200


@app.route("/api/admin/coupons", methods=["POST"])
def api_admin_create_coupon():
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403
    data        = request.get_json(silent=True) or {}
    code        = (data.get("code") or secrets.token_urlsafe(6).upper()).strip().upper()
    coupon_type = (data.get("type") or "free_months").strip()  # free_months | plan_upgrade | percent_off
    value       = int(data.get("value", 1))    # months / plan name / percent
    plan_grant  = (data.get("plan_grant") or "").strip().lower()
    max_uses    = int(data.get("max_uses", 1))
    expires_days= int(data.get("expires_days", 30))
    note        = (data.get("note") or "").strip()

    expires_at  = (datetime.datetime.now(datetime.timezone.utc) +
                   datetime.timedelta(days=expires_days)).isoformat()

    supabase.table("coupons").insert({
        "id":          str(uuid.uuid4()),
        "code":        code,
        "type":        coupon_type,
        "value":       value,
        "plan_grant":  plan_grant or None,
        "max_uses":    max_uses,
        "uses":        0,
        "expires_at":  expires_at,
        "note":        note,
        "created_at":  datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "is_active":   True,
    }).execute()

    return jsonify({"message": "Coupon created", "code": code}), 200


@app.route("/api/admin/coupons/<coupon_id>", methods=["DELETE"])
def api_admin_delete_coupon(coupon_id):
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403
    supabase.table("coupons").update({"is_active": False}).eq("id", coupon_id).execute()
    return jsonify({"message": "Coupon deactivated"}), 200


# ── Admin: Force recheck a link ───────────────────────────────────────────────

@app.route("/api/admin/links/<link_id>/recheck", methods=["POST"])
def api_admin_recheck_link(link_id):
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403
    link_res = supabase.table("links").select("*").eq("id", link_id).single().execute()
    if not link_res.data:
        return jsonify({"error": "Link not found"}), 404
    link   = link_res.data
    result = check_link(link["url"], link.get("platform", "generic"))
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    supabase.table("links").update({
        "status":        result["status"],
        "last_checked":  now_iso,
        "response_time": result.get("response_time"),
        "layer_used":    result.get("layer_used"),
        "error_message": result.get("error"),
    }).eq("id", link_id).execute()
    supabase.table("check_history").insert({
        "id":            str(uuid.uuid4()),
        "link_id":       link_id,
        "user_id":       link["user_id"],
        "status":        result["status"],
        "response_time": result.get("response_time"),
        "layer_used":    result.get("layer_used"),
        "error_message": result.get("error"),
        "checked_at":    now_iso,
    }).execute()
    return jsonify({"status": result["status"], "result": result}), 200


# ── Admin: Export users CSV ───────────────────────────────────────────────────

@app.route("/api/admin/export/users", methods=["GET"])
def api_admin_export_users():
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403
    import csv, io
    res  = supabase.table("users") \
        .select("email, full_name, plan, plan_expiry, join_date, last_login, telegram_chat_id, total_referrals") \
        .order("join_date", desc=True).execute()
    buf  = io.StringIO()
    cols = ["email", "full_name", "plan", "plan_expiry", "join_date", "last_login", "telegram_chat_id", "total_referrals"]
    w    = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for row in (res.data or []):
        w.writerow(row)
    from flask import Response
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=affiguard_users.csv"}
    )


# ── Admin: System health ──────────────────────────────────────────────────────

@app.route("/api/admin/health", methods=["GET"])
def api_admin_system_health():
    if not _admin_auth():
        return jsonify({"error": "Unauthorized"}), 403

    checks = {}

    # DB check
    try:
        supabase.table("users").select("id").limit(1).execute()
        checks["database"] = {"status": "ok"}
    except Exception as e:
        checks["database"] = {"status": "error", "error": str(e)[:100]}

    # Telegram bot check
    tg_token = os.getenv("TELEGRAM_BOT_TOKEN")
    if tg_token:
        try:
            import requests as req_lib
            r = req_lib.get(f"https://api.telegram.org/bot{tg_token}/getMe", timeout=5)
            if r.status_code == 200:
                bot_info = r.json().get("result", {})
                checks["telegram"] = {"status": "ok", "bot_username": bot_info.get("username")}
            else:
                checks["telegram"] = {"status": "error", "http": r.status_code}
        except Exception as e:
            checks["telegram"] = {"status": "error", "error": str(e)[:100]}
    else:
        checks["telegram"] = {"status": "not_configured"}

    # Cron last run (last check_history entry)
    try:
        last = supabase.table("check_history").select("checked_at") \
            .order("checked_at", desc=True).limit(1).execute()
        last_run = last.data[0]["checked_at"] if last.data else None
        checks["cron"] = {"status": "ok", "last_run": last_run}
    except Exception as e:
        checks["cron"] = {"status": "error", "error": str(e)[:100]}

    # ScraperAPI configured
    checks["scraper_api"] = {
        "status": "configured" if os.getenv("SCRAPER_API_KEY") else "not_configured"
    }

    overall = "ok" if all(v["status"] in ("ok", "not_configured", "configured") for v in checks.values()) else "degraded"
    return jsonify({"overall": overall, "checks": checks}), 200

