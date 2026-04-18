"""
alerts.py – Notification system for LinkGuardian Pro
Supports: Telegram (active), WhatsApp (stub)
"""

import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ── Telegram ───────────────────────────────────────────────────────────────────

def _get_telegram_token() -> Optional[str]:
    return os.getenv("TELEGRAM_BOT_TOKEN")


def send_telegram_message(chat_id: str, message: str) -> bool:
    """
    Send a message via Telegram Bot API.
    Returns True on success, False on failure.
    """
    token = _get_telegram_token()
    if not token:
        logger.warning("TELEGRAM_BOT_TOKEN not set – skipping alert")
        return False
    if not chat_id:
        logger.warning("No telegram_chat_id for user – skipping alert")
        return False

    import requests
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        resp = requests.post(url, json=payload, timeout=10)
        if resp.status_code == 200:
            return True
        else:
            logger.error(f"Telegram API error {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        logger.error(f"Telegram send failed: {e}")
        return False


def build_alert_message(link_name: str, link_url: str,
                        status: str, layer_used: str,
                        error_msg: Optional[str] = None) -> str:
    """Build a formatted Telegram HTML alert message."""
    emoji_map = {
        "broken":       "🔴",
        "out_of_stock": "🟡",
        "error":        "⚠️",
    }
    status_label = {
        "broken":       "BROKEN",
        "out_of_stock": "OUT OF STOCK",
        "error":        "ERROR",
    }

    emoji = emoji_map.get(status, "❓")
    label = status_label.get(status, status.upper())

    msg = (
        f"{emoji} <b>LinkGuardian Alert</b>\n\n"
        f"<b>Link:</b> {link_name}\n"
        f"<b>Status:</b> {label}\n"
        f"<b>URL:</b> <a href=\"{link_url}\">{link_url[:60]}...</a>\n"
        f"<b>Detected via:</b> {layer_used or 'N/A'}\n"
    )
    if error_msg:
        msg += f"<b>Error:</b> {error_msg[:200]}\n"

    msg += "\n🔗 <a href=\"https://linkguardian.pro/dashboard\">View Dashboard</a>"
    return msg


def build_plan_expiry_message(full_name: str, plan: str,
                               days_left: int) -> str:
    """Build a plan expiry warning message."""
    if days_left <= 0:
        return (
            f"🚫 <b>Plan Expired – LinkGuardian Pro</b>\n\n"
            f"Hi {full_name or 'there'},\n"
            f"Your <b>{plan.upper()}</b> plan has expired.\n"
            f"Link monitoring has been paused.\n\n"
            f"🔗 <a href=\"https://linkguardian.pro/dashboard\">Renew Now</a>"
        )
    return (
        f"⏰ <b>Plan Expiry Reminder – LinkGuardian Pro</b>\n\n"
        f"Hi {full_name or 'there'},\n"
        f"Your <b>{plan.upper()}</b> plan expires in "
        f"<b>{days_left} day(s)</b>.\n"
        f"Renew to keep monitoring your links.\n\n"
        f"🔗 <a href=\"https://linkguardian.pro/dashboard\">Renew Now</a>"
    )


# ── WhatsApp (stub) ────────────────────────────────────────────────────────────

def send_whatsapp_message(phone: str, message: str) -> bool:
    """
    WhatsApp alert stub.
    Implement using Twilio, Meta Cloud API, or WATI when ready.
    """
    logger.info(f"[STUB] WhatsApp to {phone}: {message[:80]}")
    return False  # stub returns False until implemented


# ── Dispatcher ────────────────────────────────────────────────────────────────

def dispatch_alert(user: dict, link: dict, status: str,
                   layer_used: str, error_msg: Optional[str] = None) -> dict:
    """
    Dispatch alert to all configured channels for a user.
    Returns dict of {channel: success_bool}.
    """
    results = {}

    message = build_alert_message(
        link_name=link.get("name", "Unnamed"),
        link_url=link.get("url", ""),
        status=status,
        layer_used=layer_used,
        error_msg=error_msg,
    )

    # Telegram
    chat_id = user.get("telegram_chat_id")
    if chat_id:
        ok = send_telegram_message(chat_id, message)
        results["telegram"] = ok

    # WhatsApp (stub)
    wa_num = user.get("whatsapp_number")
    if wa_num:
        ok = send_whatsapp_message(wa_num, message)
        results["whatsapp"] = ok

    return results
