"""
monitor.py – Multi-layer link health checker
Layer 1: Direct HTTP request
Layer 2: ScraperAPI (JS rendering)
Layer 3: Playwright (headless Chromium)

Returns a dict: { status, response_time, layer_used, error }
"""

import os
import time
import re
import requests
from typing import Optional

# ── Out-of-stock keyword patterns ─────────────────────────────────────────────

OOS_PATTERNS = {
    "amazon": [
        r"currently unavailable",
        r"this item is currently unavailable",
        r"out of stock",
        r"in stock.*?soon",
        r"notify me when available",
        r"sign up to be notified",
        r"back in stock",
        r"unavailable",
    ],
    "flipkart": [
        r"sold out",
        r"out of stock",
        r"currently unavailable",
        r"notify me",
        r"coming soon",
        r"temporarily unavailable",
    ],
    "generic": [
        r"out of stock",
        r"sold out",
        r"temporarily unavailable",
        r"not available",
        r"item unavailable",
        r"product unavailable",
        r"no longer available",
        r"discontinued",
        r"back order",
        r"pre.?order",
    ],
}

BROKEN_PATTERNS = [
    r"404",
    r"page not found",
    r"link not found",
    r"this page doesn.t exist",
    r"this page is no longer",
    r"product has been removed",
    r"listing removed",
    r"asin.*?is no longer",
]

TIMEOUT_SECONDS = 15
SCRAPER_API_BASE = "http://api.scraperapi.com"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _get_platform_patterns(platform: str) -> list[str]:
    """Return out-of-stock patterns for the given platform."""
    p = platform.lower()
    if "amazon" in p:
        return OOS_PATTERNS["amazon"]
    if "flipkart" in p:
        return OOS_PATTERNS["flipkart"]
    return OOS_PATTERNS["generic"]


def _classify_content(html: str, status_code: int, platform: str) -> str:
    """
    Given HTML content and HTTP status code, return:
      'active' | 'broken' | 'out_of_stock'
    """
    if status_code in (404, 410, 403, 401):
        return "broken"

    text = html.lower() if html else ""

    # Check broken indicators
    for pat in BROKEN_PATTERNS:
        if re.search(pat, text):
            return "broken"

    # Check out-of-stock indicators
    oos_pats = _get_platform_patterns(platform)
    for pat in oos_pats:
        if re.search(pat, text):
            return "out_of_stock"

    return "active"


def _build_headers() -> dict:
    return {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }


# ── Layer 1: Direct HTTP ───────────────────────────────────────────────────────

def check_layer1(url: str, platform: str = "generic") -> dict:
    """Direct HTTP GET request."""
    start = time.time()
    try:
        resp = requests.get(
            url,
            headers=_build_headers(),
            timeout=TIMEOUT_SECONDS,
            allow_redirects=True,
        )
        elapsed = int((time.time() - start) * 1000)
        status = _classify_content(resp.text, resp.status_code, platform)
        return {
            "status": status,
            "response_time": elapsed,
            "layer_used": "layer1",
            "http_code": resp.status_code,
            "error": None,
        }
    except requests.Timeout:
        return {
            "status": "error",
            "response_time": int((time.time() - start) * 1000),
            "layer_used": "layer1",
            "http_code": None,
            "error": "Request timed out",
        }
    except requests.ConnectionError as e:
        return {
            "status": "error",
            "response_time": int((time.time() - start) * 1000),
            "layer_used": "layer1",
            "http_code": None,
            "error": f"Connection error: {str(e)[:120]}",
        }
    except Exception as e:
        return {
            "status": "error",
            "response_time": int((time.time() - start) * 1000),
            "layer_used": "layer1",
            "http_code": None,
            "error": str(e)[:200],
        }


# ── Layer 2: ScraperAPI ────────────────────────────────────────────────────────

def check_layer2(url: str, platform: str = "generic") -> Optional[dict]:
    """ScraperAPI with JS rendering. Returns None if API key not configured."""
    api_key = os.getenv("SCRAPER_API_KEY")
    if not api_key:
        return None

    params = {
        "api_key": api_key,
        "url": url,
        "render": "true",
        "country_code": "in",  # India datacenter for Amazon.in / Flipkart
    }

    start = time.time()
    try:
        resp = requests.get(
            SCRAPER_API_BASE,
            params=params,
            timeout=60,  # ScraperAPI can be slow
        )
        elapsed = int((time.time() - start) * 1000)
        status = _classify_content(resp.text, resp.status_code, platform)
        return {
            "status": status,
            "response_time": elapsed,
            "layer_used": "layer2",
            "http_code": resp.status_code,
            "error": None,
        }
    except Exception as e:
        return {
            "status": "error",
            "response_time": int((time.time() - start) * 1000),
            "layer_used": "layer2",
            "http_code": None,
            "error": str(e)[:200],
        }


# ── Layer 3: Playwright ────────────────────────────────────────────────────────

def check_layer3(url: str, platform: str = "generic") -> Optional[dict]:
    """
    Headless Chromium via Playwright.
    Only runs if playwright is installed and ENABLE_PLAYWRIGHT=true.
    """
    if os.getenv("ENABLE_PLAYWRIGHT", "false").lower() != "true":
        return None

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return None

    start = time.time()
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                ],
            )
            context = browser.new_context(
                user_agent=_build_headers()["User-Agent"],
                locale="en-US",
            )
            page = context.new_page()
            page.set_default_timeout(30_000)

            response = page.goto(url, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)  # let JS settle

            html = page.content()
            http_code = response.status if response else 200
            elapsed = int((time.time() - start) * 1000)

            browser.close()

            status = _classify_content(html, http_code, platform)
            return {
                "status": status,
                "response_time": elapsed,
                "layer_used": "layer3",
                "http_code": http_code,
                "error": None,
            }
    except Exception as e:
        return {
            "status": "error",
            "response_time": int((time.time() - start) * 1000),
            "layer_used": "layer3",
            "http_code": None,
            "error": str(e)[:200],
        }


# ── Main entry point ───────────────────────────────────────────────────────────

def check_link(url: str, platform: str = "generic") -> dict:
    """
    Run multi-layer check. Falls through layers on error.
    Always returns a valid result dict.
    """
    # Normalise URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # ── Layer 1 ──────────────────────────────────────────────
    result = check_layer1(url, platform)
    if result["status"] in ("active", "broken", "out_of_stock"):
        return result

    # Layer 1 returned error – try Layer 2
    # ── Layer 2 ──────────────────────────────────────────────
    l2 = check_layer2(url, platform)
    if l2 is not None:
        if l2["status"] in ("active", "broken", "out_of_stock"):
            return l2
        # Layer 2 also errored – try Layer 3

    # ── Layer 3 ──────────────────────────────────────────────
    l3 = check_layer3(url, platform)
    if l3 is not None:
        return l3

    # All layers failed – return the original Layer 1 error
    return result
