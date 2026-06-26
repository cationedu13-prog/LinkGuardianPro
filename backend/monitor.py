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
import socket
import ipaddress
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

# ── Amazon "Dogs of Amazon" soft-404 page ──────────────────────────────────────
# Amazon returns HTTP 200 OK for dead/removed product pages and shows a generic
# "page not found" style page with a photo of a dog instead of a real 404 status.
# Standard status-code or keyword checks miss this entirely, so we need
# Amazon-specific phrase patterns that ONLY appear on that soft-404 page.
AMAZON_SOFT_404_PATTERNS = [
    r"looking for something\?",
    r"we.re sorry\.?\s*the web address you entered is not a functioning page",
    r"sorry,?\s*we couldn.t find that page",
    r"try checking the url for errors",                       # Amazon's exact wording
    r"dogsofamazon",                                            # image filename pattern used on the page
    r"go to amazon.s? home page",
    r"page is currently unavailable",
]

TIMEOUT_SECONDS = 8
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


def _classify_content(html: str, status_code: int, platform: str, url: str = "") -> str:
    """
    Given HTML content and HTTP status code, return:
      'active' | 'broken' | 'out_of_stock'
    """
    if status_code in (404, 410, 403, 401):
        return "broken"

    text = html.lower() if html else ""

    # Check broken indicators (generic)
    for pat in BROKEN_PATTERNS:
        if re.search(pat, text):
            return "broken"

    # Resolve real platform from URL too — covers the common case where the
    # user left platform="generic" but the URL is clearly an Amazon link.
    effective_platform = platform if platform and platform.lower() != "generic" \
        else _detect_platform_from_url(url or "")

    # Amazon-specific: detect the "Dogs of Amazon" soft-404 page.
    # Amazon returns HTTP 200 for this page, so status-code and generic
    # keyword checks both miss it — this is checked separately and only
    # for amazon URLs/platform to avoid false positives on other sites.
    if "amazon" in effective_platform.lower():
        for pat in AMAZON_SOFT_404_PATTERNS:
            if re.search(pat, text):
                return "broken"
        # Extra signal: Amazon's real product pages almost always contain
        # a "buybox"/add-to-cart area or a price block. The dog page has
        # neither. If the page is short AND missing both, treat as broken.
        if len(text) < 6000 and "add to cart" not in text and "buy now" not in text \
                and "addtocart" not in text and not re.search(r"₹|\$\s?\d", text):
            return "broken"

    # Check out-of-stock indicators
    oos_pats = _get_platform_patterns(effective_platform)
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



# ── SSRF Protection ───────────────────────────────────────────────────────────

def is_safe_url(url: str) -> tuple[bool, str]:
    """
    SEC-01 FIX: Validate a user-supplied URL before making any outbound request.
    Blocks private IPs, loopback, link-local (cloud metadata), non-HTTP schemes.
    Returns (is_safe: bool, reason: str).
    """
    if not url or not isinstance(url, str):
        return False, "URL is empty"

    normalised = url if "://" in url else "https://" + url

    try:
        from urllib.parse import urlparse
        parsed = urlparse(normalised)
    except Exception:
        return False, "Invalid URL format"

    if parsed.scheme not in ("http", "https"):
        return False, f"Scheme \"{parsed.scheme}\" not allowed — only http/https"

    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname found in URL"

    if hostname.lower() in ("localhost", "localhost.localdomain"):
        return False, "Private/internal hostname not allowed"

    try:
        ip = ipaddress.ip_address(hostname)
        if (ip.is_loopback or ip.is_private or
                ip.is_link_local or ip.is_reserved or
                not ip.is_global):
            return False, f"Private/reserved IP address not allowed: {ip}"
        return True, "ok"
    except ValueError:
        pass

    try:
        resolved = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(resolved)
        if (ip.is_loopback or ip.is_private or
                ip.is_link_local or ip.is_reserved or
                not ip.is_global):
            return False, f"Hostname resolves to private IP ({resolved})"
    except socket.gaierror:
        pass
    except Exception:
        pass

    return True, "ok"


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
        status = _classify_content(resp.text, resp.status_code, platform, url)
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
        status = _classify_content(resp.text, resp.status_code, platform, url)
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

            status = _classify_content(html, http_code, platform, url)
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


# ── Tag Guard ─────────────────────────────────────────────────────────────────

_TAG_PATTERNS: dict[str, list[str]] = {
    "amazon":     ["tag=", "ascsubtag="],
    "flipkart":   ["affid=", "affExtParam1=", "fktrp="],
    "shareasale": ["sscid=", "afftrack="],
    "clickbank":  ["hop.clickbank.net"],
    "cj":         ["aid=", "pid="],
    "impact":     ["irclickid=", "irgwc="],
    "generic":    [],
}

def _detect_platform_from_url(url: str) -> str:
    u = url.lower()
    if "amazon."    in u: return "amazon"
    if "flipkart."  in u: return "flipkart"
    if "shareasale" in u: return "shareasale"
    if "clickbank"  in u: return "clickbank"
    if "impact.com" in u: return "impact"
    if "cj.com"     in u: return "cj"
    return "generic"


def _get_country_code(url: str) -> str:
    """Dynamic ScraperAPI country — India domains get 'in', rest get 'us'."""
    u = url.lower()
    if any(d in u for d in ("amazon.in", "flipkart.com", "fkrt.it", "snapdeal.com", "meesho.com")):
        return "in"
    return "us"


def check_tag_guard(original_url: str, platform: str = "generic") -> dict:
    """
    Follow redirects and check whether an affiliate tag is in the final URL.
    Returns: { tag_present, tag_found, final_url, error }
    """
    resolved_platform = platform if platform != "generic" else _detect_platform_from_url(original_url)
    expected_tags     = _TAG_PATTERNS.get(resolved_platform, [])

    if not expected_tags:
        return {"tag_present": None, "tag_found": None, "final_url": None,
                "error": "Tag Guard not applicable for this platform"}

    if not original_url.startswith(("http://", "https://")):
        original_url = "https://" + original_url

    try:
        resp      = requests.get(original_url, headers=_build_headers(),
                                 timeout=TIMEOUT_SECONDS, allow_redirects=True)
        final_url = resp.url
        combined  = original_url + " " + final_url
        for tag in expected_tags:
            if tag.lower() in combined.lower():
                return {"tag_present": True, "tag_found": tag, "final_url": final_url, "error": None}
        return {"tag_present": False, "tag_found": None, "final_url": final_url, "error": None}
    except requests.Timeout:
        return {"tag_present": None, "tag_found": None, "final_url": None, "error": "Request timed out"}
    except Exception as e:
        return {"tag_present": None, "tag_found": None, "final_url": None, "error": str(e)[:200]}


# ── Smart Auto-Crawl ──────────────────────────────────────────────────────────

AFFILIATE_DOMAINS = [
    "amazon.in", "amazon.com", "amzn.to", "amzn.in",
    "flipkart.com", "fkrt.it", "shareasale.com", "clickbank.net",
    "cj.com", "anrdoezrs.net", "impact.com", "impactradius.com",
    "awin1.com", "awin.com", "rakuten.com", "linksynergy.com",
]

def _is_affiliate_url(url: str) -> bool:
    u = url.lower()
    return any(d in u for d in AFFILIATE_DOMAINS)

def _guess_platform(url: str) -> str:
    u = url.lower()
    if "amazon." in u or "amzn." in u: return "amazon"
    if "flipkart." in u or "fkrt." in u: return "flipkart"
    if "shareasale" in u: return "shareasale"
    if "clickbank"  in u: return "clickbank"
    if "cj.com"     in u: return "cj"
    if "impact"     in u: return "impact"
    if "awin"       in u: return "awin"
    return "generic"

def crawl_affiliate_links(page_url: str, max_links: int = 200) -> dict:
    """
    Fetch page_url and extract all affiliate links (known domains only).
    Returns: { found: [{url, name, platform}], total_on_page, error }
    """
    import html as _html
    from urllib.parse import urljoin, urlparse

    if not page_url.startswith(("http://", "https://")):
        page_url = "https://" + page_url

    try:
        resp = requests.get(page_url, headers=_build_headers(),
                            timeout=TIMEOUT_SECONDS, allow_redirects=True)
    except requests.Timeout:
        return {"found": [], "total_on_page": 0, "error": "Request timed out"}
    except Exception as e:
        return {"found": [], "total_on_page": 0, "error": str(e)[:200]}

    if resp.status_code not in (200, 301, 302):
        return {"found": [], "total_on_page": 0, "error": f"Page returned HTTP {resp.status_code}"}

    raw_hrefs    = re.findall(r'href=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
    total_on_page = len(raw_hrefs)
    seen: set[str] = set()
    found: list[dict] = []

    for href in raw_hrefs:
        href = href.strip()
        if href.startswith("//"): href = "https:" + href
        elif href.startswith("/"): href = f"{urlparse(page_url).scheme}://{urlparse(page_url).netloc}{href}"
        elif not href.startswith("http"): href = urljoin(page_url, href)

        if not _is_affiliate_url(href) or href in seen: continue
        seen.add(href)
        if len(found) >= max_links: break

        platform = _guess_platform(href)
        try:
            path = urlparse(href).path.rstrip("/").split("/")[-1]
            name = _html.unescape(path.replace("-", " ").replace("_", " "))[:80] or href[:60]
        except Exception:
            name = href[:60]
        found.append({"url": href, "name": name.strip().title() or href[:60], "platform": platform})

    return {"found": found, "total_on_page": total_on_page, "error": None}
