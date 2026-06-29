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
# Collected from multiple real Amazon dog-page variants seen over the years —
# Amazon A/B tests different wording, so we cover every known phrasing.
AMAZON_SOFT_404_PATTERNS = [
    # Most common modern variant
    r"looking for something\?",
    r"we.re sorry\.?\s*the web address you entered is not a functioning page",
    r"the web address you entered is not a functioning page on our site",

    # Classic / older variant
    r"sorry,?\s*we couldn.t find that page",
    r"try checking the url \(web address\) for misspellings",
    r"try checking the url for errors",
    r"or you can use the (?:search box above|navigation) to find what you.re looking for",

    # "Something went wrong" variant (seen during outages / Prime Day)
    r"sorry\s*[—-]?\s*something went wrong on our end",
    r"please go back and try again",
    r"or go to amazon.s? home page",
    r"go to amazon.s? home page",

    # Generic Amazon error-page scaffolding (appears across all dog-page variants)
    r"dogsofamazon",                       # image filename pattern Amazon has used for years
    r"dogs of amazon",                     # the "Meet the dogs of Amazon" link text
    r"meet the dogs of amazon",
    r"page is currently unavailable",
    r"we.re working on it",
    r"this item is no longer available",
    r"the page you.re looking for is not available",
    r"the page you requested could not be found",

    # Amazon error code references that appear only on the dog page, not real listings
    r"error code:?\s*404",
    r"http.?\s*404.{0,20}not found",

    # India-specific (amazon.in) variant wording seen in the wild
    r"we.re sorry!?\s*an error has occurred",
    r"this page could not be found",
]

# ── Amazon bot-detection / CAPTCHA page ────────────────────────────────────────
# Amazon often blocks direct (non-JS) requests with a CAPTCHA or "automated
# traffic" page instead of the real product page. This is NOT a broken link —
# it just means Layer 1 got blocked and we should let Layer 2/3 retry instead
# of wrongly reporting "broken". We detect it so we can treat it as an ERROR
# (triggers fallback to next layer) rather than BROKEN.
AMAZON_BOT_BLOCK_PATTERNS = [
    r"to discuss automated access to amazon data",
    r"enter the characters you see below",
    r"sorry, we just need to make sure you.re not a robot",
    r"type the characters you see in this image",
    r"automated access to amazon",
    r"api-services-support@amazon\.com",
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
        # First check for bot-block/CAPTCHA — this means Layer 1 got blocked,
        # NOT that the product is actually broken. Returning "error" here lets
        # check_link() fall through to Layer 2 (ScraperAPI) / Layer 3 (Playwright)
        # instead of wrongly reporting the link as broken.
        for pat in AMAZON_BOT_BLOCK_PATTERNS:
            if re.search(pat, text):
                return "error"

        for pat in AMAZON_SOFT_404_PATTERNS:
            if re.search(pat, text):
                return "broken"

        # Extra signal: Amazon's real product pages almost always contain
        # a "buybox"/add-to-cart area, a price block, or the ASIN/product
        # title markup. The dog page has none of these. Only fall back to
        # this heuristic when the page is VERY short (true empty error
        # shells are typically under 3000 chars) — a higher threshold risks
        # flagging legitimately blocked-but-real pages as broken.
        has_buy_signal  = ("add to cart" in text or "buy now" in text or
                            "addtocart" in text or re.search(r"₹|\$\s?\d", text))
        has_title_signal = ('id="producttitle"' in text or
                             'id="title"' in text or
                             "/dp/" in text)
        if len(text) < 3000 and not has_buy_signal and not has_title_signal:
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
        # Use resp.url (final URL after following redirects), not the
        # original `url`. Critical for shortlinks like amzn.to/xxxx — the
        # original URL contains no "amazon" substring, so platform
        # auto-detection and Amazon-specific soft-404 checks would
        # otherwise be skipped entirely.
        status = _classify_content(resp.text, resp.status_code, platform, resp.url)
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
        "country_code": _get_country_code(url),  # dynamic: 'in' for India domains, 'us' otherwise
    }

    start = time.time()
    try:
        resp = requests.get(
            SCRAPER_API_BASE,
            params=params,
            timeout=60,  # ScraperAPI can be slow
        )
        elapsed = int((time.time() - start) * 1000)
        # IMPORTANT: resp.url here is ScraperAPI's OWN request URL
        # (http://api.scraperapi.com/?api_key=...&url=<target>&...), NOT the
        # target site's final redirected URL — ScraperAPI is a proxy, so
        # requests' redirect-following only sees the proxy's response chain.
        # We must use the original target `url` for platform detection
        # instead of resp.url, otherwise platform detection breaks for
        # every shortlink (amzn.to, fkrt.it) routed through Layer 2.
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
            final_url = page.url  # follows redirects same as Layer 1/2
            elapsed = int((time.time() - start) * 1000)

            browser.close()

            status = _classify_content(html, http_code, platform, final_url)
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

def _resolve_shortlink(url: str) -> str:
    """
    Resolve a shortlink (amzn.to, fkrt.it, etc.) to its final destination URL
    by following redirects with a lightweight request. Used ONLY to detect
    the correct platform up front — not for content classification.
    Falls back to the original URL on any failure (timeout, blocked, etc.)
    so callers always get a usable URL.
    """
    try:
        resp = requests.head(
            url, headers=_build_headers(), timeout=5,
            allow_redirects=True,
        )
        return resp.url or url
    except Exception:
        # Some shorteners reject HEAD requests — retry with a quick GET
        try:
            resp = requests.get(
                url, headers=_build_headers(), timeout=5,
                allow_redirects=True, stream=True,
            )
            resolved = resp.url or url
            resp.close()
            return resolved
        except Exception:
            return url


def check_link(url: str, platform: str = "generic") -> dict:
    """
    Run multi-layer check. Falls through layers on error.
    Always returns a valid result dict.
    """
    # Normalise URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Resolve platform up front using the FINAL destination URL, not the
    # original. Critical for shortlinks (amzn.to, fkrt.it, bit.ly, etc.) —
    # the shortlink itself contains no "amazon"/"flipkart" substring, so
    # every layer would otherwise treat it as platform="generic" and skip
    # all Amazon/Flipkart-specific soft-404 and out-of-stock detection.
    # This resolves ONCE here so Layer 1/2/3 all get the same correct
    # platform, regardless of which layer ends up handling the request.
    effective_platform = platform
    if not platform or platform.lower() == "generic":
        resolved_url = _resolve_shortlink(url)
        detected = _detect_platform_from_url(resolved_url)
        if detected != "generic":
            effective_platform = detected

    # ── Layer 1 ──────────────────────────────────────────────
    result = check_layer1(url, effective_platform)
    if result["status"] in ("active", "broken", "out_of_stock"):
        return result

    # Layer 1 returned error – try Layer 2
    # ── Layer 2 ──────────────────────────────────────────────
    l2 = check_layer2(url, effective_platform)
    if l2 is not None:
        if l2["status"] in ("active", "broken", "out_of_stock"):
            return l2
        # Layer 2 also errored – try Layer 3

    # ── Layer 3 ──────────────────────────────────────────────
    l3 = check_layer3(url, effective_platform)
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
    if "amazon."    in u or "amzn.to" in u or "amzn.in" in u: return "amazon"
    if "flipkart."  in u or "fkrt.it" in u:                   return "flipkart"
    if "shareasale" in u:                                      return "shareasale"
    if "clickbank"  in u:                                      return "clickbank"
    if "impact.com" in u:                                      return "impact"
    if "cj.com"     in u:                                       return "cj"
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
    if not original_url.startswith(("http://", "https://")):
        original_url = "https://" + original_url

    # Fetch FIRST, then decide platform from the final (redirected) URL.
    # Critical for shortlinks (amzn.to, fkrt.it) — the original URL has no
    # "amazon"/"flipkart" substring, so detecting platform before following
    # the redirect would wrongly return "not applicable" for every shortlink.
    try:
        resp      = requests.get(original_url, headers=_build_headers(),
                                 timeout=TIMEOUT_SECONDS, allow_redirects=True)
        final_url = resp.url
    except requests.Timeout:
        return {"tag_present": None, "tag_found": None, "final_url": None, "error": "Request timed out"}
    except Exception as e:
        return {"tag_present": None, "tag_found": None, "final_url": None, "error": str(e)[:200]}

    resolved_platform = platform if platform != "generic" \
        else _detect_platform_from_url(final_url) or _detect_platform_from_url(original_url)
    expected_tags = _TAG_PATTERNS.get(resolved_platform, [])

    if not expected_tags:
        return {"tag_present": None, "tag_found": None, "final_url": final_url,
                "error": "Tag Guard not applicable for this platform"}

    combined = original_url + " " + final_url
    for tag in expected_tags:
        if tag.lower() in combined.lower():
            return {"tag_present": True, "tag_found": tag, "final_url": final_url, "error": None}
    return {"tag_present": False, "tag_found": None, "final_url": final_url, "error": None}


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
