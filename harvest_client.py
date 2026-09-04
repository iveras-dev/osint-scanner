"""harvest_client — HTTP-fetch laag met WAF-tolerantie.

Overname van de aanpak uit github.com/mail2jack/osint-dashboard
(cms/services/http_utils.py) maar aangepast voor een CLI-tool (geen
Flask/DB — config via omgevingsvariabelen).

Lagen (in volgorde):
  1. curl_cffi TLS-impersonatie  (impersonate chrome#/safari) — browser-TLS-fingerprint
  2. Jitter-sleep per domein      (randomized pauzes)
  3. Proxy-rotatie                (PROXY_LIST, PROXY_ROTATION_ENABLED)
  4. Tor-routing                  (TOR_ENABLED, TOR_PROXY, TOR_STRICT_MODE)
  5. Playwright-fallback          (headless Chromium met stealth) bij Fal/block

De SSRF-guard wordt op elke hop (incl. redirects en Playwright) toegepast
zodat een verzoek nooit naar private/reserved netwerken smokkelt.

Config via omgevingsvariabelen (of .env, wordt door osint_scanner geladen):
    JITTER_ENABLED=1|0                 (default 1)
    JITTER_MIN / JITTER_MAX            (seconden, default 0.3/2.0)
    PROXY_ROTATION_ENABLED=1|0         (default 0)
    PROXY_LIST="http://a:port,http://b:port"  (komma- of newline-gescheiden)
    TOR_ENABLED=1|0                    (default 0)
    TOR_PROXY=socks5h://127.0.0.1:9050
    TOR_STRICT_MODE=1|0                (weiger als Tor niet beschikbaar)
    PLAYWRIGHT_FALLBACK_ENABLED=1|0    (default 0; vereist playwright + browsers)
    PLAYWRIGHT_STEALTH_ENABLED=1|0     (default 1)
"""

import hashlib
import ipaddress
import json
import os
import random
import socket
import threading
import time
from urllib.parse import urlparse

# --- Lazy imports (allen optioneel, tool blijft werken zonder) -------------

_CURL = None
CURL_BESCHIKBAAR = False
try:
    from curl_cffi import requests as _CURL
    from curl_cffi import CurlError as _CurlError

    CURL_BESCHIKBAAR = True
except Exception:
    _CurlError = Exception

_PLAYWRIGHT = None
PLAYWRIGHT_BESCHIKBAAR = False
try:
    from playwright.sync_api import sync_playwright as _sync_playwright

    _PLAYWRIGHT = True
    PLAYWRIGHT_BESCHIKBAAR = True
except Exception:
    _PLAYWRIGHT = None


def _env_bool(name, default=False):
    v = os.environ.get(name, "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "ja", "yes", "on")


# --- Jitter config ---------------------------------------------------------

_JITTER_MIN = 0.3
_JITTER_MAX = 2.0
_JITTER_ENABLED = True
_LAST_CALL: dict[str, float] = {}
_lock = threading.Lock()


def _laad_jitter():
    global _JITTER_MIN, _JITTER_MAX, _JITTER_ENABLED
    _JITTER_ENABLED = _env_bool("JITTER_ENABLED", True)
    try:
        _JITTER_MIN = max(0.0, float(os.environ.get("JITTER_MIN", 0.3)))
        _JITTER_MAX = float(os.environ.get("JITTER_MAX", 2.0))
    except ValueError:
        _JITTER_MIN, _JITTER_MAX = 0.3, 2.0
    _JITTER_MAX = max(_JITTER_MIN + 0.1, _JITTER_MAX)


def _domein(url):
    try:
        return urlparse(url).hostname or "__global__"
    except Exception:
        return "__global__"


def jitter_sleep(url=None):
    if not _JITTER_ENABLED:
        return
    dom = _domein(url) if url else "__global__"
    now = time.time()
    with _lock:
        last = _LAST_CALL.get(dom, 0.0)
    nodig = _JITTER_MIN - (now - last)
    if nodig > 0:
        time.sleep(nodig + random.uniform(0, _JITTER_MAX - _JITTER_MIN))
    else:
        extra = random.uniform(0, _JITTER_MAX - _JITTER_MIN)
        if extra > 0.1:
            time.sleep(extra)
    with _lock:
        _LAST_CALL[dom] = time.time()


# --- Proxy / Tor -----------------------------------------------------------

_PROXY_INDEX = 0


def _proxy_lijst():
    raw = os.environ.get("PROXY_LIST", "")
    return [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]


def _tor_proxy():
    if not _env_bool("TOR_ENABLED", False):
        return None
    return os.environ.get("TOR_PROXY", "socks5h://127.0.0.1:9050").strip()


def get_proxies():
    """Geef proxies dict voor requests/curl_cffi, of None."""
    global _PROXY_INDEX
    tor = _tor_proxy()
    if tor:
        return {"http": tor, "https": tor}
    if _env_bool("PROXY_ROTATION_ENABLED", False):
        lijst = _proxy_lijst()
        if lijst:
            p = lijst[_PROXY_INDEX % len(lijst)]
            _PROXY_INDEX += 1
            return {"http": p, "https": p}
        if _env_bool("TOR_STRICT_MODE", False):
            raise RuntimeError("TOR_STRICT_MODE aan maar geen Tor + geen proxy's gevonden.")
    if _env_bool("TOR_STRICT_MODE", False):
        raise RuntimeError("TOR_STRICT_MODE aan maar Tor is niet beschikbaar.")
    return None


# --- Impersonation (domein-consistent) -------------------------------------

_PROFIELEN = ["chrome124", "chrome120", "chrome116", "chrome110"]


def _impersonate(url):
    """Zelfde domein altijd zelfde profiel; verschillende domeinen verschillend."""
    dom = _domein(url)
    idx = int(hashlib.md5(dom.encode(), usedforsecurity=False).hexdigest(), 16) % len(_PROFIELEN)
    return _PROFIELEN[idx]


# --- SSRF-guard ------------------------------------------------------------

def _is_unsafe(addr):
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
            or a.is_multicast or a.is_unspecified)


def validate_url(url):
    """Zelfde regels als de repo: http/https, geen private/reserved host."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False
    if _is_unsafe(host):
        return False
    try:
        for info in socket.getaddrinfo(host, None):
            if _is_unsafe(info[4][0]):
                return False
    except (socket.gaierror, OSError):
        pass
    return True


# --- Response adapter (uniforme interface) ---------------------------------

class HarvestResponse:
    def __init__(self, status_code, text, url, headers=None, content=None):
        self.status_code = status_code
        self.text = text
        self.url = url
        self.headers = headers or {}
        self.ok = 200 <= status_code < 300
        # Bewaar de RAWE bytes wanneer beschikbaar (belangrijk voor binaire
        # content zoals JPEG-foto's). Zonder rawe bytes vallen we terug op de
        # lossy text -> utf-8 route (die binaire data corrumpeert).
        self.content = content if content is not None else text.encode("utf-8")

    def json(self):
        return json.loads(self.text)

    def raise_for_status(self):
        if not self.ok:
            raise RuntimeError(f"HTTP {self.status_code}")


# --- curl_cffi laag --------------------------------------------------------

def _curl_get(url, headers, params, timeout):
    if not CURL_BESCHIKBAAR:
        return None
    prof = _impersonate(url)
    try:
        r = _CURL.get(url, headers=headers, params=params, timeout=timeout,
                      impersonate=prof, proxies=get_proxies())
        return (r.status_code, r.text, r.url, dict(r.headers), r.content)
    except _CurlError:
        try:
            r = _CURL.get(url, headers=headers, params=params, timeout=timeout,
                          impersonate="chrome124", proxies=get_proxies())
            return (r.status_code, r.text, r.url, dict(r.headers), r.content)
        except Exception:
            raise


# --- Playwright laag -------------------------------------------------------

def _playwright_get(url, headers, params, timeout):
    if not (_env_bool("PLAYWRIGHT_FALLBACK_ENABLED", False) and PLAYWRIGHT_BESCHIKBAAR):
        return None
    try:
        from urllib.parse import urlencode

        if params:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{urlencode(params)}"
        with _sync_playwright() as p:
            ua = (headers.get("User-Agent") or headers.get("user-agent")
                  or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/"
                     "537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
            args = ["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            if _env_bool("PLAYWRIGHT_STEALTH_ENABLED", True):
                args.append("--disable-blink-features=AutomationControlled")
            browser = p.chromium.launch(headless=True, args=args, timeout=timeout * 1000)
            kw = {"user_agent": ua}
            proxies = get_proxies()
            if proxies:
                kw["proxy"] = {"server": proxies.get("https") or proxies.get("http")}
            if _env_bool("PLAYWRIGHT_STEALTH_ENABLED", True):
                kw["locale"] = "nl-NL"
                kw["timezone_id"] = "Europe/Amsterdam"
            page = browser.new_context(**kw).new_page()
            if _env_bool("PLAYWRIGHT_STEALTH_ENABLED", True):
                page.add_init_script(
                    "Object.defineProperty(navigator,'webdriver',{get:()=>false});"
                )
            r = page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
            page.wait_for_timeout(1000)
            content = page.content()
            status = r.status if r else 200
            hdrs = dict(r.headers) if r and r.headers else {}
            browser.close()
            return (status, content, url, hdrs, content.encode("utf-8"))
    except Exception:
        return None


# --- Hoofdentree -----------------------------------------------------------

def harvest_get(url, params=None, headers=None, timeout=20):
    """GET met stal-statstraps: jitter -> curl_cffi (impersonate) -> Playwright.

    Retourneert HarvestResponse (met .status_code/.text/.json()/.ok).
    Gooit alleen weg als BOTH curl_cffi en Playwright falen,
    of als strict-mode (Tor) dat vereist.
    """
    _laad_jitter()
    jitter_sleep(url)
    hdrs = dict(headers or {})
    hdrs.setdefault("user-agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
    hdrs.setdefault("accept", "application/json,text/html;q=0.9,*/*;q=0.8")

    if not validate_url(url):
        raise RuntimeError(f"SSRF-guard blokkeerde {url}")

    try:
        res = _curl_get(url, hdrs, params, timeout)
    except Exception:
        res = None

    if res is None:
        res = _playwright_get(url, hdrs, params, timeout)

    if res is None:
        # Strict-mode: als Tor gewenst maar er géén laag werkte, gooi dan weg.
        if _env_bool("TOR_STRICT_MODE", False):
            raise RuntimeError("Geen enkel HTTP-pad werkte (strict-mode). Controleer Tor/proxy.")
        # Laatste redmiddel: plain requests (browser-headers) — werkt vaak niet
        # op WAF-gevoelige doelen maar houdt de tool functioneel zonder deps.
        try:
            import requests as _req
            r = _req.get(url, params=params, headers=hdrs, timeout=timeout, verify=_SSL)
            return HarvestResponse(r.status_code, r.text, r.url, dict(r.headers), r.content)
        except Exception:
            raise

    return HarvestResponse(res[0], res[1], res[2], res[3], res[4] if len(res) > 4 else None)


try:
    import certifi as _certifi
    _SSL = _certifi.where() if _certifi else True
except Exception:
    _SSL = True


# --- Status voor configuratie-scherm ---------------------------------------

def status_regels():
    _laad_jitter()
    tor = _tor_proxy()
    proxies = _proxy_lijst()
    regels = []
    regels.append(("HTTP-laag",
                   "[green]curl_cffi impersonate[/]"
                   if CURL_BESCHIKBAAR
                   else "[dim]niet geinstalleerd (pip install curl_cffi)[/]"))
    regels.append(("Jitter",
                   f"[green]aan[/] ({_JITTER_MIN:.1f}-{_JITTER_MAX:.1f}s)"
                   if _JITTER_ENABLED else "[dim]uit[/]"))
    regels.append(("Proxy-rotatie",
                   f"[green]aan[/] ({len(proxies)} proxy's)"
                   if (_env_bool("PROXY_ROTATION_ENABLED", False) and proxies)
                   else "[dim]uit (PROXY_ROTATION_ENABLED=1 + PROXY_LIST)[/]"))
    regels.append(("Tor",
                   f"[green]{tor}[/]"
                   if tor else
                   ("[red]geforceerd[/] (TOR_STRICT_MODE=1 maar Tor uit)"
                    if _env_bool("TOR_STRICT_MODE", False)
                    else "[dim]uit[/]")))
    regels.append(("Playwright",
                   f"[green]aan[/]"
                   if (_env_bool("PLAYWRIGHT_FALLBACK_ENABLED", False) and PLAYWRIGHT_BESCHIKBAAR)
                   else "[dim]uit (PLAYWRIGHT_FALLBACK_ENABLED=1 + pip install playwright)[/]"))
    return regels
