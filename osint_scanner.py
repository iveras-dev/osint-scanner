#!/usr/bin/env python3
"""
OSINT Scanner - zoekt via de Brave Search API of ddgs (DuckDuckGo), met kleurrijke CLI.

Vereisten:
    pip install ddgs requests rich pycountry holehe
    curl_cffi (optioneel, maar aanbevolen) voor politie-API's die door Akamai
        alleen op echte browser-TLS-vingerafdrukken reageren (impersonate).

Optioneel (in .env of als omgevingsvariabele):
    BRAVE_API_KEY=...       # https://brave.com/search/api -> gratis plan (2000 queries/maand)
    HIBP_API_KEY=...        # https://haveibeenpwned.com/API/Key - datalekcheck bij e-mailonderzoek
    GITHUB_TOKEN=...        # https://github.com/settings/tokens - hogere quota + code-search
    OVERHEID_IO_API_KEY=... # https://overheid.io -> gratis account, KVK-handelsregister (OpenKvK-dataset)
    INTERPOL_SNEL=1         # versnelt Interpol-zoekopdrachten (kortere pauzes; iets agressiever)

Geen proxy's, geen CAPTCHA-bypass; ingebouwde pauzes houden het netjes bij kleine volumes.
"""

import base64
import glob
import html
import json
import math
import os
import platform
import random
import re
import secrets
import socket
import subprocess
import time
import uuid
import urllib.parse
import warnings
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import threading

import requests
try:
    import pycountry
except ImportError:
    pycountry = None
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
# Interne bibliotheek-ruis dempen (zorgt niet voor verwarring bij de gebruiker)
warnings.filterwarnings(
    "ignore",
    message="Some characters could not be decoded",
)
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        DDGS = None

try:
    from holehe.core import import_submodules as _holehe_submodules
    HOLEHE_BESCHIKBAAR = True
except ImportError:
    HOLEHE_BESCHIKBAAR = False

try:
    import certifi
except ImportError:
    certifi = None

# SSL-fix: aiohttp (Maigret/socid HTTP-clients) vertrouwt op OpenSSL-cabundle.
# Op macOS/Python 3.12 faalt dat met SSLCertVerificationError. Gebruik certifi.
if certifi is not None:
    import os as _os
    _os.environ.setdefault("SSL_CERT_FILE", certifi.where())

try:
    import socid_extractor as _socid
    SOCID_BESCHIKBAAR = True
except ImportError:
    SOCID_BESCHIKBAAR = False

try:
    import harvest_client as _harvest
    HARVEST_BESCHIKBAAR = True
except ImportError:
    _harvest = None
    HARVEST_BESCHIKBAAR = False

try:
    import asyncio as _asyncio
    import logging as _logging
    from maigret import search as _maigret_search
    from maigret.sites import MaigretDatabase as _MaigretDatabase
    from importlib import resources as _importlib_resources
    MAIGRET_BESCHIKBAAR = True
except ImportError:
    MAIGRET_BESCHIKBAAR = False

DDGS_VERIFY = certifi.where() if certifi else True

console = Console()


def laad_env_bestand(pad=".env"):
    if not os.path.exists(pad):
        return
    with open(pad, encoding="utf-8") as f:
        for regel in f:
            regel = regel.strip()
            if not regel or regel.startswith("#") or "=" not in regel:
                continue
            sleutel, _, waarde = regel.partition("=")
            os.environ.setdefault(sleutel.strip(), waarde.strip().strip('"').strip("'"))


laad_env_bestand()

BRAVE_API_KEY = os.environ.get("BRAVE_API_KEY", "").strip()
HIBP_API_KEY = os.environ.get("HIBP_API_KEY", "").strip()
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
OPENHEID_API_KEY = os.environ.get("OVERHEID_IO_API_KEY", "").strip()

INTERPOL_SNEL = os.environ.get("INTERPOL_SNEL", "").strip().lower() in ("1", "true", "ja", "yes")
INTERPOL_PAUZE = 0.06 if INTERPOL_SNEL else 0.3
INTERPOL_PAUZE_TUSSEN = 0.1 if INTERPOL_SNEL else 0.5

HIBP_ENDPOINT = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
GITHUB_USERS_ENDPOINT = "https://api.github.com/search/users"
GITHUB_CODE_ENDPOINT = "https://api.github.com/search/code"
BRAVE_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"

USER_AGENT = "osint-scanner/1.0 (legitiem OSINT onderzoek)"

# ---------------------------------------------------------------------------
# Licentie-registratie + update-check (optionele telemetrie, uitschakelbaar)
# ---------------------------------------------------------------------------
LICENSE_SERVER = os.environ.get("OSINT_LICENSE_SERVER", "https://license.iveras.com")
UPDATE_REPO = os.environ.get("OSINT_UPDATE_REPO", "iveras-dev/osint-scanner")
UPDATE_BRANCH = os.environ.get("OSINT_UPDATE_BRANCH", "main")
SCANNER_DIR = os.path.dirname(os.path.abspath(__file__))
_update_resultaat = None
_update_cache = {"cached_at": 0.0, "data": None}
_scanversie = None


def _telemetrie_uit() -> bool:
    """Telemetrie/licentie-registratie expliciet uitgeschakeld via .env of env."""
    return os.environ.get("OSINT_NO_TELEMETRY", "").strip().lower() in (
        "1", "true", "ja", "yes", "aan",
    )


def _versie_lokaal() -> str:
    global _scanversie
    if _scanversie:
        return _scanversie
    try:
        with open(os.path.join(SCANNER_DIR, "VERSION"), encoding="utf-8") as f:
            _scanversie = (f.read().strip() or "0.0.0")
    except Exception:
        _scanversie = "0.0.0"
    return _scanversie


def _cfg_pad() -> str:
    return os.path.join(os.path.expanduser("~"), ".osint_scanner", "config.json")


def _lees_cfg() -> dict:
    try:
        with open(_cfg_pad(), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _schrijf_cfg(cfg: dict) -> None:
    try:
        pad = _cfg_pad()
        os.makedirs(os.path.dirname(pad), exist_ok=True)
        tmp = pad + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, pad)
        try:
            os.chmod(pad, 0o600)
        except Exception:
            pass
    except Exception:
        pass


def _laad_of_maak_install() -> tuple[str, str]:
    """Install-ID + uniek token; blijft buiten de repo (onder de homepage)."""
    cfg = _lees_cfg()
    gewijzigd = False
    install_id = cfg.get("install_id")
    token = cfg.get("install_token")
    if not install_id:
        install_id = uuid.uuid4().hex
        cfg["install_id"] = install_id
        gewijzigd = True
    if not token:
        token = secrets.token_urlsafe(32)
        cfg["install_token"] = token
        gewijzigd = True
    if gewijzigd:
        _schrijf_cfg(cfg)
    return install_id, token


def _licentie_register() -> bool:
    """Registreer deze installatie (max. 1x/dag) bij license.iveras.com.

    Nooit blokkerend-van-de-tool: elke fout wordt stilgevangen. Gebruiker kan
    alles uitschakelen met OSINT_NO_TELEMETRY=1 in .env.
    """
    if _telemetrie_uit():
        return False
    try:
        cfg = _lees_cfg()
        vandaag = datetime.now().strftime("%Y-%m-%d")
        if cfg.get("last_telemetry") == vandaag:
            return True
        install_id, token = _laad_of_maak_install()
        info = {
            "app": "osint-scanner",
            "versie": _versie_lokaal(),
            "os": platform.system(),
            "platform": platform.platform(),
            "python": platform.python_version(),
        }
        r = requests.post(
            LICENSE_SERVER + "/api/register",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Install-ID": install_id,
                "User-Agent": USER_AGENT,
            },
            json={"install_id": install_id, "info": info},
            timeout=8,
        )
        if r.status_code < 300:
            cfg["last_telemetry"] = vandaag
            _schrijf_cfg(cfg)
            return True
    except Exception:
        pass
    return False


def _licentie_register_achtergrond() -> None:
    """Registreert in een daemon-thread zodat de menustart nooit wacht."""
    threading.Thread(target=_licentie_register, daemon=True).start()


def _fetch_txt(url: str, timeout: float = 5.0):
    r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout)
    r.raise_for_status()
    return r.text.strip()


def _fetch_sha(url: str, timeout: float = 5.0):
    r = requests.get(
        url,
        headers={"Accept": "application/vnd.github.v3.sha", "User-Agent": USER_AGENT},
        timeout=timeout,
    )
    if r.status_code == 403:
        return None  # GitHub-API rate-limit: versie-vergelijking werkt dan nog
    r.raise_for_status()
    return r.text.strip()


def _git_sha_lokaal() -> str | None:
    try:
        git = _welke("git") or "/usr/bin/git"
        r = subprocess.run(
            [git, "rev-parse", "HEAD"],
            capture_output=True, text=True, cwd=SCANNER_DIR, timeout=10,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception:
        pass
    return None


def _welke(naam: str) -> str | None:
    import shutil

    return shutil.which(naam)


def _check_update(force: bool = False) -> dict:
    """Vergelijkt lokale VERSION + git-SHA met GitHub (branch `main`).

    Resultaat wordt 1 uur gecached. Nooit crashend; bij gebrek aan netwerk of
    github blokkades is dit slechts een stil gemist overzicht (banner blijft weg).
    """
    global _update_cache, _update_resultaat
    nu = time.time()
    if not force and _update_cache.get("cached_at") and (nu - _update_cache["cached_at"]) < 3600:
        return _update_cache["data"]

    resultaat = {
        "update_beschikbaar": False,
        "huidige_versie": _versie_lokaal(),
        "nieuwste_versie": None,
        "huidige_sha": _git_sha_lokaal(),
        "nieuwste_sha": None,
        "check_enabled": not _telemetrie_uit(),
    }

    if _telemetrie_uit():
        resultaat["melding"] = "Update-check uitgeschakeld (OSINT_NO_TELEMETRY)."
        _update_cache = {"cached_at": nu, "data": resultaat}
        _update_resultaat = resultaat
        return resultaat

    versie_url = (
        f"https://raw.githubusercontent.com/{UPDATE_REPO}/{UPDATE_BRANCH}/VERSION"
    )
    api_url = f"https://api.github.com/repos/{UPDATE_REPO}/commits/{UPDATE_BRANCH}"
    try:
        with ThreadPoolExecutor(max_workers=2) as ex:
            fv = ex.submit(_fetch_txt, versie_url)
            fs = ex.submit(_fetch_sha, api_url)
            try:
                resultaat["nieuwste_versie"] = fv.result(timeout=6)
            except Exception:
                resultaat["nieuwste_versie"] = None
            try:
                resultaat["nieuwste_sha"] = fs.result(timeout=6)
            except Exception:
                resultaat["nieuwste_sha"] = None
    except Exception:
        pass

    if (
        resultaat["nieuwste_sha"]
        and resultaat["huidige_sha"]
        and resultaat["nieuwste_sha"] != resultaat["huidige_sha"]
    ):
        resultaat["update_beschikbaar"] = True
    elif (
        not resultaat["nieuwste_sha"]
        and resultaat["nieuwste_versie"]
        and resultaat["nieuwste_versie"] not in ("", resultaat["huidige_versie"])
    ):
        # Git-SHA onbekend (bijv. ZIP-install): val terug op versie-vergelijking
        versie_lager = _versie_nummer_verschilt(
            resultaat["nieuwste_versie"], resultaat["huidige_versie"]
        )
        resultaat["update_beschikbaar"] = bool(versie_lager)

    _update_cache = {"cached_at": nu, "data": resultaat}
    _update_resultaat = resultaat
    return resultaat


def _versie_nummer_verschilt(nieuw: str, oud: str) -> bool:
    def _niet(n):
        try:
            return [int(x) for x in re.findall(r"\d+", n)][:3]
        except Exception:
            return []

    n, o = _niet(nieuw), _niet(oud)
    return n and o and (n > o)


def _update_banner():
    """Rich-Panel dat in het hoofdmenu verschijnt als er een update klaarstaat."""
    u = _update_resultaat or {}
    if not u.get("update_beschikbaar"):
        return None
    versie_tekst = ""
    if (
        u.get("huidige_versie")
        and u.get("nieuwste_versie")
        and u["huidige_versie"] != u["nieuwste_versie"]
    ):
        versie_tekst = f" (v{u['huidige_versie']} → v{u['nieuwste_versie']})"
    return Panel(
        f"[bold yellow]\u2191 Update beschikbaar{versie_tekst}[/]\n"
        "[dim]Er is een nieuwe versie van OSINT Scanner op GitHub "
        "gepubliceerd.[/] Druk [bold cyan]U[/] om de update te installeren.",
        title="[bold green]Update[/]",
        border_style="green",
        padding=(0, 1),
    )


def _voer_update_uit() -> None:
    """Menu-optie U: git pull --ff-only + hertoetsen (geen commit, geen push)."""
    global _update_resultaat
    try:
        git = _welke("git")
        if not git:
            console.print(
                "[red]Git is niet geinstalleerd. Download de nieuwste versie "
                "opnieuw van GitHub (repo iveras-dev/osint-scanner).[/]"
            )
            return
        r = subprocess.run(
            [git, "-C", SCANNER_DIR, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode != 0:
            console.print(
                "[red]Deze installatie is geen git-repository (bijv. een "
                "ZIP-download). Download de nieuwste versie opnieuw of clonen. "
                "Repo: iveras-dev/osint-scanner[/]"
            )
            return
        console.print("[cyan]Git-pull uitvoeren...[/]")
        pr = subprocess.run(
            [git, "-C", SCANNER_DIR, "pull", "--ff-only"],
            capture_output=True, text=True, timeout=180,
        )
        uitvoer = (pr.stdout + pr.stderr).strip()
        if uitvoer:
            console.print(uitvoer)
        if pr.returncode == 0:
            console.print(
                "[green]✔ Update toegepast. Herstart de scanner "
                "(uitvoeren van [bold]Q[/] en opnieuw ./start.sh of start.bat) "
                "om de nieuwe versie te laden.[/]"
            )
            _update_resultaat = _check_update(force=True)
        else:
            console.print(
                "[red]Update mislukt — controleer de git-status "
                "([bold]git status[/]) en los het conflict handmatig op.[/]"
            )
    except Exception as e:
        console.print(f"[red]Update mislukt: {e}[/]")

SOCIAL_HOSTS = {
    "twitter.com": "X / Twitter",
    "mobile.twitter.com": "X / Twitter",
    "x.com": "X / Twitter",
    "instagram.com": "Instagram",
    "facebook.com": "Facebook",
    "tiktok.com": "TikTok",
    "threads.net": "Threads",
    "linkedin.com": "LinkedIn",
    "youtube.com": "YouTube",
    "reddit.com": "Reddit",
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "t.me": "Telegram",
    "mastodon.social": "Mastodon",
    "mastodon.online": "Mastodon",
    "bsky.app": "Bluesky",
    "pinterest.com": "Pinterest",
    "twitch.tv": "Twitch",
    "flickr.com": "Flickr",
    "strava.com": "Strava",
    "patreon.com": "Patreon",
    "spotify.com": "Spotify",
    "soundcloud.com": "SoundCloud",
    "tumblr.com": "Tumblr",
    "odysee.com": "Odysee",
    "behance.net": "Behance",
    "dribbble.com": "Dribbble",
}

GEEN_PROFIEL_FRAGMENTEN = (
    "/intent/", "/share", "/sharer", "/dialog", "/plugins", "/login", "/signup",
    "/home", "/search", "/hashtag/", "/explore/", "/p/", "/reel", "/watch",
    "/shorts/", "/topic/", "/status/", "/comments/", "/post/", "/questions/",
    "/tags/", "/categories/", "/wiki/", "/blob/", "/tree/", "/commit/",
)

GITHUB_RESERVERD = {
    "about", "pricing", "security", "features", "topics", "collections",
    "trending", "marketplace", "sponsors", "settings", "notifications",
    "orgs", "apps", "site", "developer", "enterprise", "search", "gist",
    "join", "customers", "events", "education", "team", "readme", "new",
}

URL_RE = re.compile(r'https?://[^\s"\'<>()\[\]{}]+')

BANNER = r"""
 ██████╗ ███████╗██╗███╗   ██╗████████╗
 ██╔══██╗██╔════╝██║████╗  ██║╚══██╔══╝
 ██████╔╝███████╗██║██╔██╗ ██║   ██║
 ██╔══██╗╚════██║██║██║╚██╗██║   ██║
 ██║  ██║███████║██║██║ ╚████║   ██║
 ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝
"""


_laaste_brave_tijd = [0.0]
BRAVE_MIN_INTERVAL = 1.15

# Telstatistieken voor het Instellingen-scherm:
#  - BRAVE_EXACT_NUL: hoe vaak een exact-frase-query ("...") 0 resultaten
#    gaf bij Brave (zonder dat de quotes-hertkans dit oplost).
#  - BRAVE_FALLBACK_TELLER: hoe vaak `web_zoekopdracht` doorviel op DDG
#    omdat Brave uiteindelijk niets opleverde.
BRAVE_EXACT_NUL = [0]
BRAVE_FALLBACK_TELLER = [0]
BRAVE_FALLBACK_LAATST = [""]


def _brave_throttle():
    wacht = BRAVE_MIN_INTERVAL - (time.time() - _laaste_brave_tijd[0])
    if wacht > 0:
        time.sleep(wacht)
    _laaste_brave_tijd[0] = time.time()


def brave_zoekopdracht(query):
    headers = {
        "Accept": "application/json",
        "X-Subscription-Token": BRAVE_API_KEY,
    }

    resultaten = _brave_doe_query(query, headers)
    # Brave's gratis tier geeft bij exact-frase queries ("...") voor
    # persoonsnamen vaak 0 resultaten. Retry dan zonder de quotes zodat
    # we wél resultaten krijgen i.p.v. te blijven vallen op DuckDuckGo.
    if not resultaten and '"' in query:
        console.print("[dim]Brave: exact-frase gaf 0 -> probeer zonder aanhalingstekens...[/]")
        zoekterm = re.sub(r'"', "", query)
        if zoekterm.strip() and zoekterm.strip() != query.strip():
            resultaten = _brave_doe_query(zoekterm, headers)
            for hit in resultaten:
                hit["bron"] = "Brave (zonder quotes)"
            # Tel elke exact-frase-0-gebeurtenis (bedoeld als inzicht dat
            # Brave exact-frase bij persoonsnamen vaak niets teruggeeft).
            BRAVE_EXACT_NUL[0] += 1
    return resultaten


def _brave_doe_query(query, headers):
    r = None
    for poging in range(3):
        _brave_throttle()
        try:
            r = requests.get(BRAVE_ENDPOINT, headers=headers,
                             params={"q": query, "count": 20}, timeout=15)
        except requests.RequestException as e:
            console.print(f"[red]Brave API onbereikbaar:[/] {e}")
            return []

        if r.status_code == 429:
            wachttijd = min(int(r.headers.get("Retry-After", 2 ** poging * 2)), 30)
            console.print(f"[yellow]Brave-rate-limit - {wachttijd}s geduld ({poging + 1}/3)...[/]")
            time.sleep(wachttijd)
            r = None
            continue
        break

    if r is None:
        return []
    if r.status_code in (401, 403):
        console.print("[red]Brave API-key ongeldig.[/]")
        return []
    if r.status_code != 200:
        console.print(f"[red]Brave API fout {r.status_code}.[/]")
        return []

    resultaten = []
    for item in (r.json().get("web") or {}).get("results", [])[:20]:
        resultaten.append({
            "titel": item.get("title", "(geen titel)"),
            "link": item.get("url", ""),
            "omschrijving": item.get("description", "Geen omschrijving beschikbaar."),
            "bron": "Brave",
        })
    return resultaten


def ddgs_zoekopdracht(query):
    if DDGS is None:
        console.print("[red]'ddgs' niet geinstalleerd:[/] pip install ddgs")
        return None

    ruwe_resultaten = None
    fout = None
    for poging in range(2):
        try:
            with DDGS(verify=DDGS_VERIFY) as ddgs:
                ruwe_resultaten = list(ddgs.text(query, max_results=30))
            break
        except Exception as e:
            fout = e
            if poging == 0:
                time.sleep(random.uniform(3, 5))
    if ruwe_resultaten is None:
        hint = ""
        if "CERTIFICATE_VERIFY_FAILED" in str(fout):
            hint = (" (SSL-certificaatfout - draai: pip install certifi, "
                    "of herstart na: /Applications/Python 3.12/Install Certificates.command)")
        console.print(f"[red]Zoekopdracht mislukt ({fout}).[/] Ook na 1 retry - probeer later opnieuw.{hint}")
        return []

    time.sleep(random.uniform(2, 4))

    resultaten = []
    for r in ruwe_resultaten:
        link = r.get("href", "")
        if not link.startswith("http"):
            continue
        resultaten.append({
            "titel": r.get("title", "(geen titel)"),
            "link": link,
            "omschrijving": r.get("body", "Geen omschrijving beschikbaar."),
            "bron": "DuckDuckGo",
        })
    return resultaten


def web_zoekopdracht(query):
    if BRAVE_API_KEY:
        resultaten = brave_zoekopdracht(query)
        if resultaten:
            return resultaten
        BRAVE_FALLBACK_TELLER[0] += 1
        BRAVE_FALLBACK_LAATST[0] = time.strftime("%H:%M:%S")
        console.print("[dim]Val terug op DuckDuckGo...[/]")

    return ddgs_zoekopdracht(query)


def hibp_breaches(email):
    if not HIBP_API_KEY:
        return {"status": "overgeslagen", "melding": "Geen HIBP_API_KEY ingesteld.", "breaches": []}

    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "user-agent": USER_AGENT,
    }
    try:
        r = requests.get(HIBP_ENDPOINT.format(account=urllib.parse.quote(email)),
                         headers=headers, params={"truncateResponse": "false"}, timeout=15)
    except requests.RequestException as e:
        return {"status": "fout", "melding": f"API onbereikbaar: {e}", "breaches": []}

    if r.status_code == 404:
        return {"status": "schoon", "melding": "Geen bekende gelekte data voor dit adres.", "breaches": []}
    if r.status_code == 401:
        return {"status": "overgeslagen", "melding": "HIBP-API-key ongeldig of zonder account-lookup rechten.", "breaches": []}
    if r.status_code == 429:
        return {"status": "fout", "melding": "HIBP-rate-limit bereikt, probeer later opnieuw.", "breaches": []}
    if r.status_code != 200:
        return {"status": "fout", "melding": f"HTTP {r.status_code}", "breaches": []}

    breaches = sorted(r.json(), key=lambda b: b.get("BreachDate", ""), reverse=True)
    compact = [{
        "naam": b.get("Name", "?"),
        "datum": b.get("BreachDate", "?"),
        "gegevens": ", ".join(b.get("DataClasses", [])),
        "geverifieerd": bool(b.get("IsVerified")),
    } for b in breaches]
    return {"status": "getroffen", "melding": f"{len(compact)} bekende datalekken gevonden.", "breaches": compact}


HOLEHE_SITES = {
    "aboutme": "about.me",
    "adobe": "Adobe",
    "amazon": "Amazon",
    "bitmoji": "Snapchat Bitmoji",
    "buymeacoffee": "BuyMeACoffee",
    "codepen": "CodePen",
    "devrant": "devRant",
    "discord": "Discord",
    "ebay": "eBay",
    "ello": "Ello",
    "eventbrite": "Eventbrite",
    "flickr": "Flickr",
    "github": "GitHub",
    "google": "Google (Gmail)",
    "imgur": "Imgur",
    "instagram": "Instagram",
    "lastfm": "Last.fm",
    "lastpass": "LastPass",
    "mail_ru": "Mail.ru",
    "myspace": "MySpace",
    "odnoklassniki": "Odnoklassniki",
    "parler": "Parler",
    "patreon": "Patreon",
    "pinterest": "Pinterest",
    "protonmail": "ProtonMail",
    "quora": "Quora",
    "replit": "Replit",
    "snapchat": "Snapchat",
    "soundcloud": "SoundCloud",
    "spotify": "Spotify",
    "strava": "Strava",
    "tellonym": "Tellonym",
    "tumblr": "Tumblr",
    "twitter": "X / Twitter",
    "venmo": "Venmo",
    "vivino": "Vivino",
    "vsco": "VSCO",
    "wattpad": "Wattpad",
    "wordpress": "WordPress",
    "xing": "Xing",
    "yahoo": "Yahoo",
}


def email_account_check(email):
    """Checkt via holehe bij 40+ platforms of een e-mailadres is geregistreerd.

    Modules die een onduidelijk (rate-gelimiteerd) antwoord geven, worden een
    paar keer opnieuw geprobeerd; dat haalt veel "onbekend"-resultaten weg.
    """
    import contextlib
    import io

    if not HOLEHE_BESCHIKBAAR:
        return {"status": "overgeslagen",
                "melding": "holehe niet geinstalleerd (draai: pip install holehe)",
                "sites": []}
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return {"status": "fout", "melding": "Ongeldig e-mailadres.", "sites": []}
    try:
        import httpx
        import trio
        from holehe.core import import_submodules, launch_module
    except ImportError:
        return {"status": "fout", "melding": "holehe-dependencies ontbreken (pip install holehe).", "sites": []}

    def _functies_voor(mods, namen):
        gekozen = []
        for pad, modu in mods.items():
            if len(pad.split(".")) > 3:
                site = pad.split(".")[-1]
                if site in namen:
                    gekozen.append(modu.__dict__[site])
        return gekozen

    async def _runner(functies):
        client = httpx.AsyncClient(timeout=10)
        out = []
        async with trio.open_nursery() as nursery:
            for fn in functies:
                nursery.start_soon(launch_module, fn, email, client, out)
        await client.aclose()
        return out

    try:
        with contextlib.redirect_stderr(io.StringIO()):
            mods = import_submodules("holehe.modules")
            eerste_keer = _functies_voor(mods, set(HOLEHE_SITES))
            ruw = trio.run(_runner, eerste_keer)
            actueel = {r.get("name"): r for r in ruw}
            # retry-passes: alleen tijdelijke/onduidelijke limieten (niet "frequent")
            for _ in range(2):
                onduidelijk = [n for n, r in actueel.items()
                               if r.get("rateLimit") and not r.get("frequent_rate_limit")]
                if not onduidelijk:
                    break
                time.sleep(random.uniform(1.2, 2.5))
                extra = trio.run(_runner, _functies_voor(mods, onduidelijk))
                for r in extra:
                    naam = r.get("name")
                    vorig = actueel.get(naam)
                    nieuwer = (vorig is None
                               or (not r.get("rateLimit") and not r.get("exists"))
                               or r.get("exists"))
                    # versla alleen als er meer zekerheid is, anders behouden we de laatste stand
                    if nieuwer or (not vorig.get("rateLimit")):
                        actueel[naam] = r
    except Exception as exc:
        return {"status": "fout", "melding": f"holehe-check mislukt: {exc}", "sites": []}

    sites = []
    gevonden = onbekend = 0
    for naam, r in actueel.items():
        account = bool(r.get("exists"))
        if account:
            gevonden += 1
        blijft_onbekend = bool(r.get("rateLimit")) and not account
        if blijft_onbekend:
            onbekend += 1
        details = []
        if r.get("emailrecovery"):
            details.append(f"herstelmail: {r.get('emailrecovery')}")
        if r.get("phoneNumber"):
            details.append(f"telefoon: {r.get('phoneNumber')}")
        for sleutel in ("username", "accountId", "fullName", "displayName", "name", "id"):
            waarde = (r.get("others") or {}).get(sleutel)
            if waarde:
                details.append(f"{sleutel}: {waarde}")
        sites.append({
            "naam": HOLEHE_SITES.get(naam, naam.replace("_", " ").title()),
            "site": naam,
            "account": account,
            "rate_limit": blijft_onbekend,
            "frequent": bool(r.get("frequent_rate_limit")),
            "details": ", ".join(details),
        })
    sites.sort(key=lambda x: (not x["account"], x["rate_limit"], x["naam"]))
    melding = f"{len(sites)} platforms gecontroleerd, {gevonden} met een account"
    if onbekend:
        melding += f", {onbekend} onbekend (handmatig controleren)"
    return {"status": "ok", "melding": melding, "sites": sites, "gevonden": gevonden}


def github_lookup(zoekterm):
    headers = {"Accept": "application/vnd.github+json", "user-agent": USER_AGENT}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"

    uitkomst = {"profielen": [], "code": [], "code_melding": ""}

    try:
        r = requests.get(GITHUB_USERS_ENDPOINT, headers=headers,
                         params={"q": zoekterm, "per_page": 10}, timeout=15)
        if r.status_code == 200:
            uitkomst["profielen"] = [{
                "login": u.get("login", ""),
                "url": u.get("html_url", ""),
                "type": u.get("type", ""),
                "score": round(u.get("score", 0), 2),
            } for u in r.json().get("items", [])]
        elif r.status_code == 403:
            console.print("[yellow]GitHub-rate-limit bereikt; voeg een GITHUB_TOKEN toe voor meer quota.[/]")
    except requests.RequestException as e:
        console.print(f"[red]GitHub onbereikbaar:[/] {e}")

    if GITHUB_TOKEN:
        try:
            r = requests.get(GITHUB_CODE_ENDPOINT, headers=headers,
                             params={"q": f'"{zoekterm}"', "per_page": 10}, timeout=15)
            if r.status_code == 200:
                uitkomst["code"] = [{
                    "bestand": i.get("name", ""),
                    "repo": i.get("repository", {}).get("full_name", ""),
                    "url": i.get("html_url", ""),
                } for i in r.json().get("items", [])]
            else:
                uitkomst["code_melding"] = f"Code-search HTTP {r.status_code}."
        except requests.RequestException as e:
            uitkomst["code_melding"] = f"Code-search mislukt: {e}"
    else:
        uitkomst["code_melding"] = "Code-search overgeslagen: geen GITHUB_TOKEN ingesteld."

    return uitkomst


def directe_social_checks(username):
    h = {"user-agent": USER_AGENT}
    gevonden = []

    def probeer(url):
        try:
            r = _harvest_get_of_none(url, headers=h, timeout=10)
            if r is not None:
                return r if r.status_code == 200 else None
            return None
        except Exception:
            return None

    r = probeer(f"https://api.github.com/users/{username}")
    if r is not None and r.status_code == 200:
        gevonden.append(("GitHub", f"https://github.com/{username}"))

    r = probeer("https://gitlab.com/api/v4/users?username=" + urllib.parse.quote(username))
    if r is not None and r.status_code == 200:
        try:
            data = r.json()
            if data:
                naam = data[0].get("username", username)
                gevonden.append(("GitLab", f"https://gitlab.com/{naam}"))
        except ValueError:
            pass

    r = probeer(f"https://www.reddit.com/user/{username}/about.json")
    if r is not None and r.status_code == 200:
        try:
            naam = r.json().get("data", {}).get("name", username)
            gevonden.append(("Reddit", f"https://www.reddit.com/user/{naam}"))
        except ValueError:
            pass

    r = probeer(f"https://t.me/{username}")
    if r is not None and r.status_code == 200 and "tgme_page_title" in r.text[:20000]:
        gevonden.append(("Telegram", f"https://t.me/{username}"))

    r = probeer(f"https://www.youtube.com/@{username}")
    if r is not None and r.status_code == 200 and '"channelId"' in r.text[:50000]:
        gevonden.append(("YouTube", f"https://www.youtube.com/@{username}"))

    r = probeer(f"https://keybase.io/{username}")
    if r is not None and r.status_code == 200 and "404-page" not in r.text[:20000]:
        gevonden.append(("Keybase", f"https://keybase.io/{username}"))

    r = probeer(f"https://hub.docker.com/v2/users/{urllib.parse.quote(username)}/")
    if r is not None and r.status_code == 200:
        gevonden.append(("Docker Hub", f"https://hub.docker.com/u/{username}"))

    r = probeer("https://mastodon.social/api/v1/accounts/lookup?acct=" + urllib.parse.quote(username))
    if r is not None and r.status_code == 200:
        try:
            if r.json().get("id"):
                gevonden.append(("Mastodon", f"https://mastodon.social/@{username}"))
        except ValueError:
            pass

    r = probeer("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor="
                + urllib.parse.quote(f"{username}.bsky.social"))
    if r is not None and r.status_code == 200:
        try:
            if r.json().get("did"):
                gevonden.append(("Bluesky", f"https://bsky.app/profile/{username}.bsky.social"))
        except ValueError:
            pass

    # LinkedIn (check of profiel bestaat via public profile redirect)
    r = probeer(f"https://www.linkedin.com/in/{username}")
    if r is not None and r.status_code == 200 and "profile-card" in r.text[:50000]:
        gevonden.append(("LinkedIn", f"https://www.linkedin.com/in/{username}"))

    # TikTok (check of gebruikerspagina laadt met hydratatie-JSON)
    r = probeer(f"https://www.tiktok.com/@{username}")
    if r is not None and r.status_code == 200 and "__UNIVERSAL_DATA_FOR_REHYDRATION__" in r.text[:100000]:
        gevonden.append(("TikTok", f"https://www.tiktok.com/@{username}"))

    # Pinterest (check of profiel laadt)
    r = probeer(f"https://www.pinterest.com/{username}/")
    if r is not None and r.status_code == 200 and not r.url.endswith("/login/"):
        gevonden.append(("Pinterest", f"https://www.pinterest.com/{username}/"))

    # Twitch (via officiele helix API - werkt zonder token voor channelCheck)
    r = probeer("https://api.twitch.tv/helix/users?login=" + urllib.parse.quote(username))
    if r is not None and r.status_code == 200 and '"data":"' in r.text:
        pass  # API werkt niet zonder Client-ID
    r = probeer(f"https://www.twitch.tv/{username}")
    if r is not None and r.status_code == 200 and 'isLiveBroadcast' not in r.text[:5000]:
        # Twitch pagina's zonder channel zijn redirects naar zelfde domein met andere content
        pass  # Twitch blokkeert directe checks meestal

    # Mastodon op meerdere instanties
    for instantie in ("mastodon.social", "mastodon.online", "mastodon.world",
                      "mastodon.nl", "mstdn.social", "fosstodon.org"):
        r = probeer(f"https://{instantie}/api/v1/accounts/lookup?acct=" + urllib.parse.quote(username))
        if r is not None and r.status_code == 200:
            try:
                if r.json().get("id"):
                    gevonden.append(("Mastodon", f"https://{instantie}/@{username}"))
                    break
            except ValueError:
                pass

    # Patreon (check of creatorpagina laadt)
    r = probeer(f"https://www.patreon.com/{username}")
    if r is not None and r.status_code == 200 and "patreon" in r.text.lower() and ("pledge" in r.text.lower() or "creator" in r.text.lower()):
        gevonden.append(("Patreon", f"https://www.patreon.com/{username}"))

    # Spotify (offciele API vereist token, directe check niet mogelijk zonder)

    return gevonden


def classificeer_social_url(url):
    try:
        delen = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return None
    if delen.scheme not in ("http", "https"):
        return None
    host = delen.netloc.lower().split(":")[0]

    platform = None
    for domein, naam in SOCIAL_HOSTS.items():
        if host == domein or host.endswith("." + domein):
            platform = naam
            break
    if not platform:
        return None

    pad = urllib.parse.unquote(delen.path.rstrip("/"))
    segments = [s for s in pad.split("/") if s]
    laag = pad.lower()

    if any(x in laag for x in GEEN_PROFIEL_FRAGMENTEN):
        return None
    if not segments:
        return None
    if platform == "GitHub" and (len(segments) != 1 or segments[0].lower() in GITHUB_RESERVERD):
        return None
    if platform == "LinkedIn" and segments[0] != "in":
        return None
    if platform == "Reddit" and segments[0] not in ("user", "u"):
        return None
    if platform == "TikTok" and not segments[0].startswith("@"):
        return None

    return platform, f"https://{delen.netloc}{pad}"


def _platform_gebruiksnaam_uit_url(url):
    """Haalt de gebruikersnaam uit een social media profiel-URL (loose versie)."""
    try:
        platf, user = _parse_platform_username(url)
    except Exception:
        platf, user = None, None
    if user:
        return user.lower()
    try:
        pad = urllib.parse.urlsplit(url).path.rstrip("/")
        seg = [s for s in pad.split("/") if s]
        return (seg[-1].lstrip("@") if seg else "").lower() or None
    except Exception:
        return None


def _naam_matcht_doelwit(profiel_naam, doelwit):
    """Controleert of een profielnaam naar het doelwit verwijst.

    Voorkomt dat eigen-account/footer-ruis van een gecrawlde pagina (bv.
    twitter.com/stackoverflow op een StackOverflow-pagina) als relevant
    profiel wordt meegeteld. Alleen sociale accounts die (gedeeltelijk)
    overeenkomen met de gezochte gebruikersnaam/naam worden behouden.
    """
    if not profiel_naam or not doelwit:
        return False
    p = profiel_naam.lower().replace("_", "").replace("-", "")
    d = doelwit.lower().replace("_", "").replace("-", "").lstrip("@")
    if not p or not d:
        return False
    if p == d:
        return True
    # Doelwit is beginstuk van profielnaam of omgekeerd (bv. irversteegh -> irversteeghX).
    # Vereist minimaal 4 tekens in het kortste deel om irrelevante matches te mijden.
    if p.startswith(d) or d.startswith(p):
        return len(min(p, d, key=len)) >= 4
    return False


def analyseer_pagina_op_socials(url, max_bytes=300000):
    try:
        r = _harvest_get_of_none(url, headers={"user-agent": USER_AGENT}, timeout=10)
        if r is not None and r.status_code != 200:
            r = None
    except Exception:
        r = None
    if r is None or len(r.text) < 100:
        return {}

    gevonden = {}
    for match in URL_RE.findall(r.text[:max_bytes]):
        c = classificeer_social_url(match)
        if c:
            platform, canon = c
            gevonden.setdefault(platform, set()).add(canon)
    return gevonden


def social_media_scan(username, bron_urls, max_paginas=8):
    ruwe_profielen = []

    for platform, url in directe_social_checks(username):
        ruwe_profielen.append({"platform": platform, "url": url, "bron": "directe check (bestaat)"})

    te_crawleren = list(dict.fromkeys(bron_urls))[:max_paginas]
    doelwit_naam = username.lower().lstrip("@").strip()
    for i, url in enumerate(te_crawleren, 1):
        with console.status(f"[cyan]Resultaat analyseren {i}/{len(te_crawleren)}:[/] {urlsplit_netloc(url)}", spinner="dots"):
            per_platform = analyseer_pagina_op_socials(url)
        time.sleep(random.uniform(1, 2))
        for platform, urls in per_platform.items():
            for u in urls:
                # Filter eigen-account / footer-ruis: neem alleen sociale profielen
                # mee die verwijzen naar het doelwit. Platforms/werven zoals de
                # StackOverflow-pagina linken naar hun EIGEN Twitter/Facebook/etc.
                # (twitter.com/stackoverflow, instagram.com/thestackoverflow) —
                # die hebben niets met het doelwit te maken en zijn dode sporen.
                profiel_naam = _platform_gebruiksnaam_uit_url(u)
                if profiel_naam and not _naam_matcht_doelwit(profiel_naam, doelwit_naam):
                    continue
                ruwe_profielen.append({
                    "platform": platform,
                    "url": u,
                    "bron": f"gevonden via {urlsplit_netloc(url)}",
                })

    gezien = set()
    eindlijst = []
    for p in sorted(ruwe_profielen, key=lambda x: x["bron"] != "directe check (bestaat)"):
        sleutel = (p["platform"], p["url"].lower())
        if sleutel in gezien:
            continue
        gezien.add(sleutel)
        eindlijst.append(p)

    te_verifiëren = [p for p in eindlijst if not p["bron"].startswith("directe")][:15]
    if te_verifiëren:
        with console.status(f"[cyan]Verifiëren van {len(te_verifiëren)} social-profielen...[/]", spinner="dots"):
            for p in te_verifiëren:
                uitkomst = verifieer_social_profiel(p["platform"], p["url"])
                time.sleep(random.uniform(0.3, 0.8))
                if uitkomst is True:
                    p["bron"] = "directe check (bestaat)"
                elif uitkomst is False:
                    p["bron"] += " - NIET meer bereikbaar"
    return eindlijst


def urlsplit_netloc(url):
    try:
        return urllib.parse.urlsplit(url).netloc
    except ValueError:
        return url


SOCIAL_MEDIA_DOMAINS = {
    "linkedin.com": "LinkedIn",
    "x.com": "Twitter/X",
    "twitter.com": "Twitter/X",
    "facebook.com": "Facebook",
    "instagram.com": "Instagram",
    "youtube.com": "YouTube",
    "tiktok.com": "TikTok",
    "github.com": "GitHub",
    "reddit.com": "Reddit",
    "pinterest.com": "Pinterest",
    "threads.net": "Threads",
    "mastodon.social": "Mastodon",
    "bsky.app": "Bluesky",
    "t.me": "Telegram",
}


def detecteer_social_media_uit_resultaten(rapport):
    """Detecteert social media profielen uit DDG-zoekresultaten."""
    gevonden = []
    gezien = set()
    for data in rapport.values():
        for hit in data.get("hits", []):
            link = hit.get("link", "")
            try:
                domein = urllib.parse.urlsplit(link).netloc.lower()
            except ValueError:
                continue
            for sleutel, platform in SOCIAL_MEDIA_DOMAINS.items():
                if sleutel in domein:
                    # Bewaar de VOLLEDIGE url (incl. query-string). Voor bv.
                    # Facebook profile.php?id=... zit het profiel-ID juist in
                    # de query; die mag hier NIET weggeknipt worden, anders
                    # gaan we het ID kwijtraken vóór de ID-extractie.
                    volledige_url = link
                    canoniek = volledige_url.split("?")[0].rstrip("/")
                    sleutel_seen = (platform, canoniek)
                    if sleutel_seen not in gezien:
                        gezien.add(sleutel_seen)
                        gevonden.append({
                            "platform": platform,
                            "url": volledige_url,
                            "titel": hit.get("titel", ""),
                            "bron": hit.get("omschrijving", "")[:120],
                        })
                    break
    return gevonden


def bereken_web_presence_score(gevonden_socials, totaal_resultaten):
    """Berekent een Web Presence Score (0-10) gebaseerd op WebMii-formule."""
    unieke_platforms = len(set(p["platform"] for p in gevonden_socials))
    if totaal_resultaten == 0:
        return 0, 0
    score = 0.5756 * math.log(totaal_resultaten) - 0.3621
    score = max(0.01, min(10, score))
    return round(score, 1), unieke_platforms


def match_score(doelwit, url, titel, omschrijving, plaats=""):
    t = doelwit.lower().lstrip("@").strip()
    if not t:
        return 0
    try:
        pad = urllib.parse.urlsplit(url.lower()).path
    except ValueError:
        pad = ""

    # "EXACT ~100%" (score 4): als het doelwit een volledige naam is en de
    # naamdelen (voornaam + achternaam) samen & in volgorde in een van de
    # velden staan, is de kans groot dat dit dé persoon is, niet een naamgenoot.
    woorden = t.split()
    if len(woorden) >= 2:
        haystack = " | ".join([pad, titel.lower(), omschrijving.lower()])
        if _code_naam_match(woorden, haystack):
            return 4

    if t in pad:
        score = 3
    elif t in titel.lower():
        score = 2
    elif t in omschrijving.lower():
        score = 1
    else:
        return 0

    p = plaats.lower().strip()
    if p and score < 3 and p in (pad + " " + titel.lower() + " " + omschrijving.lower()):
        score += 1
    return min(score, 3)


def _code_naam_match(woorden, haystack):
    """True als de naamdelen in volgorde én redelijk aaneengesloten (binnen
    een kleine afstand) in de tekst staan. Dat is een sterke aanwijzing dat
    de volledige naam (bv. \"ivan versteegh\") ergens intact voorkomt."""
    afstand_max = 30
    start = 0
    vorige_einde = None
    for w in woorden:
        pos = haystack.find(w, start)
        if pos == -1:
            return False
        if vorige_einde is not None and (pos - vorige_einde) > afstand_max:
            # naamdelen liggen te ver uit elkaar -> niet als één naam aanwezig
            return False
        vorige_einde = pos + len(w)
        start = vorige_einde
    return True


SCORE_LABELS = {4: ("ok", "EXACT ~100%"), 3: ("ok", "STERK"), 2: ("warn", "MIDDEN"), 1: ("muted", "zwak"), 0: ("muted", "-")}


def verifieer_social_profiel(platform, url):
    try:
        delen = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    segments = [s for s in delen.path.split("/") if s]

    def _get(u):
        try:
            r = _harvest_get_of_none(u, headers={"user-agent": USER_AGENT}, timeout=10)
            if r is not None:
                return r if r.status_code == 200 else None
            return None
        except Exception:
            return None

    try:
        if platform == "GitHub" and len(segments) == 1:
            r = _get(f"https://api.github.com/users/{segments[0]}")
            return r is not None and r.status_code == 200
        if platform == "GitLab" and len(segments) == 1:
            r = _get("https://gitlab.com/api/v4/users?username=" + urllib.parse.quote(segments[0]))
            return r is not None and r.status_code == 200 and bool(r.json())
        if platform == "Reddit" and len(segments) == 2:
            r = _get(f"https://www.reddit.com/user/{segments[1]}/about.json")
            return r is not None and r.status_code == 200
        if platform == "Telegram" and len(segments) == 1:
            r = _get(url)
            return r is not None and r.status_code == 200 and "tgme_page_title" in r.text[:20000]
        if platform == "YouTube" and segments and segments[0].startswith("@"):
            r = _get(url)
            return r is not None and r.status_code == 200 and '"channelId"' in r.text[:50000]
        if platform == "Mastodon" and len(segments) == 1:
            acct = segments[0].lstrip("@")
            r = _get(f"https://{delen.netloc}/api/v1/accounts/lookup?acct={urllib.parse.quote(acct)}")
            return r is not None and r.status_code == 200
        if platform == "Bluesky" and len(segments) == 2 and segments[0] == "profile":
            r = _get("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor="
                     + urllib.parse.quote(segments[1]))
            return r is not None and r.status_code == 200
        if platform == "LinkedIn" and len(segments) == 2 and segments[0] == "in":
            r = _get(url)
            return r is not None and r.status_code == 200 and ("profile-card" in r.text[:50000]
                                                               or "public profile" in r.text.lower())
        if platform == "TikTok" and segments and segments[0].startswith("@"):
            r = _get(url)
            return r is not None and r.status_code == 200 and "__UNIVERSAL_DATA_FOR_REHYDRATION__" in r.text[:100000]
        if platform == "Pinterest" and len(segments) == 1:
            r = _get(url)
            return r is not None and r.status_code == 200 and not r.url.endswith("/login/")
        if platform == "Patreon" and len(segments) == 1:
            r = _get(url)
            return r is not None and r.status_code == 200 and "patreon" in r.text.lower()
    except Exception:
        return None
    return None


# =============================================================================
# Social Media ID-Extractie
# =============================================================================

YOUTUBE_API_KEY = os.environ.get("YOUTUBE_API_KEY", "").strip()


def youtube_channel_id_zoek(handle):
    """Zoekt YouTube Channel ID via officieel Data API v3 of page scraping."""
    handle = handle.lstrip("@").strip()
    if not handle:
        return None

    # Methode 1: Officieel YouTube Data API v3
    if YOUTUBE_API_KEY:
        try:
            r = requests.get(
                "https://www.googleapis.com/youtube/v3/channels",
                params={
                    "part": "snippet,statistics",
                    "forHandle": f"@{handle}",
                    "key": YOUTUBE_API_KEY,
                },
                headers={"user-agent": USER_AGENT},
                timeout=10,
            )
            if r.status_code == 200:
                items = r.json().get("items", [])
                if items:
                    ch = items[0]
                    snippet = ch.get("snippet", {})
                    stats = ch.get("statistics", {})
                    return {
                        "id": ch.get("id"),
                        "titel": snippet.get("title", ""),
                        "beschrijving": snippet.get("description", "")[:200],
                        "volgers": stats.get("subscriberCount", "0"),
                        "weergaven": stats.get("viewCount", "0"),
                        "video's": stats.get("videoCount", "0"),
                        "bron": "YouTube Data API v3",
                    }
        except requests.RequestException:
            pass

    # Methode 2: Page scraping (fallback)
    try:
        r = _harvest_get_of_none(
            f"https://www.youtube.com/@{handle}",
            headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                     "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                     "accept-language": "en-US,en;q=0.9"},
            timeout=12,
        )
        if r is not None and r.status_code == 200:
            # externalId of channelId in embedded JSON
            match = re.search(r'"externalId"\s*:\s*"(UC[\w-]{22})"', r.text)
            if not match:
                match = re.search(r'"channelId"\s*:\s*"(UC[\w-]{22})"', r.text)
            if match:
                # Probeer kanaalnaam uit title-tag
                titel = handle
                tm = re.search(r'<title>(.*?)</title>', r.text[:100000])
                if tm and "- YouTube" in tm.group(1):
                    titel = tm.group(1).replace(" - YouTube", "").strip()
                return {
                    "id": match.group(1),
                    "titel": titel,
                    "beschrijving": "",
                    "volgers": "",
                    "weergaven": "",
                    "video's": "",
                    "bron": "YouTube page scraping",
                }
    except requests.RequestException:
        pass

    return None


def instagram_user_id_zoek(username):
    """Zoekt Instagram User ID via unofficial web_profile_info endpoint of page scraping."""
    username = username.lstrip("@").strip()
    if not username or len(username) > 30:
        return None

    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "X-IG-App-ID": "936619743392459",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": f"https://www.instagram.com/{username}/",
    }

    # Methode 1: officiele i.instagram endpoint (web_profile_info)
    try:
        r = _harvest_get_of_none(
            f"https://i.instagram.com/api/v1/users/web_profile_info/?username={username}",
            headers=headers,
            timeout=10,
        )
        if r is not None and r.status_code == 200:
            data = r.json().get("data", {}).get("user", {})
            if data:
                return {
                    "id": data.get("id"),
                    "volledige_naam": data.get("full_name", ""),
                    "prive": data.get("is_private", False),
                    "geverifieerd": data.get("is_verified", False),
                    "volgers": data.get("edge_followed_by", {}).get("count", 0),
                    "bron": "Instagram unofficial API",
                }
    except (requests.RequestException, ValueError, KeyError):
        pass

    # Methode 2: page scraping (profielpagina meta/JSON)
    try:
        r = _harvest_get_of_none(
            f"https://www.instagram.com/{username}/",
            headers={"user-agent": headers["User-Agent"]},
            timeout=10,
        )
        if r is not None and r.status_code == 200:
            # profile_id of props.id in ingebedde JSON
            match = re.search(r'"profile_id":"(\d+)"', r.text[:500000])
            if not match:
                match = re.search(r'"props":\{"id":"(\d+)"', r.text[:500000])
            if match:
                # Probeer extra info uit og:description
                volgers = ""
                og = re.search(r'(\d+[KMB]?)\s+Followers', r.text[:500000])
                if og:
                    volgers = og.group(1)
                return {
                    "id": match.group(1),
                    "volledige_naam": username,
                    "prive": None,
                    "geverifieerd": None,
                    "volgers": volgers,
                    "bron": "Instagram page scraping",
                }
    except requests.RequestException:
        pass

    return None


def twitter_user_id_zoek(username):
    """Zoekt Twitter/X User ID via page scraping (unofficial).

    Methode 1: syndication info.json (soms lege body)
    Methode 2: scrape x.com profielpagina en parse __typename:"User" rest_id
    """
    username = username.lstrip("@").strip()
    if not username:
        return None

    # Methode 1: syndication info.json
    try:
        r = _harvest_get_of_none(
            "https://cdn.syndication.twimg.com/widgets/followbutton/info.json",
            params={"screen_names": username},
            headers={
                "user-agent": USER_AGENT,
                "accept": "application/json",
            },
            timeout=10,
        )
        if r is not None and r.status_code == 200 and r.text.strip():
            data = r.json()
            if data and len(data) > 0:
                user = data[0]
                if user.get("id"):
                    return {
                        "id": user.get("id"),
                        "screen_name": user.get("screen_name", username),
                        "naam": user.get("name", ""),
                        "beschrijving": user.get("description", "")[:200],
                        "volgers": user.get("followers_count", 0),
                        "geverifieerd": user.get("verified", False),
                        "bron": "Twitter syndication API (unofficial)",
                    }
    except (requests.RequestException, ValueError, IndexError):
        pass

    # Methode 2: scrape x.com profielpagina
    try:
        r = _harvest_get_of_none(
            f"https://x.com/{username}",
            headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            timeout=12,
        )
        # Faalt op andere domeinen -> probeer twitter.com
        if (r is None or r.status_code in (403, 429)
                or '"screen_name"' not in (r.text[:200000] if r else "")):
            r = _harvest_get_of_none(
                f"https://twitter.com/{username}",
                headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                timeout=12,
            )
        if r is not None and r.status_code == 200:
            # De eerste __typename:"User" block bevat het profiel-ID
            match = re.search(r'__typename:"User",rest_id:"(\d+)"', r.text[:300000])
            if match:
                return {
                    "id": match.group(1),
                    "screen_name": username,
                    "naam": "",
                    "beschrijving": "",
                    "volgers": 0,
                    "geverifieerd": None,
                    "bron": "X/Twitter page scraping",
                }
    except requests.RequestException:
        pass

    return None


def tiktok_user_id_zoek(username):
    """Zoekt TikTok User ID via page scraping (hydration JSON)."""
    username = username.lstrip("@").strip()
    if not username:
        return None

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        r = _harvest_get_of_none(
            f"https://www.tiktok.com/@{username}",
            headers=headers,
            timeout=15,
        )
        if r is not None and r.status_code == 200:
            # Methode 1: __UNIVERSAL_DATA_FOR_REHYDRATION__
            match = re.search(
                r'<script\s+id="__UNIVERSAL_DATA_FOR_REHYDRATION__"\s*[^>]*>(.*?)</script>',
                r.text,
                re.DOTALL,
            )
            if match:
                try:
                    data = json.loads(match.group(1))
                    user_info = (data.get("__DEFAULT_SCOPE__", {})
                                 .get("webapp.user-detail", {})
                                 .get("userInfo", {}))
                    user = user_info.get("user", {})
                    stats = user_info.get("stats", {})
                    if user.get("id"):
                        return {
                            "id": user.get("id"),
                            "unique_id": user.get("uniqueId") or user.get("unique_id", username),
                            "nickname": user.get("nickname", ""),
                            "sec_uid": user.get("secUid", ""),
                            "volgers": stats.get("followerCount", 0),
                            "video's": stats.get("videoCount", 0),
                            "likes": stats.get("heartCount", 0),
                            "bron": "TikTok page scraping",
                        }
                except (ValueError, KeyError):
                    pass

            # Methode 2: SIGI_STATE (oudere pagina's)
            match = re.search(r' SIGI_STATE\s*=\s*({.*?})\s*;', r.text)
            if match:
                try:
                    data = json.loads(match.group(1))
                    users = data.get("UserModule", {}).get("users", {})
                    if users:
                        user_id = list(users.keys())[0]
                        user = users[user_id]
                        return {
                            "id": user_id,
                            "unique_id": user.get("uniqueId", username),
                            "nickname": user.get("nickname", ""),
                            "sec_uid": user.get("secUid", ""),
                            "volgers": data.get("UserModule", {}).get("stats", {}).get(user_id, {}).get("followerCount", 0),
                            "video's": 0,
                            "likes": 0,
                            "bron": "TikTok SIGI_STATE",
                        }
                except (ValueError, KeyError):
                    pass

    except requests.RequestException:
        pass

    return None


def facebook_id_zoek(url_of_username):
    """Zoekt Facebook Page/Profiel ID via page scraping (al:ios:url meta)."""
    # Normaliseer input naar URL
    if url_of_username.startswith("http"):
        url = url_of_username
    else:
        url = f"https://www.facebook.com/{url_of_username.lstrip('@')}"

    # Methode 0: als de URL zelf al een numeric ID heeft (via query-parameter
    # of als het argument zelf een puur numeriek gebruikers/getal is), is dat
    # direct het profiel-ID. Nuttig bij privé/verwijderde profielen die geen
    # fb:// meta meer tonen.
    m0 = re.search(r'[?&]id=(\d+)', url)
    if not m0:
        # het argument zelf kan al een numeriek ID zijn (profile.php?id=...)
        arg = url_of_username.strip().rstrip('/')
        if re.fullmatch(r'\d+', arg):
            m0 = re.match(r'(\d+)', arg)
    if m0:
        return {
            "id": m0.group(1),
            "type": "Profiel",
            "naam": "",
            "bron": "Facebook URL id= parameter",
        }

    # Methode 1: scrape profielpagina en vind fb://profile/ID in meta
    try:
        r = _harvest_get_of_none(
            url,
            headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                     "Cookie": "locale=en_US"},
            timeout=12,
        )
        if r is not None and r.status_code == 200:
            # al:ios:url bevat fb://profile/ID of fb://page/ID
            match = re.search(r'fb://(?:profile|page)/(\d+)', r.text[:500000])
            if not match:
                match = re.search(r'"entity_id"\s*:\s*"(\d+)"', r.text[:500000])
            if match:
                type_ = "Profiel/Page"
                if re.search(r'fb://page/', r.text[:500000]):
                    type_ = "Page"
                # Probeer pagina-naam uit og:title
                naam = ""
                og = re.search(r'property="og:title"\s+content="([^"]+)"', r.text[:500000])
                if og:
                    naam = og.group(1)
                return {
                    "id": match.group(1),
                    "type": type_,
                    "naam": naam,
                    "bron": "Facebook page scraping",
                }
    except requests.RequestException:
        pass

    # Methode 2: Page Plugin embed (fallback voor Pages)
    try:
        r = _harvest_get_of_none(
            "https://www.facebook.com/plugins/page.php",
            params={"href": url, "width": "500"},
            headers={"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            timeout=10,
        )
        if r is not None and r.status_code == 200:
            match = re.search(r'page_id=(\d+)', r.text)
            if match:
                return {
                    "id": match.group(1),
                    "type": "Page",
                    "naam": "",
                    "bron": "Facebook Page Plugin",
                }
    except requests.RequestException:
        pass

    return None


def commentpicker_id_zoek(platform, username):
    """CommentPicker fallback - LET OP: vereist CAPTCHA, daily limit 2/dag.

    Deze functie wordt alleen aangeroepen als directe API's falen.
    Retourneert None als CAPTCHA vereist is (meestal).
    """
    endpoints = {
        "instagram": "/actions/instagram-id-action.php",
        "twitter": "/actions/twitter-new.php",
        "tiktok": "/actions/tiktok-id.php",
        "youtube": "/actions/youtube-channel-id.php",
        "facebook": "/actions/facebook-id.php",
    }

    if platform not in endpoints:
        return None

    # CommentPicker vereist CAPTCHA token + daily limit
    # We proberen eenmalig zonder token (soms lukt het)
    # maar meestal krijgen we een foutmelding
    try:
        params = {"username": username} if platform != "youtube" else {"url": f"https://www.youtube.com/@{username}"}
        r = _harvest_get_of_none(
            f"https://commentpicker.com{endpoints[platform]}",
            params=params,
            headers={"user-agent": USER_AGENT},
            timeout=10,
        )
        if r is not None and r.status_code == 200:
            try:
                data = r.json()
                # Als er een token-fout is, weten we dat CAPTCHA vereist is
                if "token" in str(data).lower() or "captcha" in str(data).lower():
                    return None
                # Sommige endpoints returnen data zonder token (zelden)
                if data and not data.get("error"):
                    return {
                        "data": data,
                        "bron": "CommentPicker (zonder CAPTCHA)",
                        "waarschuwing": "Resultaat mogelijk onvolledig",
                    }
            except ValueError:
                pass
    except requests.RequestException:
        pass

    return None


# =============================================================================
# socid-extractor integratie
# =============================================================================

# =============================================================================
# socid-extractor integratie (aanvulling, NIET vervanging van eigen extractie)
# =============================================================================

# Alleen platforms die wij NIET zelf ondersteunen in onze eigen ID-extractie,
# EN die door socid-extractor daadwerkelijk betrouwbaar werken (getest).
# Eigen platforms (Instagram, Twitter, YouTube, TikTok, Facebook) blijven
# volledig bij onze eigen extractie — deze lijst is puur aanvullend.
_SOCID_PLATFORM_URLS = {
    "steam": "https://steamcommunity.com/id/{username}",
    "soundcloud": "https://soundcloud.com/{username}",
    "telegram": "https://t.me/{username}",
    "medium": "https://medium.com/@{username}",
    # Let op: deze kunnen ons blokkeren (403) -> tolerantiesysteem regelt
    # dat die als laatste / minder bevraagd worden.
    "tumblr": "https://{username}.tumblr.com",
    "deviantart": "https://www.deviantart.com/{username}",
}

# Platforms die ons vaak blokkeren (403/429) -> worden gemarkeerd en minder bevraagd.
# Dit wordt runtime bijgewerkt op basis van daadwerkelijke responscodes.
_SOCID_GEBLOKKEERD = {}
_SOCID_BLOKKEER_TELLER = {}


def _socid_norm_domein(platform):
    """Normaliseert platformnaam naar domein voor blok-detectie."""
    return {
        "steam": "steamcommunity.com",
        "soundcloud": "soundcloud.com",
        "telegram": "t.me",
        "medium": "medium.com",
        "tumblr": "tumblr.com",
        "deviantart": "deviantart.com",
    }.get(platform, platform)


def _socid_is_geblokkeerd(platform):
    """Checkt of een platform ons recent geblokkeerd heeft (op basis van counter)."""
    domein = _socid_norm_domein(platform)
    terug = _SOCID_GEBLOKKEERD.get(domein, 0)
    if not terug:
        return False

    verstreken = time.time() - terug

    # Na een langere cooldown (30 min) resetten we de teller, zodat het
    # platform opnieuw een kans krijgt als de blokkering niet meer actief is.
    if verstreken > 1800:
        _SOCID_BLOKKEER_TELLER[domein] = 0
        _SOCID_GEBLOKKEERD[domein] = 0
        return False

    # Binnen de cooldown: overslaan bij >3 blokkeringen, of nog binnen 10 min
    if _SOCID_BLOKKEER_TELLER.get(domein, 0) >= 3:
        return True  # te veel blokkeringen -> overslaan binnen deze cooldown
    if verstreken < 600:  # binnen 10 min -> overslaan
        return True
    return False


def _socid_markeer_blokkering(platform, status):
    """Markeert een platform als blocker bij 403/429/5xx."""
    if status not in (403, 429, 500, 502, 503, 504):
        _SOCID_BLOKKEER_TELLER[_socid_norm_domein(platform)] = 0
        return
    domein = _socid_norm_domein(platform)
    _SOCID_GEBLOKKEERD[domein] = time.time()
    _SOCID_BLOKKEER_TELLER[domein] = _SOCID_BLOKKEER_TELLER.get(domein, 0) + 1


def socid_extract_profiel(platform, url):
    """Haalt gestructureerde profieldata op via socid-extractor.

    - Omzeilt platforms die ons blokkeren (mindere bevraging).
    - Gebruikt een browser-achtige user-agent (opsec: geen app-signature).
    - Retourneert een dict met gestandaardiseerde velden of None bij falen.
    """
    if not SOCID_BESCHIKBAAR:
        return None

    # Blok-tolerantie: overslaan als platform ons blokkeert
    if _socid_is_geblokkeerd(platform):
        _SOCID_BLOKKEER_TELLER[_socid_norm_domein(platform)] += 1
        return None

    # Opsec: browserheaders voorkómen gerichte detectie en beperken de
    # vingerafdruk die we achterlaten. Geen app-signatuur in user-agent.
    # Kleine, realistische user-agent-rotatie (gangbare Chrome-versies) om
    # monotone patronen te vermijden — standaard browserheaders, geen rotatie
    # die als anti-bot zou tellen.
    _UA_POOL = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    ]
    headers = {
        "user-agent": random.choice(_UA_POOL),
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "nl-NL,nl;q=0.9,en;q=0.8",
        "accept-encoding": "gzip, deflate",
        "connection": "keep-alive",
    }

    try:
        r = _harvest_get_of_none(
            url,
            headers=headers,
            timeout=15,
        )
        if r is None:
            return None

        # Blok-tolerantie: markeer bij verdachte statuscodes
        _socid_markeer_blokkering(platform, r.status_code)

        if r.status_code != 200:
            return None

        resultaat = _socid.extract(r.text)
        if resultaat and isinstance(resultaat, dict):
            return resultaat
    except requests.RequestException:
        # Netwerkfout: niet meteen als blokkering tellen, wel als 'niet bereikbaar'
        _SOCID_BLOKKEER_TELLER[_socid_norm_domein(platform)] = (
            _SOCID_BLOKKEER_TELLER.get(_socid_norm_domein(platform), 0) + 1
        )
    except Exception:
        pass
    return None


def socid_bulk_extract(profielen):
    """Voert socid-extractor uit op een lijst met profielen.

    Toont voortgang (counter) en slaat geblokkeerde platforms over.

    Args:
        profielen: lijst van dicts met 'platform', 'username' (alleen extra platforms)

    Returns:
        dict: {(platform, username): socid_data}
    """
    if not SOCID_BESCHIKBAAR:
        return {}

    kandidaten = []
    gezien = set()
    for profiel in profielen:
        url = profiel.get("url", "")
        platform, username = _parse_platform_username(url)
        if not platform or not username:
            continue
        # Alleen additionele platforms (niet onze kern-5)
        if platform in ("instagram", "twitter", "youtube", "tiktok", "facebook"):
            continue
        url_sjabloon = _SOCID_PLATFORM_URLS.get(platform)
        if not url_sjabloon:
            continue
        sleutel = (platform, username.lower())
        if sleutel in gezien:
            continue
        gezien.add(sleutel)
        kandidaten.append((platform, username, url_sjabloon.format(username=username)))

    if not kandidaten:
        return {}

    resultaten = {}
    totaal = len(kandidaten)
    overgeslagen = 0
    for i, (platform, username, te_url) in enumerate(kandidaten, 1):
        # Blok-tolerantie: geef aan wanneer een platform wordt overgeslagen
        if _socid_is_geblokkeerd(platform):
            overgeslagen += 1
            if overgeslagen == 1:
                console.print(
                    f"  [dim]Slaat {len([k for k in kandidaten if _socid_is_geblokkeerd(k[0])])} "
                    f"geblokkeerd platform(en) over (leren van eerdere blokkeringen)[/]"
                )
            continue
        # Voortgang: counter met platform/username
        with console.status(
            f"[cyan]Aanvulling socid-extractor[/] ({i}/{totaal}): "
            f"[bold]{platform}[/]/{username}", spinner="dots"
        ):
            data = socid_extract_profiel(platform, te_url)
        if data:
            # Normaliseer naar ons velden-schema (incl. internal_ids)
            resultaten[(platform, username)] = _socid_velden_naar_dict(data)
        # Pauze tussen verzoeken (opsec: geen burst-patroon)
        time.sleep(random.uniform(1.0, 2.5))

    return resultaten


def _socid_velden_naar_dict(data):
    """Converteert socid-extractor velden naar een leesbaar dict."""
    if not data:
        return {}

    result = {}

    # Kernvelden (genormaliseerd)
    voorkeursvelden = [
        "username", "fullname", "name", "display_name",
        "bio", "tagline", "about", "description",
        "created_at", "joined", "registration_date",
        "gender", "country", "city", "location",
        "is_verified", "is_private", "is_business",
        "followers_count", "following_count", "friends_count",
        "media_count", "posts_count", "tweets_count",
        "avatar_url", "profile_image", "photo",
        "website", "website_url",
    ]

    for veld in voorkeursvelden:
        if veld in data and data[veld] not in (None, "", 0, False, "None"):
            result[veld] = data[veld]

    # Interne IDs (de echte waarde van socid-extractor)
    id_velden = [k for k in data if "_id" in k.lower() or k in (
        "gaia_id", "uid", "pk", "user_id", "channel_id",
        "steam_id", "patreon_id", "tiktok_id", "youtube_channel_id",
    )]
    if id_velden:
        ids = {}
        for veld in id_velden:
            waarde = data[veld]
            if waarde not in (None, "", 0, "None"):
                ids[veld] = str(waarde)
        if ids:
            result["internal_ids"] = ids

    # Externe links
    if "links" in data and data["links"]:
        links = data["links"]
        if isinstance(links, str):
            try:
                links = json.loads(links.replace("'", '"'))
            except (json.JSONDecodeError, ValueError):
                links = [links]
        if isinstance(links, list):
            result["external_links"] = links[:10]

    return result


# =============================================================================
# Maigret integratie (uitgebreide username-zoekopdracht, 3000+ sites)
# =============================================================================

_MAIGRET_DB = None
_MAIGRET_LOG = _logging.getLogger("maigret") if MAIGRET_BESCHIKBAAR else None

# Beperkte site-set: niet alle 3000+ maar een gebalanceerde selectie.
# We filteren nsfw/dating, beperken tot top-sites gerangschikt op betrouwbaarheid.
# Top-150 geeft ~30-45 relevante sites in ~30-60s (balans voor interactieve CLI).
_MAIGRET_TOP = 150
_MAIGRET_MAX_CONNECTIONS = 20


def _laad_maigret_db():
    """Laadt de Maigret site-database (eenmalig)."""
    global _MAIGRET_DB
    if _MAIGRET_DB is not None or not MAIGRET_BESCHIKBAAR:
        return
    # Maigret-log ruis volledig dempen: blokkades (403/Cloudflare/rate
    # limit) zijn normaal gedrag en de samenvatting toont al hoeveel
    # sites zijn doorzocht/overgeslagen. Gebruiker hoeft de interne
    # tracebacks niet te zien.
    if _MAIGRET_LOG:
        _MAIGRET_LOG.setLevel(_logging.CRITICAL)
        _MAIGRET_LOG.propagate = False
        _MAIGRET_LOG.addHandler(_logging.NullHandler())
    try:
        data_pad = str(_importlib_resources.files("maigret") / "resources" / "data.json")
        _MAIGRET_DB = _MaigretDatabase().load_from_path(data_pad)
    except Exception as exc:
        if _MAIGRET_LOG:
            _MAIGRET_LOG.warning("Maigret DB laden mislukt: %s", exc)
        _MAIGRET_DB = None


def maigret_zoek_gebruikersnaam(username):
    """Zoekt een gebruikersnaam via Maigret op top-sites.

    Retourneert een dict met:
        sites: lijst van dicts {platform, url, bron, ids_data}
        totaal_gezocht: aantal sites dat doorzocht is
        fouten: lijst van foutmeldingen
    """
    _laad_maigret_db()
    if _MAIGRET_DB is None:
        return {"sites": [], "totaal_gezocht": 0,
                "fouten": ["Maigret database niet beschikbaar"]}

    sites = _MAIGRET_DB.ranked_sites_dict(
        top=_MAIGRET_TOP,
        excluded_tags=["nsfw", "dating"],
    )

    gefilterd = {k: v for k, v in sites.items() if not v.disabled}
    totaal = len(gefilterd)

    def _run():
        return _asyncio.run(
            _maigret_search(
                username=username,
                site_dict=gefilterd,
                logger=_MAIGRET_LOG,
                timeout=15,
                is_parsing_enabled=True,
                max_connections=_MAIGRET_MAX_CONNECTIONS,
                no_progressbar=True,
                retries=1,
            )
        )

    try:
        resultaten = _run()
    except Exception as e:
        return {"sites": [], "totaal_gezocht": totaal,
                "fouten": [f"Maigret fout: {str(e)[:80]}"]}

    sites_gevonden = []
    fouten = []
    for site_name, result in resultaten.items():
        status = result.get("status")
        if not status or not status.is_found():
            continue

        url = result.get("url_user", "")
        if not url:
            continue

        # Basis filtering tegen fout-positieven:
        # - URLs met filter-zoektermen erin
        if any(x in url for x in ("filter?", "search?", "query=")):
            continue
        # - Discord (geen echt profiel, alleen domein/uitnodigings-check)
        if "discord.com" in url and not any(x in url for x in ("/users/", "/profiles/")):
            continue

        ids_data = result.get("ids_data") or {}
        if isinstance(ids_data, str):
            ids_data = {}

        sites_gevonden.append({
            "platform": site_name,
            "url": url,
            "bron": "Maigret",
            "ids_data": ids_data if isinstance(ids_data, dict) else {},
        })

    return {"sites": sites_gevonden, "totaal_gezocht": totaal,
            "fouten": fouten}


def _parse_platform_username(url):
    """Parse platform en username uit een social media URL."""
    try:
        delen = urllib.parse.urlsplit(url)
    except ValueError:
        return None, None

    host = delen.netloc.lower().replace("www.", "")
    pad = delen.path.rstrip("/")
    segments = [s for s in pad.split("/") if s]

    if not segments:
        return None, None

    # Platform herkenning
    platform_map = {
        "instagram.com": "instagram",
        "x.com": "twitter",
        "twitter.com": "twitter",
        "youtube.com": "youtube",
        "tiktok.com": "tiktok",
        "facebook.com": "facebook",
        "steamcommunity.com": "steam",
        "steampowered.com": "steam",
        "soundcloud.com": "soundcloud",
        "t.me": "telegram",
        "tumblr.com": "tumblr",
        "medium.com": "medium",
        "bsky.app": "bluesky",
        "vimeo.com": "vimeo",
        "twitch.tv": "twitch",
        "patreon.com": "patreon",
        "keybase.io": "keybase",
        "open.spotify.com": "spotify",
        "deviantart.com": "deviantart",
        "dribbble.com": "dribbble",
        "behance.net": "behance",
        "flickr.com": "flickr",
        "gitlab.com": "gitlab",
        "pinterest.com": "pinterest",
    }

    platform = None
    for domein, platform_naam in platform_map.items():
        if host == domein or host.endswith("." + domein):
            platform = platform_naam
            break

    if not platform:
        return None, None

    # Username extractie
    if platform == "youtube":
        # /@username of /channel/UC...
        if segments[0].startswith("@"):
            return platform, segments[0][1:]
        if segments[0] == "channel" and len(segments) > 1:
            return platform, segments[1]  # Retourneer channel ID
        if segments[0] == "user" and len(segments) > 1:
            return platform, segments[1]
    elif platform == "facebook":
        # /username, /pages/name/id, en profile.php?id=...
        qid = urllib.parse.parse_qs(delen.query).get("id")
        if qid:
            # profile.php?id=<numeric> -> dat ís het profiel-ID
            return platform, qid[0]
        if segments[0] == "pages" and len(segments) >= 3:
            return platform, segments[-1]  # Pagina ID
        return platform, segments[0]
    elif platform == "tiktok":
        # /@username
        return platform, segments[0].lstrip("@")
    elif platform == "steam":
        # /id/username of /profiles/STEAMID
        if segments[0] == "id" and len(segments) > 1:
            return platform, segments[1]
        if segments[0] == "profiles" and len(segments) > 1:
            return platform, segments[1]
        return platform, segments[0] if segments else None
    elif platform == "twitter":
        return platform, segments[0]
    elif platform == "instagram":
        return platform, segments[0]
    elif platform == "telegram":
        return platform, segments[0].lstrip("@")
    elif platform == "tumblr":
        # tumblr usernames zijn subdomains, niet in path
        if segments:
            return platform, segments[0]
        return platform, None
    elif platform == "medium":
        # /@username of /username
        return platform, segments[0].lstrip("@")
    elif platform == "bluesky":
        # /profile/<handle>
        if segments[0] == "profile" and len(segments) > 1:
            return platform, segments[1]
        return platform, segments[0] if segments else None
    else:
        # Overige: neem eerste segment als username
        return platform, segments[0] if segments else None

    return platform, None


def zoek_social_media_ids(gevonden_profielen):
    """Extrahert ID's van gevonden social media profielen.

    Architectuur (kwaliteit staat voorop, socid vult alleen aan):
    1. Eigen extractie voor kernplatforms (Instagram, X/Twitter, YouTube,
       TikTok, Facebook) — compleet behouden, ongewijzigde kwaliteit.
    2. CommentPicker fallback als directe eigen API's falen.
    3. socid-extractor (aanvulling) voor additionele platforms die wij NIET
       zelf ondersteunen (Steam, SoundCloud, Telegram, etc.) — voegt data toe
       maar vervangt nooit de kern-extractie.
    """
    resultaten = []
    gezien = set()

    # Kernplatforms die we met onze eigen extractie behandelen
    KERNPLATFORMS = {"youtube", "instagram", "twitter", "tiktok", "facebook"}

    # Filter eerst op geldige profielen om een accuraat totaal te hebben
    geldige = []
    for profiel in gevonden_profielen:
        url = profiel.get("url", "")
        platform, username = _parse_platform_username(url)
        if not platform or not username:
            continue
        sleutel = (platform, username.lower())
        if sleutel in gezien:
            continue
        gezien.add(sleutel)
        geldige.append({"platform": platform, "username": username, "url": url})
    gezien.clear()

    totaal = len(geldige)
    for idx, item in enumerate(geldige, 1):
        platform = item["platform"]
        username = item["username"]
        url = item["url"]
        id_data = None

        if platform in KERNPLATFORMS:
            # Eigen extractie (primaire bron, ongewijzigd) met voortgang
            probeer_direct = {
                "youtube": lambda: youtube_channel_id_zoek(username),
                "instagram": lambda: instagram_user_id_zoek(username),
                "twitter": lambda: twitter_user_id_zoek(username),
                "tiktok": lambda: tiktok_user_id_zoek(username),
                "facebook": lambda: facebook_id_zoek(username),
            }
            if not totaal or totaal == 1:
                with console.status(
                    f"[cyan]ID-extractie:[/] {platform}/{username}", spinner="dots"
                ):
                    id_data = probeer_direct[platform]()
            else:
                with console.status(
                    f"[cyan]ID-extractie[/] ({idx}/{totaal}): "
                    f"[bold]{platform}[/]/{username}", spinner="dots"
                ):
                    id_data = probeer_direct[platform]()

            # CommentPicker fallback als directe eigen API faalde
            if not id_data:
                id_data = commentpicker_id_zoek(platform, username)

            entry = {
                "platform": platform.title(),
                "username": username,
                "url": url,
                "id": id_data.get("id") if id_data else None,
                "details": id_data or {},
                "bron": (id_data.get("bron", "onbekend") if id_data else "geen match"),
            }
            resultaten.append(entry)
        else:
            # Additionele platforms -> socid-extractor aanvulling (later, gebundeld)
            if _SOCID_PLATFORM_URLS.get(platform):
                entry = {
                    "platform": platform.title(),
                    "username": username,
                    "url": url,
                    "id": None,
                    "details": {},
                    "bron": "socid-extractor (aanvulling)",
                }
                resultaten.append(entry)

    # socid-extractor voor additionele platforms
    # Alleen uitvoeren als er additionele (niet-kern) platforms zijn
    additioneel = [item for item in geldige if item["platform"] not in KERNPLATFORMS]
    if additioneel:
        enrichdata = socid_bulk_extract(additioneel)
        for entry in resultaten:
            platform_key = entry["platform"].lower()
            username = entry.get("username", "")
            if platform_key in KERNPLATFORMS:
                continue
            socid_data = enrichdata.get((platform_key, username))
            if not socid_data:
                # Geen data -> markeer als geen match
                if entry.get("bron") == "socid-extractor (aanvulling)":
                    entry["bron"] = "geen match"
                continue

            entry["details"]["socid"] = socid_data

            # Vul ID aan als beschikbaar
            intern_ids = socid_data.get("internal_ids", {})
            if intern_ids:
                id_keys = list(intern_ids.keys())
                if id_keys:
                    entry["id"] = intern_ids[id_keys[0]]

    return resultaten


def openkvk_bedrijven(zoekterm):
    if not OPENHEID_API_KEY:
        return {"status": "overgeslagen", "melding": "Geen OVERHEID_IO_API_KEY ingesteld.", "bedrijven": []}

    headers = {"ovio-api-key": OPENHEID_API_KEY, "user-agent": USER_AGENT}
    params = {
        "query": zoekterm,
        "queryfields[]": "handelsnaam",
        "size": 25,
    }
    try:
        r = requests.get("https://api.overheid.io/openkvk", headers=headers, params=params, timeout=15)
    except requests.RequestException as e:
        return {"status": "fout", "melding": f"API onbereikbaar: {e}", "bedrijven": []}

    if r.status_code == 401:
        return {"status": "overgeslagen", "melding": "overheid.io-API-key ongeldig.", "bedrijven": []}
    if r.status_code == 429:
        return {"status": "fout", "melding": "overheid.io-rate-limit bereikt.", "bedrijven": []}
    if r.status_code != 200:
        return {"status": "fout", "melding": f"HTTP {r.status_code}", "bedrijven": []}

    try:
        data = r.json()
    except ValueError:
        return {"status": "fout", "melding": "Ongeldig JSON-antwoord van API.", "bedrijven": []}

    if isinstance(data, dict):
        items = (data.get("_embedded") or {}).get("bedrijf") or []
        totaal = data.get("totalItemCount")
    else:
        items, totaal = (data or []), None

    time.sleep(1)

    bedrijven = []
    for item in items[:25]:
        if not isinstance(item, dict):
            continue
        link = ""
        href = ((item.get("_links") or {}).get("self") or {}).get("href") or ""
        if href.startswith("/openkvk/"):
            link = "https://openkvk.nl/" + href.lstrip("/")
        elif href.startswith("/"):
            link = "https://openkvk.nl" + href
        bedrijven.append({
            "handelsnaam": str(item.get("handelsnaam") or "?"),
            "dossiernummer": str(item.get("dossiernummer") or "-"),
            "link": link,
        })

    totaal_tekst = f"{totaal} treffers in het register" if totaal is not None else "zoekopdracht voltooid"
    return {"status": "ok", "melding": totaal_tekst, "bedrijven": bedrijven}


INTERPOL_RE_ENDPOINT = "https://ws-public.interpol.int/notices/v1/red"
INTERPOL_YELLOW_ENDPOINT = "https://ws-public.interpol.int/notices/v1/yellow"

FBI_WANTED_ENDPOINT = "https://api.fbi.gov/wanted/v1/list"
FBI_VERMIST_SUBJECTS = {"kidnappings and missing persons", "vicap missing persons", "missing persons"}
FBI_GEZOCHT_SUBJECTS = {"ten most wanted fugitives", "most wanted", "criminal enterprise investigations",
                        "violent crime", "murders", "white-collar crime", "counterintelligence",
                        "seeking information", "law enforcement assistance", "indian country", "navajo"}

INTERPOL_BROWSER_HEADERS = {
    "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "accept": "application/json, text/plain, */*",
    "accept-language": "nl-NL,nl;q=0.9,en;q=0.8",
    "sec-ch-ua": '"Not.A.Brand";v="99", "Chromium";v="126", "Google Chrome";v="126"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"macOS"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    "origin": "https://www.interpol.int",
    "referer": "https://www.interpol.int/",
}


def _land_code(code):
    if not code:
        return ""
    try:
        return pycountry.countries.get(alpha_2=code.upper()).name
    except Exception:
        return code


def _taal_code(code):
    if not code:
        return ""
    try:
        land = pycountry.languages.get(alpha_3=code.lower())
        if land is None:
            land = pycountry.languages.get(alpha_2=code.lower())
        return land.name if land else code
    except Exception:
        return code


def _geslacht_label(code):
    return {"M": "Man", "F": "Vrouw", "U": "Onbekend"}.get(code, code or "")


_KLEUREN = {
    "BLK": "Zwart", "BRN": "Bruin", "BLU": "Blauw", "GRN": "Groen",
    "GRY": "Grijs", "WHI": "Wit", "BAL": "Kaal", "BK": "Zwart",
    "HGW": "Grijs-wit", "HAZ": "Hazelnoot", "RED": "Rood", "UNK": "Onbekend",
}


def _kleur_label(code):
    if not code:
        return ""
    return _KLEUREN.get(str(code).upper(), str(code))


def _formaat_lengte(waarde):
    if waarde in (None, ""):
        return ""
    try:
        return f"{float(waarde):g}".replace(".", ",") + " m"
    except (TypeError, ValueError):
        return str(waarde)


def _formaat_gewicht(waarde):
    if waarde in (None, ""):
        return ""
    try:
        return f"{float(waarde):g}".replace(".", ",") + " kg"
    except (TypeError, ValueError):
        return str(waarde)


def _apostille_notice_gegevens(entry, detail):
    """Vertaalt API-detailgegevens naar leesbare, NL labels."""
    arrest_bevelen = []
    for w in (detail.get("arrest_warrants") or []):
        aanklacht = w.get("charge_translation") or w.get("charge") or ""
        land = _land_code(w.get("issuing_country_id"))
        arrest_bevelen.append({"land": land, "aanklacht": aanklacht})

    entry["geboorteplaats"] = detail.get("place_of_birth") or ""
    entry["geslacht"] = _geslacht_label(detail.get("sex_id"))
    entry["lengte"] = _formaat_lengte(detail.get("height"))
    entry["gewicht"] = _formaat_gewicht(detail.get("weight"))
    entry["haarkleur"] = _kleur_label(detail.get("hairs_id"))
    entry["oogkleur"] = _kleur_label(detail.get("eyes_colors_id"))
    entry["talen"] = ", ".join(_taal_code(t) for t in (detail.get("languages_spoken_ids") or []))
    entry["kenmerken"] = detail.get("distinguishing_marks") or ""
    entry["landen"] = ", ".join(_land_code(c) for c in (detail.get("nationalities") or []))
    entry["geboorteland"] = _land_code(detail.get("country_of_birth_id"))
    entry["arrest_bevelen"] = arrest_bevelen
    return entry


def _voeg_fotos_toe(entry, endpoint, entity_id):
    """Haalt tot 2 foto's van een notice op en embedt ze als base64 in de entry."""
    fotos = []
    try:
        lijst_url = f"{endpoint}/{entity_id}/images"
        lijst = _harvest_get_of_none(lijst_url, headers=INTERPOL_BROWSER_HEADERS, timeout=12)
        if lijst is None or lijst.status_code != 200:
            entry["fotos"] = []
            return
        images = (lijst.json().get("_embedded") or {}).get("images") or []
        for img in images[:2]:
            href = (img.get("_links") or {}).get("self", {}).get("href", "")
            if not href:
                continue
            try:
                time.sleep(INTERPOL_PAUZE)
                foto = _harvest_get_of_none(href, headers=INTERPOL_BROWSER_HEADERS, timeout=15)
                if foto is None:
                    continue
                bytes_ = foto.content
                if (foto.status_code == 200 and bytes_ and 0 < len(bytes_) <= 250_000
                        and bytes_[:3] == b"\xff\xd8\xff"):
                    fotos.append({
                        "data": base64.b64encode(bytes_).decode("ascii"),
                        "url": href,
                    })
            except Exception:
                continue
    except Exception:
        pass
    entry["fotos"] = fotos
    return entry


def _notice_details_html(n):
    """Leesbare, uitklapbare detail-view voor een notice."""
    esc = html.escape
    regels = []
    if n.get("landen"):
        regels.append(("Nationaliteit", n["landen"]))
    if n.get("geboorteplaats"):
        regels.append(("Geboorteplaats", n["geboorteplaats"]))
    if n.get("geboorteland"):
        regels.append(("Geboorteland", n["geboorteland"]))
    if n.get("geslacht"):
        regels.append(("Geslacht", n["geslacht"]))
    if n.get("lengte"):
        regels.append(("Lengte", n["lengte"]))
    if n.get("gewicht"):
        regels.append(("Gewicht", n["gewicht"]))
    if n.get("haarkleur"):
        regels.append(("Haarkleur", n["haarkleur"]))
    if n.get("oogkleur"):
        regels.append(("Oogkleur", n["oogkleur"]))
    if n.get("talen"):
        regels.append(("Talen", n["talen"]))
    if n.get("kenmerken"):
        regels.append(("Bijzondere kenmerken", n["kenmerken"]))
    if not regels and not n.get("fotos"):
        return ""
    uit = '<details class="notice-details"><summary>Meer details</summary>'
    if n.get("url") or n.get("api_url") or n.get("zoek_url"):
        uit += ('<table class="detail-table"><tr><td class="detail-label">Links</td><td>'
                + (f'<a href="{esc(str(n["url"]))}" target="_blank" rel="noopener">Interpol-pagina</a> · ' if n.get("url") else "")
                + (f'<a href="{esc(str(n["api_url"]))}" target="_blank" rel="noopener">API-data</a> · ' if n.get("api_url") else "")
                + (f'<a href="{esc(str(n["zoek_url"]))}" target="_blank" rel="noopener">Zoeken</a>' if n.get("zoek_url") else "")
                + "</td></tr></table>")
    if n.get("fotos"):
        uit += '<div class="notice-fotos">'
        for f in n["fotos"]:
            uit += (f'<div class="notice-foto"><img src="data:image/jpeg;base64,{f["data"]}" '
                    f'alt="Noticefoto"><br>'
                    f'<a href="{esc(str(f["url"]))}" target="_blank" rel="noopener">Origineel</a></div>')
        uit += "</div>"
    uit += '<table class="detail-table">'
    for label, waarde in regels:
        uit += f"<tr><td class='detail-label'>{esc(str(label))}</td><td>{esc(str(waarde))}</td></tr>"
    for w in n.get("arrest_bevelen") or []:
        aanklacht, land = w.get("aanklacht", ""), w.get("land", "")
        uit += (f"<tr><td class='detail-label'>Arrestbevel</td>"
                f"<td class='muted'>{esc(str(aanklacht))} ({esc(str(land))})</td></tr>")
    uit += "</table></details>"
    return uit


def interpol_zoek(achternaam, voornaam=""):
    """Geverifieerde Interpol-notices via de officiele API.

    Het API-domein zit achter een Akamai-WAF die non-browser clients weert.
    Met een complete browser-headerset passeert de officiele, publieke API
    netjes. Per notice wordt de detail-API opgehaald voor leesbare gegevens
    (geboorteplaats, kenmerken, arrestbevelen, ...) - inclusief de
    subject-specifieke link (entity_id).
    """
    uitkomst = {"status": "ok", "melding": "", "red": [], "yellow": []}
    api_geblokkeerd = False

    for notice_type, endpoint in [("red", INTERPOL_RE_ENDPOINT), ("yellow", INTERPOL_YELLOW_ENDPOINT)]:
        params = {"name": achternaam, "resultPerPage": 20}
        if voornaam and notice_type == "red":
            params["forename"] = voornaam

        try:
            r = _harvest_get_of_none(endpoint, headers=INTERPOL_BROWSER_HEADERS,
                                     params=params, timeout=12)
        except Exception:
            api_geblokkeerd = True
            continue

        if r is None:
            api_geblokkeerd = True
            continue
        if r.status_code == 403:
            api_geblokkeerd = True
            continue
        if r.status_code != 200:
            continue

        try:
            data = r.json()
        except ValueError:
            continue

        notices = (data.get("_embedded") or {}).get("notices") or []
        for index, notice in enumerate(notices):
            entity_id = str(notice.get("entity_id", "")).replace("/", "-")
            entry = {
                "naam": f"{notice.get('forename', '')} {notice.get('name', '')}".strip(),
                "nationaliteit": ", ".join(notice.get("nationalities") or []),
                "geboortedatum": notice.get("date_of_birth") or "?",
                "type": "RED NOTICE" if notice_type == "red" else "YELLOW NOTICE",
                "url": (f"https://www.interpol.int/en/How-we-work/Notices/"
                        f"View-{'Red' if notice_type == 'red' else 'Yellow'}-Notices/{entity_id}"),
                "api_url": f"{endpoint}/{entity_id}",
                "zoek_url": ("https://duckduckgo.com/?q=" + urllib.parse.quote(
                    f'{notice.get("forename", "")} {notice.get("name", "")} "{entity_id}"')),
                "bron": "Interpol API (geverifieerd)",
            }
            if index < 12:
                try:
                    time.sleep(INTERPOL_PAUZE)
                    detail = _harvest_get_of_none(f"{endpoint}/{entity_id}",
                                                  headers=INTERPOL_BROWSER_HEADERS,
                                                  timeout=12)
                    if detail is not None and detail.status_code == 200:
                        entry = _apostille_notice_gegevens(entry, detail.json())
                        entry = _voeg_fotos_toe(entry, endpoint, entity_id)
                except Exception:
                    pass
            uitkomst[notice_type].append(entry)
        time.sleep(INTERPOL_PAUZE_TUSSEN)

    if api_geblokkeerd:
        uitkomst["status"] = "geblokkeerd"
        uitkomst["melding"] = (
            "Interpol gaf geen toegang tot de API (blokkade of netwerkfout). "
            "Dit gebeurt zelden: de WAF-tolerante HTTP-laag (curl_cffi/Playwright) "
            "wordt gebruikt, maar Interpol kan nog steeds weigeren vanaf dit netwerk. "
            "Zonder toegang tot de API kan deze tool geen geverifieerde notices tonen "
            "en geen subject-specifieke links maken."
        )
        console.print(f"[yellow]{uitkomst['melding']}[/]")
        return uitkomst

    if not uitkomst["red"] and not uitkomst["yellow"]:
        uitkomst["status"] = "geen"
        uitkomst["melding"] = "Geen geverifieerde notices gevonden voor deze naam."
    return uitkomst


def _fbi_classificeer(subjects):
    """Deelt een FBI-record in als 'gezocht' (fugitive) of 'vermist' (missing)."""
    subs = {str(s).strip().lower() for s in (subjects or [])}
    if subs & FBI_VERMIST_SUBJECTS:
        return "vermist"
    if subs & FBI_GEZOCHT_SUBJECTS:
        return "gezocht"
    if subs:
        return "gezocht"
    return "gezocht"


def fbi_wanted_zoek(achternaam, voornaam=""):
    """FBI Wanted/Missing Persons via de officiele, publieke API.

    De FBI-Wanted-API (api.fbi.gov/wanted/v1/list) biedt geen API-key en
    filtert server-side op de naam via de 'title'-param (ongevoelig aan
    default: SUBSTRING-match). Records worden ingedeeld als 'gezocht'
    (fugitives: Most Wanted enz.) of 'vermist' (Kidnappings and Missing
    Persons / ViCAP Missing Persons) op basis van de subjects-categorie.

    In tegenstelling tot Interpol is er geen WAF, dus de gewone requests-
    laag (via _harvest_get_of_none) volstaat.
    """
    uitkomst = {"status": "ok", "melding": "", "gezocht": [], "vermist": []}
    zoekterm = achternaam.strip()
    if not zoekterm:
        uitkomst["status"] = "geen"
        uitkomst["melding"] = "Geen achternaam opgegeven."
        return uitkomst

    pagina = 1
    pagina_totaal = None
    while True:
        try:
            r = _harvest_get_of_none(
                FBI_WANTED_ENDPOINT,
                params={"title": zoekterm, "page": pagina, "pageSize": 20},
                headers={"user-agent": USER_AGENT, "accept": "application/json"},
                timeout=20,
            )
        except Exception:
            uitkomst["status"] = "geblokkeerd"
            uitkomst["melding"] = "FBI-API gaf geen toegang (netwerkfout of blokkade)."
            return uitkomst
        if r is None or r.status_code != 200:
            uitkomst["status"] = "geblokkeerd"
            uitkomst["melding"] = "FBI-API gaf geen toegang (netwerkfout of blokkade)."
            return uitkomst
        try:
            data = r.json()
        except ValueError:
            uitkomst["status"] = "geblokkeerd"
            uitkomst["melding"] = "FBI-API retourneerde geen geldige JSON."
            return uitkomst

        pagina_totaal = int(data.get("total", 0))
        items = data.get("items") or []
        if not items:
            break

        for it in items:
            if not it:
                continue
            titel = it.get("title") or ""
            categorie = _fbi_classificeer(it.get("subjects"))
            images = it.get("images") or []
            thumb = ""
            orig = ""
            for img in images:
                if img:
                    if not orig:
                        orig = img.get("original") or ""
                    if not thumb:
                        thumb = img.get("thumb") or img.get("large") or ""
                    if thumb and orig:
                        break

            entry = {
                "naam": titel,
                "categorie": categorie,
                "subjects": ", ".join(it.get("subjects") or []),
                "url": it.get("url") or "",
                "beschrijving": it.get("description") or it.get("details") or "",
                "geslacht": it.get("sex") or "",
                "nationaliteit": it.get("nationality") or ", ".join(it.get("possible_countries") or []),
                "geboortedatum": ", ".join(it.get("dates_of_birth_used") or []),
                "leeftijd": it.get("age_range") or "",
                "lengte": _formaat_lengte(it.get("height_min")) or "",
                "gewicht": _formaat_gewicht(it.get("weight_min")) or "",
                "haar": it.get("hair_raw") or "",
                "ogen": it.get("eyes_raw") or "",
                "aliassen": ", ".join(it.get("aliases") or []),
                "locaties": ", ".join(it.get("locations") or []),
                "veldkantoren": ", ".join(it.get("field_offices") or []),
                "foto_thumb": thumb,
                "foto_orig": orig,
                "zoek_url": ("https://duckduckgo.com/?q=" + urllib.parse.quote(
                    f'{titel} "{it.get("uid")}"')),
                "bron": "FBI Wanted API (officieel)",
            }
            uitkomst[categorie].append(entry)

        if len(items) < 20 or pagina >= min((pagina_totaal // 20) + 1, 5):
            break
        pagina += 1

    if not uitkomst["gezocht"] and not uitkomst["vermist"]:
        uitkomst["status"] = "geen"
        uitkomst["melding"] = "Geen FBI Wanted/Missing-records gevonden voor deze naam."
    return uitkomst


def _fbi_details_html(n):
    """Uitklapbare detail-view voor een FBI-record (analoog aan Interpol)."""
    esc = html.escape
    regels = []
    if n.get("categorie"):
        pass
    if n.get("subjects"):
        regels.append(("Categorie", n["subjects"]))
    if n.get("nationaliteit"):
        regels.append(("Nationaliteit", n["nationaliteit"]))
    if n.get("geboortedatum"):
        regels.append(("Geboortedatum", n["geboortedatum"]))
    if n.get("leeftijd"):
        regels.append(("Leeftijd", n["leeftijd"]))
    if n.get("geslacht"):
        regels.append(("Geslacht", n["geslacht"]))
    if n.get("lengte"):
        regels.append(("Lengte", n["lengte"]))
    if n.get("gewicht"):
        regels.append(("Gewicht", n["gewicht"]))
    if n.get("haar"):
        regels.append(("Haar", n["haar"]))
    if n.get("ogen"):
        regels.append(("Ogen", n["ogen"]))
    if n.get("aliassen"):
        regels.append(("Aliassen", n["aliassen"]))
    if n.get("locaties"):
        regels.append(("Locaties", n["locaties"]))
    if n.get("veldkantoren"):
        regels.append(("Veldkantoren", n["veldkantoren"]))
    if n.get("beschrijving"):
        regels.append(("Omschrijving", n["beschrijving"]))
    if not regels and not n.get("foto_orig"):
        return ""

    uit = '<details class="notice-details"><summary>Meer details</summary>'
    if n.get("url") or n.get("foto_orig") or n.get("zoek_url"):
        uit += ('<table class="detail-table"><tr><td class="detail-label">Links</td><td>'
                + (f'<a href="{esc(str(n["url"]))}" target="_blank" rel="noopener">FBI-pagina</a> · ' if n.get("url") else "")
                + (f'<a href="{esc(str(n["foto_orig"]))}" target="_blank" rel="noopener">Originele foto</a> · ' if n.get("foto_orig") else "")
                + (f'<a href="{esc(str(n["zoek_url"]))}" target="_blank" rel="noopener">Zoeken</a>' if n.get("zoek_url") else "")
                + "</td></tr></table>")
    uit += '<table class="detail-table">'
    for label, waarde in regels:
        uit += f"<tr><td class='detail-label'>{esc(str(label))}</td><td>{esc(str(waarde))}</td></tr>"
    uit += "</table></details>"
    return uit


def _is_ruis(opsporings_uitkomst):
    """Echte zaken hebben lange URLs + een naam/ref in de slug. Ruis zijn indexpagina's."""
    titel = (opsporings_uitkomst.get("titel") or "").lower()
    link = (opsporings_uitkomst.get("link") or "").lower()
    ruis_titels = ("tv-programma", "opsporing verzocht", "oplichters", "gezocht |", "getuigenoproep |",
                   "nationale opsporingslijst |", "opsporingsbericht |", "politie.nl |",
                   "werd gezocht", "opsporingslijst", "dpg media", "wijkagenten",
                   "herkend | go-")
    if any(x in titel for x in ruis_titels):
        return True
    pad = link.split("politie.nl/gezocht")[-1].strip("/")
    secties = [s for s in pad.split("/") if s]
    if len(secties) < 2:
        return True
    return False


def _splits_naam(naam, bestaand_voornaam=""):
    """Splits een volledige naam in (voornaam, achternaam).

    Houdt rekening met Nederlandse achtervoegsels (van, de, van den, ...).
    Gebruikt bestaand_voornaam indien aanwezig.
    """
    woorden = naam.strip().split()
    if not woorden:
        return "", naam
    if bestaand_voornaam:
        # Verwijder de gegeven voornaam uit de naam zodat alleen de
        # achternaam resteert (bv. "ivan versteegh" + voornaam "ivan" -> "versteegh").
        voornaam_woorden = set(bestaand_voornaam.lower().split())
        rest = [w for w in woorden if w.lower() not in voornaam_woorden]
        if rest and rest != woorden:
            return bestaand_voornaam, " ".join(rest)
        return bestaand_voornaam, naam
    if len(woorden) == 1:
        return "", naam
    achtervoegsels = {"van", "de", "den", "der", "het", "ter", "ten",
                      "te", "op", "aan", "uit", "tot", "bij", "voor"}
    # Eerste woord is achtervoegsels:check of er uberhaupt een voornaam-kandidaat is.
    # Geen voornaam als het eerste woord een achtervoegsels is (bv. "de Vries", "van den Berg")
    if woorden[0].lower() in achtervoegsels:
        return "", naam
    if len(woorden) >= 3 and woorden[1].lower() in achtervoegsels:
        return woorden[0], " ".join(woorden[1:])
    return woorden[0], woorden[-1]


def _verwijst_naar_persoon(uitkomst, achternaam, voornaam=""):
    volledig = f"{voornaam} {achternaam}" if voornaam else achternaam
    tekst = " ".join([
        (uitkomst.get("titel") or ""),
        (uitkomst.get("omschrijving") or ""),
        (uitkomst.get("link") or ""),
    ]).lower()
    namen = [achternaam.lower()]
    if voornaam:
        namen.append(voornaam.lower())
        namen.append(volledig.lower())
    return any(n in tekst for n in namen)


def opsporingslijst_zoek(achternaam, voornaam=""):
    volle_naam = f"{voornaam} {achternaam}".strip() if voornaam else achternaam
    dorks = {
        f'exact "{volle_naam}"': f'"{volle_naam}" site:politie.nl/gezocht',
        f"achternaam '{achternaam}'": f'site:politie.nl/gezocht {achternaam}',
    }

    hits = []
    geziene_links = set()

    for label, dork in dorks.items():
        with console.status(f"[cyan]{label} op politie.nl...[/]", spinner="dots"):
            resultaten = web_zoekopdracht(dork)
        for r in (resultaten or []):
            link = r.get("link", "")
            if "politie.nl" not in link:
                continue
            if link in geziene_links:
                continue
            if _is_ruis(r):
                continue
            if not _verwijst_naar_persoon(r, achternaam, voornaam):
                continue
            geziene_links.add(link)
            hits.append({
                "titel": r.get("titel", "?"),
                "link": link,
                "omschrijving": r.get("omschrijving", ""),
                "bron": "Nationale Opsporingslijst",
            })

    extra_dork = f'"{volle_naam}" "nationale opsporingslijst"'
    with console.status("[cyan]Aanvullende opsporingsbronnen...[/]", spinner="dots"):
        extra_resultaten = web_zoekopdracht(extra_dork)

    for r in (extra_resultaten or []):
        link = r.get("link", "")
        if _is_ruis(r):
            continue
        if not _verwijst_naar_persoon(r, achternaam, voornaam):
            continue
        if link in geziene_links:
            continue
        if any(x in link for x in ("politie.nl", "opsporing", "gezocht")):
            geziene_links.add(link)
            hits.append({
                "titel": r.get("titel", "?"),
                "link": link,
                "omschrijving": r.get("omschrijving", ""),
                "bron": "Aanvullende bron",
            })

    return hits


# Wegwerp-mail domeinen (te weggoonbare e-mailadressen) - overgenomen uit
# de osint-dashboard repo (cms/routes/email.py). Vaak gebruikt voor spam/wegwerp.
_DISPOSABLE_DOMEINEN = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
    "yopmail.com", "sharklasers.com", "trashmail.com", "10minutemail.com",
    "mailnator.com", "temp-mail.org", "getairmail.com", "tempinbox.com",
    "spamgourmet.com", "mailexpire.com", "maildrop.cc", "burnermail.io",
    "inboxbear.com", "discard.email", "mintemail.com", "mailforspam.com",
    "mailnesia.com", "wegwerpmailadres.nl", "wegwerpmail.net", "spam4.me",
    "dispostable.com", "fakeinbox.com", "mytemp.email", "tmail.ws",
    "mailcatch.com", "mailmoat.com", "emailondeck.com", "mailsac.com",
    "throwawaymail.com", "noclickemail.com", "moakt.com", "expirebox.com",
}


def _is_wegwerp_email(email):
    """Bepaal of een e-mailadres van een wegwerp/weggebed-maildienst is."""
    try:
        domein = email.lower().split("@")[1].strip()
    except (IndexError, ValueError):
        return False
    if domein in _DISPOSABLE_DOMEINEN:
        return True
    # ook bekende subdomeinen/fragment omzetten
    for d in _DISPOSABLE_DOMEINEN:
        if domein.endswith("." + d):
            return True
    return False


def _email_heeft_mx(email):
    """Controleer of het domein van een e-mailadres een MX-record heeft (DNS)."""
    try:
        domein = email.split("@")[1].strip()
    except (IndexError, ValueError):
        return False
    try:
        socket.getaddrinfo(domein, 25)
        return True
    except (socket.gaierror, OSError):
        return False


def email_verrijk(email):
    """Verrijk een e-mailadres met gratis publieke checks (geen key).

    - wegwerp/weggebed-mail detectie
    - MX-record check (bestaat er een mailserver op het domein?)
    - EmailRep.io-reputatie (score/details) - gratis publieke API
    - zoeklinks (EmailRep, Hunter.io, Dehashed, Google)
    Retourneert een dict voor CLI + dashboard.
    """
    uitkomst = {
        "status": "ok",
        "email": email,
        "geldig": False,
        "domein": None,
        "wegwerp": None,
        "mx": None,
        "emailrep": None,
        "links": [],
    }

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        uitkomst.update({"status": "fout", "melding": "Ongeldig e-mailformaat."})
        return uitkomst

    uitkomst["geldig"] = True
    domein = email.split("@")[1]
    uitkomst["domein"] = domein
    uitkomst["wegwerp"] = _is_wegwerp_email(email)
    uitkomst["mx"] = _email_heeft_mx(email)

    # EmailRep.io - gratis, geen key. Geeft reputatie-score + details.
    try:
        er = _harvest_get_of_none(
            f"https://emailrep.io/{urllib.parse.quote(email)}",
            headers={"user-agent": "osint-scanner/1.0 (legitiem OSINT onderzoek)"},
            timeout=10,
        )
        if er is not None and er.status_code == 200:
            d = er.json()
            uitkomst["emailrep"] = {
                "reputatie": d.get("reputation"),
                "verdacht": d.get("suspicious"),
                "referenties": d.get("references"),
                "details": d.get("details", {}),
            }
        elif er is not None and er.status_code == 404:
            # EmailRep heeft dit adres nog nooit gezien (geen lekken/
            # registraties). Dit is een "schoon" signaal: geen record.
            uitkomst["emailrep"] = {"reputatie": None, "geen_gegevens": True}
    except Exception:
        pass

    uitkomst["links"] = [
        {"label": "EmailRep.io", "url": f"https://emailrep.io/{urllib.parse.quote(email)}"},
        {"label": "Have I Been Pwned", "url": f"https://haveibeenpwned.com/account/{urllib.parse.quote(email)}"},
        {"label": "Hunter.io", "url": f"https://hunter.io/search/{domein}"},
        {"label": "Dehashed", "url": f"https://dehashed.com/search?query={urllib.parse.quote(email)}"},
        {"label": "Google", "url": f"https://www.google.com/search?q={urllib.parse.quote(email)}"},
    ]
    return uitkomst


def _normaliseer_telefoon(tel):
    """Normaliseer een telefoonnummer naar E164-vorm (zonder '+')."""
    if not tel:
        return None, None
    cleaned = re.sub(r"[^\d+]", "", tel)
    if cleaned.startswith("+"):
        cleaned = cleaned[1:]
    elif cleaned.startswith("00"):
        cleaned = cleaned[2:]
    elif cleaned.startswith("0"):
        cleaned = cleaned[1:]
    return cleaned, cleaned



def telefoon_verrijk(tel):
    """Verrijk een telefoonnummer met gratis publieke checks (geen key).

    - land/regio/netwerk/type/tijdzone via phonenumbers (optioneel)
    - WhatsApp-existentie via api.whatsapp.com/send
    - Telegram-existentie via t.me/+<nummer>
    Retourneert een dict voor CLI + dashboard.
    """
    uitkomst = {
        "status": "ok",
        "tel": tel,
        "genormaliseerd": None,
        "land": None,
        "regio": None,
        "netwerk": None,
        "lijn_type": None,
        "tijdzone": None,
        "whatsapp": None,
        "telegram": None,
    }

    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone as _pntz
        raw = str(tel).strip()
        # Eerst internationaal/E164 parsen; anders NL-nationaal formaat (leading 0)
        parsed = None
        try:
            parsed = phonenumbers.parse(raw, None)
        except Exception:
            parsed = None
        if parsed is None or not phonenumbers.is_valid_number(parsed):
            try:
                parsed_nl = phonenumbers.parse(raw, "NL")
                if phonenumbers.is_valid_number(parsed_nl):
                    parsed = parsed_nl
            except Exception:
                pass
        if parsed is not None and phonenumbers.is_valid_number(parsed):
            uitkomst["geldig"] = True
            uitkomst["genormaliseerd"] = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.E164
            ).lstrip("+")
            try:
                uitkomst["land"] = geocoder.description_for_number(parsed, "nl")
            except Exception:
                pass
            try:
                uitkomst["regio"] = geocoder.description_for_number(parsed, None)
            except Exception:
                pass
            try:
                uitkomst["netwerk"] = carrier.name_for_number(parsed, "nl")
            except Exception:
                pass
            try:
                nt = phonenumbers.number_type(parsed)
                if nt in (phonenumbers.PhoneNumberType.MOBILE,
                          phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE):
                    uitkomst["lijn_type"] = "mobiel"
                elif nt == phonenumbers.PhoneNumberType.FIXED_LINE:
                    uitkomst["lijn_type"] = "vast"
            except Exception:
                pass
            try:
                tzs = _pntz.time_zones_for_number(parsed)
                uitkomst["tijdzone"] = tzs[0] if tzs else None
            except Exception:
                pass
        else:
            uitkomst["geldig"] = False
    except Exception:
        uitkomst["geldig"] = False

    if not uitkomst.get("genormaliseerd"):
        genorm, _ = _normaliseer_telefoon(tel)
        uitkomst["genormaliseerd"] = genorm
        uitkomst["geldig"] = bool(genorm and len(genorm) >= 10)

    genorm = uitkomst.get("genormaliseerd")
    if genorm and uitkomst.get("geldig"):
        # WhatsApp: sinds 2024 toont api.whatsapp.com identieke "share on
        # WhatsApp" content voor geldig én ongeldig — server-side detectie
        # is niet meer mogelijk zonder WhatsApp Business API-authenticatie.
        # We geven een directe handmatige check-link.
        uitkomst["whatsapp"] = None
        uitkomst["whatsapp_url"] = f"https://wa.me/{genorm}"

        # Telegram: detectie + accountinfo via de openbare t.me/-preview-pagina
        try:
            tg_url = f"https://t.me/+{genorm}"
            tg = _harvest_get_of_none(
                tg_url,
                headers={"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                       "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
                timeout=8,
            )
            uitkomst["telegram_url"] = tg_url
            if tg is None:
                uitkomst["telegram"] = None
            else:
                tekst = tg.text.lower()
                afwezig = ["doesn't appear to exist", "does not appear to exist",
                           "no account found", "user not found", "could not be found",
                           "is not registered", "not found"]
                aanwezig = ["send message", "tgme_page_action", "tgme_action_button",
                            "tgme_page_title", "open chat"]
                if any(p in tekst for p in afwezig):
                    uitkomst["telegram"] = False
                elif any(p in tekst for p in aanwezig):
                    uitkomst["telegram"] = True
                else:
                    uitkomst["telegram"] = None
        except Exception:
            uitkomst["telegram"] = None

    return uitkomst


# RDW open data (gratis, geen key): Nederlands kentekenonderzoek.
# Overgenomen uit cms/routes/rdw.py van osint-dashboard.
RDW_API_BASE = "https://opendata.rdw.nl/resource/m9d7-ebf2.json"
RDW_BRANDSTOF_BASE = "https://opendata.rdw.nl/resource/8ys7-d773.json"


def _normaal_kenteken(kenteken):
    return kenteken.upper().replace("-", "").replace(" ", "")


def _leesbaar_kenteken(kenteken):
    k = kenteken.upper().replace("-", "").replace(" ", "")
    if len(k) == 6:
        return f"{k[:2]}-{k[2:5]}-{k[5:]}"
    if len(k) == 5:
        return f"{k[:2]}-{k[2:4]}-{k[4:]}"
    return k


def _rdw_datum(waarde):
    """Verkort een RDW-datetime ('2016-12-30T00:00:00.000') tot datum."""
    if not waarde:
        return waarde
    s = str(waarde)
    return s[:10] if "T" in s and s[10:11] == "T" else s


def rdw_kenteken_zoek(kenteken):
    """Zoek een Nederlands kenteken op via de gratis RDW-open-data API (geen key).

    Haalt voertuiggegevens op (merk, model, bouwjaar, kentekenhouder-info,
    vervaldatum, co2, brandstof, etc.).
    """
    uitkomst = {"status": "ok", "fout": None, "kenteken": None, "voertuig": None}
    k = _normaal_kenteken(kenteken)
    if not k:
        uitkomst.update({"status": "fout", "fout": "Geen geldig kenteken ingevoerd."})
        return uitkomst
    uitkomst["kenteken"] = _leesbaar_kenteken(k)

    try:
        r = _harvest_get_of_none(
            f"{RDW_API_BASE}?kenteken={urllib.parse.quote(k)}",
            headers={"user-agent": USER_AGENT, "accept": "application/json"},
            timeout=12,
        )
        if r is None or r.status_code != 200:
            uitkomst.update({"status": "fout",
                             "fout": f"RDW-API gaf geen resultaat (HTTP {r.status_code if r else 'onbereikbaar'})."})
            return uitkomst
        data = r.json()
        if not data:
            uitkomst.update({"status": "geen", "fout": "Geen voertuig gevonden voor dit kenteken."})
            return uitkomst
        voertuig = data[0]

        # Brandstof/CO2 via de aparte brandstof-dataset (8ys7-d773)
        brandstof_data = {}
        try:
            r2 = _harvest_get_of_none(
                f"{RDW_BRANDSTOF_BASE}?kenteken={urllib.parse.quote(k)}",
                headers={"user-agent": USER_AGENT, "accept": "application/json"},
                timeout=10,
            )
            if r2 is not None and r2.status_code == 200:
                a2 = r2.json()
                if a2:
                    brandstof_data = a2[0]
        except Exception:
            pass

        # Datumvelden: prefereren de "DT" (makkelijk leesbare) varianten
        bouwjaar = voertuig.get("datum_eerste_toelating_dt") or voertuig.get("datum_eerste_toelating")
        vervaldatum = voertuig.get("vervaldatum_apk_dt") or voertuig.get("vervaldatum_apk")

        uitkomst["voertuig"] = {
            "kenteken": _leesbaar_kenteken(k),
            "merk": voertuig.get("merk"),
            "handelsbenaming": voertuig.get("handelsbenaming"),
            "bouwjaar": bouwjaar,
            "datum_tenaamstelling": voertuig.get("datum_tenaamstelling_dt") or voertuig.get("datum_tenaamstelling"),
            "brandstof": brandstof_data.get("brandstof_omschrijving"),
            "co2": brandstof_data.get("co2_uitstoot_gecombineerd"),
            "vervaldatum": vervaldatum,
            "categorie": voertuig.get("europese_voertuigcategorie_toevoeging") or voertuig.get("europese_voertuigcategorie"),
            "kleur": voertuig.get("eerste_kleur"),
            "inrichting": voertuig.get("inrichting"),
            "aantal_deuren": voertuig.get("aantal_deuren"),
            "aantal_zitplaatsen": voertuig.get("aantal_zitplaatsen"),
            "voertuigsoort": voertuig.get("voertuigsoort"),
            "massa_ledig": voertuig.get("massa_ledig_voertuig"),
        }
    except Exception as exc:
        uitkomst.update({"status": "fout", "fout": f"RDW-check mislukt: {exc}"})
    return uitkomst


def voer_onderzoek_uit(target_type, target_value, dorks_dict, plaats="", voornaam="", return_data=False, open_browser_prompt=True):
    console.print()
    rapport = {}

    for platform, query in dorks_dict.items():
        with console.status(f"[cyan]Doorzoeken:[/] {platform}", spinner="dots"):
            resultaten = web_zoekopdracht(query)
            if resultaten is None:
                resultaten = []
        rapport[platform] = {"query": query, "hits": resultaten}
        for hit in resultaten:
            hit["score"] = match_score(target_value, hit["link"], hit["titel"], hit["omschrijving"])
        resultaten.sort(key=lambda h: -h.get("score", 0))
        stijl = "green" if resultaten else "dim"
        console.print(f"  [{stijl}]●[/] {platform} [dim]({query})[/] -> [bold]{len(resultaten)}[/] resultaten")

    extra = {}

    # Social media detectie uit DDG-resultaten (gebaseerd op WebMii-aanpak)
    alle_resultaten = [hit for data in rapport.values() for hit in data.get("hits", [])]
    socials_uit_resultaten = detecteer_social_media_uit_resultaten(rapport)
    score, unieke_platforms = bereken_web_presence_score(socials_uit_resultaten, len(alle_resultaten))
    extra["web_presence"] = {
        "score": score,
        "unieke_platforms": unieke_platforms,
        "socials": socials_uit_resultaten,
        "totaal_resultaten": len(alle_resultaten),
    }

    if target_type == "naam":
        # Voor het handelsregister zoeken we op de achternaam (i.p.v. de
        # volledige naam), zodat bedrijven met bv. de achternaam 'versteegh'
        # in de handelsnaam nog steeds gevonden worden.
        _, kvk_achternaam = _splits_naam(target_value, voornaam)
        with console.status("[cyan]OpenKvK-handelsregister...[/]", spinner="dots"):
            extra["openkvk"] = openkvk_bedrijven(kvk_achternaam or target_value)

    if target_type == "email":
        with console.status("[cyan]HaveIBeenPwned-check...[/]", spinner="dots"):
            extra["hibp"] = hibp_breaches(target_value)
        with console.status("[cyan]Sites-check (holehe, 40+ platforms)...[/]", spinner="dots"):
            extra["holehe"] = email_account_check(target_value)
        with console.status("[cyan]E-mail verrijken (wegwerp/MX/EmailRep)...[/]", spinner="dots"):
            extra["email_verrijking"] = email_verrijk(target_value)

    if target_type in ("username", "email"):
        with console.status("[cyan]GitHub-lookup...[/]", spinner="dots"):
            extra["github"] = github_lookup(target_value)

    if target_type == "username":
        bron_urls = [hit["link"] for data in rapport.values() for hit in data["hits"]]
        extra["social"] = social_media_scan(target_value, bron_urls)
        with console.status("[cyan]Social Media ID's extraheren...[/]", spinner="dots"):
            extra["social_ids"] = zoek_social_media_ids(extra["social"])

        # Maigret: uitgebreide site-scan als aanvulling (>3000 sites)
        maigret_gevonden = {}
        maigret_gezocht = 0
        if MAIGRET_BESCHIKBAAR:
            _laad_maigret_db()
            if _MAIGRET_DB is not None:
                bestaande_platforms = set()
                for s in extra.get("social_ids", []):
                    bestaande_platforms.add(s.get("platform", "").lower())
                with console.status(
                    "[cyan]Maigret site-scan (3000+ site database, even geduld)...[/]",
                    spinner="dots",
                ):
                    extra["maigret"] = maigret_zoek_gebruikersnaam(
                        target_value
                    )
                    maigret_gevonden = {
                        s["platform"].lower(): s
                        for s in extra["maigret"].get("sites", [])
                    }
                    maigret_gezocht = extra["maigret"].get("totaal_gezocht", 0)

                # Voeg nieuwe platforms toe aan social_media detectie
                for platf, data in maigret_gevonden.items():
                    url = data.get("url", "")
                    if not url:
                        continue
                    nieuw_platform, _ = _parse_platform_username(url)
                    if nieuw_platform and nieuw_platform not in bestaande_platforms:
                        extra["social"].append({
                            "platform": nieuw_platform,
                            "url": url,
                            "bron": "Maigret site-scan",
                        })

                # Vul ontbrekende social_ids aan vanuit Maigret
                huidige_ids = {s.get("platform", "").lower(): s
                               for s in extra.get("social_ids", [])}
                nieuw_ids = []
                for platf, data in maigret_gevonden.items():
                    url = data.get("url", "")
                    ids_data = data.get("ids_data", {})
                    if not isinstance(ids_data, dict):
                        ids_data = {}
                    maid = (ids_data.get("uid") or ids_data.get("user_id")
                            or ids_data.get("external_id"))
                    if platf in huidige_ids:
                        # Verrijk bestaande entry met ontbrekende ID-data
                        bestaand = huidige_ids[platf]
                        if not bestaand.get("id") and maid:
                            bestaand["id"] = maid
                        bestaand.setdefault("details", {})["ids_data"] = ids_data
                        continue
                    nieuw_ids.append({
                        "platform": data.get("platform", platf),
                        "url": url,
                        "username": target_value,
                        "id": maid,
                        "details": {
                            "ids_data": ids_data,
                            "bron": "Maigret",
                        },
                        "gecontroleerd": False,
                    })
                if nieuw_ids:
                    extra["social_ids"] = (
                        extra.get("social_ids", []) + nieuw_ids
                    )

    # Bij naam-onderzoek ook ID's extraheren uit de gedetecteerde social profielen
    if target_type == "naam" and extra.get("web_presence", {}).get("socials"):
        social_uit_naam = extra["web_presence"]["socials"]
        with console.status("[cyan]Social Media ID's extraheren...[/]", spinner="dots"):
            extra["social_ids"] = zoek_social_media_ids(social_uit_naam)

    if target_type == "naam":
        voornaam_gevonden, achternaam_gevonden = _splits_naam(target_value, voornaam)
        with console.status("[cyan]Interpol-notice zoeken...[/]", spinner="dots"):
            extra["interpol"] = interpol_zoek(achternaam_gevonden, voornaam_gevonden)
        with console.status("[cyan]FBI Wanted/Missing zoeken...[/]", spinner="dots"):
            extra["fbi"] = fbi_wanted_zoek(achternaam_gevonden, voornaam_gevonden)
        with console.status("[cyan]Nationale Opsporingslijst...[/]", spinner="dots"):
            extra["opsporingslijst"] = opsporingslijst_zoek(achternaam_gevonden, voornaam_gevonden)

    if target_type == "telefoon":
        with console.status("[cyan]Telefoon verrijken (WhatsApp/Telegram)...[/]", spinner="dots"):
            extra["telefoon_verrijking"] = telefoon_verrijk(target_value)

    with console.status("[cyan]Rapport genereren...[/]", spinner="dots"):
        bestandsnaam = genereer_dashboard(target_type, target_value, rapport, extra, plaats, open_browser=False)

    console.clear()

    tabel = Table(title=f"Samenvatting - {target_value}", box=box.ROUNDED, header_style="bold cyan")
    tabel.add_column("Bron", style="white")
    tabel.add_column("Treffers", justify="right")
    for platform, data in rapport.items():
        tabel.add_row(platform, str(len(data["hits"])))
    if "hibp" in extra:
        kleur = {"schoon": "green", "getroffen": "red", "overgeslagen": "yellow", "fout": "yellow"}[extra["hibp"]["status"]]
        label = {"schoon": "geen lekken", "getroffen": "IN LEKKEN!", "overgeslagen": "overgeslagen", "fout": "fout"}[extra["hibp"]["status"]]
        tabel.add_row("HaveIBeenPwned", f"[{kleur}]{label}[/]")
    if "github" in extra:
        tabel.add_row("GitHub", str(len(extra["github"]["profielen"])) + " profielen")
    if "holehe" in extra:
        hh = extra["holehe"]
        if hh.get("status") == "ok":
            kleur = "red" if hh.get("gevonden") else "green"
            onbekend = sum(1 for s_ in hh.get("sites", []) if s_["rate_limit"])
            label = f"{hh.get('gevonden', 0)} accounts"
            if onbekend:
                label += f", {onbekend} onbekend"
            tabel.add_row("Sites-check (holehe)", f"[{kleur}]{label}[/]")
        else:
            tabel.add_row("Sites-check (holehe)", f"[yellow]{hh.get('melding', 'overgeslagen')}[/]")
    if "social" in extra:
        tabel.add_row("Social-profielen", str(len(extra["social"])))
    if "social_ids" in extra:
        gevonden_ids = [x for x in extra["social_ids"] if x.get("id")]
        socid_enriched = sum(1 for x in extra["social_ids"]
                            if x.get("details", {}).get("socid"))
        maigret_aantal = sum(1 for x in extra["social_ids"]
                             if x.get("details", {}).get("bron") == "Maigret")
        label = f"[cyan]{len(gevonden_ids)}/{len(extra['social_ids'])}[/] geextraheerd"
        extra_labels = []
        if socid_enriched:
            extra_labels.append(f"+{socid_enriched} socid")
        if maigret_aantal:
            extra_labels.append(f"+{maigret_aantal} maigret")
        if extra_labels:
            label += f" [dim]({' '.join(extra_labels)})[/]"
        tabel.add_row("Social IDs", label)
    if "maigret" in extra:
        mr = extra["maigret"]
        m_sites = mr.get("sites", [])
        m_gezocht = mr.get("totaal_gezocht", 0)
        m_fout = mr.get("fouten", [])
        if m_sites:
            tabel.add_row(
                "Maigret",
                f"[cyan]{len(m_sites)}[/]/{m_gezocht} sites"
                + (f" [dim]({len(m_fout)} fout)[/]" if m_fout else ""),
            )
        elif m_fout:
            tabel.add_row("Maigret", f"[yellow]fout: {m_fout[0][:40]}[/]")
        else:
            tabel.add_row("Maigret", f"[dim]0/{m_gezocht} sites[/]")
    if "web_presence" in extra:
        wp = extra["web_presence"]
        tabel.add_row("Web Presence Score", f"[cyan]{wp['score']}/10[/] ({wp['unieke_platforms']} platforms)")
    if "email_verrijking" in extra:
        ev = extra["email_verrijking"]
        if ev.get("status") == "ok":
            onderdelen = []
            if ev.get("wegwerp") is not None:
                kleur = "red" if ev["wegwerp"] else "green"
                label = "wegwerp-mail" if ev["wegwerp"] else "echt domein"
                onderdelen.append(f"[{kleur}]{label}[/]")
            if ev.get("mx"):
                onderdelen.append("[green]MX aanwezig[/]")
            elif ev.get("geldig"):
                onderdelen.append("[red]geen MX[/]")
            if ev.get("emailrep") is not None:
                er = ev["emailrep"]
                ver = er.get("reputatie")
                if ver is not None:
                    aikleur = "red" if er.get("verdacht") else "green"
                    onderdelen.append(f"[{aikleur}]EmailRep {ver}/low[/]")
                elif er.get("geen_gegevens"):
                    onderdelen.append("[green]EmailRep geen record[/]")
            tabel.add_row("E-mail verrijking", " | ".join(onderdelen) or "[dim]—[/]")
    if "telefoon_verrijking" in extra:
        tv = extra["telefoon_verrijking"]
        onderdelen = []
        if tv.get("land"):
            onderdelen.append(f"[cyan]{tv['land']}[/]")
        if tv.get("netwerk"):
            onderdelen.append(f"[cyan]{tv['netwerk']}[/]")
        if tv.get("whatsapp") is not None:
            wa_kleur = "green" if tv["whatsapp"] else "yellow"
            wa_label = "WhatsApp actief" if tv["whatsapp"] else "WhatsApp nee"
            onderdelen.append(f"[{wa_kleur}]{wa_label}[/]")
        if tv.get("telegram") is not None:
            tg_kleur = "green" if tv["telegram"] else "yellow"
            tg_label = "Telegram actief" if tv["telegram"] else "Telegram nee"
            if tv.get("telegram_url"):
                tg_label += f" [link]({tv['telegram_url']})"
            onderdelen.append(f"[{tg_kleur}]{tg_label}[/]")
        if onderdelen:
            tabel.add_row("Telefoon verrijking", " | ".join(onderdelen))
    if "rdw" in extra:
        rd = extra["rdw"]
        if rd.get("status") == "ok" and rd.get("voertuig"):
            v = rd["voertuig"]
            label = f"[cyan]{v.get('merk') or '?'}[/]"
            if v.get("handelsbenaming"):
                label += f" [cyan]{v['handelsbenaming']}[/]"
            if v.get("bouwjaar"):
                label += f" [dim]({str(v['bouwjaar'])[:4]})[/]"
            tabel.add_row(f"RDW {rd.get('kenteken') or ''}", label)
        elif rd.get("status") == "geen":
            tabel.add_row("RDW", "[yellow]geen voertuig[/]")
        elif rd.get("status") == "fout":
            tabel.add_row("RDW", f"[yellow]{rd.get('fout','fout')[:40]}[/]")
    if "interpol" in extra:
        i = extra["interpol"]
        if i.get("status") == "geblokkeerd":
            tabel.add_row("Interpol", "[yellow]API niet bereikbaar[/]")
        elif i["red"] or i["yellow"]:
            tabel.add_row("Interpol", f"[red]{len(i['red'])} red[/], [yellow]{len(i['yellow'])} yellow[/]")
        else:
            tabel.add_row("Interpol", "[dim]geen notices[/]")
    if "fbi" in extra:
        f = extra["fbi"]
        if f.get("status") == "geblokkeerd":
            tabel.add_row("FBI", "[yellow]API niet bereikbaar[/]")
        elif f["gezocht"] or f["vermist"]:
            totaal_f = len(f["gezocht"]) + len(f["vermist"])
            if f["gezocht"] and f["vermist"]:
                tabel.add_row("FBI", f"[red]{len(f['gezocht'])} gezocht[/], [yellow]{len(f['vermist'])} vermist[/]")
            elif f["gezocht"]:
                tabel.add_row("FBI", f"[red]{len(f['gezocht'])} gezocht[/]")
            else:
                tabel.add_row("FBI", f"[yellow]{len(f['vermist'])} vermist[/]")
        else:
            tabel.add_row("FBI", "[dim]geen records[/]")
    if "opsporingslijst" in extra:
        ol_count = len(extra["opsporingslijst"])
        if ol_count:
            tabel.add_row("Opsporingslijst", f"[red]{ol_count} resultaten[/]")
    console.print()
    console.print(tabel)

    sterke_hits = [
        (platform, hit)
        for platform, data in rapport.items()
        for hit in data["hits"]
        if hit.get("score", 0) == 3
    ][:5]
    if sterke_hits:
        console.print("\n[bold green]Beste matches:[/]")
        for platform, hit in sterke_hits:
            titel = hit['titel'][:48] + "…" if len(hit['titel']) > 50 else hit['titel']
            console.print(f"  [cyan]{platform}[/]  {titel}")

    console.print(f"\n[bold green]✔ Rapport opgeslagen:[/] [underline]{bestandsnaam}[/]")

    # Open het rapport pas in de browser nadat de gebruiker de samenvatting
    # heeft gezien en met een toets bevestigt. (De desktop-versie stuurt deze
    # prompt uit, die opent het rapport zelf via een 'Openen'-knop.)
    if open_browser_prompt:
        keuze = Prompt.ask(
            "\n[bold cyan]Open het rapport in de browser?[/] [dim](j/N)[/]",
            choices=["j", "n"],
            default="n",
        )
        if keuze.lower() == "j":
            webbrowser.open(f"file://{os.path.abspath(bestandsnaam)}")
            console.print("[dim]Rapport geopend in de browser.[/]")
        else:
            console.print("[dim]Rapport niet geopend.[/]")

    # De desktop-versie vraagt de gestructureerde (rapport, extra) op om zelf
    # een samenvatting + klikbare hits te renderen.
    if return_data:
        return bestandsnaam, rapport, extra
    return bestandsnaam


ZOEKBALK_JS = """
<script>
(function () {
    // Alles standaard ingeklapt openen.
    document.querySelectorAll('.card').forEach(function (kaart) {
        kaart.classList.add('collapsed');
    });
    // Kaarten inklappen/uitklappen door op de titel te klikken.
    document.querySelectorAll('.card .card-title').forEach(function (titel) {
        titel.addEventListener('click', function () {
            titel.parentElement.classList.toggle('collapsed');
        });
    });
    // Alles tegelijk openklappen / inklappen.
    document.getElementById('klapallen').addEventListener('click', function () {
        document.querySelectorAll('.card').forEach(function (kaart) {
            kaart.classList.remove('collapsed');
        });
    });
    document.getElementById('klapgeen').addEventListener('click', function () {
        document.querySelectorAll('.card').forEach(function (kaart) {
            kaart.classList.add('collapsed');
        });
    });
    var veld = document.getElementById('zoekveld');
    var telling = document.getElementById('zoektelling');
    var reset = document.getElementById('zoekreset');
    var vorige = document.getElementById('zoekvorige');
    var volgende = document.getElementById('zoekvolgende');
    if (!veld) return;

    var matchen = [];
    var huidig = -1;

    function wisMarkering() {
        var markers = document.querySelectorAll('mark');
        for (var i = markers.length - 1; i >= 0; i--) {
            markers[i].replaceWith(document.createTextNode(markers[i].textContent));
        }
        document.body.normalize();
        matchen = [];
        huidig = -1;
    }

    function activeer(mark) {
        if (!mark) return;
        mark.classList.add('mark-huidig');
        try { mark.scrollIntoView({ block: 'center', behavior: 'smooth' }); } catch (e) {}
    }

    function toonTelling() {
        if (matchen.length === 0) { telling.textContent = ''; return; }
        if (huidig === -1) {
            telling.textContent = matchen.length + ' treffer' + (matchen.length === 1 ? '' : 's');
        } else {
            telling.textContent = (huidig + 1) + ' van ' + matchen.length;
        }
    }

    function highlight(q) {
        wisMarkering();
        if (q.length < 2) { toonTelling(); return; }

        function scan(node) {
            if (node.nodeType === 3) {
                var tekst = node.textContent;
                var laag = tekst.toLowerCase();
                if (laag.indexOf(q) !== -1) {
                    var fragment = document.createDocumentFragment();
                    var pos = 0;
                    while (true) {
                        var idx = laag.indexOf(q, pos);
                        if (idx === -1) {
                            fragment.appendChild(document.createTextNode(tekst.slice(pos)));
                            break;
                        }
                        fragment.appendChild(document.createTextNode(tekst.slice(pos, idx)));
                        var mark = document.createElement('mark');
                        mark.textContent = tekst.slice(idx, idx + q.length);
                        matchen.push(mark);
                        fragment.appendChild(mark);
                        pos = idx + q.length;
                    }
                    node.parentNode.replaceChild(fragment, node);
                    return;
                }
                return;
            }
            if (node.nodeName === 'SCRIPT' || node.nodeName === 'STYLE') return;
            var kids = Array.prototype.slice.call(node.childNodes);
            for (var i = 0; i < kids.length; i++) scan(kids[i]);
        }
        scan(document.body);
        toonTelling();
    }

    function gaNaar(richting) {
        if (matchen.length === 0) return;
        var oud = matchen[huidig];
        if (oud) oud.classList.remove('mark-huidig');
        if (huidig === -1) {
            huidig = richting > 0 ? 0 : matchen.length - 1;
        } else {
            huidig = (huidig + richting + matchen.length) % matchen.length;
        }
        activeer(matchen[huidig]);
        toonTelling();
    }

    veld.addEventListener('input', function () {
        highlight(veld.value.trim().toLowerCase());
    });
    veld.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); gaNaar(e.shiftKey ? -1 : 1); }
    });
    vorige.addEventListener('click', function () { gaNaar(-1); });
    volgende.addEventListener('click', function () { gaNaar(1); });
    reset.addEventListener('click', function () {
        veld.value = '';
        highlight('');
        veld.focus();
    });
})();
</script>
"""


def _harvest_get(url, params=None, headers=None, timeout=20):
    """GET via de WAF-tolerante harvest-client (curl_cffi impersonate +
    jitter + proxy/Tor + Playwright-fallback). Deze reproduceert echte
    browser-TLS-fingerprints, zodat o.a. de politie-API's door Akamai
    worden geaccepteerd (plain Python-requests krijgt daar 403).
    """
    if HARVEST_BESCHIKBAAR:
        return _harvest.harvest_get(url, params=params, headers=headers, timeout=timeout)
    # Fallback zonder harvest_client: browser-headers via requests.
    return requests.get(
        url,
        params=params,
        headers={"user-agent": USER_AGENT, "accept": "application/json"},
        timeout=timeout,
    )


def _harvest_get_of_none(url, params=None, headers=None, timeout=20):
    """Net als _harvest_get, maar gooit nooit: retourneert None bij falen.

    Bedoeld voor publieke/WAF-gevoelige doelen (social-platforms, Interpol,
    politie.nl-scrapes) waar de callers al 'r is not None' / statuscode-checks
    doen en graceful moeten degraderen bij connectie/blokkade.
    """
    try:
        return _harvest_get(url, params=params, headers=headers, timeout=timeout)
    except Exception:
        return None


def bag_adres_zoeken(query):
    """Zoek een Nederlands adres op bij het Kadaster (gratis, open data, geen key).

    Keten:
      1) PDOK Locatieserver -> adres zoeken (coördinaten, perceel, gemeente/buurt).
      2) BAG OGC verblijfsobject -> oppervlakte, gebruiksdoel, status.
      3) BAG OGC pand -> bouwjaar, pandstatus, aantal verblijfsobjecten.
      4) api.politie.nl -> dichtstbijzijnde politiebureau (via coördinaten).
    Retourneert een dict voor de CLI en het HTML-dashboard.
    """
    headers = {"user-agent": USER_AGENT, "accept": "application/json"}
    result = {"query": query, "status": "ok", "fout": None, "adres": None}

    def _get(url, params=None):
        r = requests.get(url, params=params, headers=headers, timeout=20)
        r.raise_for_status()
        return r.json()

    try:
        # 1) Adres zoeken via PDOK locatieserver
        docs = _get(
            "https://api.pdok.nl/bzk/locatieserver/search/v3_1/free",
            {"q": query, "rows": 2, "fq": "type:adres"},
        ).get("response", {}).get("docs", [])
        if not docs:
            result["status"] = "geen_resultaat"
            result["fout"] = "Geen overeenkomend Nederlands adres gevonden."
            return result

        doc = docs[0]
        adres = {
            "weergavenaam": doc.get("weergavenaam"),
            "straat": doc.get("openbareruimte_naam") or doc.get("straatnaam"),
            "huisnummer": doc.get("huisnummer"),
            "postcode": doc.get("postcode"),
            "woonplaats": doc.get("woonplaatsnaam"),
            "gemeente": doc.get("gemeentenaam"),
            "gemeentecode": doc.get("gemeentecode"),
            "provincie": doc.get("provincienaam"),
            "buurt": doc.get("buurtnaam"),
            "wijk": doc.get("wijknaam"),
            "waterschap": doc.get("waterschapsnaam"),
            "perceel": doc.get("gekoppeld_perceel") or [],
            "coord_rd": doc.get("centroide_rd"),
            "coord_ll": doc.get("centroide_ll"),
        }
        vbo_id = doc.get("adresseerbaarobject_id")
        nra_id = doc.get("nummeraanduiding_id")
        adres["verblijfsobject_id"] = vbo_id
        adres["nummeraanduiding_id"] = nra_id
        result["adres"] = adres

        # 2) Verblijfsobject -> oppervlakte, gebruiksdoel, status
        if vbo_id:
            items = _get(
                "https://api.pdok.nl/kadaster/bag/ogc/v2/collections/verblijfsobject/items",
                {"identificatie": vbo_id},
            ).get("features", [])
            if items:
                p = items[0].get("properties", {})
                adres["gebruiksdoel"] = p.get("gebruiksdoel")
                adres["oppervlakte"] = p.get("oppervlakte")
                adres["verblijfsobject_status"] = p.get("status")
                pand_hrefs = p.get("pand.href") or []

                # 3) Pand -> bouwjaar
                if pand_hrefs:
                    try:
                        pp = _get(pand_hrefs[0]).get("properties", {})
                        adres["bouwjaar"] = pp.get("bouwjaar")
                        adres["pand_status"] = pp.get("status")
                        adres["pand_id"] = pp.get("identificatie")
                        adres["aantal_verblijfsobjecten"] = pp.get("aantal_verblijfsobjecten")
                        adres["pand_gebruiksdoel"] = pp.get("gebruiksdoel")
                    except Exception:
                        pass

        # Kaart- en politie-links op basis van coördinaten + postcode.
        ll = adres.get("coord_ll") or ""
        lat = lon = None
        if ll.startswith("POINT("):
            coords = ll.replace("POINT(", "").replace(")", "").split()
            if len(coords) == 2:
                try:
                    lon, lat = float(coords[0]), float(coords[1])
                except ValueError:
                    lon = lat = None

        bag_viewer_base = "https://bagviewer.kadaster.nl/lvbag/bag-viewer/index.html"
        adres["links"] = {}
        object_id = adres.get("pand_id") or adres.get("verblijfsobject_id")
        if object_id:
            adres["links"]["bag_viewer"] = f"{bag_viewer_base}?objectId={urllib.parse.quote(object_id)}"
        if lat is not None and lon is not None:
            adres["links"]["google_maps"] = (
                f"https://www.google.com/maps?q={lat:.7f},{lon:.7f}"
            )
            adres["links"]["openstreetmap"] = (
                f"https://www.openstreetmap.org/?mlat={lat:.7f}&mlon={lon:.7f}#map=19/{lat:.7f}/{lon:.7f}"
            )
            adres["links"]["politie_bureaus"] = f"https://www.politie.nl/mijn-buurt/politiebureaus?lat={lat:.6f}&lng={lon:.6f}"
        postcode = adres.get("postcode") or ""
        if postcode:
            pc = postcode[:4] + postcode[4:].lower()
            adres["links"]["politie_wijkagent"] = (
                f"https://www.politie.nl/mijn-buurt/wijkagenten/lijst?geoquery={pc}&distance=5.0"
            )

        # Dichtstbijzijnde politiebureau(s) automatisch ophalen via api.politie.nl.
        # Deze API antwoordt (vanaf deze machine) alleen op browser-TLS-fingerprints,
        # vandaar de harvest-client (curl_cffi impersonate) i.p.v. plain requests.
        if lat is not None and lon is not None:
            adres["politie"] = []
            try:
                pb = _harvest_get(
                    "https://api.politie.nl/politiebureaus/v1",
                    {"lat": lat, "lon": lon},
                )
                pb.raise_for_status()
                bureaus = (pb.json() or {}).get("politiebureaus", []) or []
                for s in bureaus[:3]:
                    bezoek = s.get("bezoekadres") or {}
                    adres["politie"].append(
                        {
                            "naam": s.get("naam"),
                            "adres": bezoek.get("adres"),
                            "postcode": bezoek.get("postcode"),
                            "plaats": bezoek.get("plaats"),
                            "telefoon": s.get("telefoonnummer"),
                            "url": s.get("url"),
                            "afstand_m": s.get("afstand_m"),
                        }
                    )
            except Exception:
                adres["politie"] = []
    except requests.RequestException as exc:
        result["status"] = "fout"
        result["fout"] = f"Kadaster/BAG API niet bereikbaar: {exc}"
    except Exception as exc:
        result["status"] = "fout"
        result["fout"] = f"Onverwachte fout: {exc}"

    return result


def genereer_dashboard(target_type, target_value, rapport, extra=None, plaats="", open_browser=True):
    extra = extra or {}
    e = html.escape

    css = """
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #0b0f19; color: #cbd5e1; }
        h1 { color: #38bdf8; border-bottom: 2px solid #1e293b; padding-bottom: 15px; font-size: 28px; }
        h2 { color: #38bdf8; font-size: 22px; margin-top: 35px; }
        .metadata { background: #111827; padding: 20px; border-radius: 12px; margin-bottom: 30px; border: 1px solid #1e293b; }
        .badge { background: #0284c7; color: white; padding: 4px 10px; border-radius: 6px; font-size: 12px; }
        .card { background: #1e293b; border-radius: 12px; padding: 20px; margin-bottom: 25px; border: 1px solid #334155; }
        .card.collapsed { padding: 14px 20px; margin-bottom: 6px; }
        .card-title { color: #38bdf8; font-size: 20px; margin-top: 0; display: flex; align-items: center; cursor: pointer; gap: 6px; }
        .card-title:hover { color: #7dd3fc; }
        .card-title > :first-child { margin-left: auto; }
        .card-title::after { content: " \u25be"; font-size: 16px; margin-left: 4px; color: #38bdf8; }
        .card.collapsed > :not(.card-title) { display: none; }
        .card.collapsed .card-title::after { content: " \u25b8"; }
        .card.collapsed .card-title { font-size: 16px; }
        .query-text { font-family: monospace; background: #0f172a; padding: 6px 12px; border-radius: 6px; font-size: 13px; color: #94a3b8; display: block; margin: 10px 0; border: 1px solid #1e293b; word-break: break-all; }
        .hit-table { width: 100%; border-collapse: collapse; margin-top: 15px; table-layout: fixed; }
        .hit-table th, .hit-table td { padding: 12px; border: 1px solid #334155; text-align: left; vertical-align: top; overflow-wrap: anywhere; word-break: break-word; }
        .hit-table th { background: #0f172a; color: #94a3b8; }
        .hit-table tr:hover { background: #24344d; }
        a { color: #38bdf8; text-decoration: none; font-weight: bold; }
        a:hover { text-decoration: underline; }
        .no-hits { color: #94a3b8; font-style: italic; padding: 10px 0; }
        .muted { color: #94a3b8; }
        .ok { color: #34d399; font-weight: bold; }
        .bad { color: #f43f5e; font-weight: bold; }
        .warn { color: #fbbf24; font-weight: bold; }
        .warn-text { color: #fbbf24; background: #1e293b; border-left: 4px solid #fbbf24; padding: 12px 16px; border-radius: 8px; margin-bottom: 12px; }
        .exact-row { background: #0b2233; border-left: 4px solid #38bdf8; }
        .exact-row td { color: #e2e8f0; }
        .notice-details { margin: 4px 0; }
        .notice-details summary { cursor: pointer; color: #38bdf8; font-weight: bold; font-size: 13px; }
        .detail-table { width: 100%; border-collapse: collapse; margin-top: 6px; }
        .detail-table td { padding: 4px 10px; border-bottom: 1px solid #1e293b; font-size: 13px; }
        .detail-label { color: #94a3b8; width: 40%; }
        .notice-fotos { display: flex; gap: 12px; margin: 6px 0 10px; flex-wrap: wrap; }
        .notice-foto { text-align: center; }
        .notice-foto img { max-width: 140px; max-height: 180px; border-radius: 8px; border: 1px solid #1e293b; display: block; margin-bottom: 4px; }
        .notice-foto a { font-size: 12px; font-weight: bold; color: #38bdf8; }
        .notice-thumb { max-width: 56px; max-height: 56px; border-radius: 6px; border: 1px solid #1e293b; object-fit: cover; }
        #zoekbalk { position: sticky; top: 0; z-index: 20; background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 10px 12px; display: flex; gap: 10px; align-items: center; margin-bottom: 22px; box-shadow: 0 4px 12px rgba(0,0,0,.35); }
        #zoekveld { flex: 1; background: #0b0f19; color: #e2e8f0; border: 1px solid #334155; border-radius: 8px; padding: 8px 12px; font-size: 14px; }
        #zoekveld:focus { outline: none; border-color: #38bdf8; }
        #zoektelling { color: #94a3b8; font-size: 13px; white-space: nowrap; }
        #zoekknoppen { display: flex; gap: 6px; align-items: center; }
        .zoekknop { background: #1e293b; color: #e2e8f0; border: 1px solid #334155; border-radius: 6px; padding: 5px 10px; font-size: 15px; cursor: pointer; line-height: 1.2; }
        .zoekknop:hover:not(:disabled) { border-color: #38bdf8; }
        .zoekknop:disabled { opacity: .4; cursor: default; }
        #zoekreset { background: none; border: none; color: #f43f5e; font-size: 22px; cursor: pointer; line-height: 1; padding: 0 4px; }
        #zoekreset:hover { color: #fb7185; }
        mark { background: #fbbf24; color: #0b0f19; padding: 0 1px; border-radius: 2px; }
        mark.mark-huidig { background: #f43f5e; color: #fff; outline: 2px solid #f43f5e; }
        @media print {
            body { margin: 0; background: #fff; color: #111827; }
            #zoekbalk { display: none !important; }
            h1, h2, .card-title { color: #0f172a; }
            h1 { border-bottom: 2px solid #cbd5e1; }
            .card, .metadata { background: #fff; border: 1px solid #cbd5e1; box-shadow: none; }
            .query-text { background: #f1f5f9; color: #475569; border-color: #cbd5e1; }
            .hit-table th { background: #f1f5f9; color: #334155; }
            .hit-table th, .hit-table td { border-color: #cbd5e1; }
            .hit-table tr:hover { background: #fff; }
            .muted { color: #64748b; }
            .notice-foto img { border-color: #cbd5e1; }
            a { color: #0369a1; }
            .card { break-inside: avoid; }
            .card.collapsed > :not(.card-title) { display: block; }
        }
    """

    onderdelen = []

    if "interpol" in extra:
        i = extra["interpol"]
        status = i.get("status", "ok")
        if status == "geblokkeerd":
            blok = f"""
            <div class="card">
                <div class="card-title">
                    Interpol Notices
                    <span class="warn">API GEBLOKKEERD</span>
                </div>
                <p class="warn-text">{e(i.get('melding', ''))}</p>
                <p class="muted">Handmatig controleren:
                    <a href="https://www.interpol.int/en/How-we-work/Notices/Red-Notices/View-Red-Notices" target="_blank" rel="noopener">Red Notices</a> ·
                    <a href="https://www.interpol.int/en/How-we-work/Notices/Yellow-Notices/View-Yellow-Notices" target="_blank" rel="noopener">Yellow Notices</a>
                </p>
            </div>
            """
            onderdelen.append(blok)
        else:
            alle_notices = i["red"] + i["yellow"]
            blok = f"""
            <div class="card">
                <div class="card-title">
                    Interpol Notices
                    <span class="badge">{len(alle_notices)} notices</span>
                </div>
            """
            if i["red"]:
                blok += '<h2 style="color:#f43f5e;">Red Notices (gezocht)</h2>'
                blok += ('<table class="hit-table"><thead><tr><th>Naam</th><th>Nationaliteit</th><th>Geb.datum</th><th>Type</th><th>Subject</th></tr></thead><tbody>')
                for n in i["red"]:
                    blok += (f'<tr><td>{e(n["naam"])}</td>'
                             f'<td>{e(n["nationaliteit"])}</td>'
                             f'<td class="muted">{e(n["geboortedatum"])}</td>'
                             f'<td><span style="color:#f43f5e;font-weight:bold;">RED</span></td>'
                             f'<td><a href="{e(n["url"], quote=True)}" target="_blank" rel="noopener">Interpol</a>'
                             f' · <a href="{e(n.get("api_url", ""), quote=True)}" target="_blank" rel="noopener">API-data</a>'
                             f' · <a href="{e(n.get("zoek_url", ""), quote=True)}" target="_blank" rel="noopener">Zoeken</a></td></tr>')
                    _details = _notice_details_html(n)
                    if _details:
                        blok += f'<tr><td colspan="5">{_details}</td></tr>'
                blok += "</tbody></table>"
            if i["yellow"]:
                blok += '<h2 style="color:#fbbf24;">Yellow Notices (vermist)</h2>'
                blok += ('<table class="hit-table"><thead><tr><th>Naam</th><th>Nationaliteit</th><th>Geb.datum</th><th>Type</th><th>Subject</th></tr></thead><tbody>')
                for n in i["yellow"]:
                    blok += (f'<tr><td>{e(n["naam"])}</td>'
                             f'<td>{e(n["nationaliteit"])}</td>'
                             f'<td class="muted">{e(n["geboortedatum"])}</td>'
                             f'<td><span style="color:#fbbf24;font-weight:bold;">YELLOW</span></td>'
                             f'<td><a href="{e(n["url"], quote=True)}" target="_blank" rel="noopener">Interpol</a>'
                             f' · <a href="{e(n.get("api_url", ""), quote=True)}" target="_blank" rel="noopener">API-data</a>'
                             f' · <a href="{e(n.get("zoek_url", ""), quote=True)}" target="_blank" rel="noopener">Zoeken</a></td></tr>')
                    _details = _notice_details_html(n)
                    if _details:
                        blok += f'<tr><td colspan="5">{_details}</td></tr>'
                blok += "</tbody></table>"
            if not alle_notices:
                blok += f'<p class="no-hits">{e(i.get("melding", "Geen notices gevonden voor deze naam."))}</p>'
            else:
                blok += ('<p class="muted">Klik op <em>Meer details</em> per notice voor leesbare gegevens '
                         '(geboorteplaats, kenmerken, arrestbevelen). Als een Interpol-noticepagina tijdelijk '
                         'onbeschikbaar is (HTTP 503), toont de <em>API-data</em>-link de brondata.</p>')
            blok += "</div>"
            onderdelen.append(blok)

    if "fbi" in extra:
        fbi = extra["fbi"]
        f_status = fbi.get("status", "ok")
        if f_status == "geblokkeerd":
            blok = f"""
            <div class="card">
                <div class="card-title">
                    FBI Wanted / Missing Persons
                    <span class="warn">API GEBLOKKEERD</span>
                </div>
                <p class="warn-text">{e(fbi.get('melding', ''))}</p>
                <p class="muted">Handmatig controleren:
                    <a href="https://www.fbi.gov/wanted" target="_blank" rel="noopener">FBI Wanted</a>
                </p>
            </div>
            """
            onderdelen.append(blok)
        else:
            alle_fbi = fbi["gezocht"] + fbi["vermist"]
            blok = f"""
            <div class="card">
                <div class="card-title">
                    FBI Wanted / Missing Persons
                    <span class="badge">{len(alle_fbi)} records</span>
                </div>
            """
            if fbi["gezocht"]:
                blok += '<h2 style="color:#f43f5e;">Gezocht (FBI Most Wanted)</h2>'
                blok += ('<table class="hit-table"><thead><tr><th>Naam</th><th>Categorie</th><th>Foto</th><th>Links</th></tr></thead><tbody>')
                for n in fbi["gezocht"]:
                    foto = (f'<a href="{e(n.get("foto_orig", ""), quote=True)}" target="_blank" rel="noopener">'
                            f'<img src="{e(n.get("foto_thumb", ""), quote=True)}" class="notice-thumb" alt="foto"></a>'
                            if n.get("foto_thumb") else "")
                    blok += (f'<tr><td>{e(n["naam"])}</td>'
                             f'<td class="muted">{e(n.get("subjects", ""))}</td>'
                             f'<td>{foto}</td>'
                             f'<td><a href="{e(n.get("url", ""), quote=True)}" target="_blank" rel="noopener">FBI</a>'
                             f' · <a href="{e(n.get("zoek_url", ""), quote=True)}" target="_blank" rel="noopener">Zoeken</a></td></tr>')
                    _details = _fbi_details_html(n)
                    if _details:
                        blok += f'<tr><td colspan="4">{_details}</td></tr>'
                blok += "</tbody></table>"
            if fbi["vermist"]:
                blok += '<h2 style="color:#fbbf24;">Vermist (Kidnappings / Missing Persons)</h2>'
                blok += ('<table class="hit-table"><thead><tr><th>Naam</th><th>Categorie</th><th>Foto</th><th>Links</th></tr></thead><tbody>')
                for n in fbi["vermist"]:
                    foto = (f'<a href="{e(n.get("foto_orig", ""), quote=True)}" target="_blank" rel="noopener">'
                            f'<img src="{e(n.get("foto_thumb", ""), quote=True)}" class="notice-thumb" alt="foto"></a>'
                            if n.get("foto_thumb") else "")
                    blok += (f'<tr><td>{e(n["naam"])}</td>'
                             f'<td class="muted">{e(n.get("subjects", ""))}</td>'
                             f'<td>{foto}</td>'
                             f'<td><a href="{e(n.get("url", ""), quote=True)}" target="_blank" rel="noopener">FBI</a>'
                             f' · <a href="{e(n.get("zoek_url", ""), quote=True)}" target="_blank" rel="noopener">Zoeken</a></td></tr>')
                    _details = _fbi_details_html(n)
                    if _details:
                        blok += f'<tr><td colspan="4">{_details}</td></tr>'
                blok += "</tbody></table>"
            if not alle_fbi:
                blok += f'<p class="no-hits">{e(fbi.get("melding", "Geen FBI-records gevonden voor deze naam."))}</p>'
            else:
                blok += ('<p class="muted">Officiele FBI Wanted/Missing Persons-data (publieke API, geen key). '
                         'Klik op <em>Meer details</em> per record voor kenmerken, aliassen en locaties.</p>')
            blok += "</div>"
            onderdelen.append(blok)

    if "opsporingslijst" in extra:
        ol = extra["opsporingslijst"]
        blok = f"""
        <div class="card">
            <div class="card-title">
                Nationale Opsporingslijst (Politie.nl)
                <span class="badge">{len(ol)} resultaten</span>
            </div>
        """
        if ol:
            blok += '<table class="hit-table"><thead><tr><th style="width:40%">Titel</th><th>Omschrijving</th><th>Bron</th></tr></thead><tbody>'
            for hit in ol:
                blok += (f'<tr><td><a href="{e(hit["link"], quote=True)}" target="_blank" rel="noopener">{e(hit["titel"])}</a></td>'
                         f'<td class="muted">{e(hit.get("omschrijving", ""))}</td>'
                         f'<td class="muted">{e(hit["bron"])}</td></tr>')
            blok += "</tbody></table>"
        else:
            blok += '<p class="no-hits">Geen resultaten op de Nationale Opsporingslijst.</p>'
        blok += "</div>"
        onderdelen.append(blok)

    if "telefoon_verrijking" in extra:
        tv = extra["telefoon_verrijking"]
        blok = f"""
        <div class="card">
            <div class="card-title">
                Telefoonnummer verrijking <span class="muted">({e(tv.get('tel', ''))})</span>
                <span class="badge">gratis publieke checks</span>
            </div>
            <table class="detail-table"><tbody>
        """
        if tv.get("genormaliseerd"):
            blok += f'<tr><td class="detail-label">Genormaliseerd (E164)</td><td>{e(tv["genormaliseerd"])}</td></tr>'
        if tv.get("geldig"):
            blok += '<tr><td class="detail-label">Geldig nummer</td><td class="ok">Ja</td></tr>'
        if tv.get("land"):
            blok += f'<tr><td class="detail-label">Land/regio</td><td>{e(tv["land"])}{(" · " + e(tv["regio"])) if tv.get("regio") else ""}</td></tr>'
        if tv.get("netwerk"):
            blok += f'<tr><td class="detail-label">Netwerk/aanbieder</td><td>{e(tv["netwerk"])}</td></tr>'
        if tv.get("lijn_type"):
            blok += f'<tr><td class="detail-label">Lijntype</td><td>{e(tv["lijn_type"])}</td></tr>'
        if tv.get("tijdzone"):
            blok += f'<tr><td class="detail-label">Tijdzone</td><td>{e(tv["tijdzone"])}</td></tr>'
        if tv.get("whatsapp") is not None:
            wk = "ok" if tv["whatsapp"] else "warn"
            wl = "Account actief op WhatsApp" if tv["whatsapp"] else "Geen WhatsApp-account gevonden"
            blok += f'<tr><td class="detail-label">WhatsApp</td><td class="{wk}">{wl}</td></tr>'
        elif tv.get("whatsapp_url"):
            blok += f'<tr><td class="detail-label">WhatsApp</td><td class="muted">Server-side detectie niet mogelijk (handmatig controleren: <a href="{e(tv["whatsapp_url"])}" target="_blank" rel="noopener">open WhatsApp</a>)</td></tr>'
        if tv.get("telegram") is not None:
            tk = "ok" if tv["telegram"] else "warn"
            tl = "Account actief op Telegram" if tv["telegram"] else "Geen Telegram-account gevonden"
            blok += f'<tr><td class="detail-label">Telegram</td><td class="{tk}">{tl}</td></tr>'
        elif tv.get("telegram_url"):
            blok += f'<tr><td class="detail-label">Telegram</td><td class="muted"><a href="{e(tv["telegram_url"])}" target="_blank" rel="noopener">Open Telegram</a></td></tr>'
        if tv.get("telegram_url"):
            blok += f'<tr><td class="detail-label">Telegram-link</td><td><a href="{e(tv["telegram_url"])}" target="_blank" rel="noopener">{e(tv["telegram_url"])}</a></td></tr>'
        blok += "</tbody></table></div>"
        onderdelen.append(blok)

    if "rdw" in extra:
        rd = extra["rdw"]
        v = rd.get("voertuig")
        if rd.get("status") == "ok" and v:
            def _rdw_row(lbl, val):
                return f'<tr><td class="detail-label">{e(lbl)}</td><td>{e(str(val)) if val else "-"}</td></tr>'
            blok = f"""
            <div class="card">
                <div class="card-title">
                    RDW Kentekenonderzoek - {e(rd.get("kenteken", ""))}
                    <span class="badge">open data</span>
                </div>
                <table class="detail-table">
                    {_rdw_row('Merk', v.get('merk'))}
                    {_rdw_row('Handelsbenaming', v.get('handelsbenaming'))}
                    {_rdw_row('Bouwjaar / eerste toelating', _rdw_datum(v.get('bouwjaar')))}
                    {_rdw_row('Brandstof', v.get('brandstof'))}
                    {_rdw_row('CO2-uitstoot', v.get('co2'))}
                    {_rdw_row('APK-vervaldatum', _rdw_datum(v.get('vervaldatum')))}
                    {_rdw_row('Kleur', v.get('kleur'))}
                    {_rdw_row('Voertuigsoort', v.get('voertuigsoort'))}
                    {_rdw_row('Categorie', v.get('categorie'))}
                    {_rdw_row('Aantal deuren', v.get('aantal_deuren'))}
                    {_rdw_row('Aantal zitplaatsen', v.get('aantal_zitplaatsen'))}
                    {_rdw_row('Massa ledig (kg)', v.get('massa_ledig'))}
                </table>
            </div>
            """
            onderdelen.append(blok)
        elif rd.get("status") == "geen":
            onderdelen.append(
                f'<div class="card"><div class="card-title">RDW Kentekenonderzoek</div>'
                f'<p class="no-hits">{e(rd.get("fout", "Geen voertuig gevonden."))}</p></div>'
            )
        elif rd.get("status") == "fout":
            onderdelen.append(
                f'<div class="card"><div class="card-title">RDW Kentekenonderzoek</div>'
                f'<p class="warn-text">{e(rd.get("fout", "check mislukt"))}</p></div>'
            )

    beste_matches = []
    for platform, data in rapport.items():
        for hit in data["hits"]:
            if hit.get("score", 0) >= 2:
                beste_matches.append({"platform": platform, **hit})
    beste_matches.sort(key=lambda h: -h.get("score", 0))

    if beste_matches:
        blok = f"""
        <div class="card" style="border-color:#38bdf8;">
            <div class="card-title" style="font-size:22px;">
                Beste matches ({len(beste_matches)})
                <span class="badge">Automatisch gefilterd</span>
            </div>
        """
        blok += '<table class="hit-table"><thead><tr><th style="width:15%">Platform</th><th style="width:10%">Match</th><th style="width:35%">Titel</th><th>Omschrijving</th></tr></thead><tbody>'
        for hit in beste_matches:
            score_css, score_label = SCORE_LABELS.get(hit.get("score", 0), ("muted", "-"))
            rij = ' class="exact-row"' if hit.get("score", 0) == 4 else ""
            blok += (f'<tr{rij}><td>{e(hit["platform"])}</td>'
                     f'<td class="{score_css}" style="white-space:nowrap;">{score_label}</td>'
                     f'<td><a href="{e(hit["link"], quote=True)}" target="_blank" rel="noopener">{e(hit["titel"])}</a></td>'
                     f'<td class="muted">{e(hit["omschrijving"])}</td></tr>')
        blok += "</tbody></table></div>"
        onderdelen.append(blok)

    if "bag" in extra:
        bag = extra["bag"]
        adr = bag.get("adres")
        if adr:
            def _bag_row(lbl, val):
                return f'<tr><td class="detail-label">{e(lbl)}</td><td>{e(str(val)) if val else "-"}</td></tr>'
            perceel = "<br>".join(e(x) for x in (adr.get("perceel") or [])) if adr.get("perceel") else "-"
            coord = adr.get("coord_ll", "")
            blok = f"""
            <div class="card">
                <div class="card-title">
                    Kadaster / BAG - {e(adr.get('weergavenaam', bag.get('query', '')))}
                    <span class="badge">open data</span>
                </div>
                <table class="detail-table">
                    {_bag_row('Straat', adr.get('straat'))}
                    {_bag_row('Huisnummer', adr.get('huisnummer'))}
                    {_bag_row('Postcode', adr.get('postcode'))}
                    {_bag_row('Woonplaats', adr.get('woonplaats'))}
                    {_bag_row('Gemeente', adr.get('gemeente'))}
                    {_bag_row('Provincie', adr.get('provincie'))}
                    {_bag_row('Buurt', adr.get('buurt'))}
                    {_bag_row('Wijk', adr.get('wijk'))}
                    {_bag_row('Waterschap', adr.get('waterschap'))}
                    {_bag_row('Perceel', perceel)}
                    {_bag_row('Bouwjaar', adr.get('bouwjaar'))}
                    {_bag_row('Oppervlakte (m²)', adr.get('oppervlakte'))}
                    {_bag_row('Gebruiksdoel', adr.get('gebruiksdoel'))}
                    {_bag_row('Pand-status', adr.get('pand_status'))}
                    {_bag_row('Verblijfsobject-status', adr.get('verblijfsobject_status'))}
                    {_bag_row('Aantal verblijfsobjecten', adr.get('aantal_verblijfsobjecten'))}
                    {_bag_row('Coördinaten (lat/lon)', coord)}
                    {_bag_row('Verblijfsobject ID', adr.get('verblijfsobject_id'))}
                    {_bag_row('Pand ID', adr.get('pand_id'))}
                </table>
                </div>
                """
            links = adr.get("links") or {}
            if links:
                def _bag_link(label, url):
                    return (f'<p style="margin:2px 0;"><span style="color:#94a3b8;">{e(label)}:</span> '
                            f'<a href="{e(url, quote=True)}" target="_blank" rel="noopener">{e(url)}</a></p>')
                blok += '<div style="margin-top:14px;padding-top:12px;border-top:1px solid #334155;">'
                blok += '<div style="color:#38bdf8;font-weight:bold;margin-bottom:6px;">Kaarten &amp; diensten</div>'
                if links.get("bag_viewer"):
                    blok += _bag_link("BAG viewer (kaart)", links["bag_viewer"])
                if links.get("google_maps"):
                    blok += _bag_link("Google Maps", links["google_maps"])
                if links.get("openstreetmap"):
                    blok += _bag_link("OpenStreetMap", links["openstreetmap"])
                if links.get("politie_wijkagent"):
                    blok += _bag_link("Wijkagent (politie.nl)", links["politie_wijkagent"])
                if links.get("politie_bureaus"):
                    blok += _bag_link("Politiebureau (politie.nl)", links["politie_bureaus"])
                blok += "</div>"
            politie = adr.get("politie") or []
            if politie:
                blok += ('<div style="margin-top:14px;padding-top:12px;border-top:1px solid #334155;">'
                         '<div style="color:#38bdf8;font-weight:bold;margin-bottom:6px;">Politiebureaus in de buurt</div>')
                for p in politie:
                    naam = e(p.get("naam") or "Politiebureau")
                    adress = " ".join(filter(None, [p.get("adres"), p.get("postcode"), p.get("plaats")]))
                    if p.get("url"):
                        blok += f'<p style="margin:3px 0;"><a href="{e(p["url"], quote=True)}" target="_blank" rel="noopener" style="color:#38bdf8;font-weight:bold;">{naam}</a>'
                    else:
                        blok += f'<p style="margin:3px 0;"><span style="font-weight:bold;">{naam}</span>'
                    blok += f'<br><span style="color:#94a3b8;">{e(adress or "adres onbekend")}</span>'
                    if p.get("telefoon"):
                        blok += f'<br><span style="color:#94a3b8;">{e(p["telefoon"])}</span>'
                    blok += "</p>"
                blok += "</div>"
            blok += "</div>"
            onderdelen.append(blok)
        elif bag.get("fout"):
            blok = f"""
            <div class="card">
                <div class="card-title">Kadaster / BAG<span class="warn">geen resultaat</span></div>
                <p class="warn-text">{e(bag.get('fout'))}</p>
            </div>
            """
            onderdelen.append(blok)

    for platform, data in rapport.items():
        handmatige_link = "https://duckduckgo.com/?q=" + urllib.parse.quote(data["query"])
        blok = f"""
        <div class="card">
            <div class="card-title">
                {e(platform)}
                <span class="badge">{len(data['hits'])} resultaten</span>
            </div>
            <span class="query-text">{e(data['query'])}</span>
        """
        if data["hits"]:
            blok += '<table class="hit-table"><thead><tr><th style="width:40%">Titel</th><th>Omschrijving</th><th style="width:6%">Bron</th><th style="width:8%">Match</th></tr></thead><tbody>'
            for hit in data["hits"]:
                score_css, score_label = SCORE_LABELS.get(hit.get("score", 0), ("muted", "-"))
                rij = ' class="exact-row"' if hit.get("score", 0) == 4 else ""
                bron = hit.get("bron", "")
                if bron == "Brave":
                    bron_badge = '<span class="badge ok" style="font-size:10px;">Brave</span>'
                elif bron == "Brave (zonder quotes)":
                    bron_badge = '<span class="badge" style="font-size:10px;">Brave*</span>'
                elif bron == "DuckDuckGo":
                    bron_badge = '<span class="badge warn" style="font-size:10px;">DDG</span>'
                else:
                    bron_badge = ""
                blok += (f'<tr{rij}><td><a href="{e(hit["link"], quote=True)}" target="_blank" rel="noopener">'
                         f'{e(hit["titel"])}</a></td>'
                         f'<td class="muted">{e(hit["omschrijving"])}</td>'
                         f'<td style="text-align:center;">{bron_badge}</td>'
                         f'<td class="{score_css}" style="white-space:nowrap;">{score_label}</td></tr>')
            blok += "</tbody></table>"
        else:
            blok += (f'<p class="no-hits">Geen resultaten gevonden. '
                     f'<a href="{e(handmatige_link, quote=True)}" target="_blank" rel="noopener">Handmatig openen</a></p>')
        blok += "</div>"
        onderdelen.append(blok)

    if "hibp" in extra:
        h = extra["hibp"]
        kleur = {"schoon": "ok", "getroffen": "bad", "overgeslagen": "warn", "fout": "warn"}[h["status"]]
        label = {"schoon": "GEEN LEKKEN GEVONDEN", "getroffen": "IN DATALEKKEN GEVONDEN",
                 "overgeslagen": "OVERGESLAGEN", "fout": "FOUT"}[h["status"]]
        blok = f"""
        <div class="card">
            <div class="card-title">
                HaveIBeenPwned &mdash; datalekcheck
                <span class="{kleur}">{label}</span>
            </div>
            <p>{e(h['melding'])}</p>
        """
        if h["breaches"]:
            blok += ('<table class="hit-table"><thead><tr><th>Datalek</th><th>Datum</th>'
                     '<th>Gelekte gegevens</th><th>Geverifieerd</th></tr></thead><tbody>')
            for b in h["breaches"]:
                ver = '<span class="ok">Ja</span>' if b["geverifieerd"] else '<span class="warn">Nee</span>'
                blok += (f'<tr><td>{e(b["naam"])}</td><td>{e(str(b["datum"]))}</td>'
                         f'<td class="muted">{e(b["gegevens"])}</td><td>{ver}</td></tr>')
            blok += "</tbody></table>"
        blok += "</div>"
        onderdelen.append(blok)

    if "holehe" in extra:
        hh = extra["holehe"]
        status_kleur = {"ok": "ok", "overgeslagen": "warn", "fout": "warn"}[hh.get("status", "ok")]
        gevonden = hh.get("gevonden", 0)
        label = f"{gevonden} ACCOUNTS GEVONDEN" if gevonden else "GEEN ACCOUNTS GEVONDEN"
        label_kleur = "bad" if gevonden else "ok"
        if hh.get("status") == "overgeslagen":
            label, label_kleur = "NIET GEINSTALLEERD", "warn"
        if hh.get("status") == "fout":
            label, label_kleur = "FOUT", "warn"
        blok = f"""
        <div class="card">
            <div class="card-title">
                E-mail &rarr; platform-registraties (holehe)
                <span class="{label_kleur}">{label}</span>
            </div>
            <p class="muted">{e(hh.get('melding', ''))}</p>
        """
        sites = hh.get("sites", [])
        if sites:
            blok += ('<table class="hit-table"><thead><tr><th style="width:40%">Platform</th>'
                     '<th style="width:30%">Account</th><th>Details</th></tr></thead><tbody>')
            for s_ in sites:
                details = e(s_.get("details") or "")
                if s_["account"]:
                    acc = '<span class="ok">Account gevonden</span>'
                elif s_.get("frequent") and s_["rate_limit"]:
                    acc = '<span class="warn">site-limiet (frequent)</span>'
                    if not details:
                        details = '<span class="muted">controleer handmatig</span>'
                elif s_["rate_limit"]:
                    acc = '<span class="warn">onbekend (limit)</span>'
                    if not details:
                        details = '<span class="muted">controleer handmatig</span>'
                else:
                    acc = '<span class="muted">Geen account</span>'
                blok += (f'<tr><td>{e(s_["naam"])}</td><td>{acc}</td>'
                         f'<td class="muted">{details}</td></tr>')
            blok += "</tbody></table>"
            blok += ('<p class="muted">Hint: bij &quot;onbekend (limit)&quot; gaf de site tijdens de check geen '
                     'eenduidig antwoord (rate-limit/bot-check); na automatische retries bleef dit onduidelijk. '
                     '&quot;Frequent&quot; sites blokkeren structureel — daar werkt alleen handmatig browsen. '
                     '&quot;Herstelmail gekoppeld&quot;/&quot;telefoon&quot; in Details bevestigt een account vrijwel zeker.</p>')
        elif hh.get("status") == "ok":
            blok += '<p class="no-hits">Geen site-resultaten (mogelijk rate-limited).</p>'
        blok += "</div>"
        onderdelen.append(blok)

    if "email_verrijking" in extra:
        ev = extra["email_verrijking"]
        blok = f"""
        <div class="card">
            <div class="card-title">
                E-mail verrijking <span class="muted">({e(ev.get('email', ''))})</span>
                <span class="badge">gratis publieke checks</span>
            </div>
        """
        if ev.get("status") == "ok":
            blok += '<table class="detail-table"><tbody>'
            if ev.get("wegwerp") is not None:
                wk = "bad" if ev["wegwerp"] else "ok"
                wl = "JA — wegwerp/weggebed-mail" if ev["wegwerp"] else "Nee, echt domein"
                blok += f'<tr><td class="detail-label">Wegwerp-maildienst</td><td class="{wk}">{wl}</td></tr>'
            mx = ev.get("mx")
            mx_k = "ok" if mx else "warn"
            mx_l = "MX-record aanwezig" if mx else "geen MX-record (kan niet ontvangen)"
            blok += f'<tr><td class="detail-label">MX-record (domein)</td><td class="{mx_k}">{mx_l}</td></tr>'
            if ev.get("emailrep") is not None:
                er = ev["emailrep"]
                rep = er.get("reputatie")
                verd = er.get("verdacht")
                if rep is not None:
                    rk = "bad" if verd else "ok"
                    rl = f"reputatie {rep}/low"
                    if verd:
                        rl += " — verdacht"
                    blok += f'<tr><td class="detail-label">EmailRep.io</td><td class="{rk}">{rl}</td></tr>'
                elif er.get("geen_gegevens"):
                    blok += ('<tr><td class="detail-label">EmailRep.io</td>'
                             '<td class="ok">Geen gegevens bekend (404)</td></tr>')
                refs = er.get("referenties")
                if refs:
                    blok += f'<tr><td class="detail-label">Referenties (EmailRep)</td><td>{e(str(refs))}</td></tr>'
            blok += "</tbody></table>"
            links = ev.get("links") or []
            if links:
                blok += '<p class="muted" style="margin-top:10px;">Verder zoeken: '
                blok += " · ".join(
                    f'<a href="{e(l["url"], quote=True)}" target="_blank" rel="noopener">{e(l["label"])}</a>'
                    for l in links
                )
                blok += "</p>"
        else:
            blok += f'<p class="warn-text">{e(ev.get("melding", "fout"))}</p>'
        blok += "</div>"
        onderdelen.append(blok)

    if "github" in extra:
        g = extra["github"]
        blok = f"""
        <div class="card">
            <div class="card-title">
                GitHub
                <span class="badge">{len(g['profielen'])} profielen, {len(g['code'])} codetreffers</span>
            </div>
        """
        if g["profielen"]:
            blok += '<table class="hit-table"><thead><tr><th>Account</th><th>Type</th><th>Match-score</th></tr></thead><tbody>'
            for p in g["profielen"]:
                blok += (f'<tr><td><a href="{e(p["url"], quote=True)}" target="_blank" rel="noopener">{e(p["login"])}</a></td>'
                         f'<td class="muted">{e(p["type"])}</td><td class="muted">{p["score"]}</td></tr>')
            blok += "</tbody></table>"
        else:
            blok += '<p class="no-hits">Geen profielen gevonden.</p>'

        if g["code"]:
            blok += "<h2>Codetreffers</h2>"
            blok += '<table class="hit-table"><thead><tr><th>Bestand</th><th>Repository</th></tr></thead><tbody>'
            for c in g["code"]:
                blok += (f'<tr><td><a href="{e(c["url"], quote=True)}" target="_blank" rel="noopener">{e(c["bestand"])}</a></td>'
                         f'<td class="muted">{e(c["repo"])}</td></tr>')
            blok += "</tbody></table>"
        elif g["code_melding"]:
            blok += f'<p class="no-hits">{e(g["code_melding"])}</p>'
        blok += "</div>"
        onderdelen.append(blok)

    if "social" in extra:
        blok = f"""
        <div class="card">
            <div class="card-title">
                Social Media Profielen
                <span class="badge">{len(extra['social'])} gevonden</span>
            </div>
        """
        if extra["social"]:
            blok += '<table class="hit-table"><thead><tr><th style="width:20%">Platform</th><th>Profiel</th><th>Bron</th></tr></thead><tbody>'
            for p in extra["social"]:
                blok += (f'<tr><td>{e(p["platform"])}</td>'
                         f'<td><a href="{e(p["url"], quote=True)}" target="_blank" rel="noopener">{e(p["url"])}</a></td>'
                         f'<td class="muted">{e(p["bron"])}</td></tr>')
            blok += "</tbody></table>"
        else:
            blok += '<p class="no-hits">Geen aanvullende sociale profielen gevonden.</p>'
        blok += "</div>"
        onderdelen.append(blok)

    if "social_ids" in extra:
        sid = [x for x in extra["social_ids"] if x.get("id") or x.get("data")]
        blok = f"""
        <div class="card">
            <div class="card-title">
                Social Media IDs
                <span class="badge">{len(sid)} geextraheerd</span>
            </div>
        """
        if sid:
            blok += '<table class="hit-table"><thead><tr><th style="width:12%">Platform</th><th style="width:18%">Account</th><th style="width:28%">ID</th><th>Details</th></tr></thead><tbody>'
            for p in sid:
                # ID weergeven (kan getal of string zijn)
                pid = p.get("id")
                if not pid:
                    # CommentPicker data in details dict
                    data = p.get("details", {})
                    pid = data.get("id") or data.get("userId") or "-"
                id_html = f'<code style="background:#0f172a;padding:2px 6px;border-radius:4px;color:#94a3b8;">{e(str(pid))}</code>'
                # Details opbouwen
                details_parts = []
                d = p.get("details", {})
                if p.get("platform") == "YouTube":
                    if d.get("titel"):
                        details_parts.append(f'<span class="muted">Kanaal: {e(d["titel"])}</span>')
                    if d.get("volgers"):
                        details_parts.append(f'<span class="muted">{d["volgers"]} volgers</span>')
                elif p.get("platform") == "Instagram":
                    if d.get("volledige_naam"):
                        details_parts.append(f'<span class="muted">{e(d["volledige_naam"])}</span>')
                    if d.get("volgers"):
                        details_parts.append(f'<span class="muted">{d["volgers"]} volgers</span>')
                    if d.get("geverifieerd"):
                        details_parts.append('<span class="ok">geverifieerd</span>')
                    if d.get("prive"):
                        details_parts.append('<span class="warn">prive</span>')
                elif p.get("platform") == "Twitter":
                    if d.get("naam"):
                        details_parts.append(f'<span class="muted">{e(d["naam"])}</span>')
                    if d.get("volgers"):
                        details_parts.append(f'<span class="muted">{d["volgers"]} volgers</span>')
                elif p.get("platform") == "Tiktok":
                    if d.get("nickname"):
                        details_parts.append(f'<span class="muted">{e(d["nickname"])}</span>')
                    if d.get("volgers"):
                        details_parts.append(f'<span class="muted">{d["volgers"]} volgers</span>')
                # socid-extractor verrijking voor additionele platforms
                socid = d.get("socid")
                if socid:
                    if socid.get("is_verified"):
                        details_parts.append('<span class="ok">geverifieerd</span>')
                    for veld in ("bio", "location", "country", "city", "city"):
                        if socid.get(veld):
                            details_parts.append(f'<span class="muted">{e(str(socid[veld]))[:120]}</span>')
                            break
                    if socid.get("internal_ids"):
                        for id_naam, id_val in list(socid["internal_ids"].items())[:2]:
                            details_parts.append(f'<span class="muted">{e(id_naam)}: {e(str(id_val))}</span>')
                blok += (f'<tr><td>{e(p["platform"])}</td>'
                         f'<td><a href="{e(p["url"], quote=True)}" target="_blank" rel="noopener">{e(p["username"])}</a></td>'
                         f'<td>{id_html}</td>'
                         f'<td>{" &middot; ".join(details_parts) if details_parts else f"<span class=muted>{e(str(p.get('bron', '')))}</span>"}</td></tr>')
            blok += "</tbody></table>"
            blok += '<p class="muted">ID-extractie via officiële/unofficiële API&apos;s en page scrapers. CommentPicker-resultaten zijn beperkt door CAPTCHA.</p>'
        else:
            blok += '<p class="no-hits">Geen ID&apos;s kunnen extraheren (mogelijk CAPTCHA- of API-beperkingen).</p>'
        blok += "</div>"
        onderdelen.append(blok)

    if "maigret" in extra:
        mr = extra["maigret"]
        m_sites = mr.get("sites", [])
        m_gezocht = mr.get("totaal_gezocht", 0)
        m_fout = mr.get("fouten", [])
        blok = f"""
        <div class="card">
            <div class="card-title">
                Maigret Site-scan
                <span class="badge">{len(m_sites)}/{m_gezocht} gevonden</span>
            </div>
            <p class="muted">Uitgebreide gebruikersnaam-scan via Maigret ({m_gezocht} sites, top-{_MAIGRET_TOP}). Nieuwe platforms zijn toegevoegd aan Social IDs hierboven.</p>
        """
        if m_sites:
            blok += '<table class="hit-table"><thead><tr><th style="width:22%">Platform</th><th style="width:40%">URL</th><th>Extra data</th></tr></thead><tbody>'
            for s in m_sites:
                ids = s.get("ids_data", {})
                extra_parts = []
                for k in ("uid", "user_id", "external_id", "fullname", "name", "bio", "followers"):
                    if ids.get(k):
                        extra_parts.append(f'<span class="muted">{e(k)}: {e(str(ids[k])[:60])}</span>')
                blok += (
                    f'<tr><td>{e(s["platform"])}</td>'
                    f'<td><a href="{e(s["url"], quote=True)}" target="_blank" rel="noopener">{e(s["url"][:60])}</a></td>'
                    f'<td>{" &middot; ".join(extra_parts) if extra_parts else "-"}</td></tr>'
                )
            blok += "</tbody></table>"
        elif m_fout:
            blok += f'<p class="warn">{e(m_fout[0])}</p>'
        else:
            blok += '<p class="no-hits">Geen extra&apos;s gevonden via Maigret.</p>'
        blok += "</div>"
        onderdelen.append(blok)

    if "web_presence" in extra:
        wp = extra["web_presence"]
        score_kleur = "ok" if wp["score"] >= 5 else "warn" if wp["score"] >= 2 else "muted"
        score_label = f"{wp['score']}/10"
        blok = f"""
        <div class="card">
            <div class="card-title">
                Web Presence Score
                <span class="{score_kleur}">{score_label}</span>
            </div>
            <p class="muted">Berekend op basis van {wp['totaal_resultaten']} zoekresultaten en {wp['unieke_platforms']} unieke platforms (WebMii-formule).</p>
        """
        if wp["socials"]:
            blok += '<table class="hit-table"><thead><tr><th style="width:20%">Platform</th><th style="width:40%">Profiel</th><th>Bron</th></tr></thead><tbody>'
            for p in wp["socials"]:
                titel = p.get("titel", "") or p["url"]
                blok += (f'<tr><td>{e(p["platform"])}</td>'
                         f'<td><a href="{e(p["url"], quote=True)}" target="_blank" rel="noopener">{e(titel[:80])}</a></td>'
                         f'<td class="muted">{e(p["bron"][:100])}</td></tr>')
            blok += "</tbody></table>"
        else:
            blok += '<p class="no-hits">Geen social media profielen gedetecteerd in zoekresultaten.</p>'
        webmii_url = f"https://webmii.com/people?n=%22{urllib.parse.quote(target_value)}%22"
        blok += (f'<p class="muted" style="margin-top:15px">Bekijk ook: '
                 f'<a href="{e(webmii_url, quote=True)}" target="_blank" rel="noopener">WebMii</a> '
                 f'voor een uitgebreider overzicht.</p>')
        blok += "</div>"
        onderdelen.append(blok)

    # Historische kranten: gratis doorzoekbaar via Delpher (KB) — geen
    # openbare API, dus een handmatige link i.p.v. automatische scrape.
    if target_type == "naam":
        from urllib.parse import quote
        delpher_url = "https://www.delpher.nl/nl/kranten?query=" + quote('"' + target_value + '"')
        blok = f"""
        <div class="card">
            <div class="card-title">
                Delpher &mdash; historische kranten (1618-2005)
                <span class="badge">gratis archief</span>
            </div>
            <p class="muted">2 mln gedigitaliseerde Nederlandse kranten doorzoekbaar op naam.
               Geen openbare zoek-API (alleen via mail aan de KB), daarom via een handmatige open-link.</p>
            <p><a href="{e(delpher_url, quote=True)}" target="_blank" rel="noopener">
               &raquo; Doorzoek Delpher-kranten voor &quot;{e(target_value)}&quot;</a></p>
        </div>
        """
        onderdelen.append(blok)

    if "openkvk" in extra:
        k = extra["openkvk"]
        kleur = {"ok": "ok", "overgeslagen": "warn", "fout": "warn"}[k["status"]]
        label = {"ok": f"{len(k['bedrijven'])} registraties", "overgeslagen": "OVERGESLAGEN", "fout": "FOUT"}[k["status"]]
        blok = f"""
        <div class="card">
            <div class="card-title">
                KVK-handelsregister (OpenKvK)
                <span class="{kleur}">{label}</span>
            </div>
            <p class="muted">{e(k['melding'])}</p>
        """
        if k["bedrijven"]:
            blok += ('<table class="hit-table"><thead><tr><th style="width:45%">Handelsnaam</th>'
                     '<th>Dossiernummer</th><th>Bron</th></tr></thead><tbody>')
            for b in k["bedrijven"]:
                linkcel = (f'<a href="{e(b["link"], quote=True)}" target="_blank" rel="noopener">OpenKvK</a>'
                           if b["link"] else "-")
                blok += (f'<tr><td>{e(b["handelsnaam"])}</td>'
                         f'<td>{e(b["dossiernummer"])}</td>'
                         f'<td>{linkcel}</td></tr>')
            blok += "</tbody></table>"
        blok += "</div>"
        onderdelen.append(blok)

    pagina = f"""<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<title>OSINT Rapport - {e(target_value)}</title>
<style>{css}</style>
</head>
<body>
<div id="zoekbalk">
    <span style="color:#38bdf8;font-weight:bold;">&#128269;</span>
    <input id="zoekveld" type="search" placeholder="Zoeken in resultaten (Ctrl-F, maar dan altijd zichtbaar)..." autocomplete="off">
    <span id="zoektelling"></span>
    <span id="zoekknoppen">
        <button class="zoekknop" id="klapallen" type="button" title="Alle kaarten tegelijk uitklappen">&#9660; Alles open</button>
        <button class="zoekknop" id="klapgeen" type="button" title="Alle kaarten tegelijk inklappen">&#9650; Alles dicht</button>
        <button class="zoekknop" id="zoekvorige" type="button" title="Vorige treffer (Shift+Enter)">&lsaquo;</button>
        <button class="zoekknop" id="zoekvolgende" type="button" title="Volgende treffer (Enter)">&rsaquo;</button>
        <button id="zoekreset" type="button" title="Zoekopdracht wissen">&times;</button>
    </span>
</div>
<h1>&#128737;&#65039; OSINT Rapport</h1>
<div class="metadata">
    <strong>Onderzoekstype:</strong> <span class="badge">{e(target_type.upper())}</span> |
    <strong>Doelwit:</strong> <span>{e(target_value)}</span>{' | <strong>Woonplaats:</strong> <span>' + e(plaats) + '</span>' if plaats else ''} |
    <strong>Gegenereerd:</strong> <span class="muted">{datetime.now().strftime('%d-%m-%Y %H:%M')}</span>
</div>
{''.join(onderdelen)}
<p class="muted">Zoekresultaten via Brave/DuckDuckGo; optionele checks via HaveIBeenPwned en GitHub.</p>
{ZOEKBALK_JS}
</body>
</html>
"""

    bestandsnaam = f"osint_rapport_{target_value.replace(' ', '_').replace('@','_at_')}.html"
    with open(bestandsnaam, "w", encoding="utf-8") as f:
        f.write(pagina)

    if open_browser:
        webbrowser.open(f"file://{os.path.abspath(bestandsnaam)}")
    return bestandsnaam


def _chrome_pad():
    """Zoekt het pad naar Chrome/Chromium (macOS, Linux, Windows)."""
    kandidaten = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    ]
    for pad in kandidaten:
        if os.path.exists(pad):
            return pad
    return None


def print_rapport_naar_pdf(html_pad):
    """Rendert een HTML-rapport naar een PDF via headless Chrome."""
    chrome = _chrome_pad()
    if not chrome:
        return None, "Geen Chrome/Chromium gevonden voor PDF-rendering."
    pdf_pad = os.path.splitext(html_pad)[0] + ".pdf"
    url = "file://" + os.path.abspath(html_pad)
    try:
        resultaat = subprocess.run(
            [chrome, "--headless", "--disable-gpu", "--no-sandbox",
             "--print-to-pdf=" + os.path.abspath(pdf_pad),
             "--no-pdf-header-footer", url],
            capture_output=True, timeout=60,
        )
        if os.path.exists(pdf_pad) and os.path.getsize(pdf_pad) > 0:
            return pdf_pad, None
        fout = (resultaat.stderr or b"").decode("utf-8", "ignore")[-500:]
        return None, f"PDF-rendering mislukt (Chrome-fout): {fout or 'onbekend'}"
    except subprocess.TimeoutExpired:
        return None, "PDF-rendering duurde te lang (time-out)."
    except Exception as exc:
        return None, f"PDF-rendering mislukt: {exc}"


def dorks_naam(naam, plaats=""):
    extra = f' "{plaats}"' if plaats else ""
    return {
        "LinkedIn & Zakelijk": f'"{naam}"{extra} site:linkedin.com OR site:linkedin.com/in',
        "Social Media (X/FB/IG)": f'"{naam}"{extra} (site:x.com OR site:facebook.com OR site:instagram.com)',
        "Video & Microblogs": f'"{naam}"{extra} (site:tiktok.com OR site:threads.net OR site:youtube.com)',
        "Publieke Documenten": f'"{naam}"{extra} (filetype:pdf OR filetype:docx OR filetype:xlsx)',
        "Nieuws & Media": (f'"{naam}"{extra} (site:nos.nl OR site:nu.nl OR site:rtlnieuws.nl '
                           f'OR site:ad.nl OR site:telegraaf.nl OR site:volkskrant.nl OR site:nrc.nl '
                           f'OR site:parool.nl OR site:trouw.nl OR site:fd.nl OR site:metronieuws.nl)'),
        "Regionale kranten & Vakbladen": (f'"{naam}"{extra} (site:gelderlander.nl OR site:bndestem.nl OR '
                                          f'site:pzc.nl OR site:eindhovensdagblad.nl OR site:destentor.nl OR '
                                          f'site:tubantia.nl OR site:weideblog.nl OR site:nu.nl/regio)'),
        "Personen-zoekers (NL)": f'"{naam}"{extra} (site:zydna.nl OR site:gripopjezoek.nl OR site:telefoonboek.nl OR site:pwned-zoeken.nl)',
    }


def dorks_username(user):
    return {
        "Developer Profielen": f'"{user}" (site:github.com OR site:gitlab.com OR site:stackoverflow.com)',
        "Social Media Accounts": f'"{user}" (site:x.com OR site:instagram.com OR site:reddit.com OR site:facebook.com)',
        "Video & Threads Platforms": f'"{user}" (site:tiktok.com OR site:threads.net OR site:youtube.com)',
        "Fediverse & Bluesky": f'"{user}" (site:mastodon.social OR site:mastodon.online OR site:bsky.app)',
        "Forums & Communities": f'inurl:{user} (site:reddit.com OR site:tweakers.net OR site:pastebin.com)',
    }


def dorks_email(email):
    return {
        "Code Repositories & Dumps": f'"{email}" (site:github.com OR site:pastebin.com)',
        "Documenten & Lijsten": f'"{email}" (filetype:pdf OR filetype:xlsx OR filetype:csv)',
        "Algemene Vermeldingen": f'"{email}"',
    }


def dorks_telefoon(tel, tel_int):
    return {
        "Exact Telefoonnummer": f'"{tel}"',
        "Internationaal Formaat": f'"{tel_int}"',
        "Lijsten & PDF-Gidsen": f'"{tel}" (filetype:pdf OR filetype:xlsx)',
        "Personen-zoekers (NL)": f'"{tel}" (site:zydna.nl OR site:gripopjezoek.nl OR site:telefoonboek.nl)',
    }


BEKEND_KEYS = [
    ("BRAVE_API_KEY", "Brave Search API"),
    ("HIBP_API_KEY", "HaveIBeenPwned (datalekcheck)"),
    ("GITHUB_TOKEN", "GitHub-token (code-search)"),
    ("OVERHEID_IO_API_KEY", "Overheid.io (KVK-handelsregister)"),
    ("YOUTUBE_API_KEY", "YouTube Data API (channel-ID, 10k/dag)"),
]


def _lees_env():
    waarden = {}
    if os.path.exists(".env"):
        with open(".env", encoding="utf-8") as f:
            for regel in f:
                regel = regel.strip()
                if regel and not regel.startswith("#") and "=" in regel:
                    k, _, v = regel.partition("=")
                    waarden[k.strip()] = v.strip().strip('"').strip("'")
    return waarden


def _schrijf_env(waarden):
    regels = []
    gedaan = set()
    origineel = []
    if os.path.exists(".env"):
        with open(".env", encoding="utf-8") as f:
            origineel = [r.rstrip("\n") for r in f]
    for regel in origineel:
        if "=" in regel and not regel.lstrip().startswith("#"):
            k = regel.partition("=")[0].strip()
            if k in waarden:
                gedaan.add(k)
                if waarden[k]:
                    regels.append(f"{k}={waarden[k]}")
                continue
        regels.append(regel)
    for k in sorted(waarden):
        if k not in gedaan and waarden[k]:
            regels.append(f"{k}={waarden[k]}")
    with open(".env", "w", encoding="utf-8") as f:
        f.write("\n".join(regels) + "\n")


def _herlaad_keys():
    global BRAVE_API_KEY, HIBP_API_KEY, GITHUB_TOKEN, OPENHEID_API_KEY, YOUTUBE_API_KEY
    v = _lees_env()
    BRAVE_API_KEY = v.get("BRAVE_API_KEY", "")
    HIBP_API_KEY = v.get("HIBP_API_KEY", "")
    GITHUB_TOKEN = v.get("GITHUB_TOKEN", "")
    OPENHEID_API_KEY = v.get("OVERHEID_IO_API_KEY", "")
    YOUTUBE_API_KEY = v.get("YOUTUBE_API_KEY", "")


def _masker(waarde):
    if not waarde:
        return ""
    if len(waarde) >= 8:
        return "****" + waarde[-4:]
    return "****"


def toon_instellingen():
    """API-keys beheren via het menu -> wegschrijven naar .env (live actief)."""
    while True:
        console.clear()
        waarden = _lees_env()
        tabel = Table(title="API-instellingen (.env)", box=box.ROUNDED, header_style="bold cyan")
        tabel.add_column("#", justify="right", style="bold")
        tabel.add_column("Instelling")
        tabel.add_column("Status")
        tabel.add_column("Waarde")
        bekende_keys = {k for k, _ in BEKEND_KEYS}
        for idx, (key, label) in enumerate(BEKEND_KEYS, 1):
            waarde = waarden.get(key, "")
            status = "[green]actief[/]" if waarde else "[dim]leeg[/]"
            tabel.add_row(str(idx), label, status, _masker(waarde))
        for key in sorted(k for k in waarden if k not in bekende_keys):
            waarde = waarden[key]
            tabel.add_row("-", f"Eigen: {key}", "[green]actief[/]" if waarde else "[dim]leeg[/]", _masker(waarde))
        if BRAVE_API_KEY:
            val_inrichting = (f"[yellow]{BRAVE_EXACT_NUL[0]}x exact-frase gaf 0[/]"
                              if BRAVE_EXACT_NUL[0]
                              else "[green]geen exact-frase 0[/]")
            val_fallback = (f"[yellow]{BRAVE_FALLBACK_TELLER[0]}x (laatst om {BRAVE_FALLBACK_LAATST[0]})[/]"
                            if BRAVE_FALLBACK_TELLER[0]
                            else "[green]nooit[/]")
            tabel.add_row("-", "Brave exact-frase gaf 0", val_inrichting, "")
            tabel.add_row("-", "teruggevallen op DDG", val_fallback, "")
        if _telemetrie_uit():
            tabel.add_row("-", "Telemetrie/licentieregistratie", "[dim]uit (OSINT_NO_TELEMETRY)[/]", "")
        else:
            telemetrie_status = (
                "[green]actief[/]" if _lees_cfg().get("last_telemetry") else "[dim]nog niet gelukt[/]"
            )
            tabel.add_row("-", "Telemetrie/licentieregistratie", telemetrie_status,
                          f"v{_versie_lokaal()}")
        update = _update_resultaat or {}
        if update.get("check_enabled"):
            if update.get("update_beschikbaar"):
                tabel.add_row("-", "Update beschikbaar", "[yellow]ja (druk U)[/]", "")
            elif update.get("nieuwste_versie"):
                tabel.add_row("-", "Update beschikbaar", "[green]actueel[/]", update["nieuwste_versie"])
            else:
                tabel.add_row("-", "Update beschikbaar", "[dim]onbekend (offline?)[/]", "")
            tabel.add_row("-", "Laatst gemelde versie", "[dim]lokaal[/]", update.get("huidige_versie", "?"))
            if update.get("huidige_sha") and update.get("nieuwste_sha"):
                kort = lambda s: s[:12]
                tabel.add_row("-", "Git-commit", "[dim]lokaal[/]",
                              f"{kort(update['huidige_sha'])} → {kort(update['nieuwste_sha'])}")
        else:
            tabel.add_row("-", "Update-check", "[dim]uit (OSINT_NO_TELEMETRY)[/]", "")
        console.print(tabel)
        extra = (" of '6' = eigen key toevoegen" if not waarden.get("BRAVE_API_KEY")
                 else " of 'A' = eigen key toevoegen")
        keuze = Prompt.ask(
            f"\n[bold]Wijzigen:[/] nummer van instellen, '.' = wissen, '{'A'}' = eigen key, "
            "[dim](Enter = terug)[/]",
            default="",
        ).strip()

        if not keuze:
            _herlaad_keys()
            return

        if keuze.upper() == "A":
            regel = Prompt.ask("[bold cyan]Keynaam=waarde[/] (bv. GITHUB_TOKEN=xxx)").strip()
            if "=" not in regel:
                console.print("[red]Ongeldig formaat, sla '=' over.[/]")
                continue
            k, _, v = regel.partition("=")
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if not k or not v:
                console.print("[red]Keynaam en waarde mogen niet leeg zijn.[/]")
                continue
            waarden[k] = v
            _schrijf_env(waarden)
            _herlaad_keys()
            console.print(f"[green]Opgeslagen:[/] {k}")
            continue

        if "." == keuze:
            k = Prompt.ask("[bold cyan]Welke keynaam wissen?[/]").strip()
            if k in waarden:
                del waarden[k]
                _schrijf_env(waarden)
                _herlaad_keys()
                console.print(f"[green]Verwijderd:[/] {k}")
            else:
                console.print("[yellow]Niet gevonden in .env.[/]")
            continue

        if not keuze.isdigit() or not (1 <= int(keuze) <= len(BEKEND_KEYS)):
            console.print("[yellow]Ongeldige keuze.[/]")
            continue

        key, label = BEKEND_KEYS[int(keuze) - 1]
        vorige = waarden.get(key, "")
        status = " (al aanwezig, vervang je hem?)" if vorige else ""
        nieuwe = Prompt.ask(
            f"[bold cyan]{label}:[/] nieuwe waarde ('.' = wissen){status}",
            password=True,
            default="",
        ).strip()
        if not nieuwe:
            console.print("[dim]Niet gewijzigd.[/]")
            continue
        if nieuwe == ".":
            waarden.pop(key, None)
            console.print(f"[green]Verwijderd:[/] {key}")
        else:
            waarden[key] = nieuwe.lstrip(". ") if nieuwe else nieuwe
            console.print(f"[green]Opgeslagen:[/] {key}")
        _schrijf_env(waarden)
        _herlaad_keys()


def toon_config_status():
    engine = (
        "[green]Brave[/] + ddgs-fallback" if BRAVE_API_KEY
        else "[green]DuckDuckGo (ddgs)[/]" if DDGS
        else "[red]ONTBREEKT[/] - draai: pip install ddgs"
    )
    hibp = "[green]actief[/]" if HIBP_API_KEY else "[dim]optioneel - niet ingesteld[/]"
    gh = "[green]actief[/]" if GITHUB_TOKEN else "[dim]optioneel - niet ingesteld[/]"
    kvk = "[green]actief[/]" if OPENHEID_API_KEY else "[dim]optioneel - niet ingesteld (overheid.io)[/]"
    yt = "[green]actief[/]" if YOUTUBE_API_KEY else "[dim]optioneel - gebruikt page-scraping fallback[/]"
    holehe = "[green]actief (40+ platforms)[/]" if HOLEHE_BESCHIKBAAR else "[dim]niet geinstalleerd - pip install holehe[/]"
    socid = "[green]actief (aanvulling)[/]" if SOCID_BESCHIKBAAR else "[dim]niet geinstalleerd - pip install socid-extractor[/]"
    maigret = "[green]actief (3000+ sites)[/]" if MAIGRET_BESCHIKBAAR else "[dim]niet geinstalleerd - pip install maigret[/]"
    interpol_tempo = ("[green]versneld[/] (INTERPOL_SNEL=1)" if INTERPOL_SNEL
                      else "[dim]normaal (INTERPOL_SNEL=1 voor sneller)[/]")

    tabel = Table(box=box.ROUNDED, show_header=False, pad_edge=False, width=52)
    tabel.add_column(style="bold", width=14)
    tabel.add_column()
    tabel.add_row("Zoekengine", engine)
    tabel.add_row("HaveIBeenPwned", hibp)
    tabel.add_row("Sites-check (holehe)", holehe)
    tabel.add_row("ID-aanvulling (socid)", socid)
    tabel.add_row("Site-scan (Maigret)", maigret)
    tabel.add_row("GitHub", gh)
    tabel.add_row("OpenKvK", kvk)
    tabel.add_row("YouTube API", yt)
    tabel.add_row("Interpol", "[green]gratis (geen key)[/]")
    tabel.add_row("Interpol-tempo", interpol_tempo)
    tabel.add_row("FBI Wanted/Missing", "[green]gratis (geen key)[/]")
    if HARVEST_BESCHIKBAAR:
        for label, status in _harvest.status_regels():
            tabel.add_row(label, status)
    else:
        tabel.add_row("HTTP-laag", "[dim]harvest_client niet gevonden[/]")
    console.print(Panel(tabel, title="[bold cyan]Configuratie[/]", border_style="cyan"))


def teken_hoofdmenu():
    console.clear()
    logo = Panel(
        BANNER,
        title="[bold magenta]OSINT Scanner[/]",
        subtitle="Brave · DuckDuckGo · HIBP · GitHub",
        border_style="magenta",
        width=58,
        padding=(0, 6),
    )
    # Disclaimer-vak rechts naast het logo: zelfde hoogte als het logo-vak,
    # breedte wordt automatisch gekozen zodat de tekst er precies in past.
    disclaimer = (
        "[bold yellow]Let op![/] Resultaten moeten altijd aan de hand van een "
        "tweede bron worden geverifieerd. Gebruik van deze tool is altijd voor "
        "eigen risico van de gebruiker en [bold]\"Iveras Nederland\"[/] is nooit "
        "aansprakelijk voor de resultaten, het gebruik daarvan en de gevolgen "
        "van gebruik. De tool werkt ook zonder API-keys maar dan met mindere "
        "c.q. beperkte resultaten. Bij vragen kijk in de documentatie of neem "
        "contact op met [bold cyan]osintscanner@iveras.com[/] om een case te "
        "openen (tegen betaling)."
    )

    def _breedte_voor_hoogte(tekst, doelhoogte=10, max_breedte=140):
        """Kleinste paneelbreedte zodat de tekst binnen `doelhoogte` regels past."""
        for w in range(40, max_breedte + 1):
            probeer = Panel(tekst, border_style="yellow", width=w, padding=(0, 1))
            try:
                regels = console.render_lines(probeer, console.options.update(width=w))
            except Exception:
                continue
            if len(regels) <= doelhoogte:
                return w
        return max_breedte

    zijvak = Panel(
        disclaimer,
        title="[bold yellow]\u26a0 Disclaimer[/]",
        border_style="yellow",
        width=_breedte_voor_hoogte(disclaimer, doelhoogte=10),
        padding=(0, 1),
    )
    console.print(Columns([logo, zijvak], padding=(0, 1)))
    banner = _update_banner()
    if banner:
        console.print(banner)
        console.print()
    cijfers = Table(box=box.SIMPLE_HEAVY, show_header=False, pad_edge=False)
    cijfers.add_column(width=5, justify="center", style="bold cyan")
    cijfers.add_column()
    cijfers.add_row("1", "Zoeken op volledige naam")
    cijfers.add_row("2", "Zoeken op gebruikersnaam")
    cijfers.add_row("3", "Zoeken op e-mailadres (+ lekken & sites)")
    cijfers.add_row("4", "Zoeken op telefoonnummer")
    cijfers.add_row("5", "Bedrijven zoeken (KVK-handelsregister)")
    cijfers.add_row("6", "Interpol / FBI / Opsporingslijst")
    cijfers.add_row("7", "Social Media ID extraheren")
    cijfers.add_row("", "─")
    cijfers.add_row("8", "Bestaande rapporten openen")
    cijfers.add_row("9", "Rapporten opruimen (oud / leeg)")
    cijfers.add_row("", "─")
    cijfers.add_row("A", "Zoeken op adres (Kadaster/BAG)")
    cijfers.add_row("K", "Kentekenonderzoek (RDW)")
    console.print(Panel(
        cijfers,
        title="[bold green]Zoekopties[/]",
        border_style="green",
        padding=(0, 1),
    ))

    letters = Table(box=box.SIMPLE_HEAVY, show_header=False, pad_edge=False)
    letters.add_column(width=5, justify="center", style="bold yellow")
    letters.add_column()
    letters.add_row("C", "Configuratie-status tonen")
    letters.add_row("S", "Instellingen (API-keys)")
    letters.add_row("U", "Update installeren (git pull)")
    letters.add_row("Q", "Afsluiten")
    console.print(Panel(
        letters,
        title="[bold yellow]Configuratie[/]",
        border_style="yellow",
        padding=(0, 1),
    ))


def toon_rapport_overzicht():
    rapporten = sorted(glob.glob("osint_rapport_*.html"), key=os.path.getmtime, reverse=True)
    if not rapporten:
        console.print("\n[yellow]Geen bestaande rapporten gevonden.[/]")
        return

    tabel = Table(title="Beschikbare rapporten", box=box.ROUNDED, header_style="bold cyan")
    tabel.add_column("#", justify="right", style="bold")
    tabel.add_column("Bestand")
    tabel.add_column("Laatst gewijzigd")
    tabel.add_column("Grootte", justify="right")
    for i, pad in enumerate(rapporten, 1):
        gewijzigd = datetime.fromtimestamp(os.path.getmtime(pad)).strftime("%d-%m-%Y %H:%M")
        grootte_kb = os.path.getsize(pad) / 1024
        tabel.add_row(str(i), pad, gewijzigd, f"{grootte_kb:.0f} KB")
    console.print()
    console.print(tabel)

    keuze = Prompt.ask(
        "\n[bold]Welk rapport openen?[/] (nummer, Enter = annuleren)",
        default="",
    ).strip()
    if keuze.isdigit() and 1 <= int(keuze) <= len(rapporten):
        pad = os.path.abspath(rapporten[int(keuze) - 1])
        actie = Prompt.ask(
            f"[bold]'{rapporten[int(keuze) - 1]}'[/] [dim]({rapporten[int(keuze) - 1]})[/] - [bold cyan]O[/]penen of [bold cyan]P[/]DF?",
            choices=["O", "P", "o", "p"],
            default="O",
        ).strip().upper()
        if actie == "P":
            console.print("[cyan]Rapport omzetten naar PDF...[/]")
            pdf_pad, fout = print_rapport_naar_pdf(pad)
            if pdf_pad:
                console.print(f"[green]PDF opgeslagen:[/] {os.path.basename(pdf_pad)}")
                if Prompt.ask("[bold]PDF direct openen?[/] (j/N)", default="n").strip().lower() in ("j", "ja", "y", "yes"):
                    webbrowser.open("file://" + pdf_pad)
            else:
                console.print(f"[red]{fout}[/]")
        else:
            webbrowser.open(f"file://{pad}")
            console.print(f"[green]Geopend:[/] {rapporten[int(keuze) - 1]}")
    elif keuze:
        console.print("[red]Ongeldige keuze.[/]")


def ruim_rapporten_op():
    """Verwijdert oude en/of (bijna) lege rapporten na bevestiging."""
    rapporten = sorted(glob.glob("osint_rapport_*.html"), key=os.path.getmtime)
    if not rapporten:
        console.print("\n[yellow]Geen rapporten om op te ruimen.[/]")
        return

    klein_drempel = 6 * 1024
    oude_drempel = 30 * 24 * 3600  # 30 dagen

    # Optionele datum: alle rapporten vóór deze datum worden ook kandidaat.
    datum_grens = None
    datum_invoer = Prompt.ask(
        "\n[bold]Datum (formaat dd-mm-jjjj)[/] — verwijdert rapporten [bold]vóór[/] deze datum "
        "[dim](optioneel, Enter = overslaan)[/]",
        default="",
    ).strip()
    if datum_invoer:
        try:
            datum_grens = datetime.strptime(datum_invoer, "%d-%m-%Y")
            printf_datum = datum_grens.strftime("%d-%m-%Y")
        except ValueError:
            console.print(f"[yellow]Ongeldige datum '{datum_invoer}' — verwacht dd-mm-jjjj. Alleen oud/klein-regels worden toegepast.[/]")
    else:
        console.print("[dim]Geen datum ingevoerd — alleen de regels 'oud (>30 dgn)' en 'klein (<6 KB)' worden toegepast.[/]")

    verwijderen = []
    for pad in rapporten:
        grootte = os.path.getsize(pad)
        mtime = os.path.getmtime(pad)
        leeftijd = time.time() - mtime
        redenen = []
        if grootte < klein_drempel:
            redenen.append(f"klein ({grootte // 1024} KB)")
        if leeftijd > oude_drempel:
            dagen = int(leeftijd // 86400)
            redenen.append(f"oud ({dagen} dgn)")
        if datum_grens is not None:
            gewijzigd_datum = datetime.fromtimestamp(mtime)
            if gewijzigd_datum < datum_grens:
                redenen.append(f"vóór {printf_datum}")
        if redenen:
            verwijderen.append((pad, grootte, redenen))

    if not verwijderen:
        console.print("\n[green]Geen rapporten gevonden die voldoen aan de opruimingscriteria.[/]")
        return

    tabel = Table(title="Kandidaat-verwijdering", box=box.ROUNDED, header_style="bold cyan")
    tabel.add_column("#", justify="right", style="bold")
    tabel.add_column("Bestand")
    tabel.add_column("Grootte", justify="right")
    tabel.add_column("Reden")
    for i, (pad, grootte, redenen) in enumerate(verwijderen, 1):
        tabel.add_row(str(i), pad, f"{grootte // 1024} KB", ", ".join(redenen))
    console.print()
    console.print(tabel)

    bevestig = Prompt.ask(
        f"\n[bold red]Deze {len(verwijderen)} rapport(en) definitief verwijderen?[/] (j/N)",
        default="n",
    ).strip().lower()
    if bevestig not in ("j", "ja", "y", "yes"):
        console.print("[dim]Opruimen geannuleerd.[/]")
        return

    for pad, *_ in verwijderen:
        try:
            os.remove(pad)
            console.print(f"[red]Verwijderd:[/] {pad}")
        except OSError as exc:
            console.print(f"[yellow]Niet kunnen verwijderen {pad}:[/] {exc}")
    console.print(f"[green]{len(verwijderen)} rapport(en) opgeruimd.[/]")


def _toon_een_id(profiel):
    """Toont de ID-extractie van een enkel profiel in een terminal-tabel."""
    tabel = Table(title=f"ID-extractie - {profiel.get('username', '?')}", box=box.ROUNDED, header_style="bold cyan")
    tabel.add_column("Veld", style="bold")
    tabel.add_column("Waarde")
    tabel.add_row("Platform", profiel.get("platform", "-"))
    tabel.add_row("Profiel", profiel.get("url", "-"))
    d = profiel.get("details", {})
    tabel.add_row("ID", f"[bold cyan]{profiel.get('id', '-')}[/]")
    tabel.add_row("Bron", d.get("bron", "-"))
    # Extra details per platform
    for k, v in d.items():
        if k not in ("bron", "id", "socid", "ids_data") and v not in (None, "", 0, False):
            tabel.add_row(str(k).capitalize(), str(v))
    # Maigret extra gegevens
    ids_data = d.get("ids_data")
    if ids_data:
        tabel.add_row("", "")
        tabel.add_row("[bold magenta]Maigret ids_data[/]", "[dim]extra profieldata[/]")
        for id_naam, id_waarde in list(ids_data.items())[:12]:
            if id_waarde not in (None, "", 0, False):
                tabel.add_row(f"  [cyan]{id_naam}[/]", str(id_waarde)[:120])

    # socid-extractor gegevens
    socid = d.get("socid")
    if socid:
        tabel.add_row("", "")
        tabel.add_row("[bold magenta]socid-extractor[/]", "[dim]gestandaardiseerde data[/]")
        # Kernvelden
        for veld in ("fullname", "name", "display_name", "bio", "tagline",
                      "created_at", "gender", "country", "city", "location",
                      "is_verified", "is_private", "is_business",
                      "followers_count", "following_count", "media_count",
                      "website", "website_url"):
            waarde = socid.get(veld)
            if waarde not in (None, "", 0, False, "None"):
                tabel.add_row(f"  {veld}", str(waarde)[:120])
        # Interne IDs
        intern_ids = socid.get("internal_ids", {})
        if intern_ids:
            for id_naam, id_waarde in intern_ids.items():
                tabel.add_row(f"  [cyan]{id_naam}[/]", f"[bold cyan]{id_waarde}[/]")
        # Externe links
        links = socid.get("external_links", [])
        if links:
            tabel.add_row("  Externe links", ", ".join(str(l)[:60] for l in links[:5]))

    console.print()
    console.print(tabel)


def main():
    # Eenmalig bij starten: registreer installatie (achtergrond, nooit blokkerend)
    # + update-check in het geheugen zodat de banner in het menu getoond kan worden.
    global _update_resultaat
    _licentie_register_achtergrond()
    _update_resultaat = _check_update()
    while True:
        teken_hoofdmenu()
        keuze = Prompt.ask(
            "[bold]Maak uw keuze[/]",
            choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "A", "c", "C", "k", "K", "s", "S", "u", "U", "q", "Q"],
            default="Q",
        ).upper()

        if keuze == "1":
            naam = Prompt.ask("\n[bold cyan]Voer volledige naam in[/]").strip()
            if naam:
                voornaam = Prompt.ask("[bold cyan]Voornaam (optioneel, wordt automatisch uit naam geparsed)[/]", default="").strip()
                # Voornaam automatisch splitsen als niet apart opgegeven
                if not voornaam and " " in naam:
                    voornaam = naam.rsplit(" ", 1)[0]
                plaats = Prompt.ask("[bold cyan]Woonplaats (optioneel, Enter = overslaan)[/]", default="").strip()
                # Gebruik de volledige naam (voornaam + achternaam) als doelwit
                # én in de zoek-dorks, zodat bv. 'ivan versteegh' i.p.v. alleen
                # 'versteegh' wordt doorzocht en weergegeven.
                volledige_naam = naam
                if voornaam and voornaam.lower() not in naam.lower():
                    volledige_naam = f"{voornaam} {naam}".strip()
                voer_onderzoek_uit("naam", volledige_naam, dorks_naam(volledige_naam, plaats), plaats=plaats, voornaam=voornaam)
        elif keuze == "2":
            user = Prompt.ask("\n[bold cyan]Voer gebruikersnaam in[/]").strip().lstrip("@")
            if user:
                voer_onderzoek_uit("username", user, dorks_username(user))
        elif keuze == "3":
            email = Prompt.ask("\n[bold cyan]Voer e-mailadres in[/]").strip()
            if email:
                voer_onderzoek_uit("email", email, dorks_email(email))
        elif keuze == "4":
            tel = Prompt.ask("\n[bold cyan]Voer telefoonnummer in[/] (bijv. 0612345678)").strip()
            if tel:
                tel_int = "+31" + tel[1:] if tel.startswith("0") else tel
                voer_onderzoek_uit("telefoon", tel, dorks_telefoon(tel, tel_int))
        elif keuze == "5":
            term = Prompt.ask("\n[bold cyan]Zoekterm[/] (bedrijfsnaam of deel ervan)").strip()
            if term:
                with console.status("[cyan]KVK-handelsregister doorzoeken...[/]", spinner="dots"):
                    resultaat = openkvk_bedrijven(term)
                console.print(f"\n[bold]{resultaat['melding']}[/]")
                for b in resultaat["bedrijven"][:25]:
                    console.print(f"  [cyan]{b['handelsnaam']}[/] [dim](kvk {b['dossiernummer']})[/]")
                with console.status("[cyan]Rapport genereren...[/]", spinner="dots"):
                    bestandsnaam = genereer_dashboard("bedrijven", term, {}, {"openkvk": resultaat})
                console.print(f"\n[bold green]✔ Rapport opgeslagen:[/] [underline]{bestandsnaam}[/]")
                Prompt.ask("\nDruk op Enter om terug te gaan naar het menu", default="")
        elif keuze == "A":
            adres = Prompt.ask("\n[bold cyan]Voer adres in[/] (bijv. straat + huisnummer + plaats, of postcode + huisnummer)").strip()
            if adres:
                with console.status("[cyan]Kadaster/BAG-gegevens opvragen...[/]", spinner="dots"):
                    resultaat = bag_adres_zoeken(adres)
                if resultaat.get("status") not in ("ok",):
                    console.print(f"\n[bold yellow]{resultaat.get('fout')}[/]")
                else:
                    a = resultaat["adres"]
                    console.print(f"\n[bold]Kadaster / BAG - {a.get('weergavenaam')}[/]")
                    console.print(f"  Gemeente: {a.get('gemeente')} | Provincie: {a.get('provincie')}")
                    console.print(f"  Buurt: {a.get('buurt')} | Wijk: {a.get('wijk')} | Waterschap: {a.get('waterschap')}")
                    if a.get("perceel"):
                        console.print(f"  Perceel: {', '.join(a['perceel'])}")
                    if a.get("bouwjaar"):
                        console.print(f"  Bouwjaar: [bold]{a['bouwjaar']}[/] | Oppervlakte: {a.get('oppervlakte')} m² | Gebruiksdoel: {a.get('gebruiksdoel')}")
                    if a.get("coord_ll"):
                        console.print(f"  Coördinaten: [dim]{a.get('coord_ll')}[/]")
                    links = a.get("links") or {}
                    if links:
                        console.print("  [bold]Links:[/]")
                        if links.get("bag_viewer"):
                            console.print(f"    [cyan]BAG viewer (kaart):[/] {links['bag_viewer']}")
                        if links.get("google_maps"):
                            console.print(f"    [cyan]Google Maps:[/] {links['google_maps']}")
                        if links.get("openstreetmap"):
                            console.print(f"    [cyan]OpenStreetMap:[/] {links['openstreetmap']}")
                        if links.get("politie_wijkagent"):
                            console.print(f"    [yellow]Wijkagent (politie.nl):[/] {links['politie_wijkagent']}")
                        if links.get("politie_bureaus"):
                            console.print(f"    [yellow]Politiebureau (politie.nl):[/] {links['politie_bureaus']}")
                    politie = a.get("politie") or []
                    if politie:
                        console.print("  [bold]Politiebureaus in de buurt:[/]")
                        for p in politie:
                            naam = p.get("naam") or "Politiebureau"
                            adress = " ".join(filter(None, [p.get("adres"), p.get("postcode"), p.get("plaats")]))
                            line = f"    [bold]{naam}[/] - {adress or 'adres onbekend'}"
                            if p.get("telefoon"):
                                line += f" | [dim]{p['telefoon']}[/]"
                            console.print(line)
                            if p.get("url"):
                                console.print(f"      [cyan]{p['url']}[/]")
                    console.print()
                with console.status("[cyan]Rapport genereren...[/]", spinner="dots"):
                    bestandsnaam = genereer_dashboard("adres", adres, {}, {"bag": resultaat})
                console.print(f"\n[bold green]✔ Rapport opgeslagen:[/] [underline]{bestandsnaam}[/]")
                Prompt.ask("\nDruk op Enter om terug te gaan naar het menu", default="")
        elif keuze == "K":
            kenteken = Prompt.ask("\n[bold cyan]Voer kenteken in[/] (bijv. AB-123-CD of AB123CD)").strip()
            if kenteken:
                with console.status("[cyan]RDW-kentekenonderzoek...[/]", spinner="dots"):
                    rdw = rdw_kenteken_zoek(kenteken)
                if rdw.get("status") == "ok" and rdw.get("voertuig"):
                    v = rdw["voertuig"]
                    console.print(f"\n[bold]RDW - {rdw.get('kenteken')}[/]")
                    for label, waarde in [
                        ("Merk", v.get("merk")),
                        ("Handelsbenaming", v.get("handelsbenaming")),
                        ("Bouwjaar", _rdw_datum(v.get("bouwjaar"))),
                        ("Brandstof", v.get("brandstof")),
                        ("CO2-uitstoot", v.get("co2")),
                        ("APK-vervaldatum", _rdw_datum(v.get("vervaldatum"))),
                        ("Kleur", v.get("kleur")),
                        ("Voertuigsoort", v.get("voertuigsoort")),
                        ("Categorie", v.get("categorie")),
                        ("Deuren", v.get("aantal_deuren")),
                        ("Zitplaatsen", v.get("aantal_zitplaatsen")),
                        ("Massa ledig", v.get("massa_ledig")),
                    ]:
                        if waarde:
                            console.print(f"  {label}: [bold]{waarde}[/]")
                    console.print()
                    with console.status("[cyan]Rapport genereren...[/]", spinner="dots"):
                        bestandsnaam = genereer_dashboard("kenteken", rdw.get("kenteken") or kenteken, {}, {"rdw": rdw})
                    console.print(f"\n[bold green]✔ Rapport opgeslagen:[/] [underline]{bestandsnaam}[/]")
                elif rdw.get("status") == "geen":
                    console.print(f"\n[bold yellow]{rdw.get('fout')}[/]")
                else:
                    console.print(f"\n[bold yellow]{rdw.get('fout')}[/]")
                Prompt.ask("\nDruk op Enter om terug te gaan naar het menu", default="")
        elif keuze == "6":
            achternaam = Prompt.ask("\n[bold cyan]Achternaam[/]").strip()
            if achternaam:
                voornaam7 = Prompt.ask("[bold cyan]Voornaam (optioneel)[/]", default="").strip()
                uitkomst_ol = []
                with console.status("[cyan]Interpol-notices zoeken...[/]", spinner="dots"):
                    uitkomst_interpol = interpol_zoek(achternaam, voornaam7)
                with console.status("[cyan]FBI Wanted/Missing zoeken...[/]", spinner="dots"):
                    uitkomst_fbi = fbi_wanted_zoek(achternaam, voornaam7)
                with console.status("[cyan]Nationale Opsporingslijst...[/]", spinner="dots"):
                    uitkomst_ol = opsporingslijst_zoek(achternaam, voornaam7)
                console.print()
                if uitkomst_interpol.get("status") == "geblokkeerd":
                    console.print(f"[bold yellow]{uitkomst_interpol['melding']}[/]")
                elif uitkomst_interpol["red"] or uitkomst_interpol["yellow"]:
                    if uitkomst_interpol["red"]:
                        console.print(f"[bold red]Red Notices ({len(uitkomst_interpol['red'])}):[/]")
                        for n in uitkomst_interpol["red"][:10]:
                            console.print(f"  [red]{n['naam']}[/] [dim]({n['nationaliteit']}, geb. {n['geboortedatum']})[/]")
                            _extra = ", ".join(x for x in (n.get("geboorteplaats"), n.get("kenmerken")) if x)
                            if _extra:
                                console.print(f"     [dim]{_extra[:90]}[/]")
                            if n.get("fotos"):
                                console.print(f"     [dim]Foto's: {len(n['fotos'])}[/]")
                            console.print(f"     {n['url']}  |  API-data: {n.get('api_url', '')}")
                    if uitkomst_interpol["yellow"]:
                        console.print(f"[bold yellow]Yellow Notices ({len(uitkomst_interpol['yellow'])}):[/]")
                        for n in uitkomst_interpol["yellow"][:10]:
                            console.print(f"  [yellow]{n['naam']}[/] [dim]({n['nationaliteit']}, geb. {n['geboortedatum']})[/]")
                            _extra = ", ".join(x for x in (n.get("geboorteplaats"), n.get("kenmerken")) if x)
                            if _extra:
                                console.print(f"     [dim]{_extra[:90]}[/]")
                            if n.get("fotos"):
                                console.print(f"     [dim]Foto's: {len(n['fotos'])}[/]")
                            console.print(f"     {n['url']}  |  API-data: {n.get('api_url', '')}")
                else:
                    console.print(f"[dim]{uitkomst_interpol.get('melding', 'Geen notices gevonden.')}[/]")
                if uitkomst_fbi.get("status") == "geblokkeerd":
                    console.print(f"[bold yellow]{uitkomst_fbi['melding']}[/]")
                else:
                    if uitkomst_fbi["gezocht"]:
                        console.print(f"[bold red]FBI Gezocht ({len(uitkomst_fbi['gezocht'])}):[/]")
                        for n in uitkomst_fbi["gezocht"][:10]:
                            console.print(f"  [red]{n['naam']}[/] [dim]({n.get('subjects', '')})[/]")
                            console.print(f"     {n.get('url', '')}")
                    if uitkomst_fbi["vermist"]:
                        console.print(f"[bold yellow]FBI Vermist ({len(uitkomst_fbi['vermist'])}):[/]")
                        for n in uitkomst_fbi["vermist"][:10]:
                            console.print(f"  [yellow]{n['naam']}[/] [dim]({n.get('subjects', '')})[/]")
                            console.print(f"     {n.get('url', '')}")
                    if not uitkomst_fbi["gezocht"] and not uitkomst_fbi["vermist"]:
                        console.print(f"[dim]{uitkomst_fbi.get('melding', 'Geen FBI-records gevonden.')}[/]")
                if uitkomst_ol:
                    console.print(f"[bold red]Opsporingslijst ({len(uitkomst_ol)}):[/]")
                    for hit in uitkomst_ol[:10]:
                        console.print(f"  {hit['titel'][:60]}  [dim]{hit['link'][:60]}[/]")
                else:
                    console.print("[dim]Geen resultaten op de Nationale Opsporingslijst.[/]")
                rapport7 = {}
                extra7 = {"interpol": uitkomst_interpol, "fbi": uitkomst_fbi, "opsporingslijst": uitkomst_ol}
                with console.status("[cyan]Rapport genereren...[/]", spinner="dots"):
                    bestandsnaam = genereer_dashboard("interpol", achternaam, rapport7, extra7)
                console.print(f"\n[bold green]✔ Rapport opgeslagen:[/] [underline]{bestandsnaam}[/]")
                Prompt.ask("\nDruk op Enter om terug te gaan naar het menu", default="")
        elif keuze == "7":
            id_input = Prompt.ask(
                "\n[bold cyan]Volledige social-URL of gebruikersnaam[/] "
                "[dim](bv. https://www.instagram.com/username/ of username)"
            ).strip()
            if id_input:
                # Bouw een profiel dict op uit de input
                profiel = {"platform": "Onbekend", "url": id_input, "bron": "handmatig"}
                if "://" not in id_input:
                    # Geen URL -> probeer elke bekende platform-URL
                    for platform_url, pname in [
                        (f"https://www.instagram.com/{id_input.lstrip('@')}/", "Instagram"),
                        (f"https://www.youtube.com/@{id_input.lstrip('@')}", "YouTube"),
                        (f"https://twitter.com/{id_input.lstrip('@')}", "Twitter"),
                        (f"https://www.tiktok.com/@{id_input.lstrip('@')}", "TikTok"),
                        (f"https://www.facebook.com/{id_input.lstrip('@')}", "Facebook"),
                    ]:
                        with console.status(f"[cyan]{pname}-ID opzoeken...[/]", spinner="dots"):
                            resultaat = zoek_social_media_ids([{"url": platform_url, "platform": pname, "bron": "handmatig"}])
                        if resultaat:
                            profiel = resultaat[0]
                            _toon_een_id(profiel)
                else:
                    with console.status("[cyan]Social Media ID extraheren...[/]", spinner="dots"):
                        resultaat = zoek_social_media_ids([{"url": id_input, "platform": "Onbekend", "bron": "handmatig"}])
                    if resultaat:
                        _toon_een_id(resultaat[0])
                    else:
                        console.print("[yellow]Kon geen ID extraheren. Mogelijk platform- of CAPTCHA-beperking.[/]")
                Prompt.ask("\nDruk op Enter om terug te gaan naar het menu", default="")
        elif keuze == "8":
            toon_rapport_overzicht()
            Prompt.ask("\nDruk op Enter om terug te gaan naar het menu", default="")
        elif keuze == "9":
            ruim_rapporten_op()
            Prompt.ask("\nDruk op Enter om terug te gaan naar het menu", default="")
        elif keuze == "C":
            console.print()
            toon_config_status()
            Prompt.ask("\nDruk op Enter om terug te gaan naar het menu")
        elif keuze == "S":
            toon_instellingen()
        elif keuze == "U":
            _voer_update_uit()
            Prompt.ask("\nDruk op Enter om terug te gaan naar het menu", default="")
        elif keuze == "Q":
            console.print("\n[dim]Tot ziens.[/]\n")
            break


if __name__ == "__main__":
    main()
