# OSINT Scanner

CLI-tool voor open source intelligence-onderzoek: naam, gebruikersnaam, e-mail, telefoon, bedrijven, adres, kenteken, Interpol/FBI-notices en social-media-ID-extractie — met automatische HTML-rapportage (donker dashboard) en PDF-export.

## Snel starten

### Vanuit broncode (aanbevolen)

```bash
git clone https://github.com/iveras-dev/osint-scanner.git
cd osint-scanner
```

**Mac/Linux:**
```bash
chmod +x install_mac.sh
./install_mac.sh
./start.sh
```

**Windows:**
```
Dubbelklik install_windows.bat
Dubbelklik start.bat
```

### Standalone executable (geen Python nodig op doel-pc)

Bouw eerst op een machine met Python (zie hierboven), dan:

**Mac/Linux:**
```bash
chmod +x bouw_standalone.sh
./bouw_standalone.sh      # Bouwt dist/OSINT-Scanner
./dist/OSINT-Scanner      # Starten
```

**Windows:**
```
bouw_standalone.bat       # Bouwt dist\OSINT-Scanner.exe
dist\OSINT-Scanner.exe    # Starten
```

## Systeemeisen

| Onderdeel | Vereiste |
|-----------|----------|
| Python | 3.10+ (niet nodig bij standalone) |
| Git | nodig om te klonen (of download ZIP) |
| Browser | Chrome/Edge/Chromium (alleen voor PDF-export) |
| Internet | Ja |
| Schijfruimte | ~50 MB (venv) |

## API Keys (optioneel)

Kopieer `.env.example` naar `.env` en vul je keys in:

```bash
cp .env.example .env
```

| Key | Bron | Gratis? | Wat doet het? |
|-----|------|---------|---------------|
| `BRAVE_API_KEY` | [brave.com/search/api](https://brave.com/search/api/) | 2000/maand | Snellere zoekresultaten |
| `OVERHEID_IO_API_KEY` | [overheid.io](https://overheid.io/) | Ja | KVK-handelsregister |
| `YOUTUBE_API_KEY` | [Google Cloud Console](https://console.cloud.google.com/) | 10.000/dag | YouTube Data API v3 |

Zonder keys werkt de tool via DuckDuckGo fallback en page-scraping. Alle andere bronnen (Interpol, FBI, Politie.nl, RDW, Kadaster/BAG) zijn **gratis en vereisen geen key**.

## Zoekopties

| Toets | Functie |
|-------|---------|
| 1 | Zoeken op volledige naam (dorks, nieuws, Delpher) |
| 2 | Zoeken op gebruikersnaam |
| 3 | Zoeken op e-mailadres (+ lekken & sites) |
| 4 | Zoeken op telefoonnummer |
| 5 | Bedrijven zoeken (KVK-handelsregister) |
| 6 | Interpol / FBI / Nationale Opsporingslijst |
| 7 | Social Media ID extraheren |
| A | Adres zoeken (Kadaster/BAG) + dichtstbijzijnde politiebureaus |
| K | Kentekenonderzoek (RDW, gratis open data) |
| 8 | Bestaande rapporten openen (of naar PDF exporteren) |
| 9 | Rapporten opruimen (oud / leeg) |
| C | Configuratie tonen (incl. Brave/DDG-tellers) |
| S | Instellingen / API-keys aanpassen |
| Q | Afsluiten |

## Wat doet de tool?

### Naam-onderzoek (optie 1)

Doorzoekt het web via Brave Search / DuckDuckGo met slimme dorks (social media, nieuws, forums, vacatures, kadaster, politie). Het donker HTML-dashboard toont:

- Web-resultaten met score-labels en kleurcodering
- Delpher-archieflink (2 mln gedigitaliseerde Nederlandse kranten, 1618–2005)
- Regionale en landelijke nieuwskranten (NOS, NRC, Volkskrant, Trouw, FD, AD, De Gelderlander, en meer)

### Interpol & FBI (optie 6)

- **Interpol Red Notices** (gezocht) en **Yellow Notices** (vermist) — via de officiële, publieke Interpol API
- **FBI Wanted / Missing Persons** — via de officiële, publieke FBI Wanted API (geen key nodig)
- **Nationale Opsporingslijst** (Politie.nl) — via web-dorks

### Social Media ID-extractie (optie 7)

- **Kernplatforms** (Instagram, X/Twitter, YouTube, TikTok, Facebook) via onze eigen extractie: officiële APIs, unofficial endpoints en page-scraping
- **Additionele platforms** (Steam, SoundCloud, Telegram, e.a.) via **socid-extractor** (MIT-licentie)
- **Maigret site-scan** (MIT-licentie, 3000+ sites) als aanvullende laag bij gebruikersnaam-onderzoeken

### E-mail-, telefoon- en kentekenverrijking

- **E-mail** (optie 3): wegwerpmail-detectie, MX-record-check, EmailRep.io-reputatie
- **Telefoon** (optie 4): land/regio/netwerk/type via `phonenumbers`, WhatsApp/Telegram-checks
- **Kenteken** (optie K): RDW-open-data (merk, bouwjaar, brandstof, CO₂, APK, kleur)

### Adres & politie (optie A)

Kadaster/BAG (gratis open data): perceel, bouwjaar, oppervlakte, coördinaten + dichtstbijzijnde politiebureaus via `api.politie.nl`.

### Blokkade-tolerantie & OpSec

Alle verzoeken gaan via de WAF-tolerante HTTP-laag (`harvest_client.py`):
1. `curl_cffi` TLS-impersonatie (echte Chrome-fingerprint)
2. Jitter-sleep per domein
3. Proxy-rotatie (optioneel)
4. Tor-routing (optioneel)
5. Playwright-fallback (headless Chromium, optioneel)
6. SSRF-guard tegen lekken naar private netwerken

## Dashboard

Het HTML-dashboard heeft:
- **Zoekbalk** — doorzoek alle resultaten
- **Open/Alles-knoppen** — alle kaarten tegelijk uit- of inklappen
- **Score-labels** — EXACT ~100%, STERK, MIDDEN, zwak
- **Collapsible kaarten** — per bron apart inklapbaar

## Desktop-versie (Textual)

Naast het tekstmenu (`start.sh` / `start.bat`) is er een op muis én pijltoetsen bedienbare desktop-versie (Textual):

- **Mac/Linux:** `./start-tui.sh`
- **Windows:** dubbelklik `start-tui.bat`

`textual` wordt door de startscripts automatisch geïnstalleerd wanneer die ontbreekt. De versie werkt als één **dashboard**: links een navigatie-rij met alle zoektypen (sneltoetsen 1-7, A, K) en beheer-pagina's (**I** instellingen/API-keys, **R** bestaande rapporten, **U** updates); rechts de inhoud. Research draait op de achtergrond en streamt live naar het resultaten-paneel (status, samenvatting, bronnen en klikbare hits/links), waar je het HTML-rapport direct kunt openen of naar PDF kunt exporteren.

## Rapporten

Rapporten worden opgeslagen als:
- **HTML**: `osint_rapport_{naam}.html` — donker dashboard met zoekfunctie
- **PDF**: `osint_rapport_{naam}.pdf` — via menu-optie 8 > P

## Licentie

De OSINT Scanner staat onder **GNU AGPL-3.0** (de strengste copyleft-licentie — geldt ook voor netwerkgebruik/SaaS).

De volledige licentietekst staat in `LICENSE`.

### Externe afhankelijkheden

De tool gebruikt diverse `pip`-dependencies (holehe, maigret, socid-extractor, ddgs, rich, curl_cffi, en meer) die hun eigen open-source-licenties hebben. Deze zijn gedocumenteerd in `THIRD_PARTY_NOTICES`. Er is geen broncode van deze tools overgenomen in deze repository; ze worden puur als bibliotheek geïmporteerd of als subprocess aangeroepen.

### Installatieregistratie & telemetrie

Bij het starten registreert de scanner de installatie (max. 1×/dag) bij `license.iveras.com`, zodat er zicht is op actieve installaties. Elke install krijg een eigen anoniem `install_id` + uniek token (opgeslagen onder `~/.osint_scanner/config.json`, buiten de repo). Verzonden wordt alleen: appnaam, versie, OS en Pythonversie — geen persoonlijke gegevens, geen zoektermen.

Uitschakelen (optioneel, geen gevolgen voor de werking): zet `OSINT_NO_TELEMETRY=1` in `.env`.

## Updates

De scanner toont bij het starten een **update-banner** als er op GitHub (`iveras-dev/osint-scanner`) een nieuwere commit of versie staat. Via menu-optie **U** ("Update installeren") kun je de update direct installeren (`git pull`).

Handmatig werkt dit ook:

```bash
cd osint-scanner
git pull
./install_mac.sh    # of opnieuw install_windows.bat
```
