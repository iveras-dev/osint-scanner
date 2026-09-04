# OSINT Scanner

Naam-, gebruikersnaam-, e-mail- en telefoononderzoek met automatische HTML-rapportage en PDF-export.

## Snel starten

### Optie 1: Vanuit broncode (aanbevolen)

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

### Optie 2: Standalone executable (geen Python nodig)

**Mac/Linux:**
```bash
chmod +x install_mac.sh
./install_mac.sh          # Eerst dependencies
chmod +x bouw_standalone.sh
./bouw_standalone.sh      # Bouwt dist/OSINT-Scanner
./dist/OSINT-Scanner      # Starten
```

**Windows:**
```
install_windows.bat       # Eerst dependencies
bouw_standalone.bat       # Bouwt dist\OSINT-Scanner.exe
dist\OSINT-Scanner.exe    # Starten
```

## Systeemeisen

| Onderdeel | Vereiste |
|-----------|----------|
| Python | 3.10+ (niet nodig bij standalone) |
| Browser | Chrome/Edge/Chromium (alleen voor PDF-export) |
| Internet | Ja |
| Schijfruimte | ~50 MB (venv) |

### Voor PyInstaller build (optioneel)

| Onderdeel | Vereiste |
|-----------|----------|
| Xcode CLT (Mac) | `xcode-select --install` — moet overeenkomen met CPU-architectuur |
| Visual C++ Build Tools (Windows) | Optioneel, meestal niet nodig |

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

Zonder keys werkt de tool via DuckDuckGo fallback en page-scraping.

## Social Media ID-extractie

- **Kernplatforms** (Instagram, X/Twitter, YouTube, TikTok, Facebook) gebruiken onze eigen extractie: officiële APIs, unofficial endpoints en page-scraping. Deze is primair en ongewijzigd van kwaliteit.
- **Additionele platforms** (Steam, SoundCloud, Telegram, e.a.) worden aangevuld met **socid-extractor** (MIT-licentie) — een extra laag bovenop onze eigen extractie, die stabilere interne IDs (steam_id, uid, etc.), bio's en volgers ophaalt.
- **Maigret site-scan**: bij gebruikersnaam-onderzoeken wordt **Maigret** (MIT-licentie, 3000+ sites) gedraaid als aanvullende laag. Het vindt extra platforms (Bit.ly, Substack, VK, Weibo, Twitch, etc.) die we niet zelf dekken, met profiel-URL en interne IDs. Onze eigen checks blijven primair; Maigret is uitsluitend aanvulling en de resultaten worden tegen fout-positieven gefilterd (o.a. filter-URLs en Discord-domeinchecks).
- **Voortgang**: alle ID-extractie toont een live counter (`(2/6): instagram/naam`) zodat je weet waar de zoekactie staat.

## Blokkade-tolerantie & OpSec

- Platforms die ons blokkeren (HTTP 403/429/5xx) worden automatisch onthouden en tijdelijk overgeslagen. Bij herhaalde blokkeringen worden ze binnen de sessie minder bevraagd.
- **HTTP-laag (`harvest_client.py`)**: alle externe verzoeken gaan via een WAF-tolerante client die, in oplopende mate:
  1. **`curl_cffi` TLS-impersonatie** — reproduceert een echte Chrome-TLS-fingerprint, zodat Akamai e.d. ons niet langer als Python-`requests` herkent (bv. de politie-API's: plain requests → 403, impersonate → 200).
  2. **Jitter-sleep** per domein — randomized pauzes tegen burst-patronen (config: `JITTER_ENABLED`, `JITTER_MIN`, `JITTER_MAX`).
  3. **Proxy-rotatie** — afwisselende IP's via `PROXY_LIST` + `PROXY_ROTATION_ENABLED=1`.
  4. **Tor-routing** — via `TOR_ENABLED=1` + `TOR_PROXY` (standaard `socks5h://127.0.0.1:9050`); optioneel `TOR_STRICT_MODE=1` om te weigeren als Tor uit staat.
  5. **Playwright-fallback** — headless Chromium (met stealth) als curl_cffi wordt geblokkeerd, voor doelen met JS-uitdagingen; aanzetten met `PLAYWRIGHT_FALLBACK_ENABLED=1` + `playwright install chromium`.
- Een **SSRF-guard** controleert elke hop (incl. redirects) zodat een verzoek nooit naar private/reserved netwerken lekt.
- Randomized pauzes tussen verzoeken voorkomen burst-patronen en beperken het digitale trace.

## Adres & politie (menu-optie A)

- Zoekt een Nederlands adres op bij het Kadaster/BAG (gratis open data, geen key): perceel, bouwjaar, oppervlakte, gebruiksdoel, status, coördinaten.
- Bepaalt automatisch de **dichtstbijzijnde politiebureaus** via de officiële `api.politie.nl`-API (naam, adres, telefoon, link) en genereert wijkagent-/politiebureau-links voor het betreffende postcodegebied.
- Toont kaartlinks (BAG viewer, Google Maps, OpenStreetMap).

## E-mail-, telefoon- en kentekenverrijking

Naast de bestaande lek- en sites-checks worden extra gratis publieke verrijkingen getoond:

- **E-mail** (menu-optie 3): wegwerp/weggebed-mail-detectie (tempmail, yopmail, 10minutemail etc.), MX-record-check (kan het domein überhaupt mail ontvangen?) en **EmailRep.io**-reputatie (verdacht/score). Plus quick-links naar EmailRep, HIBP, Hunter.io, Dehashed en Google.
- **Telefoon** (menu-optie 4): nummer-normalisatie (E164), land/regio/netwerk/type/tijdzone via **phonenumbers**, en bestaans-checks op **WhatsApp** en **Telegram**.
- **Kentekenonderzoek** (menu-optie **K**): gratis RDW-open-data-lookup van een Nederlands kenteken (merk, handelsbenaming, bouwjaar, brandstof, CO2, APK-vervaldatum, kleur, categorie).

Al deze bronnen (EmailRep, RDW, WhatsApp/Telegram) zijn **gratis** en vereisen **geen API-key**. WhatsApp/Telegram-checks kunnen afhankelijk zijn van geografische beschikbaarheid (Telegram kan in sommige regio's geblokkeerd zijn).

## Nieuws & kranten (gratis)

Bij naam-onderzoek wordt in twee nieuws-dork-categorieën gezocht via de zoekmachine:

- **Nieuws & Media** (landelijk): `nos.nl`, `nu.nl`, `rtlnieuws.nl`, `ad.nl`, `telegraaf.nl`, `volkskrant.nl`, `nrc.nl`, `parool.nl`, `trouw.nl`, `fd.nl`, `metronieuws.nl`.
- **Regionale kranten & Vakbladen**: `gelderlander.nl`, `bndestem.nl`, `pzc.nl`, `eindhovensdagblad.nl`, `destentor.nl`, `tubantia.nl`, `weideblog.nl`, `nu.nl/regio`.

Daarnaast toont het dashboard een **Delpher**-kaart met een handmatige open-link die de 2 mln gedigitaliseerde Nederlandse kranten (1618–2005, KB) op de volledige naam doorzoekt. Delpher is gratis zonder account, maar kent geen openbare zoek-API — daarom als directe link in plaats van een automatische scrape.

## Menu

| Toets | Functie |
|-------|---------|
| 1-7 | Zoekacties (naam, gebruiker, email, tel, bedrijven, Interpol, social IDs) — naam-onderzoek doorzoekt ook landelijke én regionale kranten plus een Delpher-archieflink |
| A | Adres zoeken (Kadaster/BAG) + dichtstbijzijnde politiebureaus |
| K | Kentekenonderzoek (RDW, gratis open data) |
| 8 | Bestaande rapporten openen (of naar PDF exporteren) |
| 9 | Rapporten opruimen (op datum of oud/klein) |
| C | Configuratie tonen (incl. Brave-exact-frase- en DDG-fallback-tellers) |
| S | Instellingen / API-keys aanpassen |
| Q | Afsluiten |

## Rapporten

Rapporten worden opgeslagen als:
- **HTML**: `osint_rapport_{naam}.html` — donker dashboard met zoekfunctie
- **PDF**: `osint_rapport_{naam}.pdf` — via menu-optie 8 > P

## Bedrijfsmap delen

Deel de volledige `gdorks/` map (zonder `.env` en `.venv/`):

```
gdorks/
  osint_scanner.py         # Het script
  harvest_client.py        # WAF-tolerante HTTP-laag (curl_cffi/Tor/proxy/Playwright)
  requirements.txt         # Dependencies
  .env.example             # API-key template
  install_mac.sh           # Mac installatie
  install_windows.bat      # Windows installatie
  start.sh                 # Mac starten
  start.bat                # Windows starten
  bouw_standalone.sh       # Mac standalone bouwen
  bouw_standalone.bat      # Windows standalone bouwen
  README.md                # Dit bestand
```

De `.env` bevat je persoonlijke API-keys en wordt **niet** gedeeld.
