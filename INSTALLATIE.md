# OSINT Scanner — Installatiehandleiding

Dit document beschrijft stap voor stap hoe je de OSINT Scanner op een **andere pc** (Mac of Windows) installeert.

> De handleiding is zo geschreven dat je elke losse code-regel gewoon **kunt copy/pasten** in de terminal. Sla per stap de commando&apos;s één voor één over.

---

## Wat heb je nodig (systeemeisen)

| Onderdeel | Vereiste |
|-----------|----------|
| Besturingssysteem | macOS of Windows |
| Python | 3.10 of hoger (zie stap 1) |
| Chrome of Edge | alleen nodig voor PDF-export (optioneel) |
| Internetverbinding | ja |
| Vrije schijfruimte | ± 100 MB |

---

## 0. Bestanden kopiëren naar de nieuwe pc

Kopieer de volledige **gdorks**-map naar de andere pc. **Belangrijk:** de persoonlijke `.env` (met jouw API-keys) en de `.venv/`-map worden NIET gedeeld — deze stel je op de nieuwe pc opnieuw in.

De map moet minimaal deze bestanden bevatten:

```
gdorks/
  osint_scanner.py          # Het hoofdprogramma
  harvest_client.py         # WAF-tolerante HTTP-laag (curl_cffi/Tor/proxy/Playwright)
  requirements.txt          # Lijst van benodigde programma-onderdelen
  .env.example              # Template voor API-keys
  install_mac.sh            # Installatiescript Mac/Linux
  install_windows.bat       # Installatiescript Windows
  start.sh                  # Opstart-script Mac/Linux
  start.bat                 # Opstart-script Windows
  bouw_standalone.sh        # (optioneel) Bouw standalone Mac/Linux
  bouw_standalone.bat       # (optioneel) Bouw standalone Windows
  INSTALLATIE.md            # Dit document
```

---

## OPTIE A — Aanbevolen: draaien vanuit Python

Dit is de eenvoudigste route en werkt het meest betrouwbaar.

### VERSIE A1: macOS

**Stap 1 — Python installeren (alleen eerste keer)**

Open de **Terminal** (druk `Cmd + Spatie`, type `Terminal`, Enter) en controleer of Python al aanwezig is:

```bash
python3 --version
```

- Staat er `Python 3.10` of hoger? → ga naar **Stap 2**.
- Staat er niks of een te lage versie? Installeer Python dan via:

```bash
open https://www.python.org/downloads/
```

Download de **nieuwste** versie, installeer deze, en open daarna een **nieuw** Terminalvenster.

**Stap 2 — naar de gdorks-map gaan**

```bash
cd ~/gdorks
```
> Pas het pad aan als je de map ergens anders hebt neergezet. Type `cd ` (met spatie erachter) en sleep de gdorks-map naar het terminalvenster, druk dan Enter.

**Stap 3 — installatiescript uitvoeren**

```bash
chmod +x install_mac.sh
./install_mac.sh
```

Dit maakt automatisch een virtuele omgeving aan, installeert alle onderdelen en legt een `.env`-bestand aan.

**Stap 4 — de tool starten**

```bash
./start.sh
```

**Klaar!** Je ziet het OSINT Scanner-menu.

---

### VERSIE A2: Windows

**Stap 1 — Python installeren (alleen eerste keer)**

1. Open de browser en ga naar: <https://www.python.org/downloads/>
2. Klik op **Download Python**.
3. Open het gedownloade bestand.
4. **BELANGRIJK:** vink onderaan **"Add Python to PATH"** aan.
5. Klik op **Install Now** en wacht tot het klaar is.

**Stap 2 — het installatiescript draaien**

1. Open de **gdorks**-map in Windows Verkenner.
2. **Dubbelklik** op `install_windows.bat`.
3. Een zwart venster (opent) dat automatisch alles installeert. Wacht tot er staat **"Installatie voltooid!"**.
4. Druk op een toets om het venster te sluiten.

**Stap 3 — de tool starten**

1. **Dubbelklik** op `start.bat`.
2. Het OSINT Scanner-menu opent.

**Klaar!**

> **Tip:** als dubbelklikken niet werkt, open dan PowerShell, `cd` naar de map en draai:
> ```powershell
> install_windows.bat
> ```

---

## OPTIE B — Standalone executable (geen Python nodig op de doel-pc)

Bouw één los uitvoerbaar bestand, dat je overal kan draaien zonder Python te installeren. Je bouwt dit **op een pc waar Python al wel werkt** en kopieert dan alleen het losse bestand naar de andere pc('s).

### VERSIE B1: macOS

Doe eerst de stappen van **Optie A1** (Python + install_mac.sh uitvoeren), en bouw daarna:

```bash
chmod +x bouw_standalone.sh
./bouw_standalone.sh
```

Het resultaat staat in `dist/OSINT-Scanner`. Kopieer dat bestand naar de andere pc en:

```bash
./OSINT-Scanner
```

#### Xcode-probleem bij het bouwen (alleen macOS)

PyInstaller heeft op macOS de **Command Line Tools** nodig. Als de build stopt met een foutmelding over Xcode, herstel dan eerst:

```bash
sudo rm -rf /Library/Developer/CommandLineTools
xcode-select --install
```

Open daarna een nieuw Terminalvenster en probeer de build opnieuw. Zorg dat de CLT-architectuur overeenkomt met je Mac (Apple Silicon vs Intel).

### VERSIE B2: Windows

Doe eerst de stappen van **Optie A2** (Python + install_windows.bat uitvoeren), en bouw daarna:

1. **Dubbelklik** op `bouw_standalone.bat`.
2. Wacht tot **Build voltooid** verschijnt.
3. Het resultaat staat in `dist\OSINT-Scanner.exe`.

Kopieer `OSINT-Scanner.exe` naar de andere pc en **dubbelklik** het bestand om te starten.

---

## Stap 5 — API-keys invullen (optioneel, maar aanbevolen)

Zonder keys werkt de tool via DuckDuckGo (langzamer) en page-scraping. Met keys wordt het sneller en betrouwbaarder.

1. Open de `gdorks`-map.
2. Open het bestand **`.env`** (dit is door de installatie aangemaakt) met een teksteditor (bijv. Kladblok of TextEdit).
3. Vul de keys in die je hebt. De tool werkt ook oningevuld, maar dan minder snel.

Welke keys zijn er en waar haal ik ze?

| Key | Waarvoor | Waar aanvragen | Gratis? |
|-----|----------|----------------|---------|
| `BRAVE_API_KEY` | Snellere zoekresultaten | <https://brave.com/search/api/> | 2000/maand |
| `OVERHEID_IO_API_KEY` | KVK-handelsregister | <https://overheid.io/> | Ja |
| `YOUTUBE_API_KEY` | YouTube Data API v3 | <https://console.cloud.google.com/> | 10.000/dag |

**Wil je alleen snel testen?** Sla deze stap over — de tool draait ook zonder specifieke keys. Kom je er later op terug, dan pas je de `.env` gewoon aan.

---

## Veelgestelde problemen (troubleshooting)

**"FOUT: Geen Python 3.10+ gevonden."**
Python ontbreekt of is te oud. Installeer Python (zie stap 1) en zorg dat het in je PATH staat. Op macOS: gebruik officiële installer van python.org, niet alleen de oud systeem-Python.

**Het venster sluit meteen weer (Windows).**
Er is een fout tijdens installatie of starten. Open PowerShell, `cd` naar de gdorks-map en draai `install_windows.bat` of `start.bat` handmatig — dan blijven de foutmeldingen zichtbaar.

**`./start.sh` werkt niet in de Terminal.**
Zorg dat je in de juiste map staat en typ:

```bash
chmod +x start.sh
./start.sh
```

**PDF-export werkt niet.**
Installeer Chrome of Edge. De tool gebruikt die browser om rapporten naar PDF om te zetten.

**Maigret / site-scan duurt lang.**
Dat is normaal: de scan bevraagt tot ~150 sites. Je ziet een voortgangsspinner. De resultaten zijn een extra laag bovenop onze eigen checks.

**"module not found" meldingen.**
De virtuele omgeving mist onderdelen. Draai het installatiescript nogmaals:

- Mac: `./install_mac.sh`
- Windows: dubbelklik `install_windows.bat`

---

## Waar worden rapporten opgeslagen?

Alle rapporten komen als HTML (en optioneel PDF) in dezelfde `gdorks`-map te staan:

```
osint_rapport_<naam>.html
osint_rapport_<naam>.pdf
```

Open je ze via **menu-optie 8** in de tool, dan kun je ze ook direct naar PDF exporteren.

---

## Nieuwste versie krijgen / updates

Om de tool bij te werken: vervang `osint_scanner.py` en `requirements.txt` door de nieuwste versies uit je bronmap, en draai het installatiescript opnieuw om eventuele nieuwe onderdelen te installeren:

- Mac: `./install_mac.sh`
- Windows: dubbelklik `install_windows.bat`
