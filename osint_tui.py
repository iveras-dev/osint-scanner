#!/usr/bin/env python3
"""
OSINT Scanner — Textual desktop-versie (dashboard-layout).

Eén scherm met een linker navigatie (alle zoektypen + beheer-pagina's) en een
inhoudsdeel rechts. Research draait in Textual-workers en levert gestructureerde
resultaten op (datainterface) — naast de live-stream van de engine-console.
Zoals voorheen wordt alleen de UI-laag herbouwd; alle zoeklogica komt uit
osint_scanner.py.

Start:  python3 osint_tui.py        (of via start-tui.sh / start-tui.bat)
"""

from __future__ import annotations

import io
import os
import re
import subprocess
import threading
import time
import webbrowser
from dataclasses import dataclass, field

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    LoadingIndicator,
    RichLog,
)

import osint_scanner as sc
from rich.console import Console

# ---------------------------------------------------------------------------
# Console-kaping: alle rich-output van de engine wordt gebufferd en gestreamd.
# ---------------------------------------------------------------------------


class _ConsoleBuffer:
    """Thread-safe rich-console-file: output wegschrijven in een StringIO."""

    def __init__(self) -> None:
        self._sluis = io.StringIO()
        self._lok = threading.Lock()

    def write(self, s: str) -> int:
        with self._lok:
            return self._sluis.write(s)

    def flush(self) -> None:
        pass

    def lees(self) -> str:
        with self._lok:
            self._sluis.seek(0)
            data = self._sluis.read()
            self._sluis.seek(0)
            self._sluis.truncate()
        return data


_geleide_buffer = _ConsoleBuffer()


def _activeer_geleide_console() -> None:
    """Vervangt de engine-console zodat prints in de buffer landen (geen ANSI)."""
    sc.console = Console(
        file=_geleide_buffer,
        color_system=None,
        force_terminal=False,
        soft_wrap=True,
    )


ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07")


def _schoone_regels(ruw: str) -> list[str]:
    """Zet ruwe buffer-output om naar nette regel-tekst (incl. spinner-opruiming)."""
    ruw = ANSI_RE.sub("", ruw)
    regels: list[str] = []
    for blok in ruw.split("\n"):
        # rich-status gebruikt \r om dezelfde regel te herschrijven; houd de
        # laatste schrijving en gooi spinners/samengedrukte regels weg.
        stukken = [s.strip() for s in blok.split("\r") if s.strip()]
        if not stukken:
            continue
        laatste = stukken[-1]
        if not laatste or laatste in ("…", "… "):
            continue
        if re.fullmatch(r"[;·•●○◦*xX.]+", laatste):
            continue
        regels.append(laatste)
    return regels


# ---------------------------------------------------------------------------
# Zoektypen en hun velden
# ---------------------------------------------------------------------------

ZOEK_OPTIES = [
    ("naam", "Zoeken op volledige naam", "1"),
    ("gebruikersnaam", "Zoeken op gebruikersnaam", "2"),
    ("email", "Zoeken op e-mailadres", "3"),
    ("telefoon", "Zoeken op telefoonnummer", "4"),
    ("bedrijven", "Bedrijven zoeken (KVK-handelsregister)", "5"),
    ("interpol", "Interpol / FBI / Opsporingslijst", "6"),
    ("socid", "Social Media ID extraheren", "7"),
    ("adres", "Zoeken op adres (Kadaster/BAG)", "A"),
    ("kenteken", "Kentekenonderzoek (RDW)", "K"),
]

ZOEK_VELDEN = {
    "naam": [
        ("volledige_naam", "Volledige naam", "bijv. Ivan Versteegh"),
        ("voornaam", "Voornaam (optioneel)", ""),
        ("plaats", "Woonplaats (optioneel)", ""),
    ],
    "gebruikersnaam": [("gebruikersnaam", "Gebruikersnaam", "")],
    "email": [("email", "E-mailadres", "bijv. naam@domein.nl")],
    "telefoon": [("telefoon", "Telefoonnummer", "bijv. 0612345678")],
    "bedrijven": [("zoekterm", "Zoekterm (bedrijfsnaam)", "")],
    "interpol": [
        ("achternaam", "Achternaam", ""),
        ("voornaam", "Voornaam (optioneel)", ""),
    ],
    "socid": [
        ("social_url", "Social-URL of gebruikersnaam", "bijv. instagram.com/naam"),
    ],
    "adres": [("adres", "Adres of postcode", "straat + nr + plaats, of postcode + huisnr")],
    "kenteken": [("kenteken", "Kenteken", "bijv. AB-123-CD of AB123CD")],
}

NAV_ITEMS = [
    *[(zt, titel, nummer) for zt, titel, nummer in ZOEK_OPTIES],
    ("instellingen", "Instellingen (API-keys)", ""),
    ("rapporten", "Bestaande rapporten", ""),
    ("updates", "Updates", ""),
]


def _veld_id(zoektype: str, naam: str) -> str:
    return f"f_{zoektype}_{naam}"


@dataclass
class ZoekResultaat:
    """Gestructureerde uitvoer van een onderzoek (datainterface)."""

    zoektype: str
    doelwit: str
    bestandsnaam: str | None = None
    samenvatting: list[str] = field(default_factory=list)
    bronnen: list[tuple[str, str]] = field(default_factory=list)
    hits: list[dict] = field(default_factory=list)
    links: list[dict] = field(default_factory=list)


class NavigatieItem(ListItem):
    """Menuregel in de linker navigatie; waarde bepaalt waarheen."""

    def __init__(self, waarde: str | None, titel: str, nummer: str = "") -> None:
        tekst = f"[bold cyan]{nummer}[/]  {titel}" if nummer else f"[bold]{titel}[/]"
        super().__init__(Label(tekst))
        self.waarde = waarde

    def on_click(self) -> None:
        if self.waarde:
            self.app.selecteer_navigatie(self.waarde)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


class OsintTui(App):
    """OSINT Scanner — desktopversie met dashboard-layout."""

    TITLE = "OSINT Scanner"
    SUB_TITLE = "desktop"

    BINDINGS = [
        Binding("1", "zoek_naam", "Naam"),
        Binding("2", "zoek_gebruikersnaam", "Gebruikersnaam"),
        Binding("3", "zoek_email", "E-mail"),
        Binding("4", "zoek_telefoon", "Telefoon"),
        Binding("5", "zoek_bedrijven", "Bedrijven"),
        Binding("6", "zoek_interpol", "Interpol"),
        Binding("7", "zoek_socid", "Social-ID"),
        Binding("a", "zoek_adres", "Adres"),
        Binding("k", "zoek_kenteken", "Kenteken"),
        Binding("i", "instellingen", "Instellingen"),
        Binding("r", "rapporten", "Rapporten"),
        Binding("u", "updates", "Updates"),
        Binding("q", "quit", "Afsluiten"),
        Binding("ctrl+q", "quit", "Afsluiten"),
        Binding("escape", "focus_navigatie", "Menu"),
        # Ctrl-varianten: werken ook terwijl de focus in een zoekveld ligt
        # (daar maken 1..7/a/k gewoon tekst). Niet in de footer tonen.
        Binding("ctrl+1", "zoek_naam", show=False),
        Binding("ctrl+2", "zoek_gebruikersnaam", show=False),
        Binding("ctrl+3", "zoek_email", show=False),
        Binding("ctrl+4", "zoek_telefoon", show=False),
        Binding("ctrl+5", "zoek_bedrijven", show=False),
        Binding("ctrl+6", "zoek_interpol", show=False),
        Binding("ctrl+7", "zoek_socid", show=False),
    ]

    CSS = """
    Screen { background: #0f1117; }
    #hoofd { height: 1fr; }
    #zijbalk { width: 36; height: 1fr; border-right: solid #44475a; }
    #kop { color: #ff79c6; text-style: bold; margin: 1 1 0 2; }
    #nav_kop { color: #6272a4; margin: 1 1 0 2; }
    #navigatie { margin: 0 1; height: auto; }
    ListItem { padding: 0 1; }
    ListItem:hover { background: #282a36; }
    ListItem.--highlight { background: #44475a; text-style: bold; }
    #nav_update { margin: 1 1 0 2; min-height: 1; }
    #inhoud { height: 1fr; }
    #paneel_titel { color: #50fa7b; text-style: bold; margin: 1 2 0 2; }
    .zoekformulier { margin: 1 2; height: auto; display: none; }
    .zoekformulier Label { margin-top: 1; color: #8be9fd; }
    .zoekformulier Input { width: 62; }
    .btnrij { margin: 2 2; }
    .btnrij Button { margin-right: 1; }
    #btnrij_zoek { display: none; }
    #resultaat { margin: 1 2; height: auto; display: none; }
    #result_status { color: #f1fa8c; margin-bottom: 1; }
    #result_status_rij { height: 3; }
    #laad_indicatie { display: none; width: 24; margin: 0 1; }
    #result_summary { color: #ddedf9; }
    #result_bronnen_kop, #result_hits_kop, #result_links_kop, #result_log_kop {
        color: #ffb86c; margin-top: 1; display: none;
    }
    #result_bronnen { display: none; }
    #result_hits, #result_links { height: auto; max-height: 12; margin: 0 0 0 1; display: none; }
    #result_log { height: 12; border: round $accent; display: none; }
    .paneel { margin: 1 2; height: auto; display: none; }
    #paneel_start { display: block; }
    .paneel Label { color: #ddedf9; }
    #keylijst { height: auto; max-height: 14; margin: 1 0; }
    #rapportlijst { height: auto; max-height: 12; margin: 1 0; }
    #sleutel_veld { width: 62; }
    #update_log { height: 1fr; border: round $primary; margin-top: 1; }
    #sleutel_info, #rapport_info { min-height: 1; }
    """

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="hoofd"):
            with Vertical(id="zijbalk"):
                yield Label("OSINT Scanner", id="kop")
                yield Label("Navigatie", id="nav_kop")
                yield ListView(id="navigatie")
                yield Label("", id="nav_update")
            with VerticalScroll(id="inhoud"):
                yield Label("OSINT Scanner — desktop", id="paneel_titel")
                with Vertical(id="paneel_start", classes="paneel"):
                    yield Label(
                        "Kies links een zoektype om een onderzoek te starten, of open "
                        "een van de beheer-pagina's (Instellingen / Rapporten / Updates).\n\n"
                        "Resultaten streamen live naar het resultaten-scherm; daar kun je "
                        "het HTML-rapport direct openen of naar PDF exporteren.",
                        id="welkom",
                    )
                with Vertical(id="paneel_instellingen", classes="paneel"):
                    yield Label("API-keys (opgeslagen in .env)", id="sleutel_kop")
                    yield ListView(id="keylijst")
                    with Horizontal():
                        yield Input(placeholder="keynaam=waarde", id="sleutel_veld")
                        yield Button("Opslaan", id="sleutel_opslaan", variant="primary")
                        yield Button("Wissen", id="sleutel_wissen")
                    yield Label("", id="sleutel_info")
                with Vertical(id="paneel_rapporten", classes="paneel"):
                    yield Label("Bestaande rapporten (HTML + PDF)", id="rapport_kop")
                    yield ListView(id="rapportlijst")
                    with Horizontal():
                        yield Button("Openen", id="rapport_open", variant="primary")
                        yield Button("PDF", id="rapport_pdf")
                        yield Button("Verwijder", id="rapport_verwijder")
                    yield Label("", id="rapport_info")
                with Vertical(id="paneel_updates", classes="paneel"):
                    yield Label("Updates", id="update_kop")
                    yield Label("", id="update_status")
                    with Horizontal():
                        yield Button("Update installeren (git pull)", id="doe_update", variant="primary")
                    yield RichLog(id="update_log", wrap=True, markup=False)
                for zt, _titel, _nummer in ZOEK_OPTIES:
                    with Vertical(id=f"form_{zt}", classes="zoekformulier"):
                        for veld, label, ph in ZOEK_VELDEN[zt]:
                            yield Label(label)
                            yield Input(placeholder=ph, id=_veld_id(zt, veld))
                with Horizontal(id="btnrij_zoek", classes="btnrij"):
                    yield Button("Zoeken", id="zoekknop", variant="primary")
                with Vertical(id="resultaat", classes="paneel"):
                    with Horizontal(id="result_status_rij"):
                        yield Label("", id="result_status")
                        yield LoadingIndicator(id="laad_indicatie")
                    yield Label("", id="result_summary")
                    yield Label("Bronnen", id="result_bronnen_kop")
                    yield Label("", id="result_bronnen")
                    yield Label("Hits — Enter of klik opent in de browser", id="result_hits_kop")
                    yield ListView(id="result_hits")
                    yield Label("Links", id="result_links_kop")
                    yield ListView(id="result_links")
                    yield Label("Live-log", id="result_log_kop")
                    yield RichLog(id="result_log", wrap=True, markup=False)
                    with Horizontal(classes="btnrij"):
                        yield Button("Openen", id="openen", variant="primary", disabled=True)
                        yield Button("PDF", id="pdf", disabled=True)
                        yield Button("Nieuw onderzoek", id="nieuw")
        yield Footer()

    def __init__(self) -> None:
        super().__init__()
        self._actief_zoektype: str | None = None
        self._laatste_bestand: str | None = None
        self._runid = 0
        self._update_info: dict = {}
        self._onderzoek_bezig = False
        self._start_tijd = 0.0
        self._laatste_seconde = -1
        self.auto_open_en_pdf = True

    def on_mount(self) -> None:
        _activeer_geleide_console()
        sc._licentie_register_achtergrond()
        nav = self.query_one("#navigatie", ListView)
        nav.clear()
        for waarde, titel, nummer in NAV_ITEMS:
            nav.append(NavigatieItem(waarde, titel, nummer))
        self.set_interval(0.25, self._stream_regels)
        self.startonderzoek()
        self.toon_paneel("paneel_start")

    # ------------------------------------------------------------------
    # Navigatie
    # ------------------------------------------------------------------

    def selecteer_navigatie(self, waarde: str) -> None:
        self._markeer_navigatie(waarde)
        if waarde in ZOEK_VELDEN:
            self.toon_formulier(waarde)
        elif waarde == "instellingen":
            self.toon_instellingen()
        elif waarde == "rapporten":
            self.toon_rapporten()
        elif waarde == "updates":
            self.toon_updates()

    def action_zoek_naam(self) -> None:
        self.toon_formulier("naam")

    def action_zoek_gebruikersnaam(self) -> None:
        self.toon_formulier("gebruikersnaam")

    def action_zoek_email(self) -> None:
        self.toon_formulier("email")

    def action_zoek_telefoon(self) -> None:
        self.toon_formulier("telefoon")

    def action_zoek_bedrijven(self) -> None:
        self.toon_formulier("bedrijven")

    def action_zoek_interpol(self) -> None:
        self.toon_formulier("interpol")

    def action_zoek_socid(self) -> None:
        self.toon_formulier("socid")

    def action_zoek_adres(self) -> None:
        self.toon_formulier("adres")

    def action_zoek_kenteken(self) -> None:
        self.toon_formulier("kenteken")

    def action_instellingen(self) -> None:
        self.toon_instellingen()

    def action_rapporten(self) -> None:
        self.toon_rapporten()

    def action_updates(self) -> None:
        self.toon_updates()

    def action_focus_navigatie(self) -> None:
        """Focus terug naar het linkermenu (Esc), ook vanuit een zoekveld."""
        self.query_one("#navigatie", ListView).focus()

    def _markeer_navigatie(self, waarde: str) -> None:
        """Zet de highlight in het linkermenu op de huidige pagina."""
        try:
            idx = next(i for i, (w, _t, _n) in enumerate(NAV_ITEMS) if w == waarde)
        except StopIteration:
            return
        self.query_one("#navigatie", ListView).index = idx

    def _verberg_inhoud(self) -> None:
        for zt, _t, _n in ZOEK_OPTIES:
            self.query_one(f"#form_{zt}").display = False
        for pid in ("paneel_start", "paneel_instellingen", "paneel_rapporten",
                    "paneel_updates", "resultaat"):
            self.query_one(f"#{pid}").display = False
        self.query_one("#btnrij_zoek").display = False

    def _zet_titel(self, tekst: str) -> None:
        self.query_one("#paneel_titel", Label).update(tekst)

    def toon_paneel(self, paneel_id: str) -> None:
        self._verberg_inhoud()
        self.query_one(f"#{paneel_id}").display = True

    def toon_formulier(self, zoektype: str) -> None:
        self._actief_zoektype = zoektype
        self._verberg_inhoud()
        self.query_one(f"#form_{zoektype}").display = True
        self.query_one("#btnrij_zoek").display = True
        titel = next((t for z, t, _ in ZOEK_OPTIES if z == zoektype), zoektype)
        self._zet_titel(f"Zoeken — {titel}")
        eerste = ZOEK_VELDEN[zoektype][0][0]
        self.query_one(f"#{_veld_id(zoektype, eerste)}", Input).focus()

    def toon_instellingen(self) -> None:
        self._verberg_inhoud()
        self.query_one("#paneel_instellingen").display = True
        self._zet_titel("Instellingen (API-keys)")
        self.ververs_keylijst()

    def toon_rapporten(self) -> None:
        self._verberg_inhoud()
        self.query_one("#paneel_rapporten").display = True
        self._zet_titel("Bestaande rapporten")
        self.ververs_rapporten()

    def toon_updates(self) -> None:
        self._verberg_inhoud()
        self.query_one("#paneel_updates").display = True
        self._zet_titel("Updates")
        self.run_worker(self._werk_ververs_update, thread=True, exit_on_error=False)

    # ------------------------------------------------------------------
    # Instellingen (API-keys)
    # ------------------------------------------------------------------

    def ververs_keylijst(self) -> None:
        waarden = sc._lees_env()
        lijst = self.query_one("#keylijst", ListView)
        lijst.clear()
        for key, label in sc.BEKEND_KEYS:
            waarde = waarden.get(key, "")
            status = "[green]actief[/]" if waarde else "[dim]leeg[/]"
            lijst.append(ListItem(Label(f"{label}  {status}  [dim]{_masker(waarde)}[/]")))

    def _sleutel_opslaan(self) -> None:
        veld = self.query_one("#sleutel_veld", Input)
        regel = veld.value.strip()
        if "=" not in regel:
            self.query_one("#sleutel_info", Label).update("[red]Ongeldig formaat (key=waarde).[/]")
            return
        key, _, waarde = regel.partition("=")
        waarden = sc._lees_env()
        waarden[key.strip()] = waarde.strip()
        sc._schrijf_env(waarden)
        sc._herlaad_keys()
        veld.value = ""
        self.query_one("#sleutel_info", Label).update("[green]Opgeslagen in .env — meteen actief.[/]")
        self.ververs_keylijst()

    def _sleutel_wissen(self) -> None:
        geselecteerd = self.query_one("#keylijst", ListView).index
        if geselecteerd is None or not (0 <= geselecteerd < len(sc.BEKEND_KEYS)):
            self.query_one("#sleutel_info", Label).update("[dim]Selecteer eerst een key.[/]")
            return
        key = sc.BEKEND_KEYS[geselecteerd][0]
        waarden = sc._lees_env()
        waarden[key] = ""
        sc._schrijf_env(waarden)
        sc._herlaad_keys()
        self.query_one("#sleutel_info", Label).update(f"[green]'{key}' gewist.[/]")
        self.ververs_keylijst()

    # ------------------------------------------------------------------
    # Rapporten
    # ------------------------------------------------------------------

    def _rapporten_lijst(self) -> list[tuple[str, int]]:
        rapporten = sorted(
            (p for p in os.listdir(".")
             if p.startswith("osint_rapport_") and p.endswith((".html", ".pdf"))),
            key=os.path.getmtime,
            reverse=True,
        )
        return [(p, os.path.getsize(p) // 1024) for p in rapporten]

    def ververs_rapporten(self) -> None:
        self._rapporten_data = self._rapporten_lijst()
        lijst = self.query_one("#rapportlijst", ListView)
        lijst.clear()
        if not self._rapporten_data:
            lijst.append(ListItem(Label("[dim]Geen rapporten gevonden.[/]")))
            return
        for pad, kb in self._rapporten_data:
            soort = "[cyan]PDF[/]" if pad.endswith(".pdf") else "[green]HTML[/]"
            lijst.append(ListItem(Label(f"{soort}  {pad}  [dim]({kb} KB)[/]")))

    def _rapport_actie(self, actie: str) -> None:
        geselecteerd = self.query_one("#rapportlijst", ListView).index
        if not self._rapporten_data or geselecteerd is None or not (0 <= geselecteerd < len(self._rapporten_data)):
            return
        pad = self._rapporten_data[geselecteerd][0]
        if actie == "open":
            webbrowser.open("file://" + os.path.abspath(pad))
        elif actie == "pdf":
            if pad.endswith(".pdf"):
                self.query_one("#rapport_info", Label).update("[yellow]Dit is al een PDF.[/]")
                return
            zelf = self.query_one("#rapport_info", Label)
            self.run_worker(lambda: self._werk_pdf(pad, zelf), thread=True, exit_on_error=False)
        else:
            os.remove(pad)
            self.ververs_rapporten()
            self.query_one("#rapport_info", Label).update(f"[green]'{pad}' verwijderd.[/]")

    # ------------------------------------------------------------------
    # Update-status en git pull
    # ------------------------------------------------------------------

    def startonderzoek(self) -> None:
        """Update-check in de achtergrond; resultaat verschijnt in de zijbalk."""

        def werk() -> None:
            try:
                self._update_info = sc._check_update(force=True)
            except Exception as exc:
                self._update_info = {"melding": f"update-check mislukt: {exc}"}
            self.call_from_thread(self._toon_nav_update)

        self.run_worker(werk, thread=True, exit_on_error=False)

    def _toon_nav_update(self) -> None:
        info = self._update_info
        label = self.query_one("#nav_update", Label)
        if info.get("update_beschikbaar"):
            label.update("[bold yellow]↑ Update beschikbaar — druk U[/]")
        elif info.get("nieuwste_versie"):
            label.update(f"[dim]Server versie {info['nieuwste_versie']} — actueel[/]")
        elif info.get("melding"):
            label.update(f"[dim]{info['melding']}[/]")

    def _werk_ververs_update(self) -> None:
        try:
            self._update_info = sc._check_update(force=False)
        except Exception as exc:
            self._update_info = {"melding": f"update-check mislukt: {exc}"}
        self.call_from_thread(self._toon_update_paneel)

    def _toon_update_paneel(self) -> None:
        info = self._update_info
        status = self.query_one("#update_status", Label)
        if info.get("update_beschikbaar"):
            status.update("[bold yellow]Er is een nieuwere versie beschikbaar.[/]")
        elif info.get("nieuwste_versie"):
            status.update(f"[dim]Versie {info['nieuwste_versie']} — actueel.[/]")
        elif info.get("melding"):
            status.update(f"[dim]{info['melding']}[/]")

    def _doe_update(self) -> None:
        log = self.query_one("#update_log", RichLog)
        log.clear()
        log.write("git pull --ff-only uitvoeren…")
        self.run_worker(lambda: self._werk_update(log), thread=True, exit_on_error=False)

    def _werk_update(self, log: RichLog) -> None:
        try:
            pr = subprocess.run(
                ["git", "-C", sc.SCANNER_DIR, "pull", "--ff-only"],
                capture_output=True, text=True, timeout=180,
            )
            uitvoer = (pr.stdout + pr.stderr).strip()
            if pr.returncode == 0:
                for regel in uitvoer.splitlines() or ["Up-to-date."]:
                    self.call_from_thread(log.write, regel)
                self.call_from_thread(
                    log.write, "✔ Klaar — herstart de scanner om de nieuwe versie te laden."
                )
            else:
                self.call_from_thread(log.write, f"[red]{uitvoer or 'pull mislukt'}[/]")
        except Exception as exc:
            self.call_from_thread(log.write, f"[red]Fout: {exc}[/]")

    # ------------------------------------------------------------------
    # Onderzoek starten (worker) + stream
    # ------------------------------------------------------------------

    def _stream_regels(self) -> None:
        try:
            log = self.query_one("#result_log", RichLog)
        except Exception:
            return
        for regel in self.nieuwe_regels():
            try:
                log.write(regel)
            except Exception:
                pass
        if self._onderzoek_bezig:
            sec = int(time.monotonic() - self._start_tijd)
            if sec != self._laatste_seconde:
                self._laatste_seconde = sec
                m, s = divmod(sec, 60)
                try:
                    self.query_one("#result_status", Label).update(
                        f"[bold green]Onderzoek bezig… {m}:{s:02d} — even geduld[/]"
                    )
                except Exception:
                    pass
        try:
            log.scroll_end(animate=False)
        except Exception:
            pass

    def nieuwe_regels(self) -> list[str]:
        data = _geleide_buffer.lees()
        if not data:
            return []
        regels = _schoone_regels(data)
        return regels

    def start_onderzoek(self) -> None:
        zt = self._actief_zoektype
        if not zt or zt not in ZOEK_VELDEN:
            return
        waarden: dict[str, str] = {}
        for inp in self.query(Input):
            if inp.id and inp.id.startswith(f"f_{zt}_"):
                waarden[inp.id[len(f"f_{zt}_"):]] = inp.value.strip()
        first = ZOEK_VELDEN[zt][0][0]
        if not waarden.get(first):
            knop = self.query_one("#zoekknop", Button)
            knop.label = "⚠ vul eerst iets in"
            self.query_one(f"#{_veld_id(zt, first)}", Input).focus()
            return
        self._runid += 1
        rid = self._runid
        self._actief_zoektype = zt
        self._laatste_bestand = None
        self._verberg_inhoud()
        self.query_one("#resultaat").display = True
        self._zet_titel(f"Zoeken — {next((t for z, t, _ in ZOEK_OPTIES if z == zt), zt)}")
        status = self.query_one("#result_status", Label)
        status.update("[bold green]Onderzoek bezig… — even geduld[/]")
        self.query_one("#laad_indicatie", LoadingIndicator).display = True
        self.query_one("#result_log_kop", Label).update(
            "Live-log — het systeem is bezig, dit kan een paar minuten duren"
        )
        self._onderzoek_bezig = True
        self._start_tijd = time.monotonic()
        self._laatste_seconde = -1
        self.query_one("#result_summary", Label).update("")
        self.query_one("#result_bronnen", Label).update("")
        self.query_one("#result_bronnen_kop").display = False
        self.query_one("#result_hits_kop").display = False
        self.query_one("#result_links_kop").display = False
        self.query_one("#result_log_kop").display = True
        hits = self.query_one("#result_hits", ListView)
        hits.clear()
        hits.display = True
        links = self.query_one("#result_links", ListView)
        links.clear()
        links.display = True
        self.query_one("#result_log", RichLog).display = True
        self.query_one("#result_log", RichLog).clear()
        self.query_one("#openen", Button).disabled = True
        self.query_one("#pdf", Button).disabled = True
        self.run_worker(
            lambda: self._werk_onderzoek(rid, zt, waarden),
            thread=True,
            group="onderzoek",
            exclusive=True,
            exit_on_error=False,
        )

    def _werk_onderzoek(self, rid: int, zoektype: str, waarden: dict) -> None:
        try:
            data = self._voer_zoek(zoektype, waarden)
            self.call_from_thread(self._onderzoek_klaar, rid, data)
        except Exception as exc:
            self.call_from_thread(self._onderzoek_gefaald, rid, f"Onverwachte fout bij het onderzoek: {exc}")

    def _onderzoek_klaar(self, rid: int, data: ZoekResultaat) -> None:
        if rid != self._runid:
            return
        self._onderzoek_bezig = False
        self.query_one("#laad_indicatie", LoadingIndicator).display = False
        self.query_one("#result_log_kop", Label).update("Live-log")
        self._laatste_bestand = data.bestandsnaam
        status = self.query_one("#result_status", Label)
        if data.bestandsnaam:
            status.update(f"[green]Klaar — rapport: {os.path.basename(data.bestandsnaam)}[/]")
        else:
            status.update("[green]Klaar.[/]")
        samenvatting = data.samenvatting or ["Geen resultaten."]
        self.query_one("#result_summary", Label).update("\n".join(samenvatting))
        if data.bronnen:
            self.query_one("#result_bronnen", Label).update(
                "\n".join(f"  • {l}: {v}" for l, v in data.bronnen)
            )
            self.query_one("#result_bronnen").display = True
            self.query_one("#result_bronnen_kop").display = True
        if data.hits:
            hv = self.query_one("#result_hits", ListView)
            hv.clear()
            for h in data.hits[:60]:
                item = ListItem(Label(self._hit_tekst(h)))
                item.data_url = h.get("url", "")
                hv.append(item)
            self.query_one("#result_hits_kop").display = True
        if data.links:
            lv = self.query_one("#result_links", ListView)
            lv.clear()
            for link in data.links[:30]:
                item = ListItem(Label(f"[dim]↗[/] {link.get('label', link.get('url', ''))}"))
                item.data_url = link.get("url", "")
                lv.append(item)
            self.query_one("#result_links_kop").display = True
        self.query_one("#result_log_kop").display = True
        self.query_one("#openen", Button).disabled = not data.bestandsnaam
        self.query_one("#pdf", Button).disabled = not data.bestandsnaam

    def _onderzoek_gefaald(self, rid: int, melding: str) -> None:
        if rid != self._runid:
            return
        self._onderzoek_bezig = False
        self.query_one("#laad_indicatie", LoadingIndicator).display = False
        self.query_one("#result_log_kop", Label).update("Live-log")
        self.query_one("#result_status", Label).update(f"[red]{melding}[/]")

    @staticmethod
    def _hit_tekst(h: dict) -> str:
        score = h.get("score")
        titel = (h.get("titel") or "").strip() or "?" 
        url = h.get("url") or ""
        if score:
            return f"[cyan]{score}[/]  {titel}  [dim]{url[:70]}[/]"
        return f"{titel}  [dim]{url[:70]}[/]"

    def _wk_pdf(self) -> None:
        bestand = self._laatste_bestand
        if not bestand:
            return
        self.query_one("#result_status", Label).update("[white]PDF-export loopt…[/]")
        self.run_worker(lambda: self._werk_pdf(bestand, self.query_one("#result_status", Label)),
                        thread=True, exit_on_error=False)

    @staticmethod
    def _werk_pdf(html_pad: str, status_label) -> None:
        from textual.app import App

        app = status_label.app
        pdf, fout = sc.print_rapport_naar_pdf(html_pad)
        if pdf:
            melding = f"[green]PDF: {os.path.basename(pdf)}[/]"
            app.call_from_thread(status_label.update, melding)
            if app.auto_open_en_pdf:
                app.call_from_thread(webbrowser.open, "file://" + os.path.abspath(pdf))
        else:
            app.call_from_thread(status_label.update, f"[yellow]{fout}[/]")

    # ------------------------------------------------------------------
    # Datainterface: engine -> ZoekResultaat
    # ------------------------------------------------------------------

    def _voer_zoek(self, zoektype: str, w: dict) -> ZoekResultaat:
        if zoektype == "naam":
            return self._voer_zoekt("naam", w, "1")
        if zoektype in ("gebruikersnaam", "email", "telefoon"):
            return self._voer_zoekt(zoektype, w, "1")
        if zoektype == "bedrijven":
            return self._voer_bedrijven(w)
        if zoektype == "adres":
            return self._voer_adres(w)
        if zoektype == "kenteken":
            return self._voer_kenteken(w)
        if zoektype == "interpol":
            return self._voer_interpol(w)
        if zoektype == "socid":
            return self._voer_socid(w)
        raise ValueError(f"onbekend zoektype: {zoektype}")

    @staticmethod
    def _voer_zoekt(zoektype: str, w: dict, _v: str) -> ZoekResultaat:
        if zoektype == "naam":
            naam = w["volledige_naam"]
            voornaam = w.get("voornaam", "")
            if not voornaam and " " in naam:
                voornaam = naam.rsplit(" ", 1)[0]
            plaats = w.get("plaats", "")
            volledige = naam
            if voornaam and voornaam.lower() not in naam.lower():
                volledige = f"{voornaam} {naam}".strip()
            dorks = sc.dorks_naam(volledige, plaats)
            best, rapport, extra = sc.voer_onderzoek_uit(
                "naam", volledige, dorks,
                plaats=plaats, voornaam=voornaam,
                return_data=True, open_browser_prompt=False,
            )
            return _data_uit_rapport("naam", volledige, best, rapport, extra)
        if zoektype == "gebruikersnaam":
            user = w["gebruikersnaam"].lstrip("@")
            best, rapport, extra = sc.voer_onderzoek_uit(
                "username", user, sc.dorks_username(user),
                return_data=True, open_browser_prompt=False,
            )
            return _data_uit_rapport("gebruikersnaam", user, best, rapport, extra)
        if zoektype == "email":
            em = w["email"]
            best, rapport, extra = sc.voer_onderzoek_uit(
                "email", em, sc.dorks_email(em),
                return_data=True, open_browser_prompt=False,
            )
            return _data_uit_rapport("email", em, best, rapport, extra)
        tel = w["telefoon"]
        tel_int = "+31" + tel[1:] if tel.startswith("0") else tel
        best, rapport, extra = sc.voer_onderzoek_uit(
            "telefoon", tel, sc.dorks_telefoon(tel, tel_int),
            return_data=True, open_browser_prompt=False,
        )
        return _data_uit_rapport("telefoon", tel, best, rapport, extra)

    @staticmethod
    def _voer_bedrijven(w: dict) -> ZoekResultaat:
        term = w["zoekterm"]
        r = sc.openkvk_bedrijven(term)
        sc.console.print(f"[bold]{r['melding']}[/]")
        bronnen = []
        for b in r["bedrijven"][:25]:
            sc.console.print(f"  {b['handelsnaam']}  (kvk {b['dossiernummer']})")
            bronnen.append((b["handelsnaam"], f"kvk {b['dossiernummer']}"))
        if not r["bedrijven"]:
            sc.console.print("[dim]Geen bedrijven gevonden.[/]")
        best = sc.genereer_dashboard("bedrijven", term, {}, {"openkvk": r}, open_browser=False)
        return ZoekResultaat("bedrijven", term, best, [r["melding"]], bronnen)

    @staticmethod
    def _voer_adres(w: dict) -> ZoekResultaat:
        adres = w["adres"]
        r = sc.bag_adres_zoeken(adres)
        samenvatting = []
        links = []
        if r.get("status") != "ok":
            melding = r.get("fout") or "adres niet gevonden"
            sc.console.print(f"[bold yellow]{melding}[/]")
            best = sc.genereer_dashboard("adres", adres, {}, {"bag": r}, open_browser=False)
            return ZoekResultaat("adres", adres, best, [melding])
        a = r["adres"]
        sc.console.print(f"[bold]Kadaster / BAG - {a.get('weergavenaam')}[/]")
        for label, veld in [
            ("Gemeente", "gemeente"), ("Provincie", "provincie"),
            ("Buurt", "buurt"), ("Wijk", "wijk"), ("Waterschap", "waterschap"),
        ]:
            waarde = a.get(veld)
            if waarde:
                samenvatting.append(f"{label}: {waarde}")
                sc.console.print(f"  {label}: {waarde}")
        if a.get("perceel"):
            samenvatting.append("Perceel: " + ", ".join(a["perceel"]))
        if a.get("bouwjaar"):
            regel = (f"Bouwjaar: {a['bouwjaar']} | Oppervlakte: {a.get('oppervlakte')} m² | "
                     f"Gebruiksdoel: {a.get('gebruiksdoel')}")
            samenvatting.append(regel)
            sc.console.print(f"  {regel}")
        if a.get("coord_ll"):
            samenvatting.append(f"Coördinaten: {a['coord_ll']}")
        (a.get("links") or {})

        br = a.get("links") or {}
        for label, veld in [
            ("BAG-viewer (kaart)", "bag_viewer"), ("Google Maps", "google_maps"),
            ("OpenStreetMap", "openstreetmap"), ("Wijkagent (politie.nl)", "politie_wijkagent"),
        ]:
            url = br.get(veld)
            if url:
                links.append({"label": label, "url": url})
        for p in a.get("politie") or []:
            naam = p.get("naam") or "Politiebureau"
            adress = " ".join(filter(None, [p.get("adres"), p.get("postcode"), p.get("plaats")]))
            if p.get("url"):
                links.append({"label": f"{naam} — {adress or 'adres onbekend'}", "url": p["url"]})
        best = sc.genereer_dashboard("adres", adres, {}, {"bag": r}, open_browser=False)
        return ZoekResultaat("adres", adres, best, samenvatting, [], [], links)

    @staticmethod
    def _voer_kenteken(w: dict) -> ZoekResultaat:
        kenteken = w["kenteken"]
        rdw = sc.rdw_kenteken_zoek(kenteken)
        samenvatting = []
        if rdw.get("status") == "ok" and rdw.get("voertuig"):
            v = rdw["voertuig"]
            sc.console.print(f"[bold]RDW - {rdw.get('kenteken')}[/]")
            for label, waarde in [
                ("Merk", v.get("merk")), ("Handelsbenaming", v.get("handelsbenaming")),
                ("Bouwjaar", sc._rdw_datum(v.get("bouwjaar"))), ("Brandstof", v.get("brandstof")),
                ("CO2-uitstoot", v.get("co2")), ("APK-vervaldatum", sc._rdw_datum(v.get("vervaldatum"))),
                ("Kleur", v.get("kleur")), ("Voertuigsoort", v.get("voertuigsoort")),
                ("Categorie", v.get("categorie")), ("Deuren", v.get("aantal_deuren")),
                ("Zitplaatsen", v.get("aantal_zitplaatsen")), ("Massa ledig", v.get("massa_ledig")),
            ]:
                if waarde:
                    samenvatting.append(f"{label}: {waarde}")
                    sc.console.print(f"  {label}: {waarde}")
            best = sc.genereer_dashboard("kenteken", rdw.get("kenteken") or kenteken, {}, {"rdw": rdw}, open_browser=False)
            return ZoekResultaat("kenteken", kenteken, best, samenvatting)
        melding = rdw.get("fout") or "geen voertuig gevonden"
        sc.console.print(f"[yellow]{melding}[/]")
        return ZoekResultaat("kenteken", kenteken, None, [melding])

    @staticmethod
    def _voer_interpol(w: dict) -> ZoekResultaat:
        achternaam = w["achternaam"]
        voornaam = w.get("voornaam", "")
        ri = sc.interpol_zoek(achternaam, voornaam)
        rf = sc.fbi_wanted_zoek(achternaam, voornaam)
        ro = sc.opsporingslijst_zoek(achternaam, voornaam)
        samenvatting = []
        links = []
        if ri.get("status") == "geblokkeerd":
            sc.console.print(f"[yellow]{ri['melding']}[/]")
            samenvatting.append(ri["melding"])
        elif ri["red"] or ri["yellow"]:
            if ri["red"]:
                sc.console.print(f"[bold red]Red Notices ({len(ri['red'])}):[/]")
                for n in ri["red"][:10]:
                    sc.console.print(f"  {n['naam']}  ({n['nationaliteit']}, geb. {n['geboortedatum']})")
                    sc.console.print(f"     {n['url']}")
                    links.append({"label": f"Red notice — {n['naam']}", "url": n["url"]})
            if ri["yellow"]:
                sc.console.print(f"[bold yellow]Yellow Notices ({len(ri['yellow'])}):[/]")
                for n in ri["yellow"][:10]:
                    sc.console.print(f"  {n['naam']}  ({n['nationaliteit']}, geb. {n['geboortedatum']})")
                    sc.console.print(f"     {n['url']}")
                    links.append({"label": f"Yellow notice — {n['naam']}", "url": n["url"]})
        else:
            sc.console.print(f"[dim]{ri.get('melding', 'Geen notices.')}[/]")
        if rf.get("status") == "geblokkeerd":
            sc.console.print(f"[yellow]{rf['melding']}[/]")
        else:
            if rf["gezocht"]:
                for n in rf["gezocht"][:10]:
                    links.append({"label": f"FBI gezocht — {n['naam']}", "url": n.get("url", "")})
            if rf["vermist"]:
                for n in rf["vermist"][:10]:
                    links.append({"label": f"FBI vermist — {n['naam']}", "url": n.get("url", "")})
        if ro:
            for hit in ro[:10]:
                links.append({"label": f"Opsporingslijst — {hit['titel'][:50]}", "url": hit["link"]})
        if ri.get("red") or ri.get("yellow"):
            samenvatting.append(f"Interpol: {len(ri['red'])} red / {len(ri['yellow'])} yellow")
        if rf["gezocht"] or rf["vermist"]:
            samenvatting.append(f"FBI: {len(rf['gezocht'])} gezocht / {len(rf['vermist'])} vermist")
        if ro:
            samenvatting.append(f"Nationale Opsporingslijst: {len(ro)} hits")
        if not samenvatting:
            samenvatting.append("Geen notificaties of opsporingslijst-hits gevonden.")
        best = sc.genereer_dashboard(
            "interpol", achternaam, {},
            {"interpol": ri, "fbi": rf, "opsporingslijst": ro},
            open_browser=False,
        )
        return ZoekResultaat("interpol", achternaam, best, samenvatting, [], [], links)

    @staticmethod
    def _voer_socid(w: dict) -> ZoekResultaat:
        id_input = w["social_url"]
        gevonden = []
        if "://" not in id_input:
            u = id_input.lstrip("@")
            for platform_url, pname in [
                (f"https://www.instagram.com/{u}/", "Instagram"),
                (f"https://www.youtube.com/@{u}", "YouTube"),
                (f"https://twitter.com/{u}", "Twitter"),
                (f"https://www.tiktok.com/@{u}", "TikTok"),
                (f"https://www.facebook.com/{u}", "Facebook"),
            ]:
                r = sc.zoek_social_media_ids([{"url": platform_url, "platform": pname, "bron": "handmatig"}])
                if r:
                    _print_socid(r[0])
                    gevonden.append(r[0])
        else:
            r = sc.zoek_social_media_ids([{"url": id_input, "platform": "Onbekend", "bron": "handmatig"}])
            if r:
                _print_socid(r[0])
                gevonden.append(r[0])
        samenvatting = [f"ID's gevonden: {len(gevonden)}"]
        links: list[dict] = []
        for p in gevonden:
            url = p.get("url") or ""
            if url:
                links.append({"label": f"{p.get('platform', 'Onbekend')} — {url}", "url": url})
            gevonden_ids = _socid_gegevens(p)
            if gevonden_ids:
                samenvatting.extend(gevonden_ids)
        if not gevonden:
            samenvatting.append(
                "Kon geen ID extraheren. Mogelijk geen profiel gevonden of platform-/CAPTCHA-beperking."
            )
            sc.console.print("[yellow]Kon geen ID extraheren (platform- of CAPTCHA-beperking).[/]")
        return ZoekResultaat("socid", id_input, None, samenvatting, [], [], links)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    @on(ListView.Selected, "#navigatie")
    def _nav_gekozen(self, event: ListView.Selected) -> None:
        waarde = getattr(event.item, "waarde", None)
        if waarde:
            self.selecteer_navigatie(waarde)

    @on(ListView.Selected, "#result_hits")
    def _hit_gekozen(self, event: ListView.Selected) -> None:
        url = getattr(event.item, "data_url", "")
        if url:
            webbrowser.open(url)

    @on(ListView.Selected, "#result_links")
    def _link_gekozen(self, event: ListView.Selected) -> None:
        url = getattr(event.item, "data_url", "")
        if url:
            webbrowser.open(url)

    @on(Input.Submitted)
    def _input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "sleutel_veld":
            self._sleutel_opslaan()
            return
        if event.input.id and event.input.id.startswith(f"f_{self._actief_zoektype}_"):
            self.start_onderzoek()

    @on(Button.Pressed)
    def _knop_gedrukt(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "zoekknop":
            self.start_onderzoek()
        elif bid == "openen":
            if self._laatste_bestand:
                webbrowser.open("file://" + os.path.abspath(self._laatste_bestand))
        elif bid == "pdf":
            self._wk_pdf()
        elif bid == "nieuw":
            if self._actief_zoektype:
                self.toon_formulier(self._actief_zoektype)
        elif bid == "sleutel_opslaan":
            self._sleutel_opslaan()
        elif bid == "sleutel_wissen":
            self._sleutel_wissen()
        elif bid == "rapport_open":
            self._rapport_actie("open")
        elif bid == "rapport_pdf":
            self._rapport_actie("pdf")
        elif bid == "rapport_verwijder":
            self._rapport_actie("verwijder")
        elif bid == "doe_update":
            self._doe_update()


def _masker(waarde: str) -> str:
    if not waarde:
        return "—"
    return waarde[:3] + "…" + waarde[-2:] if len(waarde) > 6 else "****"


def _socid_details(p: dict) -> dict:
    """Geeft de werkelijk verrijkte profieldata (onder 'details')."""
    return p.get("details") or {}


def _socid_socid_dict(p: dict) -> dict:
    """socid-extractor gegevens indien aanwezig."""
    return _socid_details(p).get("socid") or {}


def _socid_gegevens(p: dict) -> list[str]:
    """Leesbare regels uit de verrijkte profieldata (details / socid / ids_data)."""
    regels: list[str] = []
    platform = p.get("platform", "Onbekend")
    url = p.get("url", "")
    kop = f"{platform}  {url}"
    d = _socid_details(p)
    intern_top = _socid_socid_dict(p).get("internal_ids") or {}
    # ids_data (Maigret) en socid-internal_ids zijn de echte ID-waardes
    ids_data = d.get("ids_data") or {}
    id_regels = []
    for bron_dict in (ids_data, intern_top):
        for id_naam, id_waarde in bron_dict.items():
            if id_waarde not in (None, "", 0, False):
                id_regels.append(f"  · {id_naam}: {id_waarde}")
    if p.get("id"):
        id_regels.insert(0, f"  [bold]id: {p['id']}[/]")
    if id_regels:
        regels.append(kop)
        regels.extend(id_regels)
        return regels
    # Geen ID's gevonden maar wel profiel -> toon details zonder ID
    s = _socid_socid_dict(p)
    details = [
        s.get("fullname"), s.get("name"), s.get("display_name"), s.get("is_verified"),
        s.get("followers_count"), s.get("created_at"),
        d.get("fullname"), d.get("name"), d.get("display_name"),
        d.get("followers_count"), d.get("created_at"), d.get("is_verified"),
    ]
    if any(v not in (None, "", 0, False) for v in details):
        regels.append(kop)
    return regels


def _print_socid(p: dict) -> None:
    """Print de ID-extractie naar de live-log, vergelijkbaar met de CLI (_toon_een_id)."""
    sc.console.print(f"[bold cyan]{p.get('platform', 'Onbekend')}[/]  {p.get('url', '')}")
    d = _socid_details(p)
    sc.console.print(f"  ID: [bold cyan]{p.get('id', '-')}[/]")
    sc.console.print(f"  Bron: {p.get('bron', '-')}")
    s = _socid_socid_dict(p)
    for veld in ("fullname", "name", "display_name", "bio", "tagline", "created_at",
                 "gender", "country", "city", "location", "is_verified", "is_private",
                 "is_business", "followers_count", "following_count", "media_count",
                 "website", "website_url"):
        waarde = s.get(veld)
        if waarde not in (None, "", 0, False, "None"):
            sc.console.print(f"   {veld}: {str(waarde)[:120]}")
    ids_data = d.get("ids_data") or {}
    if ids_data:
        for id_naam, id_waarde in ids_data.items():
            if id_waarde not in (None, "", 0, False):
                sc.console.print(f"   [cyan]{id_naam}: {str(id_waarde)[:120]}[/]")
    intern = _socid_socid_dict(p).get("internal_ids") or {}
    for id_naam, id_waarde in intern.items():
        sc.console.print(f"   [cyan]{id_naam}: {id_waarde}[/]")
    ext = _socid_socid_dict(p).get("external_links") or []
    if ext:
        sc.console.print(f"   extern: {', '.join(str(l)[:60] for l in ext[:5])}")


def _data_uit_rapport(zoektype, doelwit, best, rapport, extra) -> ZoekResultaat:
    """Bouwt een ZoekResultaat uit de gestructureerde (rapport, extra)-uitvoer."""
    bronnen = [(p, str(len(d.get("hits", [])))) for p, d in rapport.items()]
    hits = [
        {"platform": p, "titel": h.get("titel", ""), "url": h.get("link", ""), "score": h.get("score", 0)}
        for p, d in rapport.items()
        for h in d.get("hits", [])
    ]
    samenvatting: list[str] = []
    tv = extra.get("telefoon_verrijking") or {}
    if tv.get("melding"):
        samenvatting.append(tv["melding"])
    else:
        tv_onderdelen = []
        if tv.get("geldig"):
            tv_onderdelen.append(f"Geldig ({tv.get('genormaliseerd') or '?'})")
        else:
            tv_onderdelen.append("Ongeldig nummer")
        if tv.get("land"):
            tv_onderdelen.append(f"Land: {tv['land']}")
        if tv.get("netwerk"):
            tv_onderdelen.append(f"Netwerk: {tv['netwerk']}")
        if tv.get("lijn_type"):
            tv_onderdelen.append(f"Lijn: {tv['lijn_type']}")
        if tv.get("tijdzone"):
            tv_onderdelen.append(f"Tijdzone: {tv['tijdzone']}")
        if tv.get("whatsapp") is not None:
            tv_onderdelen.append("WhatsApp actief" if tv["whatsapp"] else "WhatsApp niet gevonden")
        if tv.get("telegram") is not None:
            tv_onderdelen.append("Telegram actief" if tv["telegram"] else "Telegram niet gevonden")
        if tv_onderdelen:
            samenvatting.append("Telefoon-verrijking: " + " | ".join(tv_onderdelen))
    wp = extra.get("web_presence") or {}
    if "score" in wp:
        samenvatting.append(
            f"Web-presence-score: {wp['score']}  ({len(wp.get('socials', []))} platforms / "
            f"{wp.get('totaal_resultaten', 0)} resultaten)"
        )
    hibp = extra.get("hibp") or {}
    if hibp.get("status"):
        labels = {"schoon": "geen lekken", "getroffen": "IN LEKKEN!", "overgeslagen": "overgeslagen", "fout": "fout"}
        samenvatting.append(f"HaveIBeenPwned: {labels.get(hibp['status'], hibp['status'])}")
    gh = extra.get("github") or {}
    if "profielen" in gh:
        samenvatting.append(f"GitHub: {len(gh['profielen'])} profielen")
    hh = extra.get("holehe") or {}
    if hh.get("status") == "ok":
        onbekend = sum(1 for s_ in hh.get("sites", []) if s_["rate_limit"])
        label = f"{hh.get('gevonden', 0)} accounts"
        if onbekend:
            label += f", {onbekend} onbekend"
        samenvatting.append(f"Sites-check (holehe): {label}")
    elif hh.get("melding"):
        samenvatting.append(f"Sites-check (holehe): {hh['melding']}")
    if "social" in extra:
        samenvatting.append(f"Social-profielen: {len(extra['social'])}")
    sid = extra.get("social_ids")
    if sid is not None:
        gevonden = [x for x in sid if x.get("id")]
        samenvatting.append(f"Social-ID's: {len(gevonden)}/{len(sid)} geextraheerd")
    mr = extra.get("maigret") or {}
    if mr.get("sites") is not None:
        samenvatting.append(f"Maigret: {len(mr['sites'])} profielen ({mr.get('totaal_gezocht', 0)} sites onderzocht)")
    interp = extra.get("interpol") or {}
    if interp.get("red") or interp.get("yellow"):
        samenvatting.append(f"Interpol: {len(interp['red'])} red / {len(interp['yellow'])} yellow")
    fbi = extra.get("fbi") or {}
    if fbi.get("gezocht") or fbi.get("vermist"):
        samenvatting.append(f"FBI: {len(fbi['gezocht'])} gezocht / {len(fbi['vermist'])} vermist")
    ol = extra.get("opsporingslijst") or []
    if ol:
        samenvatting.append(f"Opsporingslijst: {len(ol)} hits")
    if not samenvatting:
        samenvatting.append("Geen extra's gevonden; alleen de web-zoekresultaten.")
    links = [
        {"label": f"{s.get('platform', '')} — {s.get('url', '')}", "url": s.get("url", "")}
        for s in (wp.get("socials") or [])
        if s.get("url")
    ]
    if tv.get("telegram") is True and tv.get("telegram_url"):
        links.append({"label": f"Telegram — {tv['genormaliseerd']}", "url": tv["telegram_url"]})
    if tv.get("whatsapp_url"):
        links.append({"label": f"WhatsApp — {tv['genormaliseerd']}", "url": tv["whatsapp_url"]})
    return ZoekResultaat(zoektype, doelwit, best, samenvatting, bronnen, hits, links)


if __name__ == "__main__":
    from pathlib import Path
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    OsintTui().run()