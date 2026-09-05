#!/usr/bin/env python3
"""
OSINT Scanner — Textual desktop-versie.

Hergebruikt de zoeklogica + HTML-dashboardgeneratie uit osint_scanner.py,
maar vervangt de CLI-menu-interface door een op muis- en pijltoetsen bedienbare
Textual-app (elevatie t.o.v. het Rich-menu).

Start:  python3 osint_tui.py        (of via start-tui.sh / start-tui.bat)

De engine-functies gebruiken een rich-console; die wordt gekaapt en naar een
in-memory buffer geleid, zodat de output live in de resultaten-view te
streamen is zonder de Textual-weergave te vervuilen.
"""

from __future__ import annotations

import io
import os
import re
import subprocess
import threading
import webbrowser

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
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


# ---------------------------------------------------------------------------
# Screens
# ---------------------------------------------------------------------------


class ZoekOptieItem(ListItem):
    def __init__(self, zoektype: str, titel: str, nummer: str) -> None:
        super().__init__(Label(f"[bold cyan]{nummer}[/]  {titel}"))
        self.zoektype = zoektype

    def on_click(self) -> None:
        self.app.ga_naar_zoeken(self.zoektype)


class HoofdScherm(Screen):
    """Hoofdmenu: muis- en pijltoets-beweegbare lijst met zoekopties."""

    update_tekst: reactive[str] = reactive("")
    SNELTOETSEN = {
        "1": "naam", "2": "gebruikersnaam", "3": "email", "4": "telefoon",
        "5": "bedrijven", "6": "interpol", "7": "socid", "a": "adres", "k": "kenteken",
    }
    BINDINGS = [
        Binding("u", "app.update", "Update"),
        Binding("i", "app.instellingen", "Instellingen"),
        Binding("r", "app.rapporten", "Rapporten"),
        Binding("q", "quit", "Afsluiten"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("OSINT Scanner", id="kop")
        items = [
            ZoekOptieItem(z, t, n) for z, t, n in ZOEK_OPTIES
        ]
        yield ListView(*items, id="menu")
        yield Label("", id="update_banner")
        yield Footer()

    def watch_update_tekst(self, nieuwe: str) -> None:
        b = self.query_one("#update_banner", Label)
        b.update(nieuwe)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        item = event.item
        if isinstance(item, ZoekOptieItem):
            self.app.ga_naar_zoeken(item.zoektype)

    def on_key(self, event) -> None:
        zoektype = self.SNELTOETSEN.get(event.key.lower())
        if zoektype:
            event.stop()
            self.app.ga_naar_zoeken(zoektype)

    def on_mount(self) -> None:
        self.app.title = "OSINT Scanner"
        self.app.instantie_banner(self)
        self.app.startonderzoek()


class ZoekScherm(Screen):
    """Invoerformulier voor een zoektype; Enter start de zoektocht."""

    BINDINGS = [
        Binding("escape", "terug", "Terug"),
        Binding("ctrl+s", "start", "Zoek"),
    ]

    def __init__(self, zoektype: str) -> None:
        super().__init__()
        self.zoektype = zoektype
        self.velden = ZOEK_VELDEN[zoektype]

    def on_mount(self) -> None:
        titel = next((t for z, t, _ in ZOEK_OPTIES if z == self.zoektype), self.zoektype)
        self.app.title = f"OSINT Scanner — {titel}"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label(f"[bold green]{next((t for z, t, _ in ZOEK_OPTIES if z == self.zoektype), self.zoektype)}[/]", id="titel")
        velden = [
            kind
            for veld_id, label, ph in self.velden
            for kind in (Label(label), Input(placeholder=ph, id=veld_id))
        ]
        fields = Vertical(*velden, id="formulier")
        yield fields
        with Horizontal(id="knoppen"):
            yield Button("Zoeken", id="zoeken", variant="primary")
            yield Button("Terug", id="terug")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "terug":
            self.action_terug()
        elif event.button.id == "zoeken":
            self.action_start()

    @on(Input.Submitted)
    def _op_enter(self, event: Input.Submitted) -> None:
        self.action_start()
        event.stop()

    def action_terug(self) -> None:
        self.app.pop_screen()

    def action_start(self) -> None:
        waarden = {
            inw.id: inw.value.strip()
            for inw in self.query(Input)
            if inw.id in {veld_id for veld_id, _, _ in self.velden}
        }
        if not waarden.get(self.velden[0][0]):
            self.query_one("#zoeken", Button).label = "⚠ eerst iets invullen"
            return
        self.app.nieuw_onderzoek(self.zoektype, waarden)


class ResultaatScherm(Screen):
    """Stroomt de live-log binnen en toont acties als het onderzoek klaar is."""

    BINDINGS = [Binding("escape", "menu", "Menu")]

    klaar: reactive[bool] = reactive(False)
    bestandsnaam: reactive[str | None] = reactive(None)

    def __init__(self) -> None:
        super().__init__()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("[bold green]Onderzoek bezig…[/]", id="status")
        yield RichLog(id="log", wrap=True, markup=False, highlight=False)
        with Horizontal(id="knoppen"):
            yield Button("Openen", id="openen", disabled=True)
            yield Button("PDF", id="pdf", disabled=True)
            yield Button("Menu", id="menu", variant="error")
        yield Footer()

    @on(Button.Pressed)
    def _knop(self, event: Button.Pressed) -> None:
        if event.button.id == "menu":
            self.action_menu()
        elif event.button.id == "openen":
            if self.bestandsnaam:
                webbrowser.open("file://" + os.path.abspath(self.bestandsnaam))
        elif event.button.id == "pdf":
            if self.bestandsnaam:
                self.query_one("#status", Label).update("[white]PDF-export loopt…[/]")
                bestand = self.bestandsnaam
                self.run_worker(lambda: self._pdf_maken(bestand), thread=True)

    def _pdf_maken(self, html_pad: str) -> None:
        pdf, fout = sc.print_rapport_naar_pdf(html_pad)
        melding = (
            f"[green]PDF: {os.path.basename(pdf)}[/]" if pdf else f"[yellow]{fout}[/]"
        )
        self.app.call_from_thread(self._pdf_toon, melding, pdf)

    def _pdf_toon(self, melding: str, pdf) -> None:
        self.query_one("#status", Label).update(melding)
        if pdf and self.app.auto_open_en_pdf:
            webbrowser.open("file://" + os.path.abspath(pdf))

    def watch_klaar(self, klaar: bool) -> None:
        self.query_one("#status", Label).update(
            "[green]Klaar — rapport opgeslagen[/]" if klaar else "[bold green]Onderzoek bezig…[/]"
        )
        op = self.query_one("#openen", Button)
        pdf = self.query_one("#pdf", Button)
        op.disabled = not (klaar and self.bestandsnaam)
        pdf.disabled = op.disabled
        if self.bestandsnaam:
            self.query_one("#status", Label).update(
                f"[green]Klaar — rapport: {os.path.basename(self.bestandsnaam)}[/]"
            )

    def watch_bestandsnaam(self, nieuwe: str | None) -> None:
        op = self.query_one("#openen", Button)
        op.disabled = not (self.klaar and nieuwe)
        self.query_one("#pdf", Button).disabled = op.disabled

    def action_menu(self) -> None:
        self.app.terug_naar_menu(self)

    def on_mount(self) -> None:
        self.set_interval(0.25, self._stream_regels)

    def _stream_regels(self) -> None:
        for regel in self.app.nieuwe_regels():
            self.query_one("#log", RichLog).write(regel)


class InstellingenScherm(Screen):
    """API-keys beheren (schrijft .env) + telemetrie/update-status."""

    BINDINGS = [Binding("escape", "terug", "Terug")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("[bold yellow]Instellingen (API-keys)[/]", id="titel")
        self.keuze = ListView(id="keylijst")
        yield self.keuze
        yield Label("", id="info")
        with Horizontal(id="knoppen"):
            yield Input(placeholder="keynaam=waarde", id="nieuw")
            yield Button("Opslaan", id="opslaan", variant="primary")
            yield Button("Wissen", id="wissen")
            yield Button("Terug", id="terug")
        yield Footer()

    def on_mount(self) -> None:
        self.ververs_keylijst()

    def ververs_keylijst(self) -> None:
        waarden = sc._lees_env()
        items = []
        for key, label in sc.BEKEND_KEYS:
            waarde = waarden.get(key, "")
            status = "[green]actief[/]" if waarde else "[dim]leeg[/]"
            items.append(ListItem(Label(f"{label}  {status}  [dim]{self._masker(waarde)}[/]")))
        self.keuze.clear()
        for it in items:
            self.keuze.append(it)

    @staticmethod
    def _masker(waarde: str) -> str:
        if not waarde:
            return "—"
        return waarde[:3] + "…" + waarde[-2:] if len(waarde) > 6 else "****"

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "terug":
            self.action_terug()
        elif event.button.id == "opslaan":
            self._opslaan()
        elif event.button.id == "wissen":
            self._wissen()

    def _opslaan(self) -> None:
        veld = self.query_one("#nieuw", Input)
        regel = veld.value.strip()
        if "=" not in regel:
            self.query_one("#info", Label).update("[red]Ongeldig formaat (key=waarde).[/]")
            return
        key, _, waarde = regel.partition("=")
        waarden = sc._lees_env()
        waarden[key.strip()] = waarde.strip()
        sc._schrijf_env(waarden)
        sc._herlaad_keys()
        veld.value = ""
        self.query_one("#info", Label).update("[green]Opgeslagen in .env — meteen actief.[/]")
        self.ververs_keylijst()

    def _wissen(self) -> None:
        geselecteerd = self.keuze.index
        if geselecteerd is None or not (0 <= geselecteerd < len(sc.BEKEND_KEYS)):
            self.query_one("#info", Label).update("[dim]Selecteer eerst een key.[/]")
            return
        key = sc.BEKEND_KEYS[geselecteerd][0]
        waarden = sc._lees_env()
        waarden[key] = ""
        sc._schrijf_env(waarden)
        sc._herlaad_keys()
        self.query_one("#info", Label).update(f"[green]'{key}' gewist.[/]")
        self.ververs_keylijst()

    def action_terug(self) -> None:
        self.app.pop_screen()


class RapportenScherm(Screen):
    """Bestaande HTML-rapporten openen, naar PDF of verwijderen."""

    BINDINGS = [Binding("escape", "terug", "Terug")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Label("[bold cyan]Bestaande rapporten[/]", id="titel")
        yield ListView(id="rapportlijst")
        with Horizontal(id="knoppen"):
            yield Button("Openen", id="openen", variant="primary")
            yield Button("PDF", id="pdf")
            yield Button("Verwijder", id="verwijder")
            yield Button("Terug", id="terug")
        yield Footer()

    def on_mount(self) -> None:
        self.ververs_lijst()

    def verschijning(self) -> list[tuple[str, str]]:
        rapporten = sorted(
            (p for p in os.listdir(".") if p.startswith("osint_rapport_") and p.endswith(".html")),
            key=os.path.getmtime,
            reverse=True,
        )
        return [(p, os.path.getsize(p) // 1024) for p in rapporten]

    def ververs_lijst(self) -> None:
        self.rapporten = self.verschijning()
        lijst = self.query_one("#rapportlijst", ListView)
        lijst.clear()
        if not self.rapporten:
            lijst.append(ListItem(Label("[dim]Geen rapporten gevonden.[/]")))
            return
        for pad, kb in self.rapporten:
            lijst.append(ListItem(Label(f"{pad}  [dim]({kb} KB)[/]")))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        geselecteerd = self.query_one("#rapportlijst", ListView).index
        if event.button.id == "terug":
            self.action_terug()
            return
        if event.button.id in ("openen", "pdf", "verwijder"):
            if not self.rapporten or geselecteerd is None or not (0 <= geselecteerd < len(self.rapporten)):
                return
            pad = self.rapporten[geselecteerd][0]
            if event.button.id == "openen":
                webbrowser.open("file://" + os.path.abspath(pad))
            elif event.button.id == "pdf":
                titel = self.query_one("#titel", Label)
                self.run_worker(lambda: self._pdf_async(pad, titel), thread=True)
            else:
                os.remove(pad)
                self.ververs_lijst()

    def _pdf_async(self, html_pad: str, titel: Label) -> None:
        pdf, fout = sc.print_rapport_naar_pdf(html_pad)
        melding = (
            f"[green]PDF: {os.path.basename(pdf)}[/]" if pdf else f"[yellow]{fout}[/]"
        )
        self.app.call_from_thread(titel.update, melding)
        if pdf:
            self.app.call_from_thread(webbrowser.open, "file://" + os.path.abspath(pdf))

    def action_terug(self) -> None:
        self.app.pop_screen()


class UpdateScherm(ModalScreen[bool]):
    """Toont git-pull-uitvoer en meldt of de scanner herstart moet worden."""

    BINDINGS = [
        Binding("escape", "terug", "Sluiten"),
        Binding("q", "quit", "Afsluiten"),
    ]

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("[bold green]Update installeren (git pull)[/]", id="titel"),
            RichLog(id="log", wrap=True, markup=False),
            Button("Terug naar menu", id="terug", variant="error"),
            id="dialoog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "terug":
            self.dismiss(True)

    def action_terug(self) -> None:
        self.dismiss(True)

    def on_mount(self) -> None:
        self._log = self.query_one("#log", RichLog)
        self.run_worker(self._voer_uit, thread=True)

    def _voer_uit(self) -> None:
        self.app.call_from_thread(self._log.write, "git pull --ff-only uitvoeren…")
        try:
            pr = subprocess.run(
                ["git", "-C", sc.SCANNER_DIR, "pull", "--ff-only"],
                capture_output=True, text=True, timeout=180,
            )
            uitvoer = (pr.stdout + pr.stderr).strip()
            if pr.returncode == 0:
                for regel in uitvoer.splitlines() or ["Up-to-date."]:
                    self.app.call_from_thread(self._log.write, regel)
                self.app.call_from_thread(
                    self._log.write,
                    "✔ Klaar — herstart de scanner om de nieuwe versie te laden.",
                )
            else:
                self.app.call_from_thread(self._log.write, f"[red]{uitvoer or 'pull mislukt'}[/]")
        except Exception as exc:
            self.app.call_from_thread(self._log.write, f"[red]Fout: {exc}[/]")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


class OsintTui(App):
    """OSINT Scanner — Textual desktop-versie."""

    TITLE = "OSINT Scanner"
    BINDINGS = [
        Binding("q", "quit", "Afsluiten"),
        Binding("ctrl+q", "quit", "Afsluiten"),
    ]
    CSS = """
    Screen { background: #0f1117; }
    #kop { color: #ff79c6; text-style: bold; margin: 1 0 0 2; }
    #titel { margin: 1 0 0 1; color: #50fa7b; }
    #menu { margin: 1 2; height: auto; }
    ListItem { padding: 0 2; }
    ListItem:hover { background: #282a36; }
    ListItem.--highlight { background: #44475a; text-style: bold; }
    #update_banner { margin: 1 2; }
    #formulier { margin: 1 2; }
    #formulier Label { margin-top: 1; }
    #formulier Input { width: 60; }
    #log { height: 1fr; margin: 1 2; border: round $accent; }
    #status, #info { margin: 1 2; }
    #knoppen { margin: 1 2; }
    #knoppen Button { margin-right: 1; }
    #keylijst { height: 1fr; margin: 1 2; }
    #rapportlijst { height: 1fr; margin: 1 2; }
    #dialoog { margin: 2 6 2 6; height: auto; }
    #dialoog #log { height: 1fr; }
    """

    def __init__(self) -> None:
        super().__init__()
        self._regels: list[str] = []
        self.auto_open_en_pdf = False
        self._banner_host = None

    def on_mount(self) -> None:
        _activeer_geleide_console()
        sc._licentie_register_achtergrond()
        self.push_screen(HoofdScherm())

    def instantie_banner(self, hoofdscherm: HoofdScherm) -> None:
        self._banner_host = hoofdscherm

    def startonderzoek(self) -> None:
        """Update-check in de achtergrond; resultaat verschijnt als banner."""
        resultaat = {"update_beschikbaar": False, "huidige_versie": sc._versie_lokaal()}

        def werk():
            try:
                r = sc._check_update(force=True)
                resultaat.update(r)
            except Exception as exc:
                resultaat["melding"] = f"update-check mislukt: {exc}"

            def toon():
                if self._banner_host is not None:
                    if resultaat.get("update_beschikbaar"):
                        self._banner_host.update_tekst = (
                            "[bold yellow]↑ Update beschikbaar — druk U om te updaten (git pull)[/]"
                        )
                    elif resultaat.get("nieuwste_versie"):
                        self._banner_host.update_tekst = (
                            f"[dim]Server versie {resultaat['nieuwste_versie']} — actueel[/]"
                        )

            self.call_from_thread(toon)

        threading.Thread(target=werk, daemon=True).start()

    def action_instellingen(self) -> None:
        self.push_screen(InstellingenScherm())

    def action_rapporten(self) -> None:
        self.push_screen(RapportenScherm())

    def action_update(self) -> None:
        self.push_screen(UpdateScherm())

    def ga_naar_zoeken(self, zoektype: str) -> None:
        self.push_screen(ZoekScherm(zoektype))

    def terug_naar_menu(self, huidig: Screen) -> None:
        self._regels.clear()
        huidig.dismiss()
        self.switch_screen(HoofdScherm())

    def nieuwe_regels(self) -> list[str]:
        """Vraagt nieuwe buffered console-regels op (niet blokkerend)."""
        data = _geleide_buffer.lees()
        if not data:
            return []
        regels = _schoone_regels(data)
        self._regels.extend(regels)
        return regels

    def nieuw_onderzoek(self, zoektype: str, waarden: dict) -> None:
        """Start een onderzoek in een worker-thread; toont de resultaten live."""
        self._regels.clear()
        resultaat = ResultaatScherm()
        self.switch_screen(resultaat)

        def werk():
            bestandsnaam = self._draai_onderzoek(zoektype, waarden)

            def klaar():
                resultaat.bestandsnaam = bestandsnaam
                resultaat.klaar = True

            self.call_from_thread(klaar)

        threading.Thread(target=werk, daemon=True).start()

    def _draai_onderzoek(self, zoektype: str, waarden: dict) -> str | None:
        """Roept de engine-flow aan (geleide console); geeft HTML-rapport terug."""
        try:
            if zoektype == "naam":
                naam = waarden["volledige_naam"]
                voornaam = waarden.get("voornaam", "")
                if not voornaam and " " in naam:
                    voornaam = naam.rsplit(" ", 1)[0]
                plaats = waarden.get("plaats", "")
                volledige_naam = naam
                if voornaam and voornaam.lower() not in naam.lower():
                    volledige_naam = f"{voornaam} {naam}".strip()
                return sc.voer_onderzoek_uit(
                    "naam", volledige_naam,
                    sc.dorks_naam(volledige_naam, plaats),
                    plaats=plaats, voornaam=voornaam,
                )
            if zoektype == "gebruikersnaam":
                user = waarden["gebruikersnaam"].lstrip("@")
                return sc.voer_onderzoek_uit("username", user, sc.dorks_username(user))
            if zoektype == "email":
                return sc.voer_onderzoek_uit("email", waarden["email"], sc.dorks_email(waarden["email"]))
            if zoektype == "telefoon":
                tel = waarden["telefoon"]
                tel_int = "+31" + tel[1:] if tel.startswith("0") else tel
                return sc.voer_onderzoek_uit("telefoon", tel, sc.dorks_telefoon(tel, tel_int))
            if zoektype == "bedrijven":
                term = waarden["zoekterm"]
                r = sc.openkvk_bedrijven(term)
                sc.console.print(f"[bold]{r['melding']}[/]")
                for b in r["bedrijven"][:25]:
                    sc.console.print(f"  {b['handelsnaam']}  (kvk {b['dossiernummer']})")
                if not r["bedrijven"]:
                    sc.console.print("[dim]Geen bedrijven gevonden.[/]")
                return sc.genereer_dashboard("bedrijven", term, {}, {"openkvk": r}, open_browser=False)
            if zoektype == "adres":
                adres = waarden["adres"]
                r = sc.bag_adres_zoeken(adres)
                if r.get("status") != "ok":
                    sc.console.print(f"[bold yellow]{r.get('fout')}[/]")
                else:
                    a = r["adres"]
                    sc.console.print(f"[bold]Kadaster / BAG - {a.get('weergavenaam')}[/]")
                    sc.console.print(f"  Gemeente: {a.get('gemeente')} | Provincie: {a.get('provincie')}")
                    if a.get("perceel"):
                        sc.console.print(f"  Perceel: {', '.join(a['perceel'])}")
                    if a.get("bouwjaar"):
                        sc.console.print(
                            f"  Bouwjaar: {a['bouwjaar']} | Oppervlakte: {a.get('oppervlakte')} m² | "
                            f"Gebruiksdoel: {a.get('gebruiksdoel')}"
                        )
                    for k in ("coord_ll",):
                        if a.get(k):
                            sc.console.print(f"  {k}: {a[k]}")
                return sc.genereer_dashboard("adres", adres, {}, {"bag": r}, open_browser=False)
            if zoektype == "kenteken":
                kenteken = waarden["kenteken"]
                rdw = sc.rdw_kenteken_zoek(kenteken)
                if rdw.get("status") == "ok" and rdw.get("voertuig"):
                    v = rdw["voertuig"]
                    sc.console.print(f"[bold]RDW - {rdw.get('kenteken')}[/]")
                    for label, waarde in [
                        ("Merk", v.get("merk")), ("Handelsbenaming", v.get("handelsbenaming")),
                        ("Bouwjaar", sc._rdw_datum(v.get("bouwjaar"))),
                        ("Brandstof", v.get("brandstof")), ("CO2", v.get("co2")),
                        ("APK", sc._rdw_datum(v.get("vervaldatum"))), ("Kleur", v.get("kleur")),
                        ("Voertuigsoort", v.get("voertuigsoort")), ("Categorie", v.get("categorie")),
                    ]:
                        if waarde:
                            sc.console.print(f"  {label}: {waarde}")
                    return sc.genereer_dashboard("kenteken", rdw.get("kenteken") or kenteken, {}, {"rdw": rdw}, open_browser=False)
                sc.console.print(f"[yellow]{rdw.get('fout')}[/]")
                return None
            if zoektype == "interpol":
                achternaam = waarden["achternaam"]
                voornaam = waarden.get("voornaam", "")
                ri = sc.interpol_zoek(achternaam, voornaam)
                rf = sc.fbi_wanted_zoek(achternaam, voornaam)
                ro = sc.opsporingslijst_zoek(achternaam, voornaam)
                if ri.get("status") == "geblokkeerd":
                    sc.console.print(f"[yellow]{ri['melding']}[/]")
                elif ri["red"] or ri["yellow"]:
                    if ri["red"]:
                        sc.console.print(f"[bold red]Red Notices ({len(ri['red'])}):[/]")
                        for n in ri["red"][:10]:
                            sc.console.print(f"  {n['naam']}  ({n['nationaliteit']}, geb. {n['geboortedatum']})")
                            sc.console.print(f"     {n['url']}")
                    if ri["yellow"]:
                        sc.console.print(f"[bold yellow]Yellow Notices ({len(ri['yellow'])}):[/]")
                        for n in ri["yellow"][:10]:
                            sc.console.print(f"  {n['naam']}  ({n['nationaliteit']}, geb. {n['geboortedatum']})")
                            sc.console.print(f"     {n['url']}")
                else:
                    sc.console.print(f"[dim]{ri.get('melding', 'Geen notices.')}[/]")
                if rf.get("status") == "geblokkeerd":
                    sc.console.print(f"[yellow]{rf['melding']}[/]")
                else:
                    if rf["gezocht"]:
                        sc.console.print(f"[bold red]FBI Gezocht ({len(rf['gezocht'])}):[/]")
                        for n in rf["gezocht"][:10]:
                            sc.console.print(f"  {n['naam']}  {n.get('url', '')}")
                    if rf["vermist"]:
                        sc.console.print(f"[bold yellow]FBI Vermist ({len(rf['vermist'])}):[/]")
                        for n in rf["vermist"][:10]:
                            sc.console.print(f"  {n['naam']}  {n.get('url', '')}")
                sc.console.print(f"[bold red]Opsporingslijst ({len(ro)}):[/]" if ro else "[dim]Geen opsporingslijst-hits.[/]")
                return sc.genereer_dashboard(
                    "interpol", achternaam, {},
                    {"interpol": ri, "fbi": rf, "opsporingslijst": ro},
                    open_browser=False,
                )
            if zoektype == "socid":
                id_input = waarden["social_url"]
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
                            self._print_socid(r[0])
                else:
                    r = sc.zoek_social_media_ids([{"url": id_input, "platform": "Onbekend", "bron": "handmatig"}])
                    if r:
                        self._print_socid(r[0])
                    else:
                        sc.console.print("[yellow]Kon geen ID extraheren (platform- of CAPTCHA-beperking).[/]")
                return None
            sc.console.print("[yellow]Onbekend zoektype.[/]")
            return None
        except Exception as exc:
            sc.console.print(f"[red]Onverwachte fout bij het onderzoek: {exc}[/]")
            return None

    @staticmethod
    def _print_socid(p: dict) -> None:
        sc.console.print(f"[bold cyan]{p.get('platform', 'Onbekend')}[/]  {p.get('url', '')}")
        for veld in ("fullname", "name", "display_name", "created_at", "is_private", "followers_count"):
            waarde = p.get(veld)
            if waarde not in (None, "", 0, False, "None"):
                sc.console.print(f"   {veld}: {str(waarde)[:120]}")
        intern = p.get("internal_ids") or {}
        for id_naam, id_waarde in intern.items():
            sc.console.print(f"   [cyan]{id_naam}: {id_waarde}[/]")
        ext = p.get("external_links") or []
        if ext:
            sc.console.print(f"   extern: {', '.join(str(l)[:60] for l in ext[:5])}")


if __name__ == "__main__":
    from pathlib import Path
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    OsintTui().run()