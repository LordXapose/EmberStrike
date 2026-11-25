import shutil
from io import StringIO

from prompt_toolkit.application import Application
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.containers import Window
from rich import box
from rich.console import Console
from rich.table import Table

from .models import Advisory, ResearchReport


def build_results_table(report: ResearchReport, selected_index: int = -1, width: int = 100) -> Table:
    table = Table(
        title="Possible Vulnerability Matches",
        border_style="white",
        header_style="bold white",
        show_lines=False,
        box=box.ASCII,
        width=width,
    )
    table.add_column("", width=2, style="green", no_wrap=True)
    table.add_column("Vulnerability Name", style="white", max_width=max(18, width - 72))
    table.add_column("CVE", style="cyan", no_wrap=True)
    table.add_column("Published", style="white", no_wrap=True)
    table.add_column("Severity", style="white", no_wrap=True)
    for index, match in enumerate(report.matches):
        table.add_row(
            ">" if index == selected_index else "",
            " ".join(match.advisory.title.split()),
            match.advisory.cve_id,
            match.advisory.published[:10] if match.advisory.published else "Unknown",
            match.advisory.severity,
            style="bold green" if index == selected_index else "",
        )
    if not report.matches:
        table.add_row("", "No matches at selected severity", "-", "-", "-")
    return table


def _source_name(advisory: Advisory, link: str) -> str:
    if "nvd.nist.gov" in link:
        return "NVD record"
    if "cisa.gov" in link:
        return "CISA KEV"
    if link in advisory.vendor_advisories:
        return "Vendor advisory"
    return "Source record"


def build_detail_tables(advisory: Advisory, width: int = 100) -> tuple[Table, Table]:
    details = Table(
        title=f"Details for {advisory.cve_id}",
        border_style="white",
        header_style="bold white",
        show_lines=False,
        box=box.ASCII,
        width=width,
    )
    details.add_column("Name", style="white", no_wrap=True)
    details.add_column("Information", style="white", max_width=max(20, width - 32))
    details.add_row("Vulnerability", " ".join(advisory.title.split())[:120])
    details.add_row("Severity", advisory.severity)
    details.add_row("Published", advisory.published[:10] or "Unknown")
    details.add_row("Updated", advisory.updated[:10] or "Unknown")
    details.add_row("Known exploited", "Yes (CISA KEV)" if advisory.known_exploited else "Not listed")
    affected = [item.label() for item in advisory.affected[:3]]
    if len(advisory.affected) > len(affected):
        affected.append(f"...and {len(advisory.affected) - len(affected)} more; see NVD")
    details.add_row("Affected ranges", "; ".join(affected) or "See linked advisory")
    remediation = " ".join(advisory.remediation.split()) or "See vendor advisory"
    details.add_row("Remediation", remediation[:160] + ("..." if len(remediation) > 160 else ""))

    links = Table(
        title="Source Links",
        border_style="white",
        header_style="bold white",
        show_lines=False,
        box=box.ASCII,
        width=width,
    )
    links.add_column("Name", style="white", no_wrap=True)
    links.add_column("Link", style="cyan", max_width=max(24, width - 24))
    source_links = list(dict.fromkeys(advisory.vendor_advisories + advisory.references))
    for link in source_links[:6]:
        links.add_row(_source_name(advisory, link), link)
    if len(source_links) > 6:
        links.add_row("More links", f"{len(source_links) - 6} additional; see NVD")
    if not source_links:
        links.add_row("Unavailable", "No source links")
    return details, links


def _render_ansi(renderables, width: int, no_color: bool) -> str:
    output = StringIO()
    console = Console(
        file=output,
        width=width,
        force_terminal=True,
        color_system=None if no_color else "standard",
        no_color=no_color,
        highlight=False,
    )
    for renderable in renderables:
        console.print(renderable)
    return output.getvalue()


def run_selectable_table(report: ResearchReport, no_color: bool = False) -> None:
    if not report.matches:
        return
    width, height = shutil.get_terminal_size((100, 24))
    width = max(80, width)
    state = {"selected": 0, "details": False}
    bindings = KeyBindings()

    @bindings.add("up")
    def move_up(event) -> None:
        if not state["details"]:
            state["selected"] = (state["selected"] - 1) % len(report.matches)
            event.app.invalidate()

    @bindings.add("down")
    def move_down(event) -> None:
        if not state["details"]:
            state["selected"] = (state["selected"] + 1) % len(report.matches)
            event.app.invalidate()

    @bindings.add("enter")
    def toggle_details(event) -> None:
        state["details"] = not state["details"]
        event.app.invalidate()

    @bindings.add("escape")
    @bindings.add("backspace")
    def back_to_results(event) -> None:
        if state["details"]:
            state["details"] = False
            event.app.invalidate()
        else:
            event.app.exit()

    @bindings.add("q")
    @bindings.add("c-c")
    def quit_table(event) -> None:
        event.app.exit()

    def get_screen():
        if state["details"]:
            details, links = build_detail_tables(
                report.matches[state["selected"]].advisory,
                width=width,
            )
            footer = "Escape or Backspace: results | Q: quit"
            renderables = [details, links, footer]
        else:
            page_size = max(1, height - 8)
            page_start = state["selected"] // page_size * page_size
            page_end = min(len(report.matches), page_start + page_size)
            paged_report = ResearchReport(
                asset=report.asset,
                matches=report.matches[page_start:page_end],
                hidden_severity_matches=report.hidden_severity_matches,
            )
            local_index = state["selected"] - page_start
            table = build_results_table(paged_report, local_index, width=width)
            footer = [
                f"Rows {page_start + 1}-{page_end} of {len(report.matches)}",
                "Up/Down: move | Enter: details | Q: quit",
                "Possible matches only; no requests were sent to the assessed asset.",
            ]
            if report.hidden_severity_matches:
                footer.append(
                    f"Low or unscored hidden: {report.hidden_severity_matches}; use --include-low to include."
                )
            renderables = [table, *footer]
        return ANSI(_render_ansi(renderables, width, no_color))

    app = Application(
        layout=Layout(Window(FormattedTextControl(get_screen), wrap_lines=False, always_hide_cursor=True)),
        key_bindings=bindings,
        full_screen=False,
        erase_when_done=False,
    )
    app.run()
