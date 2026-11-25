import os
import shutil

from prompt_toolkit.application import Application
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.layout import Layout
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.containers import Window
from prompt_toolkit.styles import Style

from .models import Advisory, ResearchReport


def _clip(value: str, width: int) -> str:
    value = " ".join(value.split())
    if len(value) > width:
        return value[:max(0, width - 3)] + ("..." if width >= 3 else "")
    return value


def _border(widths: tuple[int, ...]) -> str:
    return "+" + "+".join("-" * (width + 2) for width in widths) + "+"


def _row(values: tuple[str, ...], widths: tuple[int, ...]) -> str:
    cells = [f" {_clip(value, width):<{width}} " for value, width in zip(values, widths)]
    return "|" + "|".join(cells) + "|"


def _summary_rows(report: ResearchReport) -> list[tuple[str, ...]]:
    return [
        (
            " " if index else ">",
            match.advisory.title,
            match.advisory.cve_id,
            match.advisory.published[:10] if match.advisory.published else "Unknown",
            match.advisory.severity,
        )
        for index, match in enumerate(report.matches)
    ]


def _source_name(advisory: Advisory, link: str) -> str:
    if "nvd.nist.gov" in link:
        return "NVD record"
    if "cisa.gov" in link:
        return "CISA KEV"
    if link in advisory.vendor_advisories:
        return "Vendor advisory"
    return "Source record"


def _details_tables(advisory: Advisory, width: int) -> list[str]:
    affected = [item.label() for item in advisory.affected[:3]]
    if len(advisory.affected) > len(affected):
        affected.append(f"...and {len(advisory.affected) - len(affected)} more; see NVD")
    remediation = " ".join(advisory.remediation.split()) or "See vendor advisory"
    detail_rows = [
        ("CVE", advisory.cve_id),
        ("Vulnerability", advisory.title),
        ("Severity", advisory.severity),
        ("Published", advisory.published[:10] or "Unknown"),
        ("Updated", advisory.updated[:10] or "Unknown"),
        ("Known exploited", "Yes (CISA KEV)" if advisory.known_exploited else "Not listed"),
        ("Affected ranges", "; ".join(affected) or "See linked advisory"),
        ("Remediation", remediation),
    ]
    key_width = min(22, max(len(key) for key, _ in detail_rows))
    value_width = max(20, width - key_width - 7)
    detail_widths = (key_width, value_width)
    lines = [
        "CVE DETAILS",
        _border(detail_widths),
        _row(("Name", "Information"), detail_widths),
        _border(detail_widths),
    ]
    lines.extend(_row((key, value), detail_widths) for key, value in detail_rows)
    lines.append(_border(detail_widths))

    links = list(dict.fromkeys(advisory.vendor_advisories + advisory.references))
    link_rows = [(_source_name(advisory, link), link) for link in links[:4]]
    if len(links) > len(link_rows):
        link_rows.append(("More links", f"{len(links) - len(link_rows)} additional; see NVD"))
    if not link_rows:
        link_rows = [("Unavailable", "No source links")]
    link_key_width = max(len("Name"), *(len(name) for name, _ in link_rows))
    link_width = max(20, width - link_key_width - 7)
    link_widths = (link_key_width, link_width)
    lines += [
        "",
        "SOURCE LINKS",
        _border(link_widths),
        _row(("Name", "Link"), link_widths),
        _border(link_widths),
    ]
    lines.extend(_row(row, link_widths) for row in link_rows)
    lines.append(_border(link_widths))
    return lines


def _format_screen(
    report: ResearchReport,
    selected_index: int,
    detail_mode: bool,
    width: int,
    height: int,
) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    if detail_mode:
        advisory = report.matches[selected_index].advisory
        lines = [
            f"DETAILS FOR {advisory.cve_id}",
            "",
            *_details_tables(advisory, width),
            "",
            "Press Escape or Backspace to return to the result list. Press Q to quit.",
        ]
        result.extend(("", line + "\n") for line in lines)
        return result

    name_width = min(48, max(18, width - 62))
    widths = (1, name_width, 15, 10, 20)
    table_width = sum(widths) + 3 * len(widths) + 1
    title = "POSSIBLE VULNERABILITIES"
    result.append(("class:title", title.center(table_width) + "\n"))
    result.append(("class:header", _border(widths) + "\n"))
    result.append(("class:header", _row(("", "Vulnerability name", "CVE", "Published", "Severity"), widths) + "\n"))
    result.append(("class:header", _border(widths) + "\n"))

    page_size = max(1, height - 11)
    page_start = selected_index // page_size * page_size
    page_end = min(len(report.matches), page_start + page_size)
    for index in range(page_start, page_end):
        match = report.matches[index]
        cells = (
            ">" if index == selected_index else " ",
            match.advisory.title,
            match.advisory.cve_id,
            match.advisory.published[:10] if match.advisory.published else "Unknown",
            match.advisory.severity,
        )
        style = "class:selected" if index == selected_index else ""
        result.append((style, _row(cells, widths) + "\n"))
    result.append(("class:header", _border(widths) + "\n"))
    result.append(("", f"Showing {page_start + 1}-{page_end} of {len(report.matches)}\n"))
    if report.hidden_severity_matches:
        result.append(("", f"Hidden Low/unscored: {report.hidden_severity_matches}. Use --include-low to include them.\n"))
    result.append(("", "Use Up/Down to move, Enter to view details, Q to quit.\n"))
    result.append(("", "Possible matches only; no requests were sent to the assessed asset.\n"))
    return result


def run_selectable_table(report: ResearchReport, no_color: bool = False) -> None:
    if not report.matches:
        return
    width, height = shutil.get_terminal_size((100, 24))
    width = max(75, width)
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

    style = Style.from_dict({
        "title": "bold",
        "header": "bold",
        "selected": "" if no_color or "NO_COLOR" in os.environ else "bold ansigreen",
    })
    control = FormattedTextControl(
        lambda: _format_screen(
            report,
            state["selected"],
            state["details"],
            width,
            height,
        )
    )
    app = Application(
        layout=Layout(Window(control, wrap_lines=False, always_hide_cursor=True)),
        key_bindings=bindings,
        style=style,
        full_screen=False,
        erase_when_done=False,
    )
    app.run()
