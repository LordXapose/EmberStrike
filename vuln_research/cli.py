import argparse
import json
import os
import re
import sys
from pathlib import Path

import argcomplete
from argcomplete.completers import ChoicesCompleter
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from .models import Advisory, AssetObservation
from .banner import BANNER
from .catalog import PRODUCTS, SERVICE_TYPES, VENDORS
from .reports import (
    advisory_to_json,
    advisory_to_markdown,
    advisory_to_plain,
    to_json,
    to_markdown,
    to_plain,
)
from .research import run_research
from .sources import cisa_kev, nvd
from .sources.base import SourceError


def build_parser(prog: str = "emberstrike") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        description="EmberStrike by LordXapose — research public vulnerability records against service details you already observed. Never scans or contacts the asset.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""COMMANDS
  emberstrike [OPTIONS]             Interactive research, or research using supplied options
  emberstrike search [OPTIONS]      Search public vulnerability sources for an observation
  emberstrike services              Browse common service, product, and completion suggestions
  emberstrike show CVE-ID           Read detailed public advisory information for one CVE
  emberstrike COMMAND --help        Show help for search, services, or show

EXAMPLES
  emberstrike
  emberstrike search -n "Quarterly review" -s HTTPS -p "Apache Tomcat" -v Apache -V 9.0.80
  emberstrike services
  emberstrike show CVE-2023-42794
  emberstrike search -n "Quarterly review" --scope-notes "Written approval" \\
    -a app-01 -P 8443 --protocol https -s HTTPS -p "Apache Tomcat" \\
    -v Apache -V 9.0.80 --identified-by inventory -c Medium \\
    --format markdown --output report.md
  emberstrike search -n "Offline review" -p OpenSSL -v OpenSSL -V 3.0.12 \\
    --offline --format json --output report.json

The tool only queries public vulnerability sources; it never contacts an assessed asset.
Results are possible matches, not confirmation that a host is vulnerable.
Assessment details stay local unless you explicitly save a report. No credentials are needed.
Use only within written authorization and scope.

EmberStrike | Developer: LordXapose""",
    )
    observation = parser.add_argument_group("Observed service and asset details")
    observation.add_argument("-n", "--assessment", help="Assessment or engagement name")
    observation.add_argument("--scope-notes", help="Brief note about written authorization and scope")
    observation.add_argument("-a", "--asset", help="Asset label or hostname (optional; not contacted)")
    observation.add_argument("-P", "--port", type=int, help="Observed port (1-65535)")
    observation.add_argument("--protocol", help="Observed transport/application protocol, e.g. tcp or https")
    service_action = observation.add_argument(
        "-s", "--service", help="Detected service (tab-complete common services)"
    )
    product_action = observation.add_argument(
        "-p", "--product", help="Detected product (tab-complete common products)"
    )
    vendor_action = observation.add_argument("-v", "--vendor", help="Product vendor")
    observation.add_argument("-V", "--observed-version", "--version", dest="version", help="Observed version")
    observation.add_argument("--build-number", dest="build", help="Observed build or patch level")
    observation.add_argument("--platform", help="Operating system or platform")
    observation.add_argument("--modules", help="Modules or relevant configuration")
    observation.add_argument("--identified-by", help="How the observation was collected")
    observation.add_argument("-c", "--confidence", choices=("High", "Medium", "Low"), help="Confidence in the observation")

    output = parser.add_argument_group("Research and report options")
    output.add_argument("--format", choices=("plain", "json", "markdown"), default="plain", help="Report format (default: plain)")
    output.add_argument("--output", type=Path, help="Save the report to this local file")
    output.add_argument("--offline", action="store_true", help="Skip public-source requests")
    output.add_argument("--no-color", action="store_true", help="Disable color (also respects NO_COLOR)")
    output.add_argument("--limit", type=int, help="Maximum possible matches to report (default: all matches)")
    output.add_argument("--non-interactive", action="store_true", help="Do not prompt; fail if required input is missing")
    service_action.completer = ChoicesCompleter(SERVICE_TYPES)
    product_action.completer = ChoicesCompleter(PRODUCTS)
    vendor_action.completer = ChoicesCompleter(VENDORS)
    return parser


def _services_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="emberstrike services",
        description="Show common service and product suggestions. The list is not exhaustive.",
        epilog="Use -s to enter a service or -p to enter a product. Tab completion is available after shell setup; custom names are accepted.",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable terminal color")
    args = parser.parse_args(argv)
    console = Console(no_color=args.no_color or "NO_COLOR" in os.environ, highlight=False)
    if sys.stdout.isatty():
        render_banner(console)
    table = Table(title="COMMON SERVICE AND PRODUCT SUGGESTIONS", box=box.SIMPLE_HEAVY)
    table.add_column("Service types (-s)", style="cyan")
    table.add_column("Products (-p)", style="green")
    rows = max(len(SERVICE_TYPES), len(PRODUCTS))
    for index in range(rows):
        table.add_row(
            SERVICE_TYPES[index] if index < len(SERVICE_TYPES) else "",
            PRODUCTS[index] if index < len(PRODUCTS) else "",
        )
    console.print(table)
    console.print("[dim]The columns are independent suggestion lists, not service-to-product mappings.[/]")
    console.print("[dim]Suggestions only; you can type any service or product name.[/]")
    console.print("[dim]Example: emberstrike search -n review -s HTTPS -p 'Apache Tomcat' -v Apache -V 9.0.80[/]")
    return 0


def render_banner(console: Console) -> None:
    console.print("[bold bright_red]EmberStrike[/]")
    banner_width = max(len(line) for line in BANNER.splitlines())
    console.print(
        Text(BANNER, no_wrap=True),
        width=banner_width,
        overflow="ignore",
        crop=False,
    )
    console.print("[bold cyan]Developer:[/] LordXapose\n")


def _observation(args, console: Console, interactive: bool) -> AssetObservation:
    values = vars(args)
    fields = {
        "assessment": ("Assessment name", True),
        "scope_notes": ("Authorized scope notes", False),
        "asset": ("Asset label or hostname (optional)", False),
        "port": ("Port (optional)", False),
        "protocol": ("Protocol (optional)", False),
        "service": ("Detected service (optional)", False),
        "product": ("Detected product (optional)", False),
        "vendor": ("Vendor (optional)", False),
        "version": ("Observed version (optional)", False),
        "build": ("Build number (optional)", False),
        "platform": ("Operating system/platform (optional)", False),
        "modules": ("Modules/configuration (optional)", False),
        "identified_by": ("How was it identified? (optional)", False),
        "confidence": ("Observation confidence: High/Medium/Low", False),
    }
    prompts = {}
    if interactive:
        for key, (label, required) in fields.items():
            if values.get(key) is None:
                answer = Prompt.ask(label, console=console, default="Medium" if key == "confidence" else "")
                prompts[key] = answer.strip()
    data = {key: values.get(key) if values.get(key) is not None else prompts.get(key, "") for key in fields}
    if not data["assessment"]:
        raise ValueError("An assessment name is required (use --assessment or answer the prompt).")
    if not data["product"] and not data["service"]:
        raise ValueError("Enter at least a detected product or service using --product/--service.")
    if data["port"] == "":
        data["port"] = None
    if data["port"] is not None and not 1 <= data["port"] <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    if not data["confidence"]:
        data["confidence"] = "Medium"
    return AssetObservation(**data)


def _render_rich(report, console: Console):
    asset = report.asset
    asset_table = Table(show_header=False, box=box.SIMPLE, pad_edge=False)
    asset_table.add_column("Field", style="cyan", no_wrap=True)
    asset_table.add_column("Observed value")
    for label, value in (
        ("Assessment", asset.assessment),
        ("Authorized scope", asset.scope_notes or "Not provided"),
        ("Asset", asset.asset or "Not provided"),
        ("Service / product", " / ".join(part for part in (asset.service, asset.product) if part) or "Not provided"),
        ("Vendor / version / build", " / ".join(part or "Not provided" for part in (asset.vendor, asset.version, asset.build))),
        ("Port / protocol", f"{asset.port or 'Not provided'} / {asset.protocol or 'Not provided'}"),
        ("Platform / modules", " / ".join(part or "Not provided" for part in (asset.platform, asset.modules))),
        ("Identified by / confidence", f"{asset.identified_by or 'Not provided'} / {asset.confidence}"),
    ):
        asset_table.add_row(label, value)
    console.print(Panel(asset_table, title="[bold cyan]ASSET[/]", border_style="cyan"))

    if report.matches:
        summary = Table(title="POSSIBLE CVE MATCHES", box=box.SIMPLE_HEAVY, header_style="bold yellow")
        summary.add_column("CVE", style="cyan", no_wrap=True)
        summary.add_column("Advisory")
        summary.add_column("Severity", no_wrap=True)
        summary.add_column("Confidence", no_wrap=True)
        summary.add_column("CISA KEV", no_wrap=True)
        for match in report.matches:
            summary.add_row(
                match.advisory.cve_id,
                match.advisory.title,
                match.advisory.severity,
                match.confidence,
                "Yes" if match.advisory.known_exploited else "No",
            )
        console.print(summary)

    if report.offline:
        console.print("[yellow]Notice: Offline mode:[/] no public sources were queried.")
    elif report.source_warnings:
        for warning in report.source_warnings:
            console.print(f"[yellow]Source notice:[/] {warning}")
    if not report.matches:
        console.print(Panel("No possible matches found in available results. This does not establish that the asset is unaffected.", title="[bold yellow]POSSIBLE MATCHES[/]", border_style="yellow"))
    for match in report.matches:
        advisory = match.advisory
        color = {"High": "red", "Medium": "yellow", "Low": "green"}[match.confidence]
        content = [
            f"[bold]{advisory.title}[/]",
            f"[bold]Severity:[/] {advisory.severity}  [bold]Published / updated:[/] {advisory.published or 'Unavailable'} / {advisory.updated or 'Unavailable'}",
            f"[bold]Match confidence:[/] [{color}]{match.confidence}[/]  [bold]Known exploited:[/] {'Yes — CISA KEV' if advisory.known_exploited else 'Not reported'}",
            f"[bold]Affected product/version:[/] {'; '.join(item.label() for item in advisory.affected) or 'Unavailable'}",
            f"[bold]Why it may match:[/] {' '.join(match.why_match)}",
            f"[bold]Missing evidence:[/] {' '.join(match.missing_evidence) or 'None identified; this is not host-level verification.'}",
            f"[bold]Conflicting evidence:[/] {' '.join(match.conflicting_evidence) or 'None identified.'}",
            f"[bold]Remediation:[/] {advisory.remediation or 'Review linked vendor guidance.'}",
            f"[bold]Vendor advisories:[/] {', '.join(advisory.vendor_advisories) or 'Not identified'}",
            f"[bold]Primary sources:[/] {', '.join(advisory.references) or 'Unavailable'}",
            "[bold]Safe verification:[/] Confirm the exact build using an approved inventory or vendor-supported read-only method; do not send test payloads.",
        ]
        console.print(Panel("\n".join(content), title=f"[bold magenta]POSSIBLE MATCH — {advisory.cve_id}[/]", border_style=color))

    evidence = "Public records were compared with the supplied observation. No request was sent to the assessed asset."
    if report.offline:
        evidence = "No public sources were queried (offline mode)."
    if report.source_warnings:
        evidence += "\n" + "\n".join(report.source_warnings)
    console.print(Panel(evidence, title="[bold blue]EVIDENCE[/]", border_style="blue"))
    steps = "\n".join(
        f"{number}. {step}" for number, step in enumerate((
            "Confirm product, exact build, and patch level using an approved inventory or vendor-supported method.",
            "Review the linked vendor advisory and compare its affected-version guidance with the observation.",
            "Use only non-invasive, vendor-documented checks; do not probe or exploit the asset.",
            "Stay within written authorization and scope; record evidence and uncertainty.",
        ), 1)
    )
    console.print(Panel(steps, title="[bold green]NEXT STEPS[/]", border_style="green"))
    console.print("[dim]Possible matches are research leads, not proof that a host is vulnerable.[/]")


def _render_advisory(advisory: Advisory, source_warnings: list[str], console: Console) -> None:
    details = Table(show_header=False, box=box.SIMPLE, pad_edge=False)
    details.add_column("Field", style="cyan", no_wrap=True)
    details.add_column("Details")
    details.add_row("Severity", advisory.severity)
    details.add_row("Published / updated", f"{advisory.published or 'Unavailable'} / {advisory.updated or 'Unavailable'}")
    details.add_row("Affected products / versions", "; ".join(item.label() for item in advisory.affected) or "Unavailable")
    details.add_row("Known exploited", "Yes — CISA KEV" if advisory.known_exploited else "Not reported by queried sources")
    details.add_row("Remediation", advisory.remediation or "Review the vendor security advisory for supported remediation.")
    console.print(Panel(details, title=f"[bold magenta]{advisory.cve_id} — ADVISORY DETAILS[/]", border_style="magenta"))
    console.print(Panel(advisory.description or "No description was returned.", title="[bold blue]DESCRIPTION[/]", border_style="blue"))
    links = list(dict.fromkeys(advisory.vendor_advisories + advisory.references))
    console.print(Panel("\n".join(links) or "No source links were returned.", title="[bold cyan]PRIMARY SOURCES AND VENDOR GUIDANCE[/]", border_style="cyan"))
    console.print(Panel(
        "Confirm the installed build using an authorized inventory or vendor-supported, non-invasive method. "
        "This public advisory does not verify a specific host.",
        title="[bold green]SAFE VERIFICATION[/]",
        border_style="green",
    ))
    for warning in source_warnings:
        console.print(f"[yellow]Source notice:[/] {warning}")


def _show_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="emberstrike show",
        description="Show public advisory details for one CVE. This command does not provide exploit instructions or contact a target.",
        epilog="Displays severity, dates, affected versions, KEV status, remediation, primary links, and safe verification guidance.",
    )
    parser.add_argument("--format", choices=("plain", "json", "markdown"), default="plain")
    parser.add_argument("--output", type=Path, help="Save the advisory report locally")
    parser.add_argument("--no-color", action="store_true", help="Disable terminal color")
    parser.add_argument("cve_id", help="CVE identifier, e.g. CVE-2023-42794")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", args.cve_id.upper()):
        parser.error("Use a CVE identifier such as CVE-2025-12345.")

    no_color = args.no_color or "NO_COLOR" in os.environ
    console = Console(no_color=no_color, highlight=False)
    terminal_output = sys.stdout.isatty() and args.format == "plain"
    if terminal_output:
        render_banner(console)

    source_warnings = []
    try:
        advisory = nvd.lookup(args.cve_id.upper())
    except SourceError as exc:
        advisory = None
        source_warnings.append(f"NVD: {exc}")
    try:
        kev_advisory = next(
            (item for item in cisa_kev.fetch_all() if item.cve_id.upper() == args.cve_id.upper()),
            None,
        )
    except SourceError as exc:
        kev_advisory = None
        source_warnings.append(f"CISA KEV: {exc}")

    if advisory and kev_advisory:
        advisory.known_exploited = True
        advisory.exploitation_note = kev_advisory.exploitation_note
        advisory.remediation = kev_advisory.remediation or advisory.remediation
        advisory.sources = list(dict.fromkeys(advisory.sources + kev_advisory.sources))
        advisory.references = list(dict.fromkeys(advisory.references + kev_advisory.references))
    elif kev_advisory:
        advisory = kev_advisory

    if advisory:
        renderers = {
            "plain": advisory_to_plain,
            "json": advisory_to_json,
            "markdown": advisory_to_markdown,
        }
        rendered = renderers[args.format](advisory, source_warnings)
    elif args.format == "json":
        rendered = json.dumps({
            "cve_id": args.cve_id.upper(),
            "found": False,
            "source_warnings": source_warnings,
        }, indent=2)
    else:
        rendered = f"No public advisory record found for {args.cve_id.upper()}."
        if source_warnings:
            rendered += "\n\nSource notices:\n" + "\n".join(source_warnings)

    if args.output:
        try:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            Console(stderr=True, no_color=no_color, highlight=False).print(f"[bold red]Could not save report:[/] {exc}")
            return 1
        Console(stderr=True, no_color=no_color, highlight=False).print(f"[green]Report saved locally:[/] {args.output}")
    if advisory and terminal_output:
        _render_advisory(advisory, source_warnings, console)
    else:
        print(rendered)
    return 0 if advisory else 1


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "services":
        return _services_main(arguments[1:])
    if arguments and arguments[0] == "show":
        return _show_main(arguments[1:])
    command = None
    if arguments and arguments[0] == "search":
        command = "search"
        arguments = arguments[1:]
    parser = build_parser(prog="emberstrike search" if command else "emberstrike")
    argcomplete.autocomplete(parser)
    args = parser.parse_args(arguments)
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be at least 1.")
    no_color = args.no_color or "NO_COLOR" in os.environ
    console = Console(no_color=no_color, highlight=False)
    terminal_output = sys.stdout.isatty() and args.format == "plain"
    if terminal_output:
        render_banner(console)
    interactive = not args.non_interactive and sys.stdin.isatty()
    try:
        asset = _observation(args, console, interactive)
    except ValueError as exc:
        console.print(f"[bold red]Input error:[/] {exc}")
        return 2

    if not args.offline and args.format == "plain" and sys.stdout.isatty():
        with console.status("[bold cyan]Checking public vulnerability sources…[/]", spinner="dots"):
            report = run_research(asset, offline=False, limit=args.limit)
    else:
        report = run_research(asset, offline=args.offline, limit=args.limit)

    if args.format == "json":
        rendered = to_json(report)
    elif args.format == "markdown":
        rendered = to_markdown(report)
    else:
        rendered = to_plain(report)
    if args.output:
        try:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            Console(stderr=True, no_color=no_color, highlight=False).print(f"[bold red]Could not save report:[/] {exc}")
            return 1
        Console(stderr=True, no_color=no_color, highlight=False).print(f"[green]Report saved locally:[/] {args.output}")
    if terminal_output:
        _render_rich(report, console)
    else:
        print(rendered)
    return 0
