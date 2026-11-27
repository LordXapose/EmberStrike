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
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from .cache import (
    DEFAULT_TTL_SECONDS,
    cache_directory,
    capture_cache_events,
    clear_cache,
    format_age,
    format_cache_events,
    list_cache_entries,
)
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
from .research import filter_report_severity, run_research
from .selectable_table import (
    build_detail_tables,
    build_results_table,
    random_palette,
    run_selectable_table,
)
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
  emberstrike cache [clear]         View or clear the local public-source cache
  emberstrike COMMAND --help        Show help for search, services, show, or cache

EXAMPLES
  emberstrike
  emberstrike search -n "Quarterly review" -s HTTPS -p "Apache Tomcat" -v Apache -V 9.0.80
  emberstrike services
  emberstrike show CVE-2023-42794
  emberstrike cache
  emberstrike cache clear
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
    output.add_argument("--offline", action="store_true", help="Use only matching local cache entries; never access the network")
    output.add_argument("--refresh-cache", action="store_true", help="Refresh matching cache entries from public sources")
    output.add_argument("--no-color", action="store_true", help="Disable color (also respects NO_COLOR)")
    output.add_argument("--limit", type=int, help="Maximum possible matches to report (default: all matches)")
    output.add_argument(
        "--include-low",
        action="store_true",
        help="Include Low and unscored severity results (hidden by default)",
    )
    output.add_argument("--non-interactive", action="store_true", help="Do not prompt; fail if required input is missing")
    service_action.completer = ChoicesCompleter(SERVICE_TYPES)
    product_action.completer = ChoicesCompleter(PRODUCTS)
    vendor_action.completer = ChoicesCompleter(VENDORS)
    return parser


def _cache_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="emberstrike cache",
        description="Inspect or clear EmberStrike's local public-source response cache.",
    )
    parser.add_argument("action", nargs="?", choices=("status", "clear"), default="status")
    parser.add_argument("--no-color", action="store_true", help="Disable terminal color")
    args = parser.parse_args(argv)
    console = Console(no_color=args.no_color or "NO_COLOR" in os.environ, highlight=False)
    if args.action == "clear":
        try:
            removed = clear_cache()
        except OSError as exc:
            console.print(f"[bold red]Could not clear cache:[/] {exc}")
            return 1
        console.print(f"Cleared {removed} cached response(s).")
        return 0

    entries = list_cache_entries()
    console.print(f"Cache directory: {cache_directory()}")
    if not entries:
        console.print("No cached public-source responses.")
        return 0

    palette = random_palette()
    table = Table(
        title="LOCAL SOURCE CACHE",
        border_style=palette["border"],
        header_style=f"bold {palette['header']}",
        title_style=f"bold {palette['title']}",
        box=box.ASCII,
        show_lines=False,
    )
    table.add_column("Source", style=palette["name"])
    table.add_column("Cached at", style=palette["published"])
    table.add_column("Age", style=palette["severity"])
    table.add_column("Freshness", style=palette["detail_value"])
    for entry in entries:
        age_seconds = entry["age_seconds"]
        age = format_age(age_seconds) if isinstance(age_seconds, int) and age_seconds >= 0 else "Unknown"
        freshness = (
            "Fresh" if isinstance(age_seconds, int) and 0 <= age_seconds < DEFAULT_TTL_SECONDS
            else "Expired"
        )
        table.add_row(str(entry["source"]), str(entry["cached_at"]), age, freshness)
    console.print(table)
    console.print("[dim]Default cache freshness: 24 hours. Use --refresh-cache to update entries.[/]")
    return 0


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
    palette = random_palette()
    table = Table(
        title="COMMON SERVICE AND PRODUCT SUGGESTIONS",
        border_style=palette["border"],
        header_style=f"bold {palette['header']}",
        title_style=f"bold {palette['title']}",
        show_lines=False,
        box=box.ASCII,
    )
    table.add_column("Service types (-s)", style=palette["name"])
    table.add_column("Products (-p)", style=palette["cve"])
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
    console.print(build_results_table(report, width=console.width))
    console.print("[dim]Possible matches only; no requests were sent to the assessed asset.[/]")
    if report.hidden_severity_matches:
        console.print(
            f"[dim]{report.hidden_severity_matches} Low or unscored result(s) hidden. "
            "Use --include-low to show all severities.[/]"
        )
    if report.offline:
        console.print("[dim]Offline mode: no network requests were made; matching cached data may be used.[/]")
    for status in report.source_status:
        console.print(f"[dim]Source status: {status}[/]")
    if report.source_warnings:
        palette = random_palette()
        notices = Table(
            title="Source notices",
            border_style=palette["border"],
            header_style=f"bold {palette['header']}",
            title_style=f"bold {palette['title']}",
            show_lines=False,
            box=box.ASCII,
        )
        notices.add_column("Source", style=palette["detail_value"])
        for warning in report.source_warnings:
            notices.add_row(warning)
        console.print(notices)


def _render_advisory(advisory: Advisory, source_warnings: list[str], console: Console) -> None:
    details, links = build_detail_tables(advisory, width=console.width)
    console.print(details)
    console.print(links)
    console.print("[dim]Public advisory only; verify installed versions using an authorized inventory.[/]")
    for warning in source_warnings:
        console.print(f"[yellow]Source notice:[/] {warning}")


def _show_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="emberstrike show",
        description="Show public advisory details for one CVE. This command does not provide exploit instructions or contact a target.",
        epilog="Displays CVSS score/vector, CWE, affected configuration context, dates, KEV status, remediation, source attribution, primary links, and safe verification guidance.",
    )
    parser.add_argument("--format", choices=("plain", "json", "markdown"), default="plain")
    parser.add_argument("--output", type=Path, help="Save the advisory report locally")
    parser.add_argument("--no-color", action="store_true", help="Disable terminal color")
    parser.add_argument("--offline", action="store_true", help="Use only matching local cache entries; never access the network")
    parser.add_argument("--refresh-cache", action="store_true", help="Refresh matching cache entries from public sources")
    parser.add_argument("cve_id", help="CVE identifier, e.g. CVE-2023-42794")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", args.cve_id.upper()):
        parser.error("Use a CVE identifier such as CVE-2025-12345.")
    if args.offline and args.refresh_cache:
        parser.error("--offline cannot be used with --refresh-cache.")

    no_color = args.no_color or "NO_COLOR" in os.environ
    console = Console(no_color=no_color, highlight=False)
    terminal_output = sys.stdout.isatty() and args.format == "plain"
    if terminal_output:
        render_banner(console)

    source_warnings = []
    with capture_cache_events() as cache_events:
        try:
            advisory = nvd.lookup(
                args.cve_id.upper(),
                offline=args.offline,
                refresh=args.refresh_cache,
            )
        except SourceError as exc:
            advisory = None
            source_warnings.append(f"NVD: {exc}")
        try:
            kev_advisory = next(
                (
                    item for item in cisa_kev.fetch_all(
                        offline=args.offline,
                        refresh=args.refresh_cache,
                    )
                    if item.cve_id.upper() == args.cve_id.upper()
                ),
                None,
            )
        except SourceError as exc:
            kev_advisory = None
            source_warnings.append(f"CISA KEV: {exc}")
    source_warnings.extend(format_cache_events(cache_events))
    if args.offline:
        source_warnings.insert(0, "Offline mode: no network requests were made; cache-only lookup.")

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
    if arguments and arguments[0] == "cache":
        return _cache_main(arguments[1:])
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
    if args.offline and args.refresh_cache:
        parser.error("--offline cannot be used with --refresh-cache.")
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
            report = run_research(
                asset,
                offline=False,
                limit=args.limit,
                refresh_cache=args.refresh_cache,
            )
    else:
        report = run_research(
            asset,
            offline=args.offline,
            limit=args.limit,
            refresh_cache=args.refresh_cache,
        )
    filter_report_severity(report, include_low=args.include_low)

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
    interactive_selection = terminal_output and sys.stdin.isatty() and not args.non_interactive
    if terminal_output and not interactive_selection:
        _render_rich(report, console)
    elif interactive_selection:
        run_selectable_table(report, no_color=no_color)
    else:
        print(rendered)
    return 0
