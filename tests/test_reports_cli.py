import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

from vuln_research.cli import (
    _observation,
    _render_rich,
    build_parser,
    main,
    render_banner,
)
from vuln_research.banner import BANNER
from vuln_research.models import Advisory, AssetObservation, AffectedRange, PossibleMatch, ResearchReport
from vuln_research.reports import advisory_to_plain, to_json, to_markdown, to_plain
from vuln_research.research import filter_report_severity, run_research
from vuln_research.selectable_table import _format_screen
from rich.console import Console
from unittest.mock import patch


class InputTests(unittest.TestCase):
    def test_branding_is_in_help_and_banner(self):
        help_text = build_parser().format_help()
        self.assertIn("EmberStrike", help_text)
        self.assertIn("LordXapose", help_text)
        for command in ("search", "services", "show CVE-ID"):
            self.assertIn(command, help_text)
        self.assertIn("--scope-notes", help_text)
        self.assertIn("--non-interactive", help_text)
        output = io.StringIO()
        render_banner(Console(file=output, no_color=True))
        self.assertIn("EmberStrike", output.getvalue())
        self.assertIn("LordXapose", output.getvalue())
        self.assertIn(BANNER.splitlines()[1], output.getvalue())
        self.assertNotRegex(output.getvalue(), re.compile(r"[\U0001F300-\U0001FAFF\U00002600-\U000027BF]"))

    def test_search_subcommand_works_with_flags(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = main([
                "search", "--assessment", "Q4", "--product", "Tomcat",
                "--offline", "--format", "json",
            ])
        self.assertEqual(result, 0)
        self.assertTrue(json.loads(stdout.getvalue())["offline"])

    def test_default_search_prints_match_table_for_redirected_output(self):
        asset = AssetObservation(assessment="Q4", product="Tomcat", vendor="Apache")
        advisory = Advisory(
            "CVE-2099-1234", "Example advisory",
            published="2099-01-02T03:04:05Z",
            severity="HIGH (CVSS 3.1)",
        )
        report = ResearchReport(
            asset,
            [PossibleMatch(advisory, "Medium", ["Name matches."], ["Build unknown."], [])],
        )
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("vuln_research.cli.run_research", return_value=report), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = main([
                "search", "-n", "Q4", "-p", "Tomcat", "--non-interactive",
            ])
        self.assertEqual(result, 0)
        self.assertIn("Vulnerability name", stdout.getvalue())
        self.assertIn("CVE-2099-1234", stdout.getvalue())
        self.assertIn("2099-01-02", stdout.getvalue())
        self.assertNotIn("Affected:", stdout.getvalue())

    def test_show_subcommand_renders_cve_advisory_without_exploit_steps(self):
        advisory = Advisory(
            "CVE-2025-12345", "Sample advisory",
            affected=[AffectedRange("Example Vendor", "Example Product", end_excluding="2.0")],
            description="A sample vulnerability description.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-12345"],
        )
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("vuln_research.cli.nvd.lookup", return_value=advisory), \
             patch("vuln_research.cli.cisa_kev.fetch_all", return_value=[]), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = main(["show", "CVE-2025-12345", "--format", "json"])
        self.assertEqual(result, 0)
        detail = json.loads(stdout.getvalue())
        self.assertEqual(detail["advisory"]["cve_id"], "CVE-2025-12345")
        self.assertIn("non-invasive", detail["safe_verification"])

    def test_show_plain_report_uses_compact_tables(self):
        advisory = Advisory(
            "CVE-2025-12345", "Long example vulnerability title",
            severity="HIGH (CVSS 3.1)",
            published="2025-01-02T03:04:05Z",
            description="A lengthy description that should not be printed in the compact view.",
            affected=[AffectedRange("Example Vendor", f"Product {index}") for index in range(20)],
            vendor_advisories=["https://vendor.example/advisory"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-12345"],
        )
        rendered = advisory_to_plain(advisory)
        self.assertIn("DETAILS FOR CVE-2025-12345", rendered)
        self.assertIn("SOURCE LINKS", rendered)
        self.assertIn("https://vendor.example/advisory", rendered)
        self.assertIn("and 17 more", rendered)
        self.assertNotIn("lengthy description", rendered)
        self.assertNotIn("Product 19", rendered)

    def test_selectable_table_draws_highlighted_bordered_rows_and_details(self):
        advisory = Advisory(
            "CVE-2099-0015",
            "Selectable example",
            severity="HIGH",
            published="2099-01-02",
        )
        match = PossibleMatch(advisory, "High", [], [], [])
        report = ResearchReport(
            AssetObservation(assessment="Q4", product="Tomcat"),
            [match],
        )
        list_fragments = _format_screen(report, 0, False, 100, 24)
        list_text = "".join(text for _, text in list_fragments)
        self.assertIn("+", list_text)
        self.assertIn("Vulnerability name", list_text)
        self.assertIn("CVE-2099-0015", list_text)
        self.assertIn("Enter to view details", list_text)
        self.assertTrue(any(style == "class:selected" for style, _ in list_fragments))
        detail_fragments = _format_screen(report, 0, True, 100, 24)
        detail_text = "".join(text for _, text in detail_fragments)
        self.assertIn("CVE DETAILS", detail_text)
        self.assertIn("SOURCE LINKS", detail_text)
        self.assertIn("Escape or Backspace", detail_text)

    def test_default_search_hides_low_severity_and_include_low_restores_it(self):
        low_advisory = Advisory(
            "CVE-2099-0001", "Low example",
            severity="LOW (CVSS 3.1)", published="2099-01-01",
        )
        high_advisory = Advisory(
            "CVE-2099-0002", "High example",
            severity="HIGH (CVSS 3.1)", published="2099-01-02",
        )
        source_report = ResearchReport(
            AssetObservation(assessment="Q4", product="Tomcat"),
            [
                PossibleMatch(low_advisory, "Low", [], [], []),
                PossibleMatch(high_advisory, "Medium", [], [], []),
            ],
        )
        report = filter_report_severity(source_report)
        self.assertEqual([item.advisory.cve_id for item in report.matches], ["CVE-2099-0002"])
        self.assertEqual(report.hidden_severity_matches, 1)

        all_report = ResearchReport(
            AssetObservation(assessment="Q4", product="Tomcat"),
            [
                PossibleMatch(low_advisory, "Low", [], [], []),
                PossibleMatch(high_advisory, "Medium", [], [], []),
            ],
        )
        filter_report_severity(all_report, include_low=True)
        self.assertEqual(len(all_report.matches), 2)
        self.assertEqual(all_report.hidden_severity_matches, 0)
        self.assertTrue(build_parser().parse_args(["--include-low"]).include_low)

    def test_search_include_low_flag_changes_cli_table(self):
        def make_report():
            return ResearchReport(
                AssetObservation(assessment="Q4", product="Tomcat"),
                [
                    PossibleMatch(
                        Advisory("CVE-2099-0011", "Low item", severity="LOW"),
                        "Medium", [], [], [],
                    ),
                    PossibleMatch(
                        Advisory("CVE-2099-0012", "Medium item", severity="MEDIUM"),
                        "High", [], [], [],
                    ),
                ],
            )

        for extra_args, expected_low in (([], False), (["--include-low"], True)):
            stdout = io.StringIO()
            with patch("vuln_research.cli.run_research", return_value=make_report()), \
                 contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                result = main([
                    "search", "-n", "Q4", "-p", "Tomcat", "--non-interactive",
                    *extra_args,
                ])
            self.assertEqual(result, 0)
            self.assertEqual("CVE-2099-0011" in stdout.getvalue(), expected_low)
            self.assertIn("CVE-2099-0012", stdout.getvalue())

    def test_flags_build_observation(self):
        args = build_parser().parse_args([
            "--assessment", "Q4", "--service", "web", "--product", "Tomcat",
            "--port", "8443", "--confidence", "High", "--non-interactive",
        ])
        observation = _observation(args, Console(), interactive=False)
        self.assertEqual(observation.port, 8443)
        self.assertEqual(observation.product, "Tomcat")

    def test_short_flags_and_services_catalog(self):
        args = build_parser().parse_args([
            "-n", "Q4", "-s", "HTTPS", "-p", "Apache Tomcat",
            "-v", "Apache", "-V", "9.0.80",
        ])
        observation = _observation(args, Console(), interactive=False)
        self.assertEqual(observation.service, "HTTPS")
        self.assertEqual(observation.product, "Apache Tomcat")
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = main(["services", "--no-color"])
        self.assertEqual(result, 0)
        self.assertIn("Apache Tomcat", stdout.getvalue())
        self.assertIn("SSH", stdout.getvalue())

    def test_requires_assessment_and_product_or_service(self):
        for argv, message in ((["--product", "Tomcat"], "assessment name"), (["--assessment", "Q4"], "product or service")):
            with self.subTest(argv=argv):
                args = build_parser().parse_args(argv)
                with self.assertRaisesRegex(ValueError, message):
                    _observation(args, Console(), interactive=False)

    def test_rejects_out_of_range_port(self):
        args = build_parser().parse_args(["--assessment", "Q4", "--product", "Tomcat", "--port", "70000"])
        with self.assertRaisesRegex(ValueError, "between 1 and 65535"):
            _observation(args, Console(), interactive=False)


class ReportTests(unittest.TestCase):
    def setUp(self):
        asset = AssetObservation(assessment="Q4", product="Tomcat", vendor="Apache")
        advisory = Advisory("CVE-2099-1234", "Example advisory", affected=[])
        self.report = ResearchReport(
            asset, [PossibleMatch(advisory, "Low", ["Product appears in description."], ["Build unknown."], [])],
        )

    def test_all_formats_include_possible_match_and_safety_language(self):
        self.assertIn("CVE-2099-1234", to_json(self.report))
        self.assertIn("Possible Vulnerability Matches", to_markdown(self.report))
        self.assertIn("does not confirm", to_markdown(self.report))
        self.assertIn("| Vulnerability name | CVE | Published |", to_markdown(self.report))
        plain = to_plain(self.report)
        self.assertIn("POSSIBLE VULNERABILITIES", plain)
        self.assertIn("Vulnerability name", plain)
        self.assertIn("Published", plain)
        self.assertIn("Example advisory", plain)
        self.assertNotIn("Affected:", plain)

    def test_json_file_saving_keeps_stdout_machine_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = main([
                    "--assessment", "Q4", "--product", "Tomcat", "--offline",
                    "--format", "json", "--output", str(path),
                ])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(path.read_text())["asset"]["assessment"], "Q4")
            self.assertEqual(json.loads(stdout.getvalue())["asset"]["assessment"], "Q4")
            self.assertIn("Report saved locally", stderr.getvalue())

    def test_terminal_view_includes_possible_cve_summary_table(self):
        output = io.StringIO()
        console = Console(file=output, no_color=True, width=120)
        _render_rich(self.report, console)
        self.assertIn("POSSIBLE VULNERABILITIES", output.getvalue())
        self.assertIn("CVE-2099-1234", output.getvalue())
        self.assertIn("Published", output.getvalue())
        self.assertNotIn("Missing evidence", output.getvalue())
        self.assertNotIn("NEXT STEPS", output.getvalue())
        self.assertNotRegex(output.getvalue(), re.compile(r"[\U0001F300-\U0001FAFF\U00002600-\U000027BF]"))


if __name__ == "__main__":
    unittest.main()
