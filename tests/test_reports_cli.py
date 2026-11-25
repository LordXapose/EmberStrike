import contextlib
import io
import json
import re
import tempfile
import unittest
from pathlib import Path

from vuln_research.cli import build_parser, main, render_banner, _observation, _render_rich
from vuln_research.banner import BANNER
from vuln_research.models import Advisory, AssetObservation, AffectedRange, PossibleMatch, ResearchReport
from vuln_research.reports import to_json, to_markdown, to_plain
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
        self.assertIn("POSSIBLE MATCHES", to_markdown(self.report))
        self.assertIn("written authorization", to_markdown(self.report))
        self.assertIn("POSSIBLE MATCHES", to_plain(self.report))
        self.assertIn("not proof", to_plain(self.report))

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
        self.assertIn("POSSIBLE CVE MATCHES", output.getvalue())
        self.assertIn("CVE-2099-1234", output.getvalue())
        self.assertNotRegex(output.getvalue(), re.compile(r"[\U0001F300-\U0001FAFF\U00002600-\U000027BF]"))


if __name__ == "__main__":
    unittest.main()
