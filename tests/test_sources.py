import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.error import URLError
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from vuln_research.cache import (
    capture_cache_events,
    clear_cache,
    format_cache_events,
    list_cache_entries,
)
from vuln_research.models import AssetObservation
from vuln_research.research import run_research
from vuln_research.sources.base import SourceError, fetch_json
from vuln_research.sources.nvd import _parse_criteria, search


class NvdParsingTests(unittest.TestCase):
    def test_cpe_parser_keeps_escaped_colons_inside_fields(self):
        self.assertEqual(
            _parse_criteria(r"cpe:2.3:a:example:product\:edition:2.1:*:*:*:*:*:*:*"),
            ("example", "product:edition", "2.1"),
        )

    def test_only_primary_and_vendor_advisory_links_are_reported(self):
        cpe = {
            "vulnerable": True,
            "criteria": "cpe:2.3:a:apache:tomcat:9.0.80:*:*:*:*:*:*:*",
        }
        response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2099-0001",
                    "descriptions": [{"lang": "en", "value": "Example advisory."}],
                    "references": [
                        {"url": "https://vendor.example/security", "tags": ["Vendor Advisory"]},
                        {"url": "https://example.test/poc", "tags": ["Exploit"]},
                    ],
                    "configurations": [{"nodes": [{"cpeMatch": [cpe, cpe]}]}],
                },
            }],
        }
        with patch("vuln_research.sources.nvd.fetch_json", return_value=response):
            advisory = search("Apache Tomcat")[0]
        self.assertEqual(len(advisory.affected), 1)
        self.assertEqual(
            advisory.references,
            ["https://nvd.nist.gov/vuln/detail/CVE-2099-0001"],
        )
        self.assertEqual(advisory.vendor_advisories, ["https://vendor.example/security"])

    def test_search_fetches_every_nvd_page(self):
        def response_for_url(url, timeout):
            params = parse_qs(urlparse(url).query)
            start_index = int(params["startIndex"][0])
            page_items = [{
                "cve": {
                    "id": f"CVE-2099-{index:04d}",
                    "descriptions": [{"lang": "en", "value": "Example advisory."}],
                    "references": [],
                    "configurations": [],
                },
            } for index in range(start_index + 1, min(start_index + 3, 5 + 1))]
            return {
                "totalResults": 5,
                "startIndex": start_index,
                "resultsPerPage": 2,
                "vulnerabilities": page_items,
            }

        with patch("vuln_research.sources.nvd.fetch_json", side_effect=response_for_url) as fetch:
            advisories = search("Example product")
        self.assertEqual(len(advisories), 5)
        self.assertEqual(fetch.call_count, 3)

    def test_search_limit_stops_pagination(self):
        response = {
            "totalResults": 10,
            "startIndex": 0,
            "resultsPerPage": 2,
            "vulnerabilities": [{
                "cve": {
                    "id": f"CVE-2099-{index:04d}",
                    "descriptions": [{"lang": "en", "value": "Example advisory."}],
                    "references": [],
                    "configurations": [],
                },
            } for index in range(2)],
        }
        with patch("vuln_research.sources.nvd.fetch_json", return_value=response) as fetch:
            advisories = search("Example product", limit=1)
        self.assertEqual(len(advisories), 1)
        self.assertEqual(fetch.call_count, 1)


class SourceCacheTests(unittest.TestCase):
    class Response:
        def __init__(self, value):
            self.value = value

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def read(self):
            return json.dumps(self.value).encode()

    def test_cache_hit_and_offline_reuse_do_not_repeat_requests(self):
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Tomcat"
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"EMBERSTRIKE_CACHE_DIR": directory}
        ):
            with patch(
                "vuln_research.sources.base.urlopen",
                return_value=self.Response({"result": "cached"}),
            ) as request:
                with capture_cache_events() as first_events:
                    self.assertEqual(fetch_json(url), {"result": "cached"})
                with capture_cache_events() as hit_events:
                    self.assertEqual(fetch_json(url), {"result": "cached"})
                with capture_cache_events() as offline_events:
                    self.assertEqual(fetch_json(url, offline=True), {"result": "cached"})

            self.assertEqual(request.call_count, 1)
            self.assertIn("fetched and cached", " ".join(format_cache_events(first_events)))
            self.assertIn("cached", " ".join(format_cache_events(hit_events)))
            self.assertIn("cached offline", " ".join(format_cache_events(offline_events)))
            self.assertEqual(len(list_cache_entries()), 1)
            if hasattr(os, "fchmod"):
                cache_file = next(Path(directory).glob("*.json"))
                self.assertEqual(os.stat(cache_file).st_mode & 0o777, 0o600)
            self.assertEqual(clear_cache(), 1)
            self.assertEqual(list_cache_entries(), [])

    def test_offline_cache_miss_never_attempts_network(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"EMBERSTRIKE_CACHE_DIR": directory}
        ), patch("vuln_research.sources.base.urlopen") as request:
            with self.assertRaisesRegex(SourceError, "No cached response"):
                fetch_json("https://www.cisa.gov/feed.json", offline=True)
            request.assert_not_called()

    def test_failed_refresh_uses_cached_data_and_reports_staleness(self):
        url = "https://www.cisa.gov/feed.json"
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"EMBERSTRIKE_CACHE_DIR": directory}
        ):
            with patch(
                "vuln_research.sources.base.urlopen",
                return_value=self.Response({"vulnerabilities": []}),
            ):
                fetch_json(url)
            with patch(
                "vuln_research.sources.base.urlopen",
                side_effect=URLError("network unavailable"),
            ):
                with capture_cache_events() as events:
                    result = fetch_json(url, refresh=True)
            self.assertEqual(result, {"vulnerabilities": []})
            status = " ".join(format_cache_events(events))
            self.assertIn("stale cache", status)
            self.assertIn("network or timeout", status)

    def test_offline_research_only_reads_matching_cache_entries(self):
        asset = AssetObservation(assessment="test", product="Tomcat", vendor="Apache")
        with patch("vuln_research.research.nvd.search", return_value=[]) as nvd_search, patch(
            "vuln_research.research.cisa_kev.fetch_all", return_value=[]
        ) as kev_fetch:
            report = run_research(asset, offline=True)
        self.assertTrue(report.offline)
        nvd_search.assert_called_once_with("Apache Tomcat", offline=True, refresh=False)
        kev_fetch.assert_called_once_with(offline=True, refresh=False)


if __name__ == "__main__":
    unittest.main()
