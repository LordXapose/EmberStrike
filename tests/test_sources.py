import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

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


if __name__ == "__main__":
    unittest.main()
