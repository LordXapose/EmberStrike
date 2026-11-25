import unittest
from unittest.mock import patch

from vuln_research.sources.nvd import search


class NvdParsingTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
