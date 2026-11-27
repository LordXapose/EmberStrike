import unittest

from vuln_research.matching import match_advisory, rank_matches
from vuln_research.models import Advisory, AffectedRange, AssetObservation


class MatchingTests(unittest.TestCase):
    def setUp(self):
        self.asset = AssetObservation(
            assessment="test", product="Tomcat", vendor="Apache",
            version="9.0.80", build="package-1", identified_by="inventory",
            confidence="High",
        )

    def test_exact_product_and_range_is_high_but_still_a_possible_match(self):
        advisory = Advisory(
            cve_id="CVE-2099-0001", title="Example issue",
            affected=[AffectedRange(
                vendor="apache", product="tomcat", start_including="9.0.0",
                end_excluding="9.0.90",
            )],
        )
        result = match_advisory(advisory, self.asset)
        self.assertIsNotNone(result)
        self.assertEqual(result.confidence, "High")
        self.assertIn("falls within", " ".join(result.why_match))

    def test_out_of_range_version_is_low_and_conflicting(self):
        advisory = Advisory(
            cve_id="CVE-2099-0002", title="Example issue",
            affected=[AffectedRange(
                vendor="Apache", product="Tomcat", end_excluding="9.0.70",
            )],
        )
        result = match_advisory(advisory, self.asset)
        self.assertEqual(result.confidence, "Low")
        self.assertTrue(result.conflicting_evidence)

    def test_exact_version_accepts_equivalent_standard_version_prefix(self):
        advisory = Advisory(
            cve_id="CVE-2099-0011", title="Exact version issue",
            affected=[AffectedRange(vendor="Apache", product="Tomcat", version="v9.0.80")],
        )
        result = match_advisory(advisory, self.asset)
        self.assertEqual(result.confidence, "High")
        self.assertIn("falls within", " ".join(result.why_match))

    def test_version_range_respects_inclusive_and_exclusive_endpoints(self):
        inclusive = Advisory(
            cve_id="CVE-2099-0012", title="Inclusive endpoint",
            affected=[AffectedRange(
                vendor="Apache", product="Tomcat",
                start_including="9.0.80", end_including="9.0.80",
            )],
        )
        exclusive = Advisory(
            cve_id="CVE-2099-0013", title="Exclusive endpoint",
            affected=[AffectedRange(
                vendor="Apache", product="Tomcat",
                start_including="9.0.0", end_excluding="9.0.80",
            )],
        )
        self.assertEqual(match_advisory(inclusive, self.asset).confidence, "High")
        result = match_advisory(exclusive, self.asset)
        self.assertEqual(result.confidence, "Low")
        self.assertTrue(result.conflicting_evidence)

    def test_unparseable_vendor_version_stays_uncertain(self):
        self.asset.version = "9.0.80-redhat1"
        advisory = Advisory(
            cve_id="CVE-2099-0014", title="Vendor version issue",
            affected=[AffectedRange(
                vendor="Apache", product="Tomcat",
                start_including="9.0.0", end_excluding="9.0.90",
            )],
        )
        result = match_advisory(advisory, self.asset)
        self.assertEqual(result.confidence, "Medium")
        self.assertTrue(any("comparable affected-version range" in item for item in result.missing_evidence))
        self.assertFalse(result.conflicting_evidence)

    def test_medium_observation_caps_match_confidence(self):
        self.asset.confidence = "Medium"
        advisory = Advisory(
            cve_id="CVE-2099-0007", title="Example issue",
            affected=[AffectedRange(
                vendor="Apache", product="Tomcat", start_including="9.0.0",
                end_excluding="9.0.90",
            )],
        )
        self.assertEqual(match_advisory(advisory, self.asset).confidence, "Medium")

    def test_unrelated_product_is_not_returned(self):
        advisory = Advisory(
            cve_id="CVE-2099-0003", title="Example issue",
            affected=[AffectedRange(vendor="OpenSSL", product="OpenSSL")],
        )
        self.assertIsNone(match_advisory(advisory, self.asset))

    def test_vendor_name_alone_does_not_match_a_product(self):
        advisory = Advisory(
            cve_id="CVE-2099-0005", title="Vendor-level catalog entry",
            affected=[AffectedRange(vendor="Apache", product="Apache")],
        )
        self.assertIsNone(match_advisory(advisory, self.asset))

    def test_partial_product_names_do_not_match(self):
        advisory = Advisory(
            cve_id="CVE-2099-0008", title="Example issue",
            affected=[AffectedRange(vendor="Apache", product="Tomcat Embed Core")],
        )
        self.assertIsNone(match_advisory(advisory, self.asset))

    def test_vendor_prefix_in_observed_product_is_handled_exactly(self):
        self.asset.product = "Apache Tomcat"
        advisory = Advisory(
            cve_id="CVE-2099-0009", title="Example issue",
            affected=[AffectedRange(
                vendor="Apache", product="Tomcat", start_including="9.0.0",
                end_excluding="9.0.90",
            )],
        )
        result = match_advisory(advisory, self.asset)
        self.assertIsNotNone(result)
        self.assertEqual(result.confidence, "High")

    def test_known_product_alias_matches_without_substring_guessing(self):
        self.asset.product = "Microsoft IIS"
        self.asset.vendor = "Microsoft"
        self.asset.version = "10.0"
        advisory = Advisory(
            cve_id="CVE-2099-0010", title="Example issue",
            affected=[AffectedRange(
                vendor="Microsoft", product="Internet Information Services",
                start_including="10.0", end_excluding="11.0",
            )],
        )
        result = match_advisory(advisory, self.asset)
        self.assertIsNotNone(result)
        self.assertEqual(result.confidence, "High")

    def test_description_only_match_is_low_confidence(self):
        advisory = Advisory(
            cve_id="CVE-2099-0006",
            title="Another component",
            description="A separate component used with Apache Tomcat can be affected.",
        )
        result = match_advisory(advisory, self.asset)
        self.assertIsNotNone(result)
        self.assertEqual(result.confidence, "Low")

    def test_merge_keeps_cisa_exploitation_status(self):
        nvd = Advisory(
            "CVE-2099-0004", "NVD title",
            affected=[AffectedRange("Apache", "Tomcat"), AffectedRange("Apache", "Tomcat")],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2099-0004"],
            sources=["NVD"],
        )
        kev = Advisory(
            "CVE-2099-0004", "CISA title",
            affected=[AffectedRange("Apache", "Tomcat")],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2099-0004"],
            known_exploited=True, sources=["CISA KEV"],
        )
        result = rank_matches([nvd, kev], self.asset)[0]
        self.assertTrue(result.advisory.known_exploited)
        self.assertEqual(set(result.advisory.sources), {"NVD", "CISA KEV"})
        self.assertEqual(len(result.advisory.affected), 1)
        self.assertEqual(len(result.advisory.references), 1)

    def test_returns_all_matches_unless_a_limit_is_given(self):
        advisories = [
            Advisory(f"CVE-2099-001{i}", f"Example {i}", affected=[AffectedRange("Apache", "Tomcat")])
            for i in range(3)
        ]
        self.assertEqual(len(rank_matches(advisories, self.asset)), 3)
        self.assertEqual(len(rank_matches(advisories, self.asset, limit=1)), 1)


if __name__ == "__main__":
    unittest.main()
