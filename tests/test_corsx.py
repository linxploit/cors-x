"""
Basic unit tests for CorsX's origin-classification logic.

Run with:
    python3 -m unittest discover -s tests
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import corsx  # noqa: E402


class TestClassification(unittest.TestCase):

    def test_no_header_is_safe(self):
        risk, reflected, note = corsx.classify("reflected_arbitrary", "https://attacker.test", None, None)
        self.assertEqual(risk, "SAFE")
        self.assertFalse(reflected)

    def test_reflected_arbitrary_with_credentials_is_critical(self):
        risk, reflected, note = corsx.classify(
            "reflected_arbitrary", "https://attacker.test", "https://attacker.test", "true"
        )
        self.assertEqual(risk, "CRITICAL")
        self.assertTrue(reflected)

    def test_reflected_arbitrary_without_credentials_is_high(self):
        risk, reflected, note = corsx.classify(
            "reflected_arbitrary", "https://attacker.test", "https://attacker.test", "false"
        )
        self.assertEqual(risk, "HIGH")
        self.assertTrue(reflected)

    def test_wildcard_without_credentials_is_medium(self):
        risk, reflected, note = corsx.classify("reflected_arbitrary", "https://attacker.test", "*", None)
        self.assertEqual(risk, "MEDIUM")
        self.assertFalse(reflected)

    def test_wildcard_with_credentials_is_critical(self):
        risk, reflected, note = corsx.classify("reflected_arbitrary", "https://attacker.test", "*", "true")
        self.assertEqual(risk, "CRITICAL")

    def test_null_origin_with_credentials_is_high(self):
        risk, reflected, note = corsx.classify("null_origin", "null", "null", "true")
        self.assertEqual(risk, "HIGH")
        self.assertTrue(reflected)

    def test_null_origin_without_credentials_is_medium(self):
        risk, reflected, note = corsx.classify("null_origin", "null", "null", "false")
        self.assertEqual(risk, "MEDIUM")

    def test_bypass_trick_reflected_is_high_with_credentials(self):
        risk, reflected, note = corsx.classify(
            "suffix_trick", "https://target.test.attacker.test",
            "https://target.test.attacker.test", "true",
        )
        self.assertEqual(risk, "HIGH")
        self.assertTrue(reflected)

    def test_properly_scoped_allowlist_is_low(self):
        risk, reflected, note = corsx.classify(
            "reflected_arbitrary", "https://attacker.test", "https://trusted-partner.example", None
        )
        self.assertEqual(risk, "LOW")
        self.assertFalse(reflected)


class TestTestOriginMatrix(unittest.TestCase):

    def test_builds_seven_origins(self):
        origins = corsx.build_test_origins("target.example", "attacker.test")
        self.assertEqual(len(origins), 7)
        ids = [o[0] for o in origins]
        self.assertIn("reflected_arbitrary", ids)
        self.assertIn("null_origin", ids)

    def test_null_origin_value(self):
        origins = corsx.build_test_origins("target.example", "attacker.test")
        null_test = next(o for o in origins if o[0] == "null_origin")
        self.assertEqual(null_test[2], "null")


class TestScanResultAggregation(unittest.TestCase):

    def test_overall_risk_picks_worst(self):
        result = corsx.ScanResult(url="http://x")
        result.findings.append(corsx.CorsFinding(
            test_id="a", description="a", test_origin="o", risk="LOW",
        ))
        result.findings.append(corsx.CorsFinding(
            test_id="b", description="b", test_origin="o", risk="CRITICAL",
        ))
        self.assertEqual(result.overall_risk, "CRITICAL")

    def test_error_reported_as_error(self):
        result = corsx.ScanResult(url="http://x", error="Connection failed")
        self.assertEqual(result.overall_risk, "ERROR")

    def test_no_findings_defaults_safe(self):
        result = corsx.ScanResult(url="http://x")
        self.assertEqual(result.overall_risk, "SAFE")


if __name__ == "__main__":
    unittest.main()
