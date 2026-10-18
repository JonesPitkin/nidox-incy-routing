import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build", ROOT / "scripts" / "build.py")
build = importlib.util.module_from_spec(SPEC)
sys.modules["build"] = build
SPEC.loader.exec_module(build)


class ParsingTests(unittest.TestCase):
    def test_domains_are_normalized_and_deduplicated(self):
        self.assertEqual(build.parse_domains("Example.RU\nexample.ru.\n# note\n"), ["example.ru"])

    def test_bad_domain_is_rejected(self):
        with self.assertRaises(ValueError):
            build.parse_domains("*.example.ru\n")

    def test_overly_broad_network_is_rejected(self):
        with self.assertRaises(ValueError):
            build.parse_networks("8.0.0.0/8\n")

    def test_networks_are_sorted(self):
        self.assertEqual(build.parse_networks("185.1.0.0/16\n5.0.0.0/16\n"), ["5.0.0.0/16", "185.1.0.0/16"])


class ProfileTests(unittest.TestCase):
    def test_profile_has_bypass_lan_policy_and_generates_optional_ru_direct_variant(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            cache = temporary / "cache"
            cache.mkdir()
            original_cache, original_dist, original_build = build.CACHE, build.DIST, build.BUILD
            build.CACHE = cache
            build.DIST = temporary / "dist"
            build.BUILD = temporary / "build"
            try:
                (cache / "direct_domains.txt").write_text("gosuslugi.ru\n", encoding="utf-8")
                (cache / "direct_cidrs.txt").write_text("185.1.0.0/16\n", encoding="utf-8")
                (cache / "sni_allowlist.txt").write_text("allowed-sni.example\n", encoding="utf-8")
                profile = build.build(offline=True, now=1700000000)
                unchanged_profile = build.build(offline=True, now=1700000999)
                ru_direct_profile = json.loads(
                    (temporary / "dist" / "ru-direct-profile.json").read_text(encoding="utf-8")
                )
            finally:
                build.CACHE, build.DIST, build.BUILD = original_cache, original_dist, original_build
        self.assertEqual(profile["GlobalProxy"], "true")
        self.assertEqual(profile["DirectSites"], [])
        self.assertIn("192.168.0.0/16", profile["DirectIp"])
        self.assertEqual(profile["LastUpdated"], "1700000000")
        self.assertEqual(unchanged_profile["LastUpdated"], "1700000000")
        self.assertEqual(profile["Name"], "NIDOX · Bypass LAN / proxy fallback")
        self.assertIn("gosuslugi.ru", ru_direct_profile["DirectSites"])
        self.assertIn("rostics.ru", ru_direct_profile["DirectSites"])
        self.assertIn("order.rostics.ru", ru_direct_profile["DirectSites"])
        self.assertNotIn("allowed-sni.example", ru_direct_profile["DirectSites"])
