import importlib.util
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
    def test_profile_has_proxy_fallback_and_does_not_use_sni_as_direct(self):
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
            finally:
                build.CACHE, build.DIST, build.BUILD = original_cache, original_dist, original_build
        self.assertEqual(profile["GlobalProxy"], "true")
        self.assertIn("gosuslugi.ru", profile["DirectSites"])
        self.assertNotIn("allowed-sni.example", profile["DirectSites"])
        self.assertEqual(profile["LastUpdated"], "1700000000")
        self.assertEqual(unchanged_profile["LastUpdated"], "1700000000")
        self.assertEqual(profile["Name"], "NIDOX · RU direct / proxy fallback")
