#!/usr/bin/env python3
"""Build a conservative INCY Autorouting profile from public text feeds."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache"
BUILD = ROOT / "build"
DIST = ROOT / "dist"
TEMPLATE = ROOT / "config" / "profile.template.json"

SOURCES = {
    "direct_domains": "https://raw.githubusercontent.com/112fm/OpenSmart-Russia/main/direct-domains.txt",
    "direct_cidrs": "https://raw.githubusercontent.com/112fm/OpenSmart-Russia/main/direct-cidrs.txt",
    "sni_allowlist": "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/whitelist.txt",
}
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
LOCAL_IPS = [
    "127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
]
# Small, reviewed additions that are not present in the upstream curated feed.
# Keep this list narrow: every entry intentionally bypasses the proxy.
LOCAL_DIRECT_DOMAINS = ["rostics.ru", "order.rostics.ru"]


def download(name: str, url: str, offline: bool) -> str:
    path = CACHE / f"{name}.txt"
    if offline:
        if not path.exists():
            raise RuntimeError(f"Нет кэша для --offline: {path}")
        return path.read_text(encoding="utf-8")
    request = urllib.request.Request(url, headers={"User-Agent": "nidox-incy-routing/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            if response.status != 200:
                raise RuntimeError(f"{url}: HTTP {response.status}")
            content = response.read().decode("utf-8")
    except Exception as error:
        raise RuntimeError(f"Не удалось скачать {url}: {error}") from error
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return content


def meaningful_lines(text: str) -> list[str]:
    return [line.split("#", 1)[0].strip() for line in text.splitlines() if line.split("#", 1)[0].strip()]


def parse_domains(text: str) -> list[str]:
    values = {line.lower().rstrip(".") for line in meaningful_lines(text)}
    bad = sorted(value for value in values if not DOMAIN.fullmatch(value))
    if bad:
        raise ValueError(f"Некорректные домены: {', '.join(bad[:5])}")
    return sorted(values)


def parse_networks(text: str) -> list[str]:
    networks: set[str] = set()
    for value in meaningful_lines(text):
        network = ipaddress.ip_network(value, strict=True)
        minimum_prefix = 12 if network.version == 4 else 32
        if network.prefixlen < minimum_prefix:
            raise ValueError(f"Слишком широкая сеть для DIRECT: {network}")
        if network.is_private or network.is_loopback or network.is_multicast or network.is_unspecified:
            raise ValueError(f"Недопустимая внешняя сеть: {network}")
        networks.add(str(network))
    return sorted(networks, key=lambda value: (ipaddress.ip_network(value).version, int(ipaddress.ip_network(value).network_address), ipaddress.ip_network(value).prefixlen))


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def previous_generation() -> tuple[dict[str, str], str | None]:
    """Return source hashes and timestamp from the last valid local manifest."""
    manifest_path = DIST / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        hashes = {item["name"]: item["sha256"] for item in manifest["sources"]}
        hashes["local_direct_domains"] = manifest.get("localDirectDomainsSha256", "")
        generated_at = manifest["generatedAt"]
        if set(hashes) != set(SOURCES) | {"local_direct_domains"} or not str(generated_at).isdigit():
            raise ValueError("incomplete manifest")
        return hashes, str(generated_at)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return {}, None


def build(offline: bool = False, now: int | None = None) -> dict:
    raw = {name: download(name, url, offline) for name, url in SOURCES.items()}
    direct_domains = sorted(set(parse_domains(raw["direct_domains"])) | set(LOCAL_DIRECT_DOMAINS))
    direct_cidrs = parse_networks(raw["direct_cidrs"])
    sni_domains = parse_domains(raw["sni_allowlist"])
    profile = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    current_hashes = {name: sha256(raw[name]) for name in SOURCES}
    current_hashes["local_direct_domains"] = sha256("\n".join(LOCAL_DIRECT_DOMAINS) + "\n")
    old_hashes, old_generated_at = previous_generation()
    profile["LastUpdated"] = old_generated_at if old_hashes == current_hashes else str(int(time.time() if now is None else now))
    # Main profile mirrors INCY's "Bypass LAN" policy: only private and
    # local networks bypass the tunnel.  Keeping external services on the
    # proxy path avoids mixing direct and proxied sessions for sites that are
    # sensitive to the transport used during authentication.
    profile["DirectSites"] = []
    profile["DirectIp"] = LOCAL_IPS
    ru_direct_profile = profile | {
        "Name": "NIDOX · RU direct / proxy fallback",
        "DirectSites": direct_domains,
        "DirectIp": LOCAL_IPS + direct_cidrs,
    }
    manifest = {
        "generatedAt": profile["LastUpdated"],
        "generator": "scripts/build.py",
        "sources": [{"name": name, "url": SOURCES[name], "sha256": current_hashes[name]} for name in SOURCES],
        "counts": {"ruDirectDomains": len(direct_domains), "ruDirectCidrs": len(direct_cidrs), "diagnosticSniDomains": len(sni_domains)},
        "localDirectDomains": LOCAL_DIRECT_DOMAINS,
        "localDirectDomainsSha256": current_hashes["local_direct_domains"],
        "policy": "SNI allowlist is diagnostic only; it is not added to DirectSites.",
    }
    DIST.mkdir(parents=True, exist_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)
    (DIST / "profile.json").write_text(json.dumps(profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (DIST / "ru-direct-profile.json").write_text(
        json.dumps(ru_direct_profile, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (DIST / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (BUILD / "sni-allowlist.txt").write_text("\n".join(sni_domains) + "\n", encoding="utf-8")
    return profile


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="использовать .cache вместо сети")
    args = parser.parse_args()
    try:
        profile = build(offline=args.offline)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"build failed: {error}", file=sys.stderr)
        return 1
    print(f"Built {len(profile['DirectSites'])} DIRECT domains and {len(profile['DirectIp'])} DIRECT networks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
