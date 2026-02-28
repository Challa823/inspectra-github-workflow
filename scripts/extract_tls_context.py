"""
extract_tls_context.py

Pre-processing step that reads:
  - jdk_info.json         (from detect_jdk.py)
  - java_releases.json    (from fetch_java_releases.py)
  - endpoints_scan.json   (from ssl_scan.py)

Extracts and writes tls_context.json with:
  {
    "tls version":                  [...unique TLS versions...],
    "Cipher version":               [...unique cipher suites...],
    "CurrentJdkVersion":            "17.0.17",
    "futureJDKMinorUpgradeVersion": "17.0.18" | "Unknown",
    "FutureMajorUpgradedVersion":   "21.0.9"  | "Unknown",
    "uniqusslerrors":               [...unique SSL errors...]
  }

This keeps build_prompt.py small — it receives only the extracted context,
not the full raw JSON blobs.
"""

import json
import os
import argparse
from packaging.version import Version, InvalidVersion


def load(path: str, fallback):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    print(f"[WARN] {path} not found, using fallback.")
    return fallback


def parse_version_safe(v: str):
    """Try to parse a version string; return None on failure."""
    try:
        return Version(str(v).split("+")[0].split("-")[0].strip())
    except (InvalidVersion, TypeError):
        return None


def extract_jdk_versions(jdk_info: dict, java_releases) -> tuple[str, str, str]:
    """
    Returns (current_version, future_minor_version, future_major_version).
    All as strings; "Unknown" when not determinable.
    """
    current_str = jdk_info.get("version", "Unknown")
    current_major = jdk_info.get("major", 0)
    current_v = parse_version_safe(current_str)

    if not isinstance(java_releases, list) or not java_releases:
        return current_str, "Unknown", "Unknown"

    # Collect all parseable versions from releases
    all_versions = []
    for rel in java_releases:
        # Support both {"version": "..."} and {"jdkVersion": "..."} shapes
        ver_str = rel.get("version") or rel.get("jdkVersion") or rel.get("tag_name") or ""
        v = parse_version_safe(ver_str)
        if v and v > (current_v or Version("0")):
            all_versions.append((v, ver_str))

    all_versions.sort(key=lambda x: x[0])

    future_minor = "Unknown"
    future_major = "Unknown"

    for v, ver_str in all_versions:
        major = v.major if v.major > 1 else (int(str(v).split(".")[0]) if "." in str(v) else 0)

        # Normalise: old-style "1.8.x" → major=8
        if major == 1:
            parts = str(v).split(".")
            major = int(parts[1]) if len(parts) > 1 else 1

        if future_minor == "Unknown" and major == current_major and (current_v is None or v > current_v):
            future_minor = ver_str

        if future_major == "Unknown" and major > current_major:
            future_major = ver_str

        if future_minor != "Unknown" and future_major != "Unknown":
            break

    return current_str, future_minor, future_major


def extract_tls_and_ciphers(endpoints_scan: list) -> tuple[list, list]:
    """Extract unique TLS versions and cipher suites from endpoints_scan."""
    tls_set = set()
    cipher_set = set()

    for ep in endpoints_scan:
        # Accept both field name styles
        tls = ep.get("tlsProtocol") or ep.get("tls version") or ""
        cipher = ep.get("cipherSuite") or ep.get("Cipher version") or ""

        tls = tls.strip()
        cipher = cipher.strip()

        if tls and tls not in ("<none>", ""):
            tls_set.add(tls)
        if cipher and cipher not in ("<none>", ""):
            cipher_set.add(cipher)

    return sorted(tls_set), sorted(cipher_set)


def extract_ssl_errors(endpoints_scan: list) -> list:
    """Aggregate unique SSL errors across all endpoints."""
    error_set = set()
    for ep in endpoints_scan:
        errors = ep.get("errors", [])
        if isinstance(errors, list):
            for e in errors:
                e = e.strip()
                if e:
                    error_set.add(e)
        elif isinstance(errors, str) and errors.strip():
            error_set.add(errors.strip())
    return sorted(error_set)


def extract_tls_context(jdk_info: dict, java_releases, endpoints_scan: list) -> dict:
    current_ver, future_minor, future_major = extract_jdk_versions(jdk_info, java_releases)
    tls_versions, cipher_versions = extract_tls_and_ciphers(endpoints_scan)
    ssl_errors = extract_ssl_errors(endpoints_scan)

    return {
        "tls version":                  tls_versions,
        "Cipher version":               cipher_versions,
        "CurrentJdkVersion":            current_ver,
        "futureJDKMinorUpgradeVersion": future_minor,
        "FutureMajorUpgradedVersion":   future_major,
        "uniqusslerrors":               ssl_errors,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract TLS context for prompt building")
    parser.add_argument("--jdk-info",        default="jdk_info.json",        help="Path to jdk_info.json")
    parser.add_argument("--java-releases",   default="java_releases.json",   help="Path to java_releases.json")
    parser.add_argument("--endpoints-scan",  default="endpoints_scan.json",  help="Path to endpoints_scan.json")
    parser.add_argument("--output",          default="tls_context.json",     help="Output path for extracted context")
    args = parser.parse_args()

    jdk_info       = load(args.jdk_info,       {"vendor": "Unknown", "version": "Unknown", "major": 0})
    java_releases  = load(args.java_releases,  [])
    endpoints_scan = load(args.endpoints_scan, [])

    context = extract_tls_context(jdk_info, java_releases, endpoints_scan)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(context, f, indent=2)

    print(f"[INFO] TLS context written to {args.output}")
    print(f"       TLS versions      : {context['tls version']}")
    print(f"       Cipher suites     : {context['Cipher version']}")
    print(f"       CurrentJDK        : {context['CurrentJdkVersion']}")
    print(f"       FutureMinor       : {context['futureJDKMinorUpgradeVersion']}")
    print(f"       FutureMajor       : {context['FutureMajorUpgradedVersion']}")
    print(f"       Unique SSL errors : {len(context['uniqusslerrors'])}")
