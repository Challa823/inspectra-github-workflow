"""
fetch_java_releases.py

Fetches available Java/JDK release versions and normalises them into a flat list:
  [ {"version": "17.0.12", "major": 17, "lts": true, "source": "adoptium"}, ... ]

Sources tried in priority order:
  1. Eclipse Temurin / Adoptium API  (reliable, always returns JSON)
  2. Oracle Java Releases Cloud API  (fallback, sometimes unreliable/firewalled)

Output is written to --output (default: java_releases.json).
"""

import argparse
import json
import os
import sys
import requests

ADOPTIUM_INFO_URL   = "https://api.adoptium.net/v3/info/available_releases"
ADOPTIUM_LATEST_URL = "https://api.adoptium.net/v3/assets/latest/{major}/hotspot"
ORACLE_URL          = "https://java.oraclecloud.com/javaReleases"

TIMEOUT = 15  # seconds per request


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _get(url: str, label: str, params: dict | None = None) -> requests.Response | None:
    """GET with full request/response debug logging. Returns Response or None."""
    print(f"[DEBUG] --> GET {url}" + (f"  params={params}" if params else ""))
    try:
        resp = requests.get(url, params=params, timeout=TIMEOUT,
                            headers={"Accept": "application/json"})
        print(f"[DEBUG] <-- {resp.status_code} {resp.reason}  "
              f"content-type={resp.headers.get('content-type','?')}  "
              f"bytes={len(resp.content)}")
        preview = resp.text[:400].replace("\n", " ")
        print(f"[DEBUG]     body preview: {preview}")
        resp.raise_for_status()
        return resp
    except requests.Timeout:
        print(f"[WARN]  {label}: request timed out after {TIMEOUT}s")
    except requests.HTTPError as exc:
        print(f"[WARN]  {label}: HTTP error – {exc}")
    except requests.RequestException as exc:
        print(f"[WARN]  {label}: connection error – {exc}")
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Source 1 – Eclipse Temurin / Adoptium
# ──────────────────────────────────────────────────────────────────────────────

def _fetch_adoptium() -> list[dict]:
    """
    1. GET /v3/info/available_releases  → list of LTS + non-LTS major versions
    2. For each major: GET /v3/assets/latest/{major}/hotspot  → semver string
    Returns normalised list [{version, major, lts, source}]
    """
    print("[INFO] Trying Adoptium (Eclipse Temurin) API …")
    resp = _get(ADOPTIUM_INFO_URL, "Adoptium info")
    if resp is None:
        return []

    try:
        info = resp.json()
    except ValueError as exc:
        print(f"[WARN]  Adoptium info: JSON parse error – {exc}")
        return []

    lts_set = set(info.get("available_lts_releases", []))
    all_majors = info.get("available_releases", [])
    print(f"[INFO]  Adoptium: majors={all_majors}  LTS={sorted(lts_set)}")

    releases: list[dict] = []
    for major in all_majors:
        params = {
            "architecture": "x64",
            "image_type":   "jdk",
            "jvm_impl":     "hotspot",
            "os":           "linux",
            "vendor":       "eclipse",
        }
        r2 = _get(ADOPTIUM_LATEST_URL.format(major=major),
                  f"Adoptium latest/{major}", params=params)
        if r2 is None:
            print(f"[WARN]  Adoptium latest/{major}: skipping")
            releases.append({
                "version": str(major),
                "major":   major,
                "lts":     major in lts_set,
                "source":  "adoptium",
            })
            continue

        try:
            assets = r2.json()
        except ValueError as exc:
            print(f"[WARN]  Adoptium latest/{major}: JSON parse – {exc}")
            continue

        if not isinstance(assets, list) or not assets:
            print(f"[WARN]  Adoptium latest/{major}: empty asset list")
            continue

        # assets[0].version.semver  e.g. "17.0.12+7"
        semver = (assets[0].get("version") or {}).get("semver", "")
        if not semver:
            semver = assets[0].get("release_name", str(major))

        # strip build metadata (+7)
        clean = semver.split("+")[0].split("-")[0].strip()
        print(f"[INFO]  Adoptium JDK {major}: version={clean}")
        releases.append({
            "version": clean,
            "major":   major,
            "lts":     major in lts_set,
            "source":  "adoptium",
        })

    return releases


# ──────────────────────────────────────────────────────────────────────────────
# Source 2 – Oracle Java Releases Cloud API (fallback)
# ──────────────────────────────────────────────────────────────────────────────

def _fetch_oracle() -> list[dict]:
    """
    GET https://java.oraclecloud.com/javaReleases
    Oracle returns a JSON object with a "items" list or a flat list.
    We normalise to [{version, major, lts, source}].
    """
    print("[INFO] Trying Oracle Java Releases API …")
    resp = _get(ORACLE_URL, "Oracle javaReleases")
    if resp is None:
        return []

    try:
        raw = resp.json()
    except ValueError as exc:
        print(f"[WARN]  Oracle: JSON parse error – {exc}")
        return []

    # Oracle may return:  {"items": [...], ...}  or  [...]
    items = raw if isinstance(raw, list) else raw.get("items", [])
    print(f"[INFO]  Oracle: {len(items)} raw release records")

    releases: list[dict] = []
    for item in items:
        # field names vary by Oracle API version
        ver = (item.get("jdkVersion")
               or item.get("version")
               or item.get("releaseVersion")
               or "")
        if not ver:
            continue
        ver = str(ver).strip()
        try:
            major = int(ver.split(".")[0])
            if major == 1:          # old-style 1.8.x
                major = int(ver.split(".")[1])
        except (ValueError, IndexError):
            major = 0

        releases.append({
            "version": ver,
            "major":   major,
            "lts":     item.get("lts", item.get("isLTS", False)),
            "source":  "oracle",
        })

    releases.sort(key=lambda r: r["major"])
    return releases


# ──────────────────────────────────────────────────────────────────────────────
# Public entry point
# ──────────────────────────────────────────────────────────────────────────────

def fetch_java_releases() -> list[dict]:
    """Try Adoptium first, Oracle second. Always returns a list (may be empty)."""
    releases = _fetch_adoptium()
    if releases:
        print(f"[INFO] Adoptium returned {len(releases)} release records.")
        return releases

    print("[WARN] Adoptium returned nothing – falling back to Oracle.")
    releases = _fetch_oracle()
    if releases:
        print(f"[INFO] Oracle returned {len(releases)} release records.")
        return releases

    print("[ERROR] All sources failed. Returning empty release list.")
    return []


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch Java/JDK release versions")
    parser.add_argument(
        "--output", default="java_releases.json",
        help="Output JSON file path (default: java_releases.json)"
    )
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    releases = fetch_java_releases()

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(releases, f, indent=2)

    print(f"[INFO] {len(releases)} release records written to {args.output}")
    if releases:
        print(f"[INFO] Sample: {json.dumps(releases[:3], indent=2)}")
    else:
        print("[WARN] No releases fetched – downstream steps will see an empty list.")
        sys.exit(1)   # non-zero so CI marks this step as failed (continue-on-error keeps pipeline alive)