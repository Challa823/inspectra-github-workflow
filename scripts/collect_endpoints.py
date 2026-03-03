import os
import glob
import re
import json
import argparse
from urllib.parse import quote


def detect_env_from_path(filepath):
    """
    Extract environment directly from folder names or filename in the path.
    No hardcoded list — just reads path parts as-is.

    Strategy:
    1. Check filename for application-{env}.yml pattern
    2. Check folder parts (skip generic ones)
    3. Fall back to filename itself
    """
    normalized = filepath.replace("\\", "/")
    parts = normalized.split("/")
    filename = os.path.splitext(parts[-1])[0]  # filename without extension

    # Strategy 1: application-{env}.yml / application-{env}.properties pattern
    match = re.search(r'[-_.]([a-zA-Z0-9]+)$', filename)
    if match:
        env_candidate = match.group(1).lower()
        if env_candidate not in ("yml", "yaml", "properties", "xml", "json"):
            return env_candidate

    # Strategy 2: use folder names directly, skipping generic ones
    skip_parts = {"src", "main", "resources", "config", "conf",
                  "settings", "properties", "environments", "env",
                  "application", "services", "api", "app", "project"}
    for part in parts[:-1]:  # exclude filename
        part_lower = part.lower()
        if part_lower and part_lower not in skip_parts:
            return part_lower

    # Strategy 3: use filename as env
    if filename.lower() not in skip_parts:
        return filename.lower()

    return "unknown"


def extract_urls_from_file(filepath):
    """Extract all URLs from a file with line number and context."""
    url_pattern = re.compile(r'https?://[^\s\'">,;{}()\[\]]+')
    results = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line_no, line in enumerate(f, 1):
                for match in url_pattern.finditer(line):
                    url = match.group().rstrip('/')
                    results.append({
                        "url": url,
                        "line": line_no,
                        "context": line.strip()
                    })
    except Exception as e:
        print(f"[WARN] Could not read {filepath}: {e}")
    return results


def url_to_hostport(url):
    """Convert URL to host:port."""
    scheme, rest = url.split("://", 1)
    hostport = rest.split('/')[0].split('?')[0].split('#')[0]
    if ':' not in hostport:
        hostport += ":443" if scheme == "https" else ":80"
    return hostport


def collect_endpoints(files_glob="**/*.{properties,yml,yaml}", base_dir="."):
    endpoints = []
    seen = set()

    # Handle brace expansion manually (glob doesn't support {a,b})
    if '{' in files_glob and '}' in files_glob:
        prefix = files_glob[:files_glob.index('{')]
        exts_str = files_glob[files_glob.index('{')+1:files_glob.index('}')]
        suffix = files_glob[files_glob.index('}')+1:]
        patterns = [f"{prefix}{ext}{suffix}" for ext in exts_str.split(',')]
    else:
        patterns = [files_glob]

    for pattern in patterns:
        for filepath in glob.glob(os.path.join(base_dir, pattern), recursive=True):
            filepath = os.path.normpath(filepath)
            rel_path = os.path.relpath(filepath, base_dir)

            # Derive env directly from path — no hardcoded env list
            env = detect_env_from_path(rel_path)

            for hit in extract_urls_from_file(filepath):
                url = hit["url"]
                try:
                    hostport = url_to_hostport(url)
                except Exception:
                    continue

                key = (hostport, rel_path)
                if key in seen:
                    continue
                seen.add(key)

                # Build a direct GitHub blob link to the exact line so that
                # downstream Markdown / SARIF / Sonar reports can use it
                # without needing to re-derive env vars.
                _gh_server = os.getenv("GITHUB_SERVER_URL",  "https://github.com")
                _gh_repo   = os.getenv("GITHUB_REPOSITORY",  "")
                _gh_ref    = os.getenv("GITHUB_REF_NAME", "") or os.getenv("GITHUB_SHA", "")
                _line_no   = hit["line"]
                git_link   = (
                    f"{_gh_server}/{_gh_repo}/blob/{quote(_gh_ref)}/{rel_path}#L{_line_no}"
                    if _gh_repo and _gh_ref else ""
                )

                endpoints.append({
                    "host_port":   hostport,
                    "url":         url,
                    "env":         env,        # derived from path
                    "source_file": rel_path,   # relative file path
                    "line":        hit["line"], # line number in file
                    "context":     hit["context"],
                    "git_link":    git_link,    # GitHub blob URL with #L anchor
                })

    return sorted(endpoints, key=lambda x: (x["env"], x["host_port"]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect TLS endpoints from config files")
    parser.add_argument("--files-glob", default="**/*.{properties,yml,yaml}")
    parser.add_argument("--base-dir", default=".", help="Root directory to scan")
    parser.add_argument("--output", default="endpoints.txt")
    args = parser.parse_args()

    collected = collect_endpoints(files_glob=args.files_glob, base_dir=args.base_dir)

    # Write host:port list for endpoint_tls_scans.py
    with open(args.output, 'w') as f:
        for ep in collected:
            f.write(ep["host_port"] + "\n")

    # Write full structured JSON
    json_output = args.output.replace(".txt", ".json")
    with open(json_output, 'w') as f:
        json.dump(collected, f, indent=2)

    print(f"[INFO] Found {len(collected)} endpoints")
    print(f"\n{'ENV':<15} {'HOST:PORT':<35} {'SOURCE FILE':<45} {'LINE'}")
    print("-" * 100)
    for ep in collected:
        print(f"{ep['env']:<15} {ep['host_port']:<35} {ep['source_file']:<45} {ep['line']}")