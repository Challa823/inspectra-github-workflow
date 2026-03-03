import json
import os
import argparse


def load_endpoints_metadata(endpoints_json_path):
    """
    Load the structured output from collect_endpoints.py.
    Returns a dict keyed by host_port for quick lookup.
    Each value is a list of matches (same host:port may appear in multiple files).
    """
    if not os.path.exists(endpoints_json_path):
        print(f"[WARN] endpoints.json not found at {endpoints_json_path}, source info will be empty.")
        return {}

    with open(endpoints_json_path) as f:
        collected = json.load(f)

    # Build lookup: host_port -> list of endpoint metadata entries
    lookup = {}
    for ep in collected:
        hp = ep["host_port"]
        lookup.setdefault(hp, []).append(ep)
    return lookup


def get_support_status(item):
    supported = item.get("compatibility", {}).get("supported")
    if supported is True:
        return "Supported"
    elif supported is False:
        return "Not Supported"
    return "Unknown"


# Canonical severity order
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "WARNING", "INFO"]


def count_severities(analysis_data: list) -> dict:
    """Count findings per severity in CRITICAL→HIGH→WARNING→INFO order.
    Missing or unrecognised severity is treated as INFO."""
    counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
    for item in analysis_data:
        sev = (item.get("severity") or "INFO").upper()
        if sev not in counts:
            sev = "INFO"
        counts[sev] += 1
    return counts


def generate_sarif_report(analysis_data, endpoints_meta, severity_summary: dict | None = None):
    """
    Generate SARIF report enriched with source file and line from collect_endpoints.py output.
    severity_summary is added to the run-level properties (does not affect SARIF schema validity).
    """
    sarif_report = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "tls-endpoint-audit",
                    "rules": [{
                        "id": "TLS001",
                        "name": "TLSEndpointCompatibility",
                        "shortDescription": {"text": "TLS endpoint SSL/TLS compatibility check"}
                    }]
                }
            },
            "properties": {
                "severitySummary": severity_summary or count_severities(analysis_data)
            },
            "results": []
        }]
    }

    for item in analysis_data:
        endpoint = item.get("endpoint", "")
        status = get_support_status(item)
        reason = item.get("compatibility", {}).get("reason", "")

        # Use severity field from analysis.json directly (CRITICAL/HIGH/WARNING/INFO)
        sev_field = (item.get("severity") or "").upper()
        severity = {
            "CRITICAL": "error",
            "HIGH":     "error",
            "WARNING":  "warning",
            "INFO":     "note",
        }.get(sev_field) or {"Supported": "note", "Unknown": "warning", "Not Supported": "error"}.get(status, "note")

        # Look up source file info from collect_endpoints.py result
        meta_entries = endpoints_meta.get(endpoint, [])

        locations = []
        if meta_entries:
            for meta in meta_entries:
                locations.append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": meta["source_file"].replace("\\", "/")},
                        "region": {
                            "startLine": meta["line"],
                            "snippet": {"text": meta["context"]}
                        }
                    },
                    "logicalLocations": [{
                        "name": meta.get("env", "unknown"),
                        "kind": "namespace"
                    }]
                })
        else:
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {"uri": ".github/workflows"},
                    "region": {"startLine": 1}
                }
            })

        result = {
            "ruleId": "TLS001",
            "level": severity,
            "message": {
                "text": (
                    f"[{meta_entries[0]['env'].upper() if meta_entries else 'UNKNOWN'}] "
                    f"{endpoint} — {status} — {reason}"
                    + (f" (source: {meta_entries[0]['source_file']}:{meta_entries[0]['line']})" if meta_entries else "")
                )
            },
            "locations": locations,
            "properties": {
                "url":        meta_entries[0]["url"]               if meta_entries else endpoint,
                "env":        meta_entries[0]["env"]               if meta_entries else "unknown",
                "sourceFile": meta_entries[0]["source_file"]       if meta_entries else "",
                "sourceLine": meta_entries[0]["line"]              if meta_entries else 0,
                "gitLink":    meta_entries[0].get("git_link", "")  if meta_entries else "",
            }
        }
        sarif_report["runs"][0]["results"].append(result)

    return sarif_report


def generate_sonar_report(analysis_data, endpoints_meta, severity_summary: dict | None = None):
    """
    Generate SonarQube Generic Issue report enriched with source file and line
    from collect_endpoints.py output.
    severity_summary added as root-level metadata (not part of Sonar schema, informational).
    """
    sonar_report = {
        "severitySummary": severity_summary or count_severities(analysis_data),
        "issues": [],
    }

    for item in analysis_data:
        endpoint = item.get("endpoint", "")
        status = get_support_status(item)
        reason = item.get("compatibility", {}).get("reason", "")

        # Use severity field from analysis.json directly (CRITICAL/HIGH/WARNING/INFO)
        sev_field = (item.get("severity") or "").upper()
        severity = {
            "CRITICAL": "CRITICAL",
            "HIGH":     "MAJOR",
            "WARNING":  "MINOR",
            "INFO":     "INFO",
        }.get(sev_field) or {"Supported": "INFO", "Unknown": "MINOR", "Not Supported": "MAJOR"}.get(status, "INFO")

        meta_entries = endpoints_meta.get(endpoint, [])
        meta = meta_entries[0] if meta_entries else {}

        source_file = meta.get("source_file", "security/reports").replace("\\", "/")
        line     = meta.get("line", 1)
        env      = meta.get("env", "unknown")
        url      = meta.get("url", endpoint)
        git_link = meta.get("git_link", "")

        issue = {
            "engineId": "tls-endpoint-audit",
            "ruleId": "TLS001",
            "severity": severity,
            "type": "VULNERABILITY",
            "gitLink": git_link,
            "primaryLocation": {
                "message": f"[{env.upper()}] {endpoint} — {status} — {reason} (url: {url})",
                "filePath": source_file,
                "textRange": {
                    "startLine": line,
                    "endLine": line,
                    "startColumn": 0,
                    "endColumn": len(meta.get("context", ""))
                }
            }
        }
        sonar_report["issues"].append(issue)

    return sonar_report


def save_report(report, filename):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"[INFO] Saved: {filename}")


def main():
    parser = argparse.ArgumentParser(description="Generate SARIF and Sonar reports from TLS analysis")
    parser.add_argument("--analysis", default="security/reports/analysis.json", help="AI analysis JSON file")
    parser.add_argument("--endpoints-json", default="endpoints.json", help="Output from collect_endpoints.py")
    parser.add_argument("--out-dir", default="security/reports", help="Output directory for reports")
    args = parser.parse_args()

    if not os.path.exists(args.analysis):
        print(f"[ERROR] Analysis file not found: {args.analysis}")
        return

    with open(args.analysis) as f:
        analysis_data = json.load(f)

    # Load enriched endpoint metadata from collect_endpoints.py output
    endpoints_meta = load_endpoints_metadata(args.endpoints_json)

    # ── Compute severity summary (shared across both reports) ─────────────────
    sev_summary = count_severities(analysis_data)
    print("[INFO] Severity summary:", " | ".join(f"{k}={v}" for k, v in sev_summary.items()))

    sarif_report = generate_sarif_report(analysis_data, endpoints_meta, severity_summary=sev_summary)
    save_report(sarif_report, os.path.join(args.out_dir, "tls-audit.sarif"))

    sonar_report = generate_sonar_report(analysis_data, endpoints_meta, severity_summary=sev_summary)
    save_report(sonar_report, os.path.join(args.out_dir, "sonar-tls-audit.json"))

    print(f"[INFO] Reports generated successfully ({len(analysis_data)} endpoints processed).")


if __name__ == "__main__":
    main()