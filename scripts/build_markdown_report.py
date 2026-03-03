#!/usr/bin/env python3
# build_markdown_report.py
import os, json, argparse, re, sys
from urllib.parse import quote

def load_json(path):
    if not path or not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return None

def try_extract_from_ai(ai):
    """
    Try to pull structured JSON sections from ai_response.json message content.
    Supports:
      - "endpoints_scan_augmented": [...]
      - "analysis": [...]
      - "compatibility": [...]
      - "extraction": {...}
    """
    endpoints_aug = None
    analysis = None
    compatibility = None
    extraction = None

    try:
        content = ai.get("choices", [{}])[0].get("message", {}).get("content", "")
    except Exception:
        content = ""

    def extract_json_array(name):
        m = re.search(rf'"{name}"\s*:\s*(\[[\s\S]*?\])', content)
        if not m: return None
        try:
            return json.loads(m.group(1))
        except Exception:
            return None

    def extract_json_object(name):
        m = re.search(rf'"{name}"\s*:\s*(\{{[\s\S]*?\}})', content)
        if not m: return None
        try:
            return json.loads(m.group(1))
        except Exception:
            return None

    endpoints_aug = extract_json_array("endpoints_scan_augmented")
    analysis      = extract_json_array("analysis")
    compatibility = extract_json_array("compatibility")
    extraction    = extract_json_object("extraction")
    return endpoints_aug, analysis, compatibility, extraction

def md_escape(text):
    if text is None:
        return ""
    s = str(text)
    return s.replace("|", r"\|")

def build_file_link(server_url, repo, ref, path):
    if not path: return ""
    server = server_url or "https://github.com"
    ref_or_sha = ref or os.getenv("GITHUB_SHA", "")
    return f"{server}/{repo}/blob/{quote(ref_or_sha)}/{path}"

def severity_rank(sev):
    s = (sev or "").upper()
    if s == "CRITICAL": return 0
    if s == "HIGH":     return 1
    if s == "WARNING":  return 2
    if s == "INFO":     return 3
    return 4

def coalesce(*vals, default=""):
    for v in vals:
        if v is not None and v != "" and v != "Unknown":
            return v
    return default

def determine_severity(now, fut_minor_status, fut_major_status, fallback="WARNING"):
    def norm(v):
        v = (v or "").strip().lower()
        if v in ("true","supported","ok"): return "Supported"
        if v in ("false","not supported","fail","failed","no"): return "Not Supported"
        if v in ("unknown","",): return "Unknown"
        return v.title()

    n  = norm(now)
    mn = norm(fut_minor_status)
    # Rule 1 & 5: current NOT SUPPORTED → CRITICAL
    if n == "Not Supported":
        return "CRITICAL"
    # Rule 2: current SUPPORTED, futureMinor NOT SUPPORTED → HIGH
    if n == "Supported" and mn == "Not Supported":
        return "HIGH"
    # Rule 3: current SUPPORTED, futureMinor UNKNOWN → WARNING
    if n == "Supported" and mn == "Unknown":
        return "WARNING"
    # Rule 4: current SUPPORTED, futureMinor SUPPORTED → INFO
    if n == "Supported" and mn == "Supported":
        return "INFO"
    return fallback

def truncate(s, n=180):
    s = s or ""
    return (s[:n] + "…") if len(s) > n else s


# Canonical severity order — used for summary table and sorting
SEVERITY_ORDER = ["CRITICAL", "HIGH", "WARNING", "INFO"]


def count_severities(rows: list) -> dict:
    """Count rows per severity in CRITICAL→HIGH→WARNING→INFO order.
    Any unrecognised or missing severity is treated as INFO."""
    counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
    for r in rows:
        sev = (r.get("Severity") or "INFO").upper()
        if sev not in counts:
            sev = "INFO"
        counts[sev] += 1
    return counts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ai-response",  default="ai_response.json",              help="(unused, kept for backward compat)")
    ap.add_argument("--analysis",     default="security/reports/analysis.json", help="Primary input: analysis.json from extract_analysis.py")
    ap.add_argument("--tls-context",  default="security/reports/tls_context.json", help="(unused, kept for backward compat)")
    ap.add_argument("--endpoints",    default="security/reports/endpoints.json",    help="(unused, kept for backward compat)")
    ap.add_argument("--jdk-info",     default="security/reports/jdk_info.json",     help="(unused, kept for backward compat)")
    ap.add_argument("--output-md",    default="security/reports/tls-audit.md")
    args = ap.parse_args()

    # ── Load analysis.json — single source of truth ───────────────────────────
    endpoint_items = load_json(args.analysis)
    if not isinstance(endpoint_items, list) or not endpoint_items:
        print("ERROR: analysis.json is missing or empty.", file=sys.stderr)
        endpoint_items = []

    server_url = os.getenv("GITHUB_SERVER_URL", "https://github.com")
    repo       = os.getenv("GITHUB_REPOSITORY", "")
    ref_name   = os.getenv("GITHUB_REF_NAME", "") or os.getenv("GITHUB_REF", "")

    rows = []
    for item in endpoint_items:
        endpoint = item.get("endpoint") or ""
        tls_v    = item.get("tlsVersion")    or ""
        cipher   = item.get("CipherVersion") or ""

        # JDK versions — flat fields written by extract_analysis.py
        cur_jdk_ver    = item.get("CurrentJDKVersion",            "Unknown") or "Unknown"
        fut_minor_ver  = item.get("futureJDKMinorUpgradeVersion", "Unknown") or "Unknown"
        fut_major_ver  = item.get("FutureMajorUpgradedVersion",   "Unknown") or "Unknown"

        # TLS compatibility status — flat fields written by extract_analysis.py
        now_status       = item.get("CurrentJdkTlsStatus",    "Unknown") or "Unknown"
        fut_minor_status = item.get("FutureJdkMinorTlsStatus","Unknown") or "Unknown"
        fut_major_status = item.get("FutureJdkMajorTlsStatus","Unknown") or "Unknown"

        severity = item.get("severity") or ""
        if not severity:
            severity = determine_severity(now_status, fut_minor_status, fut_major_status)

        reason = item.get("reason") or ""
        action = item.get("action") or ""

        # environment comes directly from the 'env' field
        environment = item.get("env") or ""

        # source_file is the filename; build a GitHub blob link from it
        file_path = item.get("source_file") or ""
        link = build_file_link(server_url, repo, ref_name or os.getenv("GITHUB_SHA", ""), file_path) if file_path else ""

        rows.append({
            "Severity":              severity,
            "Environment":           environment,
            "FileName":              file_path,
            "FileLink":              link,
            "Host_Port":             endpoint,
            "TlsVersion":            tls_v,
            "CipherVersion":         cipher,
            "CurrentJDKVersion":     cur_jdk_ver,
            "CurrentJDKTlsStatus":   now_status,
            "FutureJDKMinorVersion": fut_minor_ver,
            "FutureJDKMinorTlsStatus": fut_minor_status,
            "FutureJDKMajorVersion": fut_major_ver,
            "FutureJDKMajorTlsStatus": fut_major_status,
            "Reason":                truncate(reason),
            "Action":                truncate(action),
        })

    rows.sort(key=lambda r: (severity_rank(r["Severity"]), r["Environment"] or "", r["Host_Port"] or ""))

    # ── Severity summary table ────────────────────────────────────────────────
    severity_counts = count_severities(rows)
    summary_lines = [
        "## Severity Summary\n",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for sev in SEVERITY_ORDER:
        summary_lines.append(f"| {sev} | {severity_counts[sev]} |")
    summary_md = "\n".join(summary_lines) + "\n\n"
    print("[INFO] Severity summary:", " | ".join(f"{k}={v}" for k, v in severity_counts.items()))

    headers = [
        "Severity", "Environment", "FileName (link)", "Host_Port",
        "TlsVersion", "CipherVersion",
        "CurrentJDKVersion", "CurrentJDKTlsStatus",
        "FutureJDKMinorVersion", "FutureJDKMinorTlsStatus",
        "FutureJDKMajorVersion", "FutureJDKMajorTlsStatus",
        "Reason", "Action",
    ]

    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join(["---"] * len(headers)) + " |"]

    for r in rows:
        if r["FileLink"] and r["FileName"]:
            fname_disp = f"[{md_escape(r['FileName'])}]({r['FileLink']})"
        else:
            fname_disp = md_escape(r["FileName"])

        row = [
            md_escape(r["Severity"]),
            md_escape(r["Environment"]),
            fname_disp,
            md_escape(r["Host_Port"]),
            md_escape(r["TlsVersion"]),
            md_escape(r["CipherVersion"]),
            md_escape(r["CurrentJDKVersion"]),
            md_escape(r["CurrentJDKTlsStatus"]),
            md_escape(r["FutureJDKMinorVersion"]),
            md_escape(r["FutureJDKMinorTlsStatus"]),
            md_escape(r["FutureJDKMajorVersion"]),
            md_escape(r["FutureJDKMajorTlsStatus"]),
            md_escape(r["Reason"]),
            md_escape(r["Action"]),
        ]
        lines.append("| " + " | ".join(row) + " |")

    detail_md = "## Endpoint Detail\n\n" + "\n".join(lines) + "\n"
    md = "# TLS Endpoint Audit — Summary\n\n" + summary_md + detail_md

    os.makedirs(os.path.dirname(args.output_md), exist_ok=True)
    with open(args.output_md, "w", encoding="utf-8") as f:
        f.write(md)

    step_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as f:
            f.write(md)

    print(f"Wrote report to {args.output_md}")
    print(f"Rows: {len(rows)}")

if __name__ == "__main__":
    main()