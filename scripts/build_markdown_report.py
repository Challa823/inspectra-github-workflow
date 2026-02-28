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
    return 2

def coalesce(*vals, default=""):
    for v in vals:
        if v is not None and v != "" and v != "Unknown":
            return v
    return default

def determine_severity(now, fut_minor_status, fut_major_status, fallback="OK"):
    def norm(v):
        v = (v or "").strip().lower()
        if v in ("true","supported","ok"): return "Supported"
        if v in ("false","not supported","fail","failed","no"): return "Not Supported"
        if v in ("unknown","",): return "Unknown"
        return v.title()

    mn = norm(fut_minor_status)
    mj = norm(fut_major_status)
    if mn == "Not Supported":
        return "CRITICAL"
    if mn == "Supported" and mj == "Not Supported":
        return "HIGH"
    if norm(now) == "Not Supported":
        return "HIGH"
    return fallback

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ai-response", default="ai_response.json")
    ap.add_argument("--analysis", default="security/reports/analysis.json")
    ap.add_argument("--tls-context", default="security/reports/tls_context.json")
    ap.add_argument("--endpoints", default="security/reports/endpoints.json")
    ap.add_argument("--jdk-info", default="security/reports/jdk_info.json")
    ap.add_argument("--output-md", default="security/reports/tls-audit.md")
    ap.add_argument("--environment", default="")
    args = ap.parse_args()

    ai = load_json(args.ai_response)
    analysis_direct = load_json(args.analysis)
    tls_context = load_json(args.tls_context) or {}
    endpoints_map = load_json(args.endpoints) or []
    jdk_info = load_json(args.jdk_info) or {}

    # Build endpoint->file mapping (if collector populated it)
    ep_to_file = {}
    if isinstance(endpoints_map, list):
        for it in endpoints_map:
            ep = it.get("endpoint") or it.get("host_port") or it.get("hostPort")
            fp = it.get("file") or it.get("path")
            if ep and fp:
                ep_to_file.setdefault(ep, fp)

    server_url = os.getenv("GITHUB_SERVER_URL", "https://github.com")
    repo = os.getenv("GITHUB_REPOSITORY", "")
    ref_name = os.getenv("GITHUB_REF_NAME", "") or os.getenv("GITHUB_REF", "")
    environment_label = args.environment or (f"{repo}@{ref_name}" if repo else "workflow")

    endpoints_aug, analysis_ai, compatibility_ai, extraction_ai = (None, None, None, None)
    if ai:
        endpoints_aug, analysis_ai, compatibility_ai, extraction_ai = try_extract_from_ai(ai)

    endpoint_items = None
    for candidate in (analysis_direct, endpoints_aug, analysis_ai):
        if isinstance(candidate, list) and candidate:
            endpoint_items = candidate
            break
    if not endpoint_items:
        print("No endpoint-level analysis found in analysis.json nor ai_response.json.", file=sys.stderr)
        endpoint_items = []

    # future versions from context/extraction
    extraction = (tls_context.get("extraction") if isinstance(tls_context, dict) else None) or extraction_ai or tls_context
    future_minor_ver = None
    future_major_ver = None
    if isinstance(extraction, dict):
        future_minor_ver = extraction.get("futureJDKMinorUpgradeVersion") or extraction.get("futureMinor") or extraction.get("futureJdkMinorVersion")
        future_major_ver = extraction.get("FutureMajorUpgradedVersion") or extraction.get("futureMajor") or extraction.get("futureJdkMajorVersion")
    current_jdk = jdk_info.get("version") or (extraction.get("CurrentJdkVersion") if isinstance(extraction, dict) else None)

    # Helper to match composite against compatibility list to pull reason/action/status
    def match_compat(tls_v, cipher_v):
        comp_list = compatibility_ai or tls_context.get("compatibility")
        if not isinstance(comp_list, list):
            return {}
        for c in comp_list:
            cv_tls = c.get("tlsVersion") or c.get("tls version") or ""
            cv_cip = c.get("CipherVersion") or c.get("Cipher version") or ""
            if cv_tls == tls_v and cv_cip == cipher_v:
                return {
                    "futureMinor": c.get("futureMinor") or "",
                    "futureMajor": c.get("futureMajor") or "",
                    "reason": c.get("reason") or "",
                    "action": c.get("action") or "",
                    "now":    c.get("now") or ""
                }
        return {}

    rows = []
    for item in endpoint_items:
        endpoint = item.get("endpoint") or item.get("host_port") or item.get("hostPort") or ""
        tls_v = item.get("tlsVersion") or item.get("tlsProtocol") or item.get("tls version") or ""
        cipher = item.get("CipherVersion") or item.get("cipherSuite") or item.get("Cipher version") or ""

        cur_jdk_ver = coalesce(item.get("CurrentJDKVersion"),
                               (item.get("jdk") or {}).get("version"),
                               current_jdk,
                               default="Unknown")

        comp = item.get("compatibility") or {}
        now_status = None
        if isinstance(comp, dict) and "supported" in comp:
            now_status = "Supported" if comp.get("supported") is True else ("Not Supported" if comp.get("supported") is False else "Unknown")
        now_status = coalesce(item.get("CurrentJdkTlsStatus"), now_status, default="Unknown")

        fut_minor_ver = coalesce(item.get("futureJdkMinorVersion"), future_minor_ver, default="Unknown")
        fut_major_ver = coalesce(item.get("FutureJdkMajorVersion") or item.get("FutureMajorUpgradedVersion"),
                                 future_major_ver, default="Unknown")

        fut_minor_status = item.get("FutureJdkTlsStatus") or item.get("futureMinor") or ""
        fut_major_status = item.get("futureJdkTlsStatus") or item.get("futureMajor") or ""

        # Pull reason/action from the best available place:
        # Priority:
        # 1) Endpoint-level "Review comments"/"Action" (if augmented)
        # 2) Endpoint-level compatibility.reason/action
        # 3) Matching composite in compatibility list
        reason = coalesce(item.get("Review comments"), comp.get("reason"), default="")
        action = coalesce(item.get("Action"), comp.get("action"), default="")

        if not fut_minor_status or not fut_major_status or not reason or not action:
            m = match_compat(tls_v, cipher)
            fut_minor_status = fut_minor_status or m.get("futureMinor", "")
            fut_major_status = fut_major_status or m.get("futureMajor", "")
            reason = reason or m.get("reason", "")
            action = action or m.get("action", "")
            now_status = now_status or m.get("now", "")

        severity = item.get("severity")
        if not severity:
            severity = determine_severity(now_status, fut_minor_status, fut_major_status)

        # filename link
        file_path = ep_to_file.get(endpoint, "")
        link = build_file_link(server_url, repo, ref_name or os.getenv("GITHUB_SHA", ""), file_path) if file_path else ""

        # (optional) truncate very long reason/action for table readability (keep full in JSON artifacts)
        def truncate(s, n=180):
            s = s or ""
            return (s[:n] + "…") if len(s) > n else s

        rows.append({
            "Severity": severity,
            "environment": environment_label,
            "filename": file_path,
            "filelink": link,
            "Host_port": endpoint,
            "tlsVersion": tls_v,
            "CipherVersion": cipher,
            "CurrentJDKVersion": cur_jdk_ver,
            "CurrentJdkTlsStatus": now_status or "Unknown",
            "futureJdkMinorVersion": fut_minor_ver,
            "FutureJdkTlsStatus": fut_minor_status or "Unknown",
            "FutureJdkMajorVersion": fut_major_ver,
            "futureJdkTlsStatus": fut_major_status or "Unknown",
            "Reason": truncate(reason),
            "Action": truncate(action),
        })

    rows.sort(key=lambda r: (severity_rank(r["Severity"]), r["Host_port"] or ""))

    headers = [
        "Severity","environment","filename (link)","Host_port","tlsVersion","CipherVersion",
        "CurrentJDKVersion","CurrentJdkTlsStatus",
        "futureJdkMinorVersion","FutureJdkTlsStatus",
        "FutureJdkMajorVersion","futureJdkTlsStatus",
        "Reason","Action"
    ]

    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join(["---"]*len(headers)) + " |"]

    for r in rows:
        # filename as markdown link if available
        if r["filelink"] and r["filename"]:
            fname_disp = f"[{md_escape(r['filename'])}]({r['filelink']})"
        else:
            fname_disp = md_escape(r["filename"])

        row = [
            md_escape(r["Severity"]),
            md_escape(r["environment"]),
            fname_disp,
            md_escape(r["Host_port"]),
            md_escape(r["tlsVersion"]),
            md_escape(r["CipherVersion"]),
            md_escape(r["CurrentJDKVersion"]),
            md_escape(r["CurrentJdkTlsStatus"]),
            md_escape(r["futureJdkMinorVersion"]),
            md_escape(r["FutureJdkTlsStatus"]),
            md_escape(r["FutureJdkMajorVersion"]),
            md_escape(r["futureJdkTlsStatus"]),
            md_escape(r["Reason"]),
            md_escape(r["Action"]),
        ]
        lines.append("| " + " | ".join(row) + " |")

    md = "# TLS Endpoint Audit — Summary\n\n" + "\n".join(lines) + "\n"

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