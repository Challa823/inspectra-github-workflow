import json
import os
import argparse


def _now_to_supported(now: str) -> bool | None:
    """Map a compatibility 'now' string to a bool for generate_reports.py."""
    v = (now or "").strip().lower()
    if v == "supported":
        return True
    if v in ("not supported", "false", "no"):
        return False
    return None


def extract_analysis(
    ai_response_file: str,
    output_analysis_file: str,
    output_summary_file: str,
    endpoints_scan_file: str = "",
):
    """
    Read ai_response.json (GitHub Models API reply) and endpoints_scan.json
    (SSL scan results), then produce analysis.json by joining on TLS version
    + cipher suite.

    For every endpoint in endpoints_scan.json the model's compatibility array
    is searched for a row where both "tls version" and "Cipher version" match
    the endpoint's tlsProtocol / cipherSuite.  When a match is found the
    following fields are populated from the AI response:

        CurrentJDKVersion            ← extraction.CurrentJdkVersion
        futureJDKMinorUpgradeVersion ← extraction.futureJDKMinorUpgradeVersion
        FutureMajorUpgradedVersion   ← extraction.FutureMajorUpgradedVersion
        CurrentJdkTlsStatus          ← compatibility[match].now
        FutureJdkMinorTlsStatus      ← compatibility[match].futureMinor
        FutureJdkMajorTlsStatus      ← compatibility[match].futureMajor
        severity                     ← compatibility[match].severity
        reason                       ← compatibility[match].reason
        action                       ← compatibility[match].action

    The nested "compatibility" sub-object is preserved for backward
    compatibility with generate_reports.py and build_markdown_report.py.
    """

    # ── Load AI response ──────────────────────────────────────────────────────
    with open(ai_response_file, "r", encoding="utf-8") as f:
        response = json.load(f)

    content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
    if not content:
        raise ValueError("Model response contains no content in choices[0].message.content")

    try:
        parsed = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        print("[WARN] Model response is not valid JSON. Storing raw-text fallback entry.")
        parsed = None

    # ── Extract top-level fields from AI response ─────────────────────────────
    extraction: dict = {}
    compat_list: list = []

    if isinstance(parsed, dict):
        extraction  = parsed.get("extraction", {})
        compat_list = parsed.get("compatibility", [])

    current_jdk         = extraction.get("CurrentJdkVersion",            "Unknown")
    future_minor_ver    = extraction.get("futureJDKMinorUpgradeVersion",  "Unknown")
    future_major_ver    = extraction.get("FutureMajorUpgradedVersion",    "Unknown")

    # Build lookup: (tls_version, cipher_version) → compatibility row
    # Keys use the exact field names the model returns.
    compat_by_pair: dict[tuple[str, str], dict] = {}
    for row in compat_list:
        tls_key    = (row.get("tls version") or "").strip()
        cipher_key = (row.get("Cipher version") or "").strip()
        if tls_key or cipher_key:
            compat_by_pair[(tls_key, cipher_key)] = row

    # ── Load endpoints_scan.json ──────────────────────────────────────────────
    endpoints_scan: list = []
    scan_path = endpoints_scan_file or ""
    if scan_path and os.path.exists(scan_path):
        with open(scan_path, "r", encoding="utf-8") as f:
            endpoints_scan = json.load(f)
        print(f"[INFO] Loaded {len(endpoints_scan)} entries from {scan_path}")
    else:
        # Fallback: try endpoints_scan_augmented from the AI response
        if isinstance(parsed, dict):
            endpoints_scan = parsed.get("endpoints_scan_augmented", [])
        if not endpoints_scan:
            print("[WARN] No endpoints_scan file provided and endpoints_scan_augmented is empty.")

    # ── Join endpoints_scan × compatibility ───────────────────────────────────
    analysis_list: list[dict] = []

    for ep in endpoints_scan:
        endpoint  = ep.get("endpoint") or ep.get("host_port") or ""
        tls_proto = (ep.get("tlsProtocol") or ep.get("tls_version") or ep.get("tls version") or "").strip()
        cipher    = (ep.get("cipherSuite")  or ep.get("cipher")     or ep.get("Cipher version") or "").strip()

        # Look up matching compatibility row
        compat_row = compat_by_pair.get((tls_proto, cipher), {})

        # If no exact match, try without Cipher (TLS-only match) as a fallback
        if not compat_row and tls_proto:
            for (tk, ck), row in compat_by_pair.items():
                if tk == tls_proto:
                    compat_row = row
                    break

        now_val          = compat_row.get("now",          "Unknown")
        future_minor_val = compat_row.get("futureMinor",  "Unknown")
        future_major_val = compat_row.get("futureMajor",  "Unknown")
        severity         = compat_row.get("severity",     "Unknown")
        reason           = compat_row.get("reason",       "")
        action           = compat_row.get("action",       "")

        # Endpoints with no TLS (e.g. timeout / <none>) keep "Unknown" statuses
        if tls_proto in ("<none>", "", None):
            now_val = future_minor_val = future_major_val = "Unknown"
            if not severity or severity == "Unknown":
                severity = "UNKNOWN"

        analysis_list.append({
            # ── Endpoint identity ─────────────────────────────────────────
            "endpoint":    endpoint,
            "tlsVersion":  tls_proto,
            "CipherVersion": cipher,

            # ── JDK version info (from AI extraction) ─────────────────────
            "CurrentJDKVersion":            current_jdk,
            "futureJDKMinorUpgradeVersion": future_minor_ver,
            "FutureMajorUpgradedVersion":   future_major_ver,

            # ── TLS compatibility status (joined from AI compatibility) ────
            "CurrentJdkTlsStatus":    now_val,
            "FutureJdkMinorTlsStatus": future_minor_val,
            "FutureJdkMajorTlsStatus": future_major_val,

            # ── Risk / remediation ────────────────────────────────────────
            "severity": severity,
            "reason":   reason,
            "action":   action,

            # ── Nested compatibility block (backward compat) ──────────────
            "compatibility": {
                "supported":   _now_to_supported(now_val),
                "reason":      reason,
                "action":      action,
                "severity":    severity,
                "tls_version": tls_proto,
                "cipher":      cipher,
                "now":         now_val,
                "futureMinor": future_minor_val,
                "futureMajor": future_major_val,
            },

            # ── Source location (from endpoints_scan) ─────────────────────
            "source_url":  ep.get("url",         ""),
            "env":         ep.get("env",          ""),
            "source_file": ep.get("source_file",  ""),
            "line":        ep.get("line",          0),
        })

    # ── Fallback: AI returned a plain list ────────────────────────────────────
    if not analysis_list and isinstance(parsed, list):
        print("[INFO] Using plain-list AI response as analysis.")
        analysis_list = parsed

    # ── Fallback: nothing usable ──────────────────────────────────────────────
    if not analysis_list:
        print("[WARN] No analysis data produced. Writing raw-content fallback.")
        analysis_list = [{
            "endpoint": "unknown",
            "compatibility": {
                "supported": None,
                "reason": "Model returned non-JSON or no endpoints were scanned.",
            },
            "raw_content": content,
        }]

    # ── Write analysis.json ───────────────────────────────────────────────────
    with open(output_analysis_file, "w", encoding="utf-8") as f:
        json.dump(analysis_list, f, indent=2)
    print(f"[INFO] Analysis saved to {output_analysis_file} ({len(analysis_list)} entries)")

    # ── Write human-readable summary.txt ─────────────────────────────────────
    with open(output_summary_file, "w", encoding="utf-8") as f:
        has_raw = analysis_list and "raw_content" in analysis_list[0]
        if has_raw:
            f.write(content)
        else:
            f.write("---- TLS ENDPOINT SUMMARY ----\n")
            f.write(f"CurrentJDK : {current_jdk}\n")
            f.write(f"Future Minor JDK : {future_minor_ver}\n")
            f.write(f"Future Major JDK : {future_major_ver}\n\n")
            for entry in analysis_list:
                ep_  = entry.get("endpoint", "?")
                tls_ = entry.get("tlsVersion", "?")
                cip_ = entry.get("CipherVersion", "?")
                sev_ = entry.get("severity", "?")
                now_ = entry.get("CurrentJdkTlsStatus", "?")
                fm_  = entry.get("FutureJdkMinorTlsStatus", "?")
                fM_  = entry.get("FutureJdkMajorTlsStatus", "?")
                rea_ = entry.get("reason", "")
                f.write(
                    f"{ep_} | tls={tls_} | cipher={cip_} | severity={sev_} "
                    f"| now={now_} | futureMinor={fm_} | futureMajor={fM_} | {rea_}\n"
                )
    print(f"[INFO] Summary saved to {output_summary_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Join AI model analysis with endpoints_scan.json to produce analysis.json"
    )
    parser.add_argument(
        "--model-response", default="ai_response.json",
        help="Path to the raw AI model API response JSON (produced by call_github_models.py)"
    )
    parser.add_argument(
        "--endpoints-scan", default="endpoints_scan.json",
        help="Path to endpoints_scan.json (produced by ssl_scan.py)"
    )
    parser.add_argument(
        "--output", default="analysis.json",
        help="Output path for the structured analysis JSON (consumed by generate_reports.py)"
    )
    parser.add_argument(
        "--summary-out", default="summary.txt",
        help="Output path for the human-readable summary"
    )
    args = parser.parse_args()

    if not os.path.exists(args.model_response):
        print(f"[ERROR] Model response file not found: {args.model_response}")
        raise SystemExit(1)

    extract_analysis(
        ai_response_file=args.model_response,
        output_analysis_file=args.output,
        output_summary_file=args.summary_out,
        endpoints_scan_file=args.endpoints_scan,
    )


if __name__ == "__main__":
    main()