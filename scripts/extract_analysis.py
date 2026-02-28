import json
import os
import argparse


def extract_analysis(ai_response_file: str, output_analysis_file: str, output_summary_file: str):
    """
    Read the raw GitHub Models API response, extract the model's content,
    parse it as JSON, reshape it into the format consumed by generate_reports.py,
    and write analysis.json + summary.txt.

    generate_reports.py expects analysis.json to be a list where every item has:
        { "endpoint": "<host:port>", "compatibility": { "supported": bool|None,
          "reason": str, ... }, ... }

    build_prompt.py instructs the model to return a JSON object with keys:
        extraction, compatibility, highSummaryFromErrors, endpoints_scan_augmented
    """
    with open(ai_response_file, "r", encoding="utf-8") as f:
        response = json.load(f)

    # Pull the model's reply text
    content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
    if not content:
        raise ValueError("Model response contains no content in choices[0].message.content")

    # ── Try to parse the model content as JSON ────────────────────────────────
    analysis_list = []
    parse_ok = False
    try:
        parsed = json.loads(content)
        parse_ok = True
    except (json.JSONDecodeError, ValueError):
        print("[WARN] Model response is not valid JSON. Storing raw-text fallback entry.")
        parsed = None

    if parse_ok and isinstance(parsed, dict) and "endpoints_scan_augmented" in parsed:
        # Build a quick lookup: (tls_version, cipher) → compatibility row
        compat_by_pair: dict = {}
        for row in parsed.get("compatibility", []):
            key = (row.get("tls version", ""), row.get("Cipher version", ""))
            compat_by_pair[key] = row

        for ep in parsed["endpoints_scan_augmented"]:
            host_port = ep.get("host_port", ep.get("endpoint", ""))
            tls_ver   = ep.get("tls_version", ep.get("tls version", ""))
            cipher    = ep.get("cipher",      ep.get("Cipher version", ""))
            compat_row = compat_by_pair.get((tls_ver, cipher), {})

            is_supported: bool | None = None
            if compat_row:
                is_supported = compat_row.get("now", "Unknown") == "Supported"

            analysis_list.append({
                "endpoint":    host_port,
                "compatibility": {
                    "supported":   is_supported,
                    "reason":      compat_row.get("reason",      ep.get("Review comments", "")),
                    "action":      compat_row.get("action",      ep.get("Action", "")),
                    "severity":    compat_row.get("severity",    "OK"),
                    "tls_version": tls_ver,
                    "cipher":      cipher,
                    "now":         compat_row.get("now",         "Unknown"),
                    "futureMinor": compat_row.get("futureMinor", "Unknown"),
                    "futureMajor": compat_row.get("futureMajor", "Unknown"),
                },
                "source_url":  ep.get("url", ""),
                "env":         ep.get("env", ""),
                "source_file": ep.get("source_file", ""),
                "line":        ep.get("line", 0),
            })

    elif parse_ok and isinstance(parsed, list):
        # Model returned a plain list — assume it already has the right shape
        analysis_list = parsed

    else:
        # Non-JSON or unexpected structure — store as a single fallback entry
        analysis_list = [{
            "endpoint": "unknown",
            "compatibility": {
                "supported": None,
                "reason": "Model returned non-JSON or unexpected JSON content",
            },
            "raw_content": content,
        }]

    # ── Write analysis.json (consumed by generate_reports.py) ─────────────────
    with open(output_analysis_file, "w", encoding="utf-8") as f:
        json.dump(analysis_list, f, indent=2)
    print(f"[INFO] Analysis saved to {output_analysis_file} ({len(analysis_list)} entries)")

    # ── Write human-readable summary.txt ──────────────────────────────────────
    with open(output_summary_file, "w", encoding="utf-8") as f:
        has_raw = analysis_list and "raw_content" in analysis_list[0]
        if has_raw:
            f.write(content)
        else:
            f.write("---- TLS ENDPOINT SUMMARY ----\n")
            for entry in analysis_list:
                ep     = entry.get("endpoint", "?")
                compat = entry.get("compatibility", {})
                sev    = compat.get("severity", "?")
                now    = compat.get("now", "?")
                reason = compat.get("reason", "")
                f.write(f"{ep} | severity={sev} | now={now} | {reason}\n")
    print(f"[INFO] Summary saved to {output_summary_file}")


def main():
    parser = argparse.ArgumentParser(description="Extract and structure AI model analysis from raw API response")
    parser.add_argument(
        "--model-response", default="ai_response.json",
        help="Path to the raw AI model API response JSON (produced by call_github_models.py)"
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

    extract_analysis(args.model_response, args.output, args.summary_out)


if __name__ == "__main__":
    main()