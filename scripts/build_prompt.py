import json
import os
import argparse

SYSTEM_PROMPT = """You are a senior TLS/SSL security engineer and build engineer. Follow all instructions exactly,
preserve field names exactly as specified, and only derive values from the provided JSON inputs.
Do not invent fields or rename keys. When data is missing, use "Unknown" values and explain briefly.

STATUS NORMALIZATION RULES
- Normalize values case-insensitively:
  • "supported", "ok", "true" → Supported
  • "not supported", "false", "fail", "no" → Not Supported
  • "", null, "unknown" → Unknown

NEW SEVERITY RULES (OVERRIDE ALL PREVIOUS)
1. If currentJdktlsStatus (now) is NOT SUPPORTED → Severity = CRITICAL
2. If currentJdktlsStatus is SUPPORTED AND futureMinorJdlTlsStatus is NOT SUPPORTED → Severity = HIGH
3. If currentJdktlsStatus is SUPPORTED AND futureMinorJdlTlsStatus is UNKNOWN → Severity = WARNING
4. If currentJdktlsStatus is SUPPORTED AND futureMinorJdlTlsStatus is SUPPORTED → Severity = INFO
5. If BOTH currentJdktlsStatus and futureMinorJdlTlsStatus are NOT SUPPORTED → Severity = CRITICAL

Notes:
- futureMajor is still computed and returned but DOES NOT affect severity under the new rules unless current is not supported.
- Always prioritize rule (1) and (5) over everything else.
- Severity must be one of: CRITICAL, HIGH, WARNING, INFO.
- Reason and Action must be concise (≤ 140 chars).
"""

USER_TEMPLATE = """# INPUT: Pre-extracted TLS context
<<<TLS_CONTEXT_JSON>>>

# COMPATIBILITY EVALUATION
For EACH observed composite pair (cartesian product) of:
- one entry from "tls version"
- one entry from "Cipher version"

determine whether the pair is supported:
- NOW               (CurrentJdkVersion → currentJdktlsStatus)
- FUTURE MINOR      (futureJDKMinorUpgradeVersion → futureMinorJdlTlsStatus)
- FUTURE MAJOR      (FutureMajorUpgradedVersion → futureMajorJdkTlsStatus, informational only)

Use all available information from TLS context, JDK info, release metadata, and endpoint scan metadata.

Assumptions (apply conservatively):
- TLS 1.3: JDK 11+. TLS 1.2: JDK 7+. TLS < 1.2: Not Supported.
- AEAD ciphers (GCM/CHACHA20) with ECDHE preferred.
- RC4/3DES/NULL/EXPORT/MD5/SHA-1 contexts: Not Supported in modern baselines.
- If CurrentJdkVersion major < 11, no TLS 1.3 unless stated.
- If release data is insufficient, verdict = "Unknown".

STATUS NORMALIZATION:
- Supported / Not Supported / Unknown (case-insensitive)
- Missing → Unknown

SEVERITY RULES (MANDATORY):
1. If currentJdktlsStatus is Not Supported → CRITICAL
2. If currentJdktlsStatus is Supported AND futureMinorJdlTlsStatus is Not Supported → HIGH
3. If currentJdktlsStatus is Supported AND futureMinorJdlTlsStatus is Unknown → WARNING
4. If currentJdktlsStatus is Supported AND futureMinorJdlTlsStatus is Supported → INFO
5. If BOTH current and futureMinor are Not Supported → CRITICAL

# OUTPUT — PAGE 1 (valid JSON only)
1) "extraction" — copy the input TLS context exactly as-is.

2) "compatibility" array — one object per composite pair:
   {
     "tls version":          "<TLS value>",
     "Cipher version":       "<Cipher value>",
     "now":                  "Supported|Not Supported|Unknown",
     "futureMinor":          "Supported|Not Supported|Unknown",
     "futureMajor":          "Supported|Not Supported|Unknown",
     "severity":             "CRITICAL|HIGH|WARNING|INFO",
     "reason":               "<short reason, <= 140 chars>",
     "action":               "<short action, <= 140 chars>"
   }

3) "highSummaryFromErrors" — one paragraph synthesising risks from "uniqusslerrors". If none, return "".

# OUTPUT — PAGE 2
"endpoints_scan_augmented" — ALL original endpoint objects returned unchanged PLUS:
- "Review comments": explanation if severity is CRITICAL/HIGH/ WARNING for that endpoint’s composite.
- "Action": concise remediation.
If severity is INFO, set both to "".

Preserve all original keys and values exactly.

Output order MUST be:
1. extraction
2. compatibility
3. highSummaryFromErrors
4. endpoints_scan_augmented

NO markdown. NO commentary. ONLY valid JSON.
"""


def build_prompt(tls_context: dict) -> tuple[str, str]:
    """Inject pre-extracted tls_context into the prompt template."""
    user_prompt = USER_TEMPLATE.replace(
        "<<<TLS_CONTEXT_JSON>>>",
        json.dumps(tls_context, indent=2)
    )
    return SYSTEM_PROMPT, user_prompt


def main():
    parser = argparse.ArgumentParser(description="Build AI prompts for TLS audit")
    parser.add_argument("--tls-context", default="tls_context.json",  help="Path to tls_context.json from extract_tls_context.py")
    parser.add_argument("--system-out",  default="prompt_system.txt", help="Output file for system prompt")
    parser.add_argument("--user-out",    default="prompt_user.txt",   help="Output file for user prompt")
    args = parser.parse_args()

    if not os.path.exists(args.tls_context):
        print(f"[ERROR] tls_context.json not found: {args.tls_context}")
        raise SystemExit(1)

    with open(args.tls_context, encoding="utf-8") as f:
        tls_context = json.load(f)

    system_prompt, user_prompt = build_prompt(tls_context)

    with open(args.system_out, "w", encoding="utf-8") as f:
        f.write(system_prompt)
    print(f"[INFO] System prompt -> {args.system_out} ({len(system_prompt)} chars)")

    with open(args.user_out, "w", encoding="utf-8") as f:
        f.write(user_prompt)
    print(f"[INFO] User prompt   -> {args.user_out} ({len(user_prompt)} chars)")


if __name__ == "__main__":
    main()
