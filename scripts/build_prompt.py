import json
import os
import argparse

SYSTEM_PROMPT = """\
You are a senior TLS/SSL security engineer and build engineer. Follow all instructions exactly, \
preserve field names exactly as specified, and only derive values from the provided JSON inputs. \
Do not invent fields or rename keys. When data is missing, use "Unknown" values and explain briefly.\
"""

USER_TEMPLATE = """\
# INPUT: Pre-extracted TLS context
<<<TLS_CONTEXT_JSON>>>

# COMPATIBILITY EVALUATION
For EACH observed composite pair (cartesian product) of:
- one entry from "tls version"
- one entry from "Cipher version"

determine whether the pair is supported:
- NOW     (CurrentJdkVersion)
- FUTURE MINOR (futureJDKMinorUpgradeVersion)
- FUTURE MAJOR (FutureMajorUpgradedVersion)

Assumptions (apply conservatively):
- TLS 1.3: JDK 11+. TLS 1.2: JDK 7+. TLS < 1.2: Not Supported.
- AEAD ciphers (GCM/CHACHA20) with ECDHE preferred.
- RC4/3DES/NULL/EXPORT/MD5/SHA-1 contexts: Not Supported in modern baselines.
- If CurrentJdkVersion major < 11, no TLS 1.3 unless stated.
- If release data is insufficient, verdict = "Unknown".

Severity mapping:
- NOT supported in futureMinor => "CRITICAL"
- Supported in futureMinor but NOT in futureMajor => "HIGH"
- Supported in both => "INFO"

# OUTPUT - PAGE 1 (exact structure, valid JSON only, no markdown)
1) "extraction" object — copy the input context exactly as-is (same keys, same values).
2) "compatibility" array — one item per composite pair:
   {
     "tls version":    "<TLS value>",
     "Cipher version": "<Cipher value>",
     "now":            "Supported|Not Supported|Unknown",
     "futureMinor":    "Supported|Not Supported|Unknown",
     "futureMajor":    "Supported|Not Supported|Unknown",
     "severity":       "CRITICAL|HIGH|INFO",
     "reason":         "<short reason, max 140 chars>",
     "action":         "<short remediation, max 140 chars>"
   }
3) "highSummaryFromErrors" string — one paragraph synthesising risks from "uniqusslerrors". If empty, use "".

# OUTPUT - PAGE 2 (augment endpoints from endpoints_scan_augmented)
"endpoints_scan_augmented" array — ALL endpoint objects unmodified PLUS two new keys each:
- "Review comments": explanation if severity is CRITICAL/HIGH for that endpoint's (tls version, Cipher version); else "".
- "Action": concise fix; else "".
Preserve all original keys exactly.

Output order: extraction, compatibility, highSummaryFromErrors, endpoints_scan_augmented.
No markdown, no extra commentary. Valid JSON only.
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
