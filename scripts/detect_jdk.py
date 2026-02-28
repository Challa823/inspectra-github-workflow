import subprocess
import json
import argparse
import sys


def detect_jdk() -> dict:
    try:
        output = subprocess.check_output(
            ['java', '-version'],
            stderr=subprocess.STDOUT,
            text=True
        )
        # java -version output format: openjdk version "17.0.11" 2024-04-16
        vendor = output.split()[0]  # e.g. "openjdk" or "java"
        full_version = output.split('"')[1]  # e.g. "17.0.11"
        major_str = full_version.split('.')[0]
        major = int(major_str) if major_str.isdigit() else 0

        return {
            "vendor": vendor,
            "version": full_version,
            "major": major
        }
    except subprocess.CalledProcessError as e:
        print(f"[WARN] Error running java -version: {e.output}", file=sys.stderr)
    except Exception as e:
        print(f"[WARN] Unexpected error detecting JDK: {e}", file=sys.stderr)

    return {"vendor": "Unknown", "version": "Unknown", "major": 0}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect JDK version and write to JSON")
    parser.add_argument("--output", default="jdk_info.json", help="Output JSON file path")
    args = parser.parse_args()

    jdk_info = detect_jdk()

    with open(args.output, "w") as f:
        json.dump(jdk_info, f, indent=2)

    print(f"[INFO] JDK info written to {args.output}")
    print(json.dumps(jdk_info, indent=2))
