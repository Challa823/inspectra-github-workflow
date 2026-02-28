import os
import json
import argparse
import requests

GITHUB_MODELS_URL = "https://models.inference.ai.azure.com/chat/completions"


def call_github_models(system_prompt: str, user_prompt: str, model: str = "gpt-4o-mini") -> dict:
    """Call the GitHub Models Chat Completions API and return the raw JSON response."""
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if not token:
        raise EnvironmentError(
            "Neither GITHUB_TOKEN nor GH_TOKEN environment variable is set."
        )

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.0,
        "max_tokens": 4000,
        "stream": False,
    }

    response = requests.post(GITHUB_MODELS_URL, headers=headers, json=payload, timeout=120)
    response.raise_for_status()
    return response.json()


def main():
    parser = argparse.ArgumentParser(description="Call GitHub Models Chat Completions API")
    parser.add_argument(
        "--prompt-file", default="prompt_user.txt",
        help="Path to the user prompt text file (produced by build_prompt.py)"
    )
    parser.add_argument(
        "--system-file", default="prompt_system.txt",
        help="Path to the system prompt text file (produced by build_prompt.py)"
    )
    parser.add_argument(
        "--model", default="gpt-4o-mini",
        help="GitHub Model identifier to use (default: gpt-4o-mini)"
    )
    parser.add_argument(
        "--output", default="ai_response.json",
        help="Output file for the raw API JSON response"
    )
    args = parser.parse_args()

    # Read system prompt (fall back to built-in default if file missing)
    if os.path.exists(args.system_file):
        with open(args.system_file, "r", encoding="utf-8") as f:
            system_prompt = f.read()
        print(f"[INFO] System prompt loaded from {args.system_file}")
    else:
        system_prompt = (
            "You are a senior TLS/SSL security engineer. "
            "Be precise and concise. Return valid JSON only."
        )
        print(f"[WARN] System prompt file not found ({args.system_file}), using built-in default.")

    # Read user prompt (required)
    if not os.path.exists(args.prompt_file):
        print(f"[ERROR] User prompt file not found: {args.prompt_file}")
        raise SystemExit(1)
    with open(args.prompt_file, "r", encoding="utf-8") as f:
        user_prompt = f.read()
    print(f"[INFO] User prompt loaded from {args.prompt_file} ({len(user_prompt)} chars)")

    print(f"[INFO] Calling GitHub Models API (model={args.model}) ...")
    try:
        result = call_github_models(system_prompt, user_prompt, model=args.model)
    except Exception as exc:
        print(f"[ERROR] GitHub Models API call failed: {exc}")
        raise SystemExit(1)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"[INFO] API response saved to {args.output}")


if __name__ == "__main__":
    main()