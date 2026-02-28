import os
import json
import requests

def call_github_models(system_prompt, user_prompt, model="gpt-4o-mini"):
    url = "https://models.github.ai/inference/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {os.getenv('GH_TOKEN')}"
    }
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.0,
        "max_tokens": 4000,
        "stream": False
    }
    
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()  # Raise an error for bad responses
    return response.json()

if __name__ == "__main__":
    # Example usage (replace with actual prompts)
    system_prompt = "You are a senior SSL/TLS security engineer. Be precise and concise."
    user_prompt = "Given the collected scan data, determine for each endpoint whether it is 'Supported', 'Not Supported', or 'Unknown'."
    
    try:
        analysis_result = call_github_models(system_prompt, user_prompt)
        print(json.dumps(analysis_result, indent=2))
    except Exception as e:
        print(f"Error calling GitHub Models API: {e}")