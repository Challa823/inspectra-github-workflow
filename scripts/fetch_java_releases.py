import requests
import json

def fetch_java_releases():
    url = "https://java.oraclecloud.com/javaReleases"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses
        return response.json()  # Return the JSON response
    except requests.RequestException as e:
        print(f"Error fetching Java releases: {e}")
        return {"note": "fetch failed; using empty payload"}

if __name__ == "__main__":
    java_releases = fetch_java_releases()
    with open("java_releases.json", "w") as f:
        json.dump(java_releases, f, indent=2)