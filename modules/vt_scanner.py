import json
import urllib.request
import os

# VirusTotal API configuration
# Users should set the VT_API_KEY environment variable
API_KEY = os.environ.get("VT_API_KEY", "")

def check_file_hash_vt(file_hash, api_key=None):
    """
    Checks a file hash (SHA256) on VirusTotal.
    Returns detection summary if found, or error/not found messages.
    """
    key = api_key if api_key else API_KEY
    
    if not key:
        return {"error": "VirusTotal API Key missing. Set VT_API_KEY env var."}
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": key,
        "Accept": "application/json"
    }
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        # Determine risk level
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        return {
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "total_engines": sum(stats.values()),
            "type": attributes.get("type_description", "Unknown"),
            "meaningful_name": attributes.get("meaningful_name", "Unknown")
        }
        
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False, "message": "Hash not found in VirusTotal database."}
        elif e.code == 401:
            return {"error": "Invalid VirusTotal API Key."}
        elif e.code == 429:
            return {"error": "VirusTotal API rate limit exceeded."}
        else:
            return {"error": f"API Error: HTTP {e.code}"}
    except Exception as e:
        return {"error": f"Connection Error: {str(e)}"}

def scan_multi_hashes(hashes, api_key=None):
    """Checks multiple hashes and returns a consolidated report."""
    results = {}
    for h in hashes:
        results[h] = check_file_hash_vt(h, api_key)
    return results
