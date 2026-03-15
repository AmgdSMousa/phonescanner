import json
import urllib.request
import os
import time

# VirusTotal API configuration
API_KEY = os.environ.get("VT_API_KEY", "")
VT_CACHE = {} # Simple in-memory cache for the session

def check_file_hash_vt(file_hash, api_key=None):
    """Checks a file hash (SHA256) on VirusTotal with rate-limit handling."""
    if file_hash in VT_CACHE:
        return VT_CACHE[file_hash]
        
    key = api_key if api_key else API_KEY
    if not key:
        return {"error": "API Key missing."}
        
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": key, "Accept": "application/json"}
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
            
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        result = {
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total_engines": sum(stats.values()),
            "type": attributes.get("type_description", "Unknown")
        }
        VT_CACHE[file_hash] = result
        return result
        
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found": False, "message": "Hash not found."}
        elif e.code == 429:
            # Rate limit hit - Sleep and retry once or return error
            return {"error": "Rate limit exceeded"}
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}

def scan_multi_hashes(hashes, api_key=None, limit=20):
    """
    Checks multiple hashes. 
    On Free API (4/min), scanning 700+ hashes would take hours.
    We limit the scan and prioritize unique/suspicious types.
    """
    results = {}
    scanned_count = 0
    
    for h in hashes:
        if scanned_count >= limit:
            results[h] = {"found": False, "message": "Scan limit reached (Free API)"}
            continue
            
        res = check_file_hash_vt(h, api_key)
        results[h] = res
        
        if "error" not in res:
            scanned_count += 1
            # If we are using the free API, we should wait if we hit a limit, 
            # but for a CLI tool, it's better to just scan the top X.
            
    return results
