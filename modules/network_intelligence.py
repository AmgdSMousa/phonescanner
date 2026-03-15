import json
import urllib.request
import socket
import re

# Simple in-memory cache to avoid redundant API calls during a single scan
IP_CACHE = {}

def is_private_ip(ip):
    """Checks if an IP address is private/local."""
    # IPv4 Private ranges
    private_patterns = [
        r"^127\.", r"^10\.", r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", r"^192\.168\.", r"^0\.0\.0\.0", r"^::1$", r"^fe80:"
    ]
    return any(re.match(i, ip) for i in private_patterns) or ip == "localhost" or ip == "::"

def get_ip_info(ip):
    """Fetches geolocation and ISP info for a given public IP using ip-api.com."""
    if not ip or is_private_ip(ip):
        return None
        
    if ip in IP_CACHE:
        return IP_CACHE[ip]
        
    try:
        # Use ip-api.com (free for non-commercial, no API key needed for basic usage)
        # We limit the fields to reduce bandwidth
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query"
        with urllib.request.urlopen(url, timeout=3) as response:
            data = json.loads(response.read().decode())
            
        if data.get("status") == "success":
            info = {
                "country": data.get("country"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org")
            }
            IP_CACHE[ip] = info
            return info
    except Exception:
        pass
    
    return None

def extract_ip_from_netstat_line(line):
    """Extracts the remote IP address from a netstat/ss line."""
    # Handle different formats for tcp/tcp6/udp
    # Example: 192.168.100.4:54770  142.250.74.170:443
    parts = re.split(r'\s+', line.strip())
    if len(parts) < 5:
        return None
        
    remote_addr = parts[4] if "LISTEN" not in line else parts[3]
    
    # Strip port number
    if "]:" in remote_addr: # IPv6
        ip = remote_addr.split("]:")[0].replace("[", "").replace("]", "")
    elif ":" in remote_addr:
        ip = remote_addr.split(":")[0]
    else:
        ip = remote_addr
        
    # Remove IPv6 prefix if present (e.g. ::ffff:)
    if ip.startswith("::ffff:"):
        ip = ip.replace("::ffff:", "")
        
    return ip if ip and ip != "*" and ip != "0.0.0.0" and ip != "::" else None

def enrich_connections(connections_list):
    """Enriches a list of connection strings with geolocation data."""
    enriched_results = []
    
    # Only process unique public IPs to minimize API calls
    unique_ips = set()
    for conn in connections_list:
        ip = extract_ip_from_netstat_line(conn)
        if ip and not is_private_ip(ip):
            unique_ips.add(ip)
            
    # Pre-fetch IP info (Note: ip-api has a rate limit of 45 requests per minute)
    # For a few connections, this is fine.
    ip_data_map = {}
    for ip in list(unique_ips)[:15]: # Limit to 15 unique IPs per scan to be safe
        info = get_ip_info(ip)
        if info:
            ip_data_map[ip] = info
            
    for conn in connections_list:
        ip = extract_ip_from_netstat_line(conn)
        enrichment = ip_data_map.get(ip)
        
        if enrichment:
            loc = f"{enrichment['city']}, {enrichment['country']}"
            isp = enrichment['isp']
            enriched_results.append(f"{conn} [{loc} | ISP: {isp}]")
        else:
            enriched_results.append(conn)
            
    return enriched_results
