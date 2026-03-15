import re
from .adb_utils import run_adb_command

# Common malware indicators of compromise (IoCs) and suspicious patterns
MALWARE_PATTERNS = {
    "Reverse Shell": [r"nc\s+-e\s+/bin/sh", r"bash\s+-i\s+>\s+&", r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+"],
    "Persistence": [r"reboot\s+&&", r"init\.d", r"crontab"],
    "Obfuscation/Execution": [r"eval\(base64", r"sh\s+-c\s+'", r"chmod\s+\+x", r"exec\s+>\s+/dev/null"],
    "Sensitive Data Exposure": [r"grep\s+-r\s+password", r"sqlite3\s+.*\.db\s+.*SELECT"],
    "C2/Botnet Activity": [r"wget\s+http://[a-z0-9.-]+/[a-z0-9]", r"curl\s+-s\s+http://"]
}

def scan_file_content(file_path, device_id=None):
    """Searches for suspicious patterns inside a specific file on the device."""
    findings = []
    
    # Use grep on the device to avoid pulling large files
    for category, patterns in MALWARE_PATTERNS.items():
        for pattern in patterns:
            # -E for extended regex, -q for quiet (just exit status)
            # We want the content if it matches, so we use -m 5 to limit output
            cmd = ["shell", "grep", "-Ei", pattern, file_path]
            output = run_adb_command(cmd, device_id)
            
            if output and "Error" not in output and "No such file" not in output:
                findings.append({
                    "category": category,
                    "pattern": pattern,
                    "snippet": output.strip().split("\n")[0][:100] # Get first match snippet
                })
    return findings

def audit_apk_shallow(package_name, device_id=None):
    """Performs a shallow audit of an app's metadata using dumpsys."""
    findings = []
    output = run_adb_command(["shell", "dumpsys", "package", package_name], device_id)
    
    if "Error" in output:
        return findings
        
    # Look for suspicious intent filters or flags
    if "android.intent.action.BOOT_COMPLETED" in output:
        findings.append("Starts automatically on boot")
        
    if "SYSTEM_ALERT_WINDOW" in output or "draw over other apps" in output.lower():
        findings.append("Can display overlays (Potential Screen Overlay attack)")
        
    if "BIND_ACCESSIBILITY_SERVICE" in output:
        findings.append("Requests Accessibility Service access")
        
    return findings

def content_scan_sdcard(device_id=None):
    """Scans suspicious files on /sdcard for malicious content."""
    # We target files found by the file_scanner (scripts, hidden files)
    # For now, we use a broad find + grep approach for efficiency
    
    results = []
    # Targeted extensions/hidden files
    target_exts = [".sh", ".js", ".py", ".bin", ".*", "config*"]
    
    for ext in target_exts:
        # Find files and grep them directly on the device
        # Limit to 2 levels deep to avoid massive lag
        find_cmd = f"find /sdcard -maxdepth 2 -name '*{ext}' -type f"
        files_output = run_adb_command(["shell", find_cmd], device_id)
        
        if not files_output or "Error" in files_output:
            continue
            
        files = files_output.splitlines()
        for f in files:
            f = f.strip()
            if not f: continue
            
            file_findings = scan_file_content(f, device_id)
            if file_findings:
                results.append({
                    "file": f,
                    "issues": file_findings
                })
                
    return results
