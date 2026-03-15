from .adb_utils import run_adb_command

def get_installed_packages(device_id=None):
    """Gets a list of all installed packages on the device."""
    # Try multiple methods for maximum compatibility (supports multi-user)
    methods = [
        ["shell", "pm", "list", "packages", "-f", "--user", "0"],
        ["shell", "pm", "list", "packages", "--user", "0"],
        ["shell", "cmd", "package", "list", "packages", "--user", "0"],
        ["shell", "pm", "list", "packages", "-f"],
        ["shell", "pm", "list", "packages"],
        ["shell", "dumpsys", "package", "packages"]
    ]
    
    packages_found = {}
    
    # Try the standard pm/cmd methods
    for cmd in methods[:-1]:
        output = run_adb_command(cmd, device_id)
        if output.strip() and "Error:" not in output:
            lines = output.splitlines()
            for line in lines:
                line = line.strip()
                if not line: continue
                
                # Strip 'package:' prefix
                clean_line = line[8:].strip() if line.startswith("package:") else line
                
                if "=" in clean_line:
                    parts = clean_line.split("=")
                    package_name = parts[-1].strip()
                    path = parts[0].strip()
                else:
                    package_name = clean_line
                    path = "Unknown"
                
                if package_name and "." in package_name:
                    is_system = any(path.startswith(p) for p in ["/system", "/vendor", "/product", "/apex"]) or \
                                any(package_name.startswith(p) for p in ["com.android.", "com.google.android.", "com.miui.", "com.xiaomi.", "com.samsung.", "com.sec."])
                    packages_found[package_name] = {"name": package_name, "path": path, "is_system": is_system}
            
            if packages_found:
                break
    
    # If standard methods failed, try dumpsys (parsing is different)
    if not packages_found:
        output = run_adb_command(methods[-1], device_id)
        if output.strip() and "Error:" not in output:
            import re
            # Matches "Package [com.foo.bar]" or "Package{... com.foo.bar/..."
            matches = re.findall(r'Package \[?([a-zA-Z0-9._]+)\]?', output)
            for package_name in set(matches):
                if "." in package_name and len(package_name.split(".")) > 1:
                    is_system = any(package_name.startswith(p) for p in ["com.android.", "com.google.android.", "com.samsung.", "com.sec.", "com.google."])
                    packages_found[package_name] = {"name": package_name, "path": "Dumpsys", "is_system": is_system}
            
    return list(packages_found.values())

def scan_for_suspicious_packages(packages):
    """Checks for packages with known suspicious names or characteristics."""
    suspicious = []
    # Common keywords for potentially unwanted apps or malware
    keywords = ["spy", "track", "keylog", "hack", "root", "metasploit", "superman", "kingroot"]
    
    for pkg in packages:
        name = pkg["name"].lower()
        if any(kw in name for kw in keywords):
            suspicious.append({**pkg, "reason": "Suspicious keyword in package name"})
            
    return suspicious
