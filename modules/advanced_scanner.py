from .adb_utils import run_adb_command

def get_launcher_apps(device_id=None):
    """Gets a list of all packages that have a launcher icon."""
    output = run_adb_command(["shell", "pm", "query-intent-activities", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER"], device_id)
    if "Error" in output:
        return []
    
    launcher_packages = set()
    import re
    # Broadly search for anything that looks like a package name in the output
    # This catches 'pkg=com.foo', 'package=com.foo', 'com.foo/.Activity', etc.
    matches = re.findall(r'([a-z][a-z0-9_]*\.[a-z][a-z0-9_.]+)', output.lower())
    for pkg in matches:
        # Avoid matching partial names like 'android.intent'
        if len(pkg.split('.')) >= 2:
            launcher_packages.add(pkg)
    return launcher_packages

def get_enabled_accessibility_services(device_id=None):
    """Gets a list of enabled accessibility services."""
    output = run_adb_command(["shell", "settings", "get", "secure", "enabled_accessibility_services"], device_id)
    if "Error" in output or "null" in output or not output.strip():
        return []
    return [s for s in output.split(":") if s.strip()]

def get_device_admins(device_id=None):
    """Gets a list of active device administrators."""
    output = run_adb_command(["shell", "dumpsys", "device_policy"], device_id)
    if "Error" in output:
        return []
    
    admins = []
    found_section = False
    for line in output.split("\n"):
        if "Active Administrators:" in line:
            found_section = True
            continue
        if found_section:
            if ":" in line and "/" in line:
                pkg = line.strip().split("/")[0]
                if pkg.startswith("Admin Info"):
                    pkg = pkg.split("{")[1].split("/")[0]
                admins.append(pkg)
            elif line.strip() == "" or "---" in line:
                break # End of section
    return list(set(admins))

def get_active_connections(device_id=None):
    """Checks for active network listeners (netstat)."""
    # Modern Android restricted netstat for non-root; using fallback if needed.
    output = run_adb_command(["shell", "netstat", "-tulpen"], device_id)
    if "Error" in output or not output.strip():
        # Fallback to local socket check or simple netstat
        output = run_adb_command(["shell", "netstat", "-ant"], device_id)
    
    return output
