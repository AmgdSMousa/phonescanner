from .adb_utils import run_adb_command

# List of sensitive permissions that could be used for malicious purposes
SENSITIVE_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES"
]

def get_package_permissions(package_name, device_id=None):
    """Gets all granted permissions for a specific package."""
    output = run_adb_command(["shell", "dumpsys", "package", package_name], device_id)
    if "Error" in output:
        return []
    
    granted_permissions = set()
    # Simple parsing logic for dumpsys output
    start_granted = False
    for line in output.split("\n"):
        line = line.strip()
        if "install permissions:" in line or "requested permissions:" in line:
            start_granted = True
            continue
        if start_granted and ":" in line:
            # We hit another section
            if not line.startswith("android.permission"):
                continue
        if start_granted and line.startswith("android.permission"):
            perm = line.split(":")[0].strip()
            if "granted=true" in line or line.endswith("granted=true"):
                granted_permissions.add(perm)
    return list(granted_permissions)

def analyze_permissions(packages, device_id=None):
    """Analyze all installed apps for sensitive permissions."""
    results = []
    for pkg in packages:
        # Skip system apps for speed or focus on user apps? Let's check user apps mainly but allow system if requested.
        # For now, let's scan all but tag them.
        perms = get_package_permissions(pkg["name"], device_id)
        sensitive_found = [p for p in perms if p in SENSITIVE_PERMISSIONS]
        if sensitive_found:
            results.append({
                "name": pkg["name"],
                "sensitive_permissions": sensitive_found
            })
    return results
