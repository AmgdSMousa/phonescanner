from .adb_utils import run_adb_command

def check_root_access(device_id=None):
    """Checks if the device has root access by trying to call 'su'."""
    output = run_adb_command(["shell", "which", "su"], device_id)
    if "Error" not in output and "/su" in output:
        return True
    
    # Fallback: check su execution directly
    output = run_adb_command(["shell", "su", "-c", "whoami"], device_id)
    if "root" in output:
        return True
        
    return False

def check_bootloader_status(device_id=None):
    """Checks if the bootloader is unlocked (if available via props)."""
    # Manufacturer-specific props for BL status
    props = [
        "ro.boot.flash.locked",
        "ro.boot.verifiedbootstate",
        "ro.secure",
        "ro.debuggable"
    ]
    
    results = {}
    for prop in props:
        value = run_adb_command(["shell", "getprop", prop], device_id)
        results[prop] = value
        
    return results

def check_busybox(device_id=None):
    """Checks if busybox is installed (often present on rooted/modded devices)."""
    output = run_adb_command(["shell", "which", "busybox"], device_id)
    return "busybox" in output
