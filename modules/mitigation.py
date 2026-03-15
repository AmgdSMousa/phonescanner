from modules.adb_utils import run_adb_command

def freeze_app(package_name, device_id):
    """Disables an app for the current user (Freeze)."""
    if not package_name: return False
    # Using 'disable-user' is safer as it doesn't require root and is reversible
    result = run_adb_command(["shell", "pm", "disable-user", "--user", "0", package_name], device_id)
    return "disabled" in result.lower() or "new state" in result.lower()

def unfreeze_app(package_name, device_id):
    """Enables a previously disabled app."""
    if not package_name: return False
    result = run_adb_command(["shell", "pm", "enable", package_name], device_id)
    return "enabled" in result.lower() or "new state" in result.lower()

def uninstall_app(package_name, device_id):
    """Uninstalls an app from the device."""
    if not package_name: return False
    result = run_adb_command(["shell", "pm", "uninstall", package_name], device_id)
    return "success" in result.lower()

def force_stop_app(package_name, device_id):
    """Forcefully stops a running application."""
    if not package_name: return False
    run_adb_command(["shell", "am", "force-stop", package_name], device_id)
    # am force-stop doesn't return output on success, so we assume it worked
    return True

def get_mitigation_menu():
    """Returns a formatted string for the mitigation menu."""
    return """
[ Mitigation Menu ]
1. Freeze/Disable App (Safe - Stops app from running until enabled)
2. Uninstall App (Permanent - Removes app from device)
3. Force Stop App (Kills current process only)
4. Skip/Exit
"""
