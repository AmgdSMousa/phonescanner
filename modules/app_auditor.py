from .adb_utils import run_adb_command
import subprocess
import os

def get_apk_path(package_name, device_id=None):
    """Gets the on-device path to an app's APK."""
    output = run_adb_command(["shell", "pm", "path", package_name], device_id)
    if "package:" in output:
        return output.replace("package:", "").strip()
    return None

def deep_audit_app(package_name, device_id=None):
    """
    Performs a deep audit of an app. 
    1. Uses dumpsys for intent/service info.
    2. Optional: Pulls APK metadata via aapt.
    """
    findings = {
        "intents": [],
        "services": [],
        "receivers": [],
        "risk_level": "LOW",
        "detailed_flags": []
    }
    
    # 1. Manifest / Component Audit via dumpsys
    output = run_adb_command(["shell", "dumpsys", "package", package_name], device_id)
    if not output or "Error" in output:
        return findings

    # Look for hidden/dangerous components
    patterns = {
        "SMS_RECEIVE": "android.provider.Telephony.SMS_RECEIVED",
        "BOOT_START": "android.intent.action.BOOT_COMPLETED",
        "ADMIN_REQ": "BIND_DEVICE_ADMIN",
        "OVERLAY": "SYSTEM_ALERT_WINDOW"
    }
    
    for key, pattern in patterns.items():
        if pattern in output:
            findings["detailed_flags"].append(f"Contains {key} component")
            if key in ["SMS_RECEIVE", "ADMIN_REQ"]:
                findings["risk_level"] = "HIGH"
    
    # 2. Extract specific intents
    import re
    intents = re.findall(r'([a-z0-9._]+\/[a-z0-9._$]+)', output)
    findings["intents"] = list(set(intents[:10])) # limit output
    
    return findings

def host_side_audit(package_name, device_id=None):
    """
    Experimental: Pulls the APK and uses local aapt for inspection.
    Only recommended for highly suspicious apps due to data usage.
    """
    apk_remote_path = get_apk_path(package_name, device_id)
    if not apk_remote_path:
        return "Could not locate APK on device."
    
    temp_apk = f"/tmp/{package_name}.apk"
    try:
        # We only pull the first part of the APK to save time if possible? 
        # Actually aapt might need the whole thing. Let's pull it.
        subprocess.run(["adb", "-s", device_id if device_id else "", "pull", apk_remote_path, temp_apk], capture_output=True)
        
        if os.path.exists(temp_apk):
            # Run aapt
            res = subprocess.run(["aapt", "dump", "badging", temp_apk], capture_output=True, text=True)
            os.remove(temp_apk)
            return res.stdout
    except Exception as e:
        return f"Host-side audit failed: {e}"
    
    return "Audit incomplete."
