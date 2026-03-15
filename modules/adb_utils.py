import subprocess
import os

def run_adb_command(command, device_id=None):
    """Executes an ADB command and returns the output."""
    prefix = ["adb"]
    if device_id:
        prefix.extend(["-s", device_id])
    
    full_command = prefix + command
    try:
        # Use errors='replace' to handle non-UTF-8 characters gracefully (common in file systems)
        result = subprocess.run(full_command, capture_output=True, text=True, check=True, errors='replace')
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr.strip() if e.stderr else str(e)}"

def get_connected_devices():
    """Returns a list of connected device IDs."""
    output = run_adb_command(["devices"])
    lines = output.split("\n")[1:] # Skip header
    devices = []
    for line in lines:
        if line.strip():
            parts = line.split()
            if parts[1] == "device":
                devices.append(parts[0])
    return devices

def is_device_connected():
    """Checks if at least one device is connected."""
    return len(get_connected_devices()) > 0

def get_detailed_device_info(device_id=None):
    """Extracts detailed metadata about the device."""
    props = {
        "Model": "ro.product.model",
        "Manufacturer": "ro.product.manufacturer",
        "Android Version": "ro.build.version.release",
        "Security Patch": "ro.build.version.security_patch",
        "Build ID": "ro.build.display.id",
        "Kernel": "ro.kernel.version"
    }
    
    info = {"Serial": device_id if device_id else "Unknown"}
    for label, prop in props.items():
        val = run_adb_command(["shell", "getprop", prop], device_id)
        info[label] = val if val and "Error" not in val else "Unknown"
        
    return info
