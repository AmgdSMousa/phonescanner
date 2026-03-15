from .adb_utils import run_adb_command
import re

def get_running_processes(device_id=None):
    """Gets a list of running processes on the device."""
    # Using 'ps -A' for modern Android, 'ps' as fallback
    output = run_adb_command(["shell", "ps", "-A", "-o", "USER,PID,PPID,VSZ,RSS,WCHAN,ADDR,S,NAME"], device_id)
    if "Error" in output:
        output = run_adb_command(["shell", "ps"], device_id)
        
    processes = []
    lines = output.split("\n")
    if not lines: return []
    
    header = lines[0].split()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= len(header):
            # Map process to a dict
            proc_info = {
                "user": parts[0],
                "pid": parts[1],
                "name": parts[-1]
            }
            processes.append(proc_info)
    return processes

def identify_suspicious_processes(processes, packages):
    """Identifies processes that might be suspicious."""
    # Suspicious:
    # 1. Names that aren't in the package list (for user apps)
    # 2. Known shell/reverse shell names
    # 3. Root processes that aren't expected
    
    package_names = set(p["name"] for p in packages)
    system_prefixes = [
        "com.android.", "com.google.android.", "com.miui.", "com.xiaomi.", 
        "android.", "system", "healthd", "adbd", "com.qualcomm.", "vendor.",
        "com.qti.", "com.nxp.", "com.mediatek."
    ]
    
    suspicious = []
    for proc in processes:
        name = proc["name"]
        
        # Skip kernel/system workers usually starting with [ or / or .
        if name.startswith("[") or name.startswith("/") or ":" in name or name.startswith("."):
            continue
            
        # If it's a "user" process but not a known package
        if proc["user"].startswith("u0_"): # Standard Android user prefix
            if name not in package_names and not any(name.startswith(p) for p in system_prefixes):
                if name not in ["sh", "ps", "toybox", "logcat", "magisk", "su"]: # Common temp shells/tools
                    suspicious.append({**proc, "reason": "Background process not associated with any installed app package"})
        
        # Check for common reverse shell/hacking names
        hacking_names = ["nc", "ncat", "socat", "metasploit", "meterpreter"]
        if name in hacking_names:
            suspicious.append({**proc, "reason": f"Potentially malicious binary name: {name}"})
            
    return suspicious

def correlate_network_with_processes(device_id=None):
    """Tries to find which process is using network (requires root or specific adb permissions)."""
    # Best effort: /proc/net is restricted on modern Android.
    output = run_adb_command(["shell", "cat", "/proc/net/tcp"], device_id)
    if "Error" in output:
        return "Not available on this device without root."
    return "Network tracing active..."
