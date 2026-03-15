from .adb_utils import run_adb_command
import re

SUSPICIOUS_EXTENSIONS = [".sh", ".exe", ".bat", ".py", ".php", ".js", ".apk"]

def list_files_recursive(path, device_id=None):
    """Lists files recursively in a given path."""
    # Using 'find' if available, else 'ls -R'
    output = run_adb_command(["shell", "find", path, "-type", "f"], device_id)
    if "not found" in output or "Error" in output:
        # Fallback to ls -R
        output = run_adb_command(["shell", "ls", "-R", path], device_id)
    return output

def scan_storage_for_malware(device_id=None):
    """Scans /sdcard for suspicious files."""
    results = {
        "suspicious_files": [],
        "hidden_files": [],
        "apks_found": []
    }
    
    # Common paths to check
    scan_paths = ["/sdcard/Download", "/sdcard/Documents", "/sdcard/Android/data"]
    
    for path in scan_paths:
        # Get list of files
        output = run_adb_command(["shell", "ls", "-laR", path], device_id)
        if "Error" in output:
            continue
            
        lines = output.split("\n")
        current_dir = path
        for line in lines:
            line = line.strip()
            if not line: continue
            
            # Directory marker
            if line.endswith(":"):
                current_dir = line[:-1]
                continue
            
            # File info parsing (ls -laR format)
            # drwxrwx--x 2 root sdcard_rw 4096 2024-01-01 12:00 filename
            parts = line.split()
            if len(parts) < 8: continue
            
            filename = parts[-1]
            full_path = f"{current_dir}/{filename}"
            
            # 1. Check for APKs (could be side-loaded malware)
            if filename.lower().endswith(".apk"):
                results["apks_found"].append(full_path)
            
            # 2. Check for hidden files/folders (starting with .) in user directories
            if filename.startswith(".") and filename not in [".", ".."]:
                results["hidden_files"].append(full_path)
            
            # 3. Check for suspicious scripts or executables
            if any(filename.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS if ext != ".apk"):
                results["suspicious_files"].append(full_path)
                
    return results

def get_file_hash(file_path, device_id=None):
    """Calculates the SHA256 hash of a file on the device."""
    output = run_adb_command(["shell", "sha256sum", file_path], device_id)
    if "Error" in output or "not found" in output:
        # Fallback to md5sum if sha256sum is missing
        output = run_adb_command(["shell", "md5sum", file_path], device_id)
        
    if " " in output:
        return output.split()[0].strip()
    return "Unknown"

def get_large_files(device_id=None, min_mb=50):
    """Finds unusually large files (might be encrypted data or hidden archives)."""
    # find /sdcard -type f -size +50M
    output = run_adb_command(["shell", "find", "/sdcard", "-type", "f", "-size", f"+{min_mb}M"], device_id)
    if "Error" in output:
        return []
    return [line.strip() for line in output.split("\n") if line.strip()]
