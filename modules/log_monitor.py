import subprocess
import threading
import time
import re

# Threat patterns to watch for in logcat
LOG_WATCH_PATTERNS = [
    {"name": "Camera Access", "pattern": r"CameraService.*opened", "severity": "WARNING"},
    {"name": "Location Access", "pattern": r"LocationManager.*get[a-zA-Z]*Location", "severity": "INFO"},
    {"name": "SMS Activity", "pattern": r"SMS.*send|SMS.*receive", "severity": "WARNING"},
    {"name": "Accessibility Abuse", "pattern": r"AccessibilityManager.*enabled", "severity": "WARNING"},
    {"name": "Process Execution", "pattern": r"ActivityManager.*startProcess", "severity": "INFO"}
]

class LogMonitor:
    """Monitors adb logcat for security-relevant events in a background thread."""
    def __init__(self, device_id=None, callback=None):
        self.device_id = device_id
        self.callback = callback # Function to call when a threat is detected
        self.is_running = False
        self.process = None
        self.thread = None

    def _monitor_loop(self):
        """Continuously reads logcat output and matches against threat patterns."""
        cmd = ["adb"]
        if self.device_id:
            cmd.extend(["-s", self.device_id])
        cmd.extend(["logcat", "-v", "task", "-T", "1"]) # -T 1 starts from now

        try:
            self.process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                errors='replace'
            )
            
            while self.is_running:
                line = self.process.stdout.readline()
                if not line:
                    break
                
                for item in LOG_WATCH_PATTERNS:
                    if re.search(item["pattern"], line, re.IGNORECASE):
                        if self.callback:
                            self.callback(item["name"], item["severity"], line[:100].strip())
                            
        except Exception as e:
            if self.is_running:
                print(f"[-] LogMonitor Error: {e}")

    def start(self):
        """Starts the monitoring thread."""
        if not self.is_running:
            self.is_running = True
            self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.thread.start()

    def stop(self):
        """Stops the monitoring thread and kills the adb process."""
        self.is_running = False
        if self.process:
            self.process.terminate()
        if self.thread:
            self.thread.join(timeout=2)
