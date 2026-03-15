import time
import threading
from .advanced_scanner import get_active_connections

class NetworkTelemetry:
    """Tracks network connection changes over time to detect intermittent C2 activity."""
    def __init__(self, device_id=None, interval=5):
        self.device_id = device_id
        self.interval = interval
        self.is_running = False
        self.known_connections = set()
        self.new_connections = []
        self.thread = None

    def _track_loop(self):
        while self.is_running:
            current = get_active_connections(self.device_id)
            lines = current.splitlines()
            for line in lines:
                if "ESTABLISHED" in line:
                    if line not in self.known_connections:
                        self.known_connections.add(line)
                        self.new_connections.append({
                            "time": time.strftime("%H:%M:%S"),
                            "details": line.strip()
                        })
            time.sleep(self.interval)

    def start(self):
        self.is_running = True
        self.thread = threading.Thread(target=self._track_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.is_running = False
        if self.thread:
            self.thread.join(timeout=1)
        return self.new_connections
