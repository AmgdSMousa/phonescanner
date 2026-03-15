from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.live import Live
from rich.layout import Layout
from rich import box
import time
from datetime import datetime

console = Console()

def create_header(device_model, serial):
    """Creates a premium header for the dashboard."""
    grid = Table.grid(expand=True)
    grid.add_column(justify="center", ratio=1)
    grid.add_column(justify="right")
    
    title = f"[bold white on blue] 🛡️ MOBILE SECURITY SCANNER PRO [/]"
    grid.add_row(
        title,
        f"[dim]{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/]"
    )
    
    subtitle = f"[bold cyan]Device:[/] {device_model} | [bold cyan]Serial:[/] {serial}"
    
    return Panel(grid, title=subtitle, title_align="left", border_style="blue", box=box.ROUNDED)

def create_scan_table(scan_results):
    """Creates a table to show the current scan status and findings."""
    table = Table(box=box.SIMPLE, expand=True)
    table.add_column("Module", style="cyan", width=25)
    table.add_column("Status", justify="center", width=15)
    table.add_column("Findings/Alerts", style="white")

    for module, result in scan_results.items():
        status_style = "green" if result['status'] == "OK" else "bold yellow" if result['status'] == "WARNING" else "bold red"
        table.add_row(
            module,
            f"[{status_style}]{result['status']}[/]",
            result['summary']
        )
    
    return table

def render_dashboard(device_info, scan_results, current_task=None, alerts=None):
    """Renders the full dashboard view."""
    header = create_header(device_info.get('Model', 'Unknown'), device_info.get('Serial', 'N/A'))
    table = create_scan_table(scan_results)
    
    # Alerts Panel
    alert_content = "\n".join(alerts) if alerts else "[dim]No real-time events detected...[/]"
    alerts_panel = Panel(alert_content, title="[bold red] ⚠️ LIVE SECURITY EVENTS [/]", border_style="red", box=box.ROUNDED)

    footer_text = f"Current Activity: [bold yellow]{current_task}[/]" if current_task else "[dim]Finalizing scan report...[/]"
    footer = Panel(footer_text, border_style="blue", box=box.ROUNDED)
    
    body_layout = Layout()
    body_layout.split_row(
        Layout(Panel(table, title="[bold white]Real-Time Security Audit[/]", border_style="cyan"), ratio=2),
        Layout(alerts_panel, ratio=1)
    )
    
    layout = Layout()
    layout.split(
        Layout(header, size=5),
        body_layout,
        Layout(footer, size=3)
    )
    
    return layout

class DashboardManager:
    """Manages the lifecycle of the TUI dashboard."""
    def __init__(self, device_info):
        self.device_info = device_info
        self.scan_results = {}
        self.live_alerts = [] # New: stores real-time security events
        self.live = None
        self.current_task = "Initializing..."

    def add_alert(self, name, severity, detail):
        """Adds a real-time alert and refreshes the display."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        alert_str = f"[{timestamp}] [{severity}] {name}: {detail[:50]}..."
        self.live_alerts.insert(0, alert_str)
        self.live_alerts = self.live_alerts[:5] # Keep only last 5 alerts
        if self.live:
            self.live.update(render_dashboard(self.device_info, self.scan_results, self.current_task, self.live_alerts))

    def update(self, module_name, status, summary):
        """Updates a module's result and refreshes the live display."""
        self.scan_results[module_name] = {"status": status, "summary": summary}
        if self.live:
            self.live.update(render_dashboard(self.device_info, self.scan_results, self.current_task, self.live_alerts))

    def set_task(self, task_name):
        self.current_task = task_name
        if self.live:
            self.live.update(render_dashboard(self.device_info, self.scan_results, self.current_task, self.live_alerts))

    def start(self):
        self.live = Live(render_dashboard(self.device_info, self.scan_results, self.current_task, self.live_alerts), refresh_per_second=4)
        self.live.start()

    def stop(self):
        if self.live:
            time.sleep(1) # Final refresh
            self.live.stop()
