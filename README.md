# Mobile Security Scanner Pro

A comprehensive, industry-grade security scanner for Android devices. This tool performs deep analysis via ADB, providing detailed insights and active remediation capabilities.

## Key Features

- **🛡️ Interactive Dashboard**: Professional real-time TUI with live progress updates.
- **⚔️ Active Remediation**:
    - **Freeze/Disable**: Safely stop suspicious apps from running.
    - **Uninstall**: Remove identified threats permanently.
    - **Force Stop**: Kill malicious background processes instantly.
- **🌍 Network Intelligence**: Geolocation and ISP identification for all active connections.
- **📈 Vulnerability Assessment**: CVE tracking based on the device's security patch level.
- **🔍 VirusTotal Integration**: Hash-based cloud malware scanning using 70+ AV engines.
- **🕵️ Advanced Behavioral Analysis**:
    - **Hidden App Detection**: Finds apps without launcher icons and audits their metadata.
    - **Accessibility Audit**: Flags potential spyware using accessibility services.
- **📂 File System Audit**: Deep scan of storage for suspicious scripts, side-loaded APKs, and hidden files.
- **⚙️ Resilient Engine**: Fully compatible with modern Android (12-16) and various OEM distributions.

## How to Use

### 1. Launching the Scanner
Run the scan with the interactive dashboard:
```bash
python3 scanner.py -u
```

### 2. Full Security Audit (Cloud Connect)
Combine the dashboard with VirusTotal malware checks:
```bash
python3 scanner.py -u -k <YOUR_API_KEY>
```

### 3. Remediation
After the scan completes, the tool will automatically identify "High Interest" threats and invite the user to choose active remediation actions such as freezing or uninstalling apps.

## Security Note
This tool is designed for security professionals and enthusiasts. Always verify findings before performing actions like uninstallation.
