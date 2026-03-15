import argparse
import os
import datetime
import time
import json
import sys
from modules.adb_utils import is_device_connected, get_connected_devices, get_detailed_device_info
from modules.package_scanner import get_installed_packages, scan_for_suspicious_packages
from modules.integrity_check import check_root_access, check_bootloader_status, check_busybox
from modules.permission_analyzer import analyze_permissions
from modules.advanced_scanner import get_launcher_apps, get_enabled_accessibility_services, get_device_admins, get_active_connections
from modules.file_scanner import scan_storage_for_malware, get_large_files, get_file_hash
from modules.process_scanner import get_running_processes, identify_suspicious_processes
from modules.content_inspector import content_scan_sdcard, audit_apk_shallow
from modules.network_intelligence import enrich_connections
from modules.vulnerability_scanner import check_vulnerabilities
from modules.vt_scanner import check_file_hash_vt
from modules.dashboard import DashboardManager
from modules.mitigation import freeze_app, uninstall_app, force_stop_app, get_mitigation_menu
from modules.log_monitor import LogMonitor
from modules.exploit_hunter import scan_world_writable, audit_system_props
from modules.app_auditor import deep_audit_app
from modules.reports_v2 import generate_html_report
from modules.network_telemetry import NetworkTelemetry

def print_header(title, file=None):
    text = f"\n{'='*60}\n  {title}\n{'='*60}"
    print(text)
    if file:
        file.write(text + "\n")

def log(text, file=None):
    print(text)
    if file:
        file.write(text + "\n")

def main():
    parser = argparse.ArgumentParser(description="Deep Mobile Security Scanner (Android)")
    parser.add_argument("-d", "--device", help="Specify device ID if multiple are connected")
    parser.add_argument("-s", "--skip-perms", action="store_true", help="Skip permission analysis (takes more time)")
    parser.add_argument("-k", "--vt-key", help="VirusTotal API Key for cloud-based malware scanning")
    parser.add_argument("-u", "--ui", action="store_true", help="Launch professional Interactive Dashboard (TUI)")
    args = parser.parse_args()

    print_header("Mobile Security Scanner Starting...")

    if not is_device_connected():
        print("[-] Error: No Android device detected via ADB. Please connect your phone and enable USB debugging.")
        sys.exit(1)

    devices = get_connected_devices()
    device_id = args.device if args.device else devices[0]
    
    # Initialize scan result variables to prevent NameErrors if sections are skipped
    packages = []
    suspicious = []
    user_apps_risk = []
    hidden_and_sensitive = []
    hidden_user_apps = []
    conn_list = []
    file_results = {"apks_found": [], "suspicious_files": [], "hidden_files": []}
    suspicious_procs = []
    content_findings = []
    vt_results = {}
    writable = []
    dangerous_props = []
    integrity_summary = "Audit pending"
    integrity_status = "INFO"
    hunter_status = "INFO"

    # Get Device Info
    device_info = get_detailed_device_info(device_id)
    
    # Initialize Dashboard if requested
    db = None
    if args.ui:
        db = DashboardManager(device_info)
        db.start()

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"reports/Scan_{device_info['Model'].replace(' ', '_')}_{device_id}_{timestamp}.txt"
    report_file = open(report_name, "w", encoding="utf-8")

    monitor = None
    telemetry = None
    if args.ui and db:
        monitor = LogMonitor(device_id, callback=db.add_alert)
        monitor.start()
        telemetry = NetworkTelemetry(device_id)
        telemetry.start()

    print_header("Mobile Security Scanner Starting...", report_file)
    log(f"[+] Scanning device: {device_id}", report_file)
    
    print_header("Device Metatdata", report_file)
    for label, val in device_info.items():
        log(f"[*] {label:16}: {val}", report_file)

    # 1. System Integrity Check
    if db: db.set_task("Checking System Integrity...")
    print_header("1. System Integrity Check", report_file)
    is_rooted = check_root_access(device_id)
    has_busybox = check_busybox(device_id)
    bootloader = check_bootloader_status(device_id)

    log(f"[*] Root Access: {'[!] DETECTED' if is_rooted else '[OK] Not Rooted'}", report_file)
    log(f"[*] Busybox:     {'[!] INSTALLED' if has_busybox else '[OK] Not Found'}", report_file)
    
    for prop, val in bootloader.items():
        log(f"[*] {prop}: {val if val else 'Unknown'}", report_file)
    
    if db:
        integrity_status = "WARNING" if is_rooted or has_busybox else "OK"
        integrity_summary = "Rooted/Busybox present" if integrity_status == "WARNING" else "Secure partition state"
        db.update("System Integrity", integrity_status, integrity_summary)

    # 2. Package Scanner
    if db: db.set_task("Scanning installed packages...")
    print_header("2. Package Scanner", report_file)
    log("[*] Fetching installed packages...", report_file)
    packages = get_installed_packages(device_id)
    log(f"[*] Total packages found: {len(packages)}", report_file)
    
    suspicious = scan_for_suspicious_packages(packages)
    if suspicious:
        log(f"[!] Warning: Found {len(suspicious)} suspicious package names:", report_file)
        for pkg in suspicious:
            log(f"    - {pkg['name']} ({pkg['reason']})", report_file)
    else:
        log("[OK] No obviously suspicious package names found.", report_file)
        
    if db:
        pkg_status = "WARNING" if suspicious else "OK"
        pkg_summary = f"Found {len(packages)} total packages"
        db.update("Package Scanner", pkg_status, pkg_summary)

    # 3. Permission Analysis
    if not args.skip_perms:
        if db: db.set_task("Analyzing app permissions...")
        print_header("3. Permission Analysis (Deep Scan)", report_file)
        log("[*] Analyzing apps with high-risk permissions...", report_file)
        perm_results = analyze_permissions(packages, device_id)
        
        user_apps_risk = [item for item in perm_results if not next(p for p in packages if p['name'] == item['name'])['is_system']]
        system_apps_risk = [item for item in perm_results if next(p for p in packages if p['name'] == item['name'])['is_system']]

        if user_apps_risk:
            log(f"\n[!] ALERT: {len(user_apps_risk)} USER apps have sensitive permissions:", report_file)
            for item in user_apps_risk[:20]:
                log(f"    - {item['name']}: {', '.join(item['sensitive_permissions'])}", report_file)
            if len(user_apps_risk) > 20:
                log(f"    ... and {len(user_apps_risk) - 20} more user apps.", report_file)
        else:
            log("\n[OK] No USER apps with critical permission sets found.", report_file)

        if system_apps_risk:
            log(f"\n[i] Info: {len(system_apps_risk)} SYSTEM apps have sensitive permissions (Normal for MIUI/Android):", report_file)
            for item in system_apps_risk[:5]: # Only show 5 system apps to avoid clutter
                log(f"    - {item['name']}", report_file)
            log(f"    ... and {len(system_apps_risk) - 5} more system apps.", report_file)
            
        if db:
            perm_status = "WARNING" if user_apps_risk else "OK"
            perm_summary = f"{len(user_apps_risk)} apps with risky permissions"
            db.update("Permission Audit", perm_status, perm_summary)
    else:
        log("\n[*] Skipping Permission Analysis as requested.", report_file)
        if db: db.update("Permission Audit", "INFO", "Skipped by user")

    # 4. Advanced Behavioral Analysis
    if db: db.set_task("Performing advanced behavioral analysis...")
    print_header("4. Advanced Behavioral Analysis", report_file)
    
    # 4.1 Hidden Apps
    launcher_apps = get_launcher_apps(device_id)
    hidden_user_apps = [p for p in packages if not p['is_system'] and p['name'] not in launcher_apps]
    
    # Cross-reference with permissions to find "High Interest" hidden apps
    sensitive_pkg_names = [item['name'] for item in perm_results]
    hidden_and_sensitive = [app for app in hidden_user_apps if app['name'] in sensitive_pkg_names]
    just_hidden = [app for app in hidden_user_apps if app['name'] not in sensitive_pkg_names]

    if hidden_and_sensitive:
        log(f"[!] ALERT: Found {len(hidden_and_sensitive)} HIDDEN apps with sensitive permissions:", report_file)
        for app in hidden_and_sensitive:
            perms = next(item['sensitive_permissions'] for item in perm_results if item['name'] == app['name'])
            log(f"    - {app['name']}: {', '.join(perms[:3])}...", report_file)
            # Add shallow audit for these high-interest hidden apps
            audit = audit_apk_shallow(app['name'], device_id)
            if audit:
                log(f"      [!] Behavior: {', '.join(audit)}", report_file)
    
    if just_hidden:
        log(f"\n[i] Info: Found {len(just_hidden)} other hidden user apps (Likely background services/plugins):", report_file)
        for app in just_hidden[:5]:
            log(f"    - {app['name']}", report_file)
        if len(just_hidden) > 5:
            log(f"    ... and {len(just_hidden) - 5} more.", report_file)
    
    if not hidden_user_apps:
        log("[OK] No hidden user apps found.", report_file)

    # 4.2 Accessibility Services
    acc_services = get_enabled_accessibility_services(device_id)
    if acc_services:
        log(f"\n[!] ALERT: {len(acc_services)} Accessibility Services are enabled:", report_file)
        for svc in acc_services:
            log(f"    - {svc.strip()}", report_file)
    else:
        log("\n[OK] No Accessibility Services enabled.", report_file)

    # 4.3 Device Admins
    admins = get_device_admins(device_id)
    if admins:
        log(f"\n[!] ALERT: {len(admins)} Device Administrator(s) found:", report_file)
        for admin in admins:
            is_sys = any(p['name'] == admin and p['is_system'] for p in packages)
            tag = "[SYSTEM]" if is_sys else "[!] USER"
            log(f"    - {tag} {admin}", report_file)
    else:
        log("\n[OK] No active Device Administrators found.", report_file)

    # 4.4 Network Summary
    if db: db.set_task("Auditing network connections...")
    connections = get_active_connections(device_id)
    conn_list = [l.strip() for l in connections.split("\n") if "ESTABLISHED" in l or "LISTEN" in l or "CLOSE_WAIT" in l]
    if conn_list:
        log(f"\n[*] Active Network Connections/Listeners: {len(conn_list)}", report_file)
        
        # Enrich connections with Geolocation Intelligence
        log("[*] Enriching IP addresses with Geolocation data...", report_file)
        enriched_conns = enrich_connections(conn_list)
        
        # Log top 20 connections to screen, all to report
        log("[i] Detailed Network Activity:", report_file)
        for i, conn in enumerate(enriched_conns):
            if i < 20:
                log(f"    - {conn}", report_file)
            else:
                report_file.write(f"    - {conn}\n")
        
        if len(conn_list) > 20:
            print(f"    ... and {len(conn_list) - 20} more (view full report for all).")
    else:
        log("\n[*] No active network connections detected.", report_file)
        
    if db:
        behavior_status = "WARNING" if hidden_and_sensitive or acc_services else "OK"
        behavior_summary = f"{len(hidden_user_apps)} hidden apps, {len(conn_list)} connections"
        db.update("Analysis & Network", behavior_status, behavior_summary)

    # 5. File System Deep Scan
    if db: db.set_task("Performing deep file system scan...")
    print_header("5. File System Deep Scan", report_file)
    log("[*] Auditing storage (/sdcard) for suspicious files...", report_file)
    file_results = scan_storage_for_malware(device_id)
    
    if file_results["apks_found"]:
        log(f"\n[!] ALERT: Found {len(file_results['apks_found'])} APK files in storage (Potential side-loaded apps):", report_file)
        for apk in file_results["apks_found"][:10]:
            log(f"    - {apk}", report_file)
    
    if file_results["suspicious_files"]:
        log(f"\n[!] ALERT: Found {len(file_results['suspicious_files'])} suspicious scripts/executables:", report_file)
        for f in file_results["suspicious_files"][:5]:
            sha = get_file_hash(f, device_id)
            log(f"    - {f}", report_file)
            log(f"      [SHA256]: {sha}", report_file)
            
    if file_results["hidden_files"]:
        user_hidden = [f for f in file_results["hidden_files"] if "/." not in f.split("/")[-2]]
        if user_hidden:
            log(f"\n[!] Found {len(user_hidden)} hidden files/folders in user storage:", report_file)
            for h in user_hidden[:5]:
                sha = get_file_hash(h, device_id)
                log(f"    - {h} (SHA: {sha[:16]}...)", report_file)
    
    if db:
        file_status = "WARNING" if file_results['apks_found'] or file_results['suspicious_files'] else "OK"
        file_summary = f"Found {len(file_results['apks_found'])} APKs, {len(file_results['suspicious_files'])} scripts"
        db.update("File System Scan", file_status, file_summary)

    # 6. Real-Time Runtime Analysis
    if db: db.set_task("Monitoring running processes...")
    print_header("6. Real-Time Runtime Analysis", report_file)
    log("[*] Monitoring running processes...", report_file)
    procs = get_running_processes(device_id)
    suspicious_procs = identify_suspicious_processes(procs, packages)
    
    if suspicious_procs:
        log(f"[!] ALERT: Found {len(suspicious_procs)} processes without a linked app package:", report_file)
        for sp in suspicious_procs[:10]:
            log(f"    - [PID {sp['pid']}] {sp['name']} ({sp['reason']})", report_file)
    else:
        log("[OK] All user processes are linked to known installed packages.", report_file)
        
    if db:
        proc_status = "WARNING" if suspicious_procs else "OK"
        proc_summary = f"Audited {len(procs)} active processes"
        db.update("Runtime Audit", proc_status, proc_summary)

    # 7. Deep Content Inspection (Malware Pattern Matching)
    if db: db.set_task("Checking file contents for malware patterns...")
    print_header("7. Deep Content Inspection (Malware Patterns)", report_file)
    log("[*] Searching for malicious string patterns in suspicious files...", report_file)
    content_findings = content_scan_sdcard(device_id)
    
    if content_findings:
        log(f"[!] ALERT: Found {len(content_findings)} files with suspicious content patterns:", report_file)
        for cf in content_findings:
            log(f"    - File: {cf['file']}", report_file)
            for issue in cf['issues']:
                log(f"      [!] {issue['category']}: Match '{issue['pattern']}'", report_file)
                log(f"          Snippet: {issue['snippet']}", report_file)
    else:
        log("[OK] No suspicious content patterns found in scanned files.", report_file)
        
    if db:
        content_status = "WARNING" if content_findings else "OK"
        content_summary = f"Scanned internal file strings"
        db.update("Content Inspection", content_status, content_summary)

    # 8. Vulnerability Assessment (CVE Checker)
    if db: db.set_task("Analyzing system vulnerabilities (CVE)...")
    print_header("8. Vulnerability Assessment (CVE Tracker)", report_file)
    log(f"[*] Analyzing security patch level: {device_info['Security Patch']}...", report_file)
    vuln_results = check_vulnerabilities(device_info['Security Patch'], device_info['Android Version'])
    
    if "error" in vuln_results:
        log(f"[-] Error: {vuln_results['error']}", report_file)
    else:
        log(f"[*] Security Status: {vuln_results['status']}", report_file)
        log(f"[*] Patch Age:      {vuln_results['months_outdated']} months", report_file)
        
        if vuln_results['potential_cves']:
            log(f"\n[!] ALERT: Found {len(vuln_results['potential_cves'])} potential critical vulnerabilities:", report_file)
            for v in vuln_results['potential_cves']:
                log(f"    - {v['id']} ({v['severity']}): {v['description']}", report_file)
        else:
            log("\n[OK] No common critical CVEs found for this patch level.", report_file)
            
    if db:
        vuln_status = "bold red" if vuln_results.get('status') == "Critically Outdated" else "OK"
        vuln_summary = f"Patch Level: {device_info['Security Patch']}"
        db.update("CVE Tracker", vuln_status, vuln_summary)

    # 9. VirusTotal Analysis (Cloud-based Malware Check)
    if db: db.set_task("Querying VirusTotal for file hashes...")
    print_header("9. VirusTotal Analysis (Cloud Check)", report_file)
    # VirusTotal Analysis (Scanner 2.0 Cloud Check)
    vt_results = {}
    if args.vt_key or os.environ.get("VT_API_KEY"):
        vt_key = args.vt_key if args.vt_key else os.environ.get("VT_API_KEY")
        if db: db.set_task("Cloud-checking hashes on VirusTotal...")
        print_header("9. VirusTotal Analysis (Cloud Check)", report_file)
        # Collect unique hashes from file scanner results
        all_candidates = file_results.get("apks_found", []) + file_results.get("suspicious_files", [])
        hash_to_path = {}
        all_hashes = []
        for f in all_candidates:
            sha = get_file_hash(f, device_id)
            if sha and sha != "Unknown":
                all_hashes.append(sha)
                hash_to_path[sha] = os.path.basename(f)
        all_hashes = list(set(all_hashes))
        
        if all_hashes:
            log(f"[*] Checking {len(all_hashes)} unique file hashes on VirusTotal...", report_file)
            from modules.vt_scanner import scan_multi_hashes
            vt_results = scan_multi_hashes(all_hashes, vt_key, limit=30)
            
            for h, vt_res in vt_results.items():
                fname = hash_to_path.get(h, "Unknown File")
                if vt_res.get('found'):
                    tag = "[!] MALICIOUS" if vt_res['malicious'] > 0 else "[OK] Clean"
                    log(f"    - {fname[:20]:20} | {tag} ({vt_res['malicious']}/{vt_res.get('total_engines', 0)} engines) | {h[:16]}...", report_file)
                else:
                    log(f"    - {fname[:20]:20} | {vt_res.get('message', 'Not scanned (Limit reached)')} | {h[:16]}...", report_file)
            vt_summary = f"Cloud-scanned {min(len(all_hashes), 30)} hashes"
        else:
            log("[OK] No suspicious local files found to check on VT.", report_file)
            vt_summary = "No files to scan"
            
        if db: db.update("VirusTotal Cloud", "OK", vt_summary)
    else:
        log("[i] Skip: VirusTotal API Key not provided.", report_file)

    # 10. Local Exploit Hunter (Scanner 2.0)
    if db: db.set_task("Hunting for local exploits...")
    print_header("10. Local Exploit Hunter", report_file)
    writable = scan_world_writable(device_id)
    dangerous_props = audit_system_props(device_id)
    
    hunter_status = "OK"
    if writable or dangerous_props:
        hunter_status = "WARNING"
        log(f"[!] Warning: Found {len(writable)} writable files and {len(dangerous_props)} dangerous props.", report_file)
        for w in writable:
            log(f"    - [{w['type']}] {w['path']}", report_file)
        for p in dangerous_props:
            log(f"    - [Prop] {p['risk']}", report_file)
    else:
        log("[OK] No obvious local exploits found.", report_file)
    
    if db: db.update("Exploit Hunter", hunter_status, f"Found {len(writable)} risks")

    if monitor: monitor.stop()
    new_conns = telemetry.stop() if telemetry else []

    # Finalize Reports
    print_header("Scan Complete", report_file)
    log(f"[i] Report saved to: {report_name}", report_file)
    
    html_report_path = report_name.replace(".txt", ".html")
    if db: db.set_task("Generating visual HTML report...")
    
    # Enrichment for HTML report
    vt_findings = [f"MALICIOUS: {h[:16]}..." for h, r in vt_results.items() if r.get('malicious', 0) > 0]
    
    html_data = {
        "device_info": device_info,
        "System Integrity": {"summary": integrity_summary, "severity": integrity_status},
        "Package Scanner": {"summary": f"Scanned {len(packages)} apps", "findings": [p['name'] for p in suspicious], "severity": "WARNING" if suspicious else "OK"},
        "VirusTotal Cloud": {"summary": f"Checked {len(vt_results)} files", "findings": vt_findings, "severity": "HIGH" if vt_findings else "OK"},
        "Network Telemetry": {"summary": f"Tracked {len(new_conns)} new connections", "findings": [f"[{c['time']}] {c['details']}" for c in new_conns], "severity": "INFO"},
        "Permission Audit": {"summary": f"Analyzed {len(packages)} packages", "findings": [f"{p['name']}: {', '.join(p['sensitive_permissions'])}" for p in user_apps_risk], "severity": "WARNING" if user_apps_risk else "OK"},
        "Behavioral Analysis": {"summary": f"Detected {len(hidden_and_sensitive)} hidden sensitive apps", "findings": [h['name'] for h in hidden_and_sensitive], "severity": "HIGH" if hidden_and_sensitive else "OK"},
        "Exploit Hunter": {"summary": f"Detected {len(writable)} risks", "findings": [f"{w['type']}: {w['path']}" for w in writable], "severity": hunter_status}
    }
    generate_html_report(html_data, html_report_path)
    log(f"[+] Advanced HTML report generated: {html_report_path}", report_file)
    if db: db.stop()

    log("[i] Remember: This is a static analysis tool. Deeply hidden malware might still exist.", report_file)
    report_file.close()

    # --- Post-Scan Mitigation Interaction ---
    all_suspicious_pkgs = list(set([p['name'] for p in suspicious] + [p['name'] for p in hidden_and_sensitive]))
    
    if all_suspicious_pkgs:
        print(f"\n{'!'*60}")
        print("  ACTIVE THREAT REMEDIATION")
        print(f"{'!'*60}")
        print(f"[!] Found {len(all_suspicious_pkgs)} suspicious apps that may require action.")
        
        take_action = input("\n[?] Would you like to take action against any of these apps? (y/n): ").lower()
        if take_action == 'y':
            while True:
                print("\nSuspicious Apps:")
                for idx, pkg in enumerate(all_suspicious_pkgs):
                    print(f"{idx + 1}. {pkg}")
                print(f"{len(all_suspicious_pkgs) + 1}. Exit Remediation")
                
                try:
                    choice = int(input("\n[?] Select an app number to manage: "))
                    if choice == len(all_suspicious_pkgs) + 1:
                        break
                    if 1 <= choice <= len(all_suspicious_pkgs):
                        target_pkg = all_suspicious_pkgs[choice - 1]
                        print(get_mitigation_menu())
                        action = input("[?] Choose action (1-4): ")
                        
                        if action == '1':
                            if freeze_app(target_pkg, device_id):
                                print(f"[+] Successfully froze {target_pkg}")
                            else:
                                print(f"[-] Failed to freeze {target_pkg}")
                        elif action == '2':
                            confirm = input(f"[!] Are you sure you want to UNINSTALL {target_pkg}? (y/n): ").lower()
                            if confirm == 'y':
                                if uninstall_app(target_pkg, device_id):
                                    print(f"[+] Successfully uninstalled {target_pkg}")
                                    all_suspicious_pkgs.remove(target_pkg)
                                else:
                                    print(f"[-] Failed to uninstall {target_pkg}")
                        elif action == '3':
                            if force_stop_app(target_pkg, device_id):
                                print(f"[+] Force-stopped {target_pkg}")
                        elif action == '4':
                            continue
                    else:
                        print("[-] Invalid choice.")
                except ValueError:
                    print("[-] Please enter a valid number.")
                    
    print("\n[i] Mobile Security Scanner finished. Stay safe!")

if __name__ == "__main__":
    main()
