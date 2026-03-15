import os
import datetime

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mobile Security Audit - {model}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-deep: #0f172a;
            --grad-primary: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
            --glass: rgba(255, 255, 255, 0.05);
            --text-main: #f8fafc;
            --accent-green: #22c55e;
            --accent-red: #ef4444;
            --accent-orange: #f59e0b;
        }}
        
        body {{
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg-deep);
            color: var(--text-main);
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}

        header {{
            background: var(--grad-primary);
            padding: 40px;
            border-radius: 20px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            text-align: center;
            position: relative;
            overflow: hidden;
        }}

        header::after {{
            content: "";
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, transparent 70%);
            animation: rotate 20s linear infinite;
        }}

        @keyframes rotate {{
            from {{ transform: rotate(0deg); }}
            to {{ transform: rotate(360deg); }}
        }}

        .card {{
            background: var(--glass);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 25px;
            transition: all 0.3s ease;
        }}

        .severity-high {{ border-left: 5px solid var(--accent-red); }}
        .severity-warning {{ border-left: 5px solid var(--accent-orange); }}
        .severity-ok {{ border-left: 5px solid var(--accent-green); }}

        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 10px;
        }}

        h3 {{ margin: 0; font-weight: 600; font-size: 1.25em; }}

        .status-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .badge-ok {{ background: rgba(34, 197, 94, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }}
        .badge-warning {{ background: rgba(245, 158, 11, 0.2); color: var(--accent-orange); border: 1px solid var(--accent-orange); }}
        .badge-high {{ background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        th {{ text-align: left; opacity: 0.6; padding: 12px; font-size: 0.8em; text-transform: uppercase; }}
        td {{ padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); font-size: 0.9em; }}

        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-top: 25px;
        }}

        .meta-item {{
            background: rgba(0, 0, 0, 0.2);
            padding: 12px;
            border-radius: 12px;
            text-align: left;
        }}

        .meta-label {{ display: block; font-size: 0.7em; opacity: 0.5; margin-bottom: 4px; text-transform: uppercase; }}
        .meta-value {{ font-weight: 600; font-size: 1em; }}

    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1 style="margin:0; font-size: 2.2em; font-weight: 600;">Mobile Security Intelligence</h1>
            <p style="opacity: 0.8; margin-top: 5px;">Scanner 2.0 Professional Audit Report</p>
            <div class="meta-grid">
                <div class="meta-item"><span class="meta-label">DEVICE</span><span class="meta-value">{model}</span></div>
                <div class="meta-item"><span class="meta-label">SERIAL</span><span class="meta-value">{serial}</span></div>
                <div class="meta-item"><span class="meta-label">SECURITY PATCH</span><span class="meta-value">{patch}</span></div>
                <div class="meta-item"><span class="meta-label">SCAN TIME</span><span class="meta-value">{date}</span></div>
            </div>
        </header>

        {sections}

        <footer>
            &copy; 2026 Mobile Security Suite | Professional Android Audit Report
        </footer>
    </div>
</body>
</html>
"""

def generate_section(title, content, severity):
    sev_class = severity.lower()
    return f"""
    <div class="card severity-{sev_class}">
        <div class="section-header">
            <h3>{title}</h3>
            <span class="status-badge badge-{sev_class}">{severity}</span>
        </div>
        {content}
    </div>
    """

def generate_html_report(scan_data, output_path):
    sections_html = ""
    
    # 1. Device Info
    device_info = scan_data.get("device_info", {})
    
    # 2. Map scan_data to HTML sections
    # (Simplified for now, will expand based on scanner.py data)
    for module, data in scan_data.items():
        if module == "device_info": continue
        
        summary = data.get('summary', 'Audit complete.')
        content = f"<p><strong>Status:</strong> <span class='badge badge-{data.get('severity', 'info').lower()}'>{data.get('severity', 'OK')}</span></p>"
        content += f"<p>{summary}</p>"
        
        if 'findings' in data and data['findings']:
            content += "<table><thead><tr><th>Finding</th></tr></thead><tbody>"
            for f in data['findings']:
                content += f"<tr><td>{f}</td></tr>"
            content += "</tbody></table>"
            
        sections_html += generate_section(module, content, data.get('severity', 'info'))

    full_html = HTML_TEMPLATE.format(
        model=device_info.get("Model", "Unknown"),
        serial=device_info.get("Serial", "N/A"),
        patch=device_info.get("Security Patch", "Unknown"),
        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        sections=sections_html
    )
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(full_html)
    
    return output_path
