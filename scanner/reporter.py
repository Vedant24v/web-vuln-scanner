from datetime import datetime

def generate_report(url, all_findings, output_file="report.html"):
    severity_colors = {
        "CRITICAL": "#e74c3c",
        "HIGH": "#e67e22",
        "MEDIUM": "#f1c40f",
        "LOW": "#2ecc71",
        "INFO": "#3498db",
    }

    rows = ""
    if not all_findings:
        rows = "<tr><td colspan='3' style='text-align:center;color:green;'>✅ No vulnerabilities found</td></tr>"
    else:
        for f in all_findings:
            color = severity_colors.get(f["severity"], "#ccc")
            rows += f"""
            <tr>
                <td><span style='color:{color};font-weight:bold;'>{f['severity']}</span></td>
                <td>{f['type']}</td>
                <td>{f['detail']}</td>
            </tr>
            """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerability Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; padding: 30px; background: #f4f4f4; }}
            h1 {{ color: #2c3e50; }}
            .meta {{ color: #666; margin-bottom: 20px; }}
            table {{ width: 100%; border-collapse: collapse; background: white; }}
            th {{ background: #2c3e50; color: white; padding: 12px; text-align: left; }}
            td {{ padding: 10px; border-bottom: 1px solid #eee; }}
            tr:hover {{ background: #f9f9f9; }}
        </style>
    </head>
    <body>
        <h1>🔍 Web Vulnerability Scan Report</h1>
        <div class="meta">
            <b>Target:</b> {url}<br>
            <b>Scan Time:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
            <b>Total Findings:</b> {len(all_findings)}
        </div>
        <table>
            <tr><th>Severity</th><th>Type</th><th>Details</th></tr>
            {rows}
        </table>
    </body>
    </html>
    """

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    return output_file