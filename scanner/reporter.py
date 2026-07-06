from datetime import datetime
from html import escape


def generate_report(url, all_findings, output_file="report.html"):
    severity_colors = {
        "CRITICAL": "#ff6b6b",
        "HIGH": "#ff9f43",
        "MEDIUM": "#feca57",
        "LOW": "#48dbfb",
        "INFO": "#6c5ce7",
    }

    if not all_findings:
        rows = (
            "<tr><td colspan='5' style='text-align:center;color:#54e38e;'>"
            "No vulnerabilities found by the configured passive and low-impact checks."
            "</td></tr>"
        )
    else:
        rendered_rows = []
        for finding in all_findings:
            severity = escape(finding.get("severity", "INFO"))
            color = severity_colors.get(severity, "#cbd5e1")
            rendered_rows.append(
                f"""
                <tr>
                    <td><span class="pill" style="background:{color}22;color:{color};border-color:{color}55;">{severity}</span></td>
                    <td>{escape(finding.get("type", "Unknown"))}</td>
                    <td>{escape(finding.get("detail", ""))}</td>
                    <td><code>{escape(finding.get("evidence", "") or "-")}</code></td>
                    <td>{escape(finding.get("remediation", "") or "Review and remediate based on the application context.")}</td>
                </tr>
                """
            )
        rows = "".join(rendered_rows)

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>Web Vulnerability Scan Report</title>
        <style>
            :root {{
                color-scheme: dark;
                --bg: #0b1220;
                --panel: #111827;
                --panel-2: #0f172a;
                --border: rgba(148, 163, 184, 0.16);
                --text: #e5eef9;
                --muted: #94a3b8;
                --accent: #56d4ff;
            }}
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0;
                padding: 32px;
                font-family: Inter, Segoe UI, Arial, sans-serif;
                background:
                    radial-gradient(circle at top right, rgba(86, 212, 255, 0.12), transparent 28%),
                    linear-gradient(180deg, #09111d, #0b1220 38%, #0c1527);
                color: var(--text);
            }}
            .shell {{
                max-width: 1180px;
                margin: 0 auto;
            }}
            .hero, .table-wrap, .notice {{
                background: rgba(15, 23, 42, 0.88);
                border: 1px solid var(--border);
                border-radius: 20px;
                box-shadow: 0 18px 55px rgba(0, 0, 0, 0.35);
            }}
            .hero {{
                padding: 28px;
                margin-bottom: 18px;
            }}
            h1 {{
                margin: 0 0 12px;
                font-size: 34px;
            }}
            .lede {{
                margin: 0;
                color: var(--muted);
                line-height: 1.6;
                max-width: 760px;
            }}
            .meta {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                gap: 12px;
                margin-top: 22px;
            }}
            .meta-card {{
                padding: 14px 16px;
                border-radius: 16px;
                background: rgba(148, 163, 184, 0.05);
                border: 1px solid rgba(148, 163, 184, 0.12);
            }}
            .meta-card span {{
                display: block;
                color: var(--muted);
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.12em;
                margin-bottom: 6px;
            }}
            .meta-card strong {{
                color: var(--text);
                word-break: break-word;
            }}
            .notice {{
                padding: 16px 18px;
                margin-bottom: 18px;
                color: #f8d38e;
                line-height: 1.5;
            }}
            .table-wrap {{
                overflow: hidden;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                text-align: left;
                vertical-align: top;
                padding: 14px 16px;
                border-bottom: 1px solid rgba(148, 163, 184, 0.1);
                font-size: 14px;
                line-height: 1.55;
            }}
            th {{
                background: rgba(86, 212, 255, 0.08);
                color: #dff7ff;
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.12em;
            }}
            tr:last-child td {{
                border-bottom: none;
            }}
            .pill {{
                display: inline-flex;
                align-items: center;
                padding: 5px 10px;
                border-radius: 999px;
                border: 1px solid transparent;
                font-size: 12px;
                font-weight: 700;
            }}
            code {{
                display: inline-block;
                max-width: 360px;
                white-space: pre-wrap;
                word-break: break-word;
                color: var(--accent);
                font-family: "JetBrains Mono", Consolas, monospace;
                font-size: 12px;
            }}
            @media (max-width: 720px) {{
                body {{ padding: 18px; }}
                h1 {{ font-size: 26px; }}
                th, td {{ padding: 12px; }}
            }}
        </style>
    </head>
    <body>
        <div class="shell">
            <section class="hero">
                <h1>Web Vulnerability Scan Report</h1>
                <p class="lede">
                    This report summarizes passive and low-impact black-box checks run against the supplied target.
                    Findings should be validated in context before remediation decisions are made.
                </p>
                <div class="meta">
                    <div class="meta-card">
                        <span>Target</span>
                        <strong>{escape(url)}</strong>
                    </div>
                    <div class="meta-card">
                        <span>Scan Time</span>
                        <strong>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</strong>
                    </div>
                    <div class="meta-card">
                        <span>Total Findings</span>
                        <strong>{len(all_findings)}</strong>
                    </div>
                </div>
            </section>

            <section class="notice">
                Authorized security testing only. Unauthorized scanning of systems you do not own or have explicit written authorization to test may be illegal.
            </section>

            <section class="table-wrap">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Category</th>
                            <th>Description</th>
                            <th>Evidence</th>
                            <th>Remediation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows}
                    </tbody>
                </table>
            </section>
        </div>
    </body>
    </html>
    """

    with open(output_file, "w", encoding="utf-8") as file_handle:
        file_handle.write(html)

    return output_file
