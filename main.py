import argparse
import requests
from rich.console import Console
from rich.table import Table
from rich import box

from scanner.headers import check_headers
from scanner.xss import check_xss
from scanner.sqli import check_sqli
from scanner.reporter import generate_report

console = Console()

def run_scan(url):
    console.print(f"\n[bold cyan]🔍 Starting scan on:[/bold cyan] {url}\n")

    all_findings = []

    # --- Fetch the page ---
    try:
        console.print("[yellow]→ Fetching target...[/yellow]")
        response = requests.get(url, timeout=10)
        console.print(f"[green]✓ Got response: HTTP {response.status_code}[/green]\n")
    except requests.RequestException as e:
        console.print(f"[red]✗ Could not reach target: {e}[/red]")
        return

    # --- Check Headers ---
    console.print("[yellow]→ Checking security headers...[/yellow]")
    header_findings, present = check_headers(response)
    console.print(f"[green]✓ {len(present)} headers present, {len(header_findings)} missing[/green]")
    all_findings.extend(header_findings)

    # --- Check XSS ---
    console.print("[yellow]→ Testing for reflected XSS...[/yellow]")
    xss_findings = check_xss(url)
    console.print(f"[green]✓ XSS check done: {len(xss_findings)} finding(s)[/green]")
    all_findings.extend(xss_findings)

    # --- Check SQLi ---
    console.print("[yellow]→ Testing for SQL Injection...[/yellow]")
    sqli_findings = check_sqli(url)
    console.print(f"[green]✓ SQLi check done: {len(sqli_findings)} finding(s)[/green]")
    all_findings.extend(sqli_findings)

    # --- Display Results Table ---
    console.print("\n[bold cyan]📋 Scan Results:[/bold cyan]")
    table = Table(box=box.ROUNDED, show_lines=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Type", width=25)
    table.add_column("Detail", width=60)

    severity_style = {
        "CRITICAL": "red",
        "HIGH": "orange3",
        "MEDIUM": "yellow",
        "LOW": "green",
    }

    if not all_findings:
        console.print("[bold green]✅ No vulnerabilities found![/bold green]")
    else:
        for f in all_findings:
            style = severity_style.get(f["severity"], "white")
            table.add_row(
                f"[{style}]{f['severity']}[/{style}]",
                f["type"],
                f["detail"]
            )
        console.print(table)

    # --- Generate HTML Report ---
    report_file = generate_report(url, all_findings)
    console.print(f"\n[bold green]📄 Report saved:[/bold green] {report_file}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Vulnerability Scanner")
    parser.add_argument("--target", required=True, help="Target URL to scan")
    args = parser.parse_args()

    run_scan(args.target)
