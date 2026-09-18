import asyncio
from datetime import datetime
import sys
from typing import List, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ctf_recon.models import (
    AIAnalysisResult,
    FlagFinding,
    PortScanResult,
    TriageReport,
    WebTriageResult,
)
from ctf_recon.report.markdown_writer import export_report_to_markdown
from ctf_recon.scanner.port_scanner import parse_ports, scan_ports
from ctf_recon.scanner.web_triage import run_web_triage
from ctf_recon.triage.ai_advisor import DEFAULT_MODEL, run_ai_advisor
from ctf_recon.triage.flag_matcher import scan_target_for_flags

console = Console()

app = typer.Typer(
    name="ctf-recon",
    help="CTF Recon & Triage CLI tool for service scanning, web triage, and AI-assisted analysis.",
    no_args_is_help=True,
)


@app.callback()
def main():
    """
    CTF Recon & Triage CLI - Automated reconnaissance and AI triage.
    """
    pass


async def _execute_scan(
    target: str,
    ports_arg: Optional[str],
    ai: bool,
    model: str,
    output: str,
    timeout: float,
    api_key: Optional[str] = None,
) -> TriageReport:
    """Core asynchronous scan pipeline."""
    ports_to_scan = parse_ports(ports_arg)

    console.print(
        Panel(
            f"[bold green]Target:[/bold green] {target}\n"
            f"[bold green]Ports to check:[/bold green] {len(ports_to_scan)}\n"
            f"[bold green]Timeout:[/bold green] {timeout}s\n"
            f"[bold green]AI Analysis:[/bold green] {'Enabled (' + model + ')' if ai else 'Disabled'}\n"
            f"[bold green]Report Output:[/bold green] {output}",
            title="[bold cyan]CTF Recon & Triage Initializing[/bold cyan]",
            border_style="cyan",
        )
    )

    # 1. Port Scan
    with console.status(
        f"[bold yellow]Scanning {len(ports_to_scan)} TCP ports on {target}...[/bold yellow]",
        spinner="dots",
    ):
        open_ports: List[PortScanResult] = await scan_ports(
            target=target,
            ports=ports_to_scan,
            timeout=timeout,
        )

    if open_ports:
        port_table = Table(
            title="[bold green]Discovered Open Ports[/bold green]",
            header_style="bold magenta",
        )
        port_table.add_column("Port", style="bold cyan", justify="right")
        port_table.add_column("Protocol", style="cyan")
        port_table.add_column("State", style="green")
        port_table.add_column("Banner / Service", style="white")

        for p in open_ports:
            port_table.add_row(
                str(p.port),
                p.protocol.upper(),
                p.state,
                p.banner or "[dim]-[/dim]",
            )
        console.print(port_table)
    else:
        console.print("[yellow][!] No open ports detected on target.[/yellow]")

    # 2. Web Triage
    web_findings: List[WebTriageResult] = []
    if open_ports:
        with console.status(
            "[bold blue]Running web triage on discovered services...[/bold blue]",
            spinner="dots",
        ):
            web_findings = await run_web_triage(
                target=target,
                open_ports=open_ports,
                timeout=timeout,
            )

    if web_findings:
        web_table = Table(
            title="[bold blue]Web Application Triage[/bold blue]",
            header_style="bold blue",
        )
        web_table.add_column("URL", style="bold cyan")
        web_table.add_column("Status", justify="center")
        web_table.add_column("Server", style="dim")
        web_table.add_column("Findings", style="yellow")

        for w in web_findings:
            status_style = "bold green" if w.status_code == 200 else "bold yellow"
            findings_text = "\n".join(w.findings) if w.findings else "[dim]None[/dim]"
            web_table.add_row(
                w.url,
                f"[{status_style}]{w.status_code}[/{status_style}]",
                w.server_header or "[dim]-[/dim]",
                findings_text,
            )
        console.print(web_table)

    # 3. Flag & Blob Engine
    banners = [p.banner for p in open_ports if p.banner]
    flags_found: List[FlagFinding] = scan_target_for_flags(
        banners=banners,
        web_results=web_findings,
    )

    if flags_found:
        flags_text_lines = []
        for f in flags_found:
            flags_text_lines.append(
                f"[bold red]★ FLAG DETECTED:[/bold red] [bold yellow]{f.flag_text}[/bold yellow] "
                f"([cyan]{f.format_type}[/cyan] from [dim]{f.source}[/dim])"
            )
        console.print(
            Panel(
                "\n".join(flags_text_lines),
                title="[bold red]🚩 Flags & Secrets Discovered[/bold red]",
                border_style="red",
            )
        )
    else:
        console.print("[dim]No flags or suspicious encoded tokens discovered.[/dim]")

    # 4. AI Strategic Analysis
    ai_analysis: Optional[AIAnalysisResult] = None
    if ai:
        with console.status(
            f"[bold magenta]Querying Gemini ({model}) for strategic triage analysis...[/bold magenta]",
            spinner="dots",
        ):
            ai_analysis = run_ai_advisor(
                target=target,
                open_ports=open_ports,
                web_findings=web_findings,
                flags_found=flags_found,
                api_key=api_key,
                enable_ai=True,
                model_name=model,
            )

        if ai_analysis:
            ai_content = []
            if ai_analysis.service_criticality:
                ai_content.append("[bold underline]Service Criticality:[/bold underline]")
                for svc, crit in ai_analysis.service_criticality.items():
                    crit_color = "red" if crit.lower() in {"critical", "high"} else "yellow"
                    ai_content.append(f"  • {svc}: [{crit_color}]{crit}[/{crit_color}]")
                ai_content.append("")

            if ai_analysis.probable_cves:
                ai_content.append("[bold underline]Probable CVEs:[/bold underline]")
                for cve in ai_analysis.probable_cves:
                    ai_content.append(f"  • [bold red]{cve}[/bold red]")
                ai_content.append("")

            if ai_analysis.suggested_cli_commands:
                ai_content.append("[bold underline]Suggested Follow-up Commands:[/bold underline]")
                for cmd in ai_analysis.suggested_cli_commands:
                    ai_content.append(f"  [cyan]$ {cmd}[/cyan]")
                ai_content.append("")

            if ai_analysis.attack_vectors:
                ai_content.append("[bold underline]Attack Vectors / Angles:[/bold underline]")
                for vec in ai_analysis.attack_vectors:
                    ai_content.append(f"  • {vec}")

            console.print(
                Panel(
                    "\n".join(ai_content),
                    title=f"[bold magenta]🤖 Gemini AI Triage ({model})[/bold magenta]",
                    border_style="magenta",
                )
            )
        else:
            console.print(
                "[yellow][!] AI analysis did not return recommendations (check GEMINI_API_KEY or connection).[/yellow]"
            )

    # 5. Export Report
    report = TriageReport(
        target=target,
        scan_timestamp=datetime.now(),
        open_ports=open_ports,
        web_findings=web_findings,
        flags_found=flags_found,
        ai_analysis=ai_analysis,
    )

    saved_path = export_report_to_markdown(report, output)
    console.print(f"\n[bold green]✓ Triage report exported to:[/bold green] [underline]{saved_path}[/underline]\n")

    return report


@app.command(name="scan")
def scan(
    target: str = typer.Argument(
        ...,
        help="Target IP address or domain to scan"
    ),
    ports: Optional[str] = typer.Option(
        None,
        "-p",
        "--ports",
        help="Port range (e.g. '1-1000', '80,443', or 'top100')"
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Enable tactical analysis assisted by Google Gemini"
    ),
    key: Optional[str] = typer.Option(
        None,
        "-k",
        "--key",
        "--api-key",
        help="Google Gemini API key (can also be set via GEMINI_API_KEY environment variable)",
        envvar="GEMINI_API_KEY",
    ),
    model: str = typer.Option(
        DEFAULT_MODEL,
        "-m",
        "--model",
        help=f"Gemini model name to use for AI triage (default: {DEFAULT_MODEL})"
    ),
    output: str = typer.Option(
        "writeup_triage.md",
        "-o",
        "--output",
        help="Path to export the Markdown triage report"
    ),
    timeout: float = typer.Option(
        1.5,
        "--timeout",
        help="Connection timeout per port/probe in seconds (default: 1.5)"
    ),
):
    """
    Scans a target for open ports, web endpoints, CTF flags, and AI triage recommendations.
    """
    # If the user explicitly provided an API key flag or a custom model, activate AI analysis automatically
    if (key or model != DEFAULT_MODEL) and not ai:
        ai = True

    try:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(
                    lambda: asyncio.run(
                        _execute_scan(
                            target=target,
                            ports_arg=ports,
                            ai=ai,
                            model=model,
                            output=output,
                            timeout=timeout,
                            api_key=key,
                        )
                    )
                ).result()
        else:
            asyncio.run(
                _execute_scan(
                    target=target,
                    ports_arg=ports,
                    ai=ai,
                    model=model,
                    output=output,
                    timeout=timeout,
                    api_key=key,
                )
            )
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Scan cancelled by user (Ctrl+C).[/bold yellow]")
        raise typer.Exit(code=130)
    except Exception as exc:
        console.print(f"\n[bold red][!] Scan error:[/bold red] {exc}")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
