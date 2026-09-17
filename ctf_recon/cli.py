from typing import Optional
import typer

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
    model: str = typer.Option(
        "gemini-2.5-flash",
        "-m",
        "--model",
        help="Gemini model name to use for AI triage (default: gemini-2.5-flash)"
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
    typer.echo(f"Scanning target: {target} [AI: {ai}, Model: {model}]")


if __name__ == "__main__":
    app()
