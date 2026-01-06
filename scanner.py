#!/usr/bin/env python3
"""OWASP Agentic AI Top 10 Security Scanner.

A static analysis tool that scans codebases for security risks defined in the
OWASP Top 10 for Agentic AI Applications (December 2025).

Usage:
    python scanner.py /path/to/codebase
    python scanner.py /path/to/codebase --format json
    python scanner.py /path/to/codebase --rules goal_hijack,tool_misuse
"""

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from rules import ALL_RULES, BaseRule
from rules.base import Finding
from reporters.console import ConsoleReporter
from reporters.json_reporter import JsonReporter

app = typer.Typer(
    name="owasp-agentic-scanner",
    help="Scan codebases for OWASP Agentic AI Top 10 security risks.",
    add_completion=False,
)
console = Console()

# Map short names to rule classes
RULE_MAP = {
    "goal_hijack": "AA01",
    "tool_misuse": "AA02",
    "privilege_abuse": "AA03",
    "supply_chain": "AA04",
    "code_execution": "AA05",
    "memory_poisoning": "AA06",
    "excessive_agency": "AA07",
    "insecure_plugin": "AA08",
    "overreliance": "AA09",
    "model_theft": "AA10",
}


def get_rules_by_filter(rule_filter: Optional[str]) -> list[BaseRule]:
    """Get rules matching the filter."""
    if not rule_filter:
        return ALL_RULES

    selected_ids = set()
    for name in rule_filter.split(","):
        name = name.strip().lower()
        if name in RULE_MAP:
            selected_ids.add(RULE_MAP[name])
        elif name.upper().startswith("AA"):
            selected_ids.add(name.upper())

    if not selected_ids:
        console.print(f"[yellow]Warning: No rules matched filter '{rule_filter}'[/yellow]")
        return ALL_RULES

    return [r for r in ALL_RULES if r.rule_id in selected_ids]


def scan_codebase(path: Path, rules: list[BaseRule]) -> list[Finding]:
    """Scan a codebase with the given rules."""
    findings: list[Finding] = []

    for rule in rules:
        if path.is_file():
            findings.extend(rule.scan_file(path))
        else:
            findings.extend(rule.scan_directory(path))

    # Sort by severity (critical first), then by file
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity.value, 5), f.file_path))

    return findings


@app.command()
def scan(
    path: str = typer.Argument(
        ...,
        help="Path to directory or file to scan",
    ),
    format: str = typer.Option(
        "console",
        "--format",
        "-f",
        help="Output format: console or json",
    ),
    rules: Optional[str] = typer.Option(
        None,
        "--rules",
        "-r",
        help="Comma-separated rule names or IDs (e.g., goal_hijack,AA02)",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (for JSON format)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed findings",
    ),
) -> None:
    """Scan a codebase for OWASP Agentic AI security risks."""
    scan_path = Path(path)

    if not scan_path.exists():
        console.print(f"[red]Error: Path does not exist: {path}[/red]")
        raise typer.Exit(1)

    # Get rules to use
    selected_rules = get_rules_by_filter(rules)

    console.print(f"[bold]Scanning:[/bold] {scan_path}")
    console.print(f"[bold]Rules:[/bold] {len(selected_rules)} active")
    console.print()

    # Perform scan
    with console.status("[bold green]Scanning..."):
        findings = scan_codebase(scan_path, selected_rules)

    # Output results
    if format.lower() == "json":
        reporter = JsonReporter()
        if output:
            reporter.report_to_file(findings, str(scan_path), output)
            console.print(f"[green]Report written to: {output}[/green]")
        else:
            print(reporter.report(findings, str(scan_path)))
    else:
        reporter = ConsoleReporter()
        reporter.report(findings, str(scan_path))

        if verbose and findings:
            console.print("[bold]Detailed Findings:[/bold]")
            console.print()
            for finding in findings:
                reporter.print_finding_details(finding)
                console.print()

    # Exit with error if critical/high findings
    critical_high = [f for f in findings if f.severity.value in ("critical", "high")]
    if critical_high:
        raise typer.Exit(1)


@app.command()
def list_rules() -> None:
    """List all available detection rules."""
    from rich.table import Table

    table = Table(title="OWASP Agentic AI Top 10 Detection Rules")
    table.add_column("ID", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Short Name", style="dim")
    table.add_column("Patterns", justify="right")

    short_names = {v: k for k, v in RULE_MAP.items()}

    for rule in ALL_RULES:
        table.add_row(
            rule.rule_id,
            rule.rule_name,
            short_names.get(rule.rule_id, ""),
            str(len(rule.patterns)),
        )

    console.print(table)


def main() -> None:
    """Entry point."""
    app()


if __name__ == "__main__":
    main()

