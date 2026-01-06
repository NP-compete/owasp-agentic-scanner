"""Console reporter for scan results."""

from collections import defaultdict
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from rules.base import Finding, Severity


class ConsoleReporter:
    """Rich console output for scan results."""

    SEVERITY_COLORS = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    SEVERITY_ICONS = {
        "critical": "[!]",
        "high": "[H]",
        "medium": "[M]",
        "low": "[L]",
        "info": "[i]",
    }

    def __init__(self) -> None:
        self.console = Console()

    def report(self, findings: list["Finding"], scan_path: str) -> None:
        """Generate console report from findings."""
        if not findings:
            self.console.print(
                Panel(
                    "[bold green]No security findings detected.[/bold green]",
                    title="OWASP Agentic AI Scan Complete",
                    border_style="green",
                )
            )
            return

        # Group by severity
        by_severity: dict[str, list["Finding"]] = defaultdict(list)
        for f in findings:
            by_severity[f.severity.value].append(f)

        # Summary panel
        summary = self._build_summary(findings, by_severity, scan_path)
        self.console.print(summary)
        self.console.print()

        # Findings by category
        by_category: dict[str, list["Finding"]] = defaultdict(list)
        for f in findings:
            by_category[f.owasp_category].append(f)

        for category in sorted(by_category.keys()):
            self._print_category(category, by_category[category])

    def _build_summary(
        self,
        findings: list["Finding"],
        by_severity: dict[str, list["Finding"]],
        scan_path: str,
    ) -> Panel:
        """Build summary panel."""
        lines = [
            f"[bold]Scanned:[/bold] {scan_path}",
            f"[bold]Total Findings:[/bold] {len(findings)}",
            "",
        ]

        severity_order = ["critical", "high", "medium", "low", "info"]
        for sev in severity_order:
            count = len(by_severity.get(sev, []))
            if count > 0:
                color = self.SEVERITY_COLORS[sev]
                lines.append(f"  [{color}]{sev.upper()}:[/{color}] {count}")

        return Panel(
            "\n".join(lines),
            title="[bold]OWASP Agentic AI Top 10 Scan Results[/bold]",
            border_style="red" if by_severity.get("critical") else "yellow",
        )

    def _print_category(self, category: str, findings: list["Finding"]) -> None:
        """Print findings for a category."""
        self.console.print(f"[bold cyan]{category}[/bold cyan]")
        self.console.print()

        table = Table(show_header=True, header_style="bold", expand=True)
        table.add_column("Sev", width=4)
        table.add_column("File", style="dim")
        table.add_column("Line", justify="right", width=6)
        table.add_column("Message")

        for f in sorted(findings, key=lambda x: x.severity.value):
            sev_color = self.SEVERITY_COLORS[f.severity.value]
            sev_icon = self.SEVERITY_ICONS[f.severity.value]

            table.add_row(
                Text(sev_icon, style=sev_color),
                f.file_path.split("/")[-1],
                str(f.line_number),
                f.message,
            )

        self.console.print(table)
        self.console.print()

    def print_finding_details(self, finding: "Finding") -> None:
        """Print detailed information for a single finding."""
        sev_color = self.SEVERITY_COLORS[finding.severity.value]

        self.console.print(
            Panel(
                f"""[bold]Rule:[/bold] {finding.rule_id} - {finding.rule_name}
[bold]Category:[/bold] {finding.owasp_category}
[bold]Severity:[/bold] [{sev_color}]{finding.severity.value.upper()}[/{sev_color}]
[bold]Confidence:[/bold] {finding.confidence}

[bold]File:[/bold] {finding.file_path}
[bold]Line:[/bold] {finding.line_number}

[bold]Code:[/bold]
[dim]{finding.line_content.strip()}[/dim]

[bold]Issue:[/bold]
{finding.message}

[bold]Recommendation:[/bold]
[green]{finding.recommendation}[/green]""",
                title=f"[{sev_color}]Finding Details[/{sev_color}]",
            )
        )

