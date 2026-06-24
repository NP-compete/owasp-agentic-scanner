#!/usr/bin/env python3
"""OWASP Agentic AI Top 10 Security Scanner.

A static analysis tool that scans codebases for security risks defined in the
OWASP Top 10 for Agentic AI Applications (December 2025).

Usage:
    owasp-scan scan /path/to/codebase
    owasp-scan scan /path/to/codebase --format json
    owasp-scan scan /path/to/codebase --format sarif
    owasp-scan scan /path/to/codebase --rules goal_hijack,tool_misuse
"""

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import typer
from rich.console import Console
from rich.logging import RichHandler

from owasp_agentic_scanner import __version__
from owasp_agentic_scanner.reporters.console import ConsoleReporter
from owasp_agentic_scanner.reporters.json_reporter import JsonReporter
from owasp_agentic_scanner.reporters.sarif_reporter import SarifReporter
from owasp_agentic_scanner.rules import ALL_RULES
from owasp_agentic_scanner.rules.base import BaseRule, Finding

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(rich_tracebacks=True, show_time=False)],
)
logger = logging.getLogger("owasp_scanner")

app = typer.Typer(
    name="owasp-scan",
    help="Scan codebases for OWASP Agentic AI Top 10 security risks.",
    add_completion=False,
)
console = Console()

# Map short names to rule IDs
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

# Regex for inline suppressions:
NOQA_PATTERN = re.compile(r"#\s*noqa:\s*([\w,\s]+)", re.IGNORECASE)


def get_rules_by_filter(rule_filter: str | None) -> list[BaseRule]:
    """Get rules matching the filter."""
    if not rule_filter:
        return list(ALL_RULES)

    selected_ids: set[str] = set()
    for name in rule_filter.split(","):
        name = name.strip().lower()
        if name in RULE_MAP:
            selected_ids.add(RULE_MAP[name])
        elif name.upper().startswith("AA"):
            selected_ids.add(name.upper())

    if not selected_ids:
        console.print(f"[yellow]Warning: No rules matched filter '{rule_filter}'[/yellow]")
        return list(ALL_RULES)

    return [r for r in ALL_RULES if r.rule_id in selected_ids]


def is_suppressed(line: str, rule_id: str) -> bool:
    """Check if a finding is suppressed via inline noqa comment."""
    match = NOQA_PATTERN.search(line)
    if not match:
        return False

    suppressed_rules = [r.strip().upper() for r in match.group(1).split(",")]
    return rule_id in suppressed_rules or "ALL" in suppressed_rules


def filter_suppressed(findings: list[Finding]) -> list[Finding]:
    """Filter out findings that are suppressed via noqa comments."""
    return [f for f in findings if not is_suppressed(f.line_content, f.rule_id)]


def scan_file_with_rule(rule: BaseRule, file_path: Path) -> list[Finding]:
    """Scan a single file with a single rule (for parallel execution)."""
    return rule.scan_file(file_path)


def scan_codebase(
    path: Path,
    rules: list[BaseRule],
    parallel: bool = True,
    max_workers: int = 4,
) -> list[Finding]:
    """Scan a codebase with the given rules."""
    findings: list[Finding] = []

    if path.is_file():
        for rule in rules:
            findings.extend(rule.scan_file(path))
    elif parallel:
        # Collect all files to scan
        files_to_scan: list[Path] = []
        for file_path in path.rglob("*"):
            if file_path.is_file():
                files_to_scan.append(file_path)

        # Parallel scan
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for rule in rules:
                for file_path in files_to_scan:
                    if rule.should_scan_file(file_path):
                        futures.append(executor.submit(scan_file_with_rule, rule, file_path))

            for future in as_completed(futures):
                try:
                    findings.extend(future.result())
                except Exception as e:
                    logger.warning(f"Error scanning file: {e}")
    else:
        for rule in rules:
            findings.extend(rule.scan_directory(path))

    # Filter suppressed findings
    findings = filter_suppressed(findings)

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
        help="Output format: console, json, or sarif",
    ),
    rules: str | None = typer.Option(
        None,
        "--rules",
        "-r",
        help="Comma-separated rule names or IDs (e.g., goal_hijack,AA02)",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (for JSON/SARIF format)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show detailed findings",
    ),
    parallel: bool = typer.Option(
        True,
        "--parallel/--no-parallel",
        help="Enable parallel scanning (default: enabled)",
    ),
    workers: int = typer.Option(
        4,
        "--workers",
        "-w",
        help="Number of parallel workers",
    ),
    min_severity: str = typer.Option(
        "info",
        "--min-severity",
        "-s",
        help="Minimum severity to report: critical, high, medium, low, info",
    ),
    use_optimized: bool = typer.Option(
        True,
        "--optimized/--no-optimized",
        help="Use optimized scanner with better resource management",
    ),
    use_cache: bool = typer.Option(
        False,
        "--cache/--no-cache",
        help="Enable caching to skip unchanged files",
    ),
    cache_dir: str | None = typer.Option(
        None,
        "--cache-dir",
        help="Custom cache directory (default: .owasp-scan-cache)",
    ),
    baseline_file: str | None = typer.Option(
        None,
        "--baseline",
        "-b",
        help="Baseline file to filter existing issues",
    ),
    create_baseline: str | None = typer.Option(
        None,
        "--create-baseline",
        help="Create baseline file from current findings",
    ),
    config_file: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to config file (.owasp-scan.toml)",
    ),
    git_diff: str | None = typer.Option(
        None,
        "--git-diff",
        help="Only scan files changed from git ref (e.g., origin/main)",
    ),
) -> None:
    """Scan a codebase for OWASP Agentic AI security risks."""
    # Input validation
    valid_severities = {"critical", "high", "medium", "low", "info"}
    if min_severity.lower() not in valid_severities:
        console.print(
            f"[red]Error: Invalid severity '{min_severity}'. Must be one of: {', '.join(valid_severities)}[/red]"
        )
        raise typer.Exit(1)

    valid_formats = {"console", "json", "sarif"}
    if format.lower() not in valid_formats:
        console.print(
            f"[red]Error: Invalid format '{format}'. Must be one of: {', '.join(valid_formats)}[/red]"
        )
        raise typer.Exit(1)

    # Validate scan path
    scan_path = Path(path)
    if not scan_path.exists():
        console.print(f"[red]Error: Path does not exist: {path}[/red]")
        raise typer.Exit(1)

    # Validate cache directory if provided
    if cache_dir:
        try:
            cache_path_obj = Path(cache_dir).resolve(strict=False)
        except (OSError, ValueError) as e:
            console.print(f"[red]Error: Invalid cache directory: {e}[/red]")
            raise typer.Exit(1) from None

        # Explicitly block dangerous directories FIRST (resolve them too)
        dangerous_paths = [
            Path("/etc").resolve(strict=False),
            Path("/sys").resolve(strict=False),
            Path("/proc").resolve(strict=False),
            Path("/dev").resolve(strict=False),
        ]
        for danger in dangerous_paths:
            try:
                if cache_path_obj.is_relative_to(danger):
                    console.print("[red]Error: Cannot use system directory for cache[/red]")
                    raise typer.Exit(1)
            except ValueError:
                # is_relative_to raises ValueError on different drives (Windows)
                pass

        # Define allowed base directories
        import tempfile

        allowed_bases = [
            Path.home(),  # User home directory
            Path.cwd(),  # Current working directory
            Path("/tmp").resolve(strict=False),  # noqa: S108  # nosec B108 - Temp directory
            Path(tempfile.gettempdir()).resolve(
                strict=False
            ),  # System temp (may differ from /tmp on macOS)
        ]

        # Check if resolved path is under any allowed base
        is_allowed = False
        for base in allowed_bases:
            try:
                if cache_path_obj.is_relative_to(base):
                    is_allowed = True
                    break
            except ValueError:
                # is_relative_to raises ValueError on different drives (Windows)
                pass

        if not is_allowed:
            console.print("[red]Error: Cache directory must be under home, cwd, or /tmp[/red]")
            raise typer.Exit(1)

    # Load config file if specified
    config = None
    if config_file:
        try:
            from owasp_agentic_scanner.config import ScanConfig

            config = ScanConfig.load(Path(config_file))
            if format.lower() == "console":
                console.print(f"[dim]Loaded config from: {config_file}[/dim]")
        except ImportError:
            logger.warning("Config module not available")
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")

    # Override config with CLI arguments if provided
    if config:
        if rules is None and hasattr(config, "enabled_rules"):
            rules = ",".join(config.enabled_rules)
        if min_severity == "info" and hasattr(config, "min_severity"):
            min_severity = config.min_severity
        if workers == 4 and hasattr(config, "max_workers") and config.max_workers > 0:
            workers = config.max_workers

    # Get rules to use
    selected_rules = get_rules_by_filter(rules)

    if format.lower() == "console":
        console.print(f"[bold]Scanning:[/bold] {scan_path}")
        console.print(f"[bold]Rules:[/bold] {len(selected_rules)} active")
        console.print()

    # Initialize cache if enabled
    cache = None
    files_to_scan = None
    if use_cache:
        try:
            from owasp_agentic_scanner.cache import ScanCache

            cache_path = Path(cache_dir) if cache_dir else None
            cache = ScanCache(
                project_root=scan_path if scan_path.is_dir() else scan_path.parent,
                cache_dir=cache_path,
            )
            cache.load()
            if format.lower() == "console":
                console.print(f"[dim]Cache enabled: {cache.cache_file}[/dim]")
        except ImportError:
            logger.warning("Cache module not available, proceeding without cache")
            use_cache = False
        except Exception as e:
            logger.warning(f"Failed to initialize cache: {e}")
            use_cache = False

    # Get files to scan from git diff if specified
    if git_diff:
        try:
            from owasp_agentic_scanner.cache import GitAwareCache

            git_cache = GitAwareCache(
                project_root=scan_path if scan_path.is_dir() else scan_path.parent
            )
            changed_files = git_cache.get_changed_files(git_diff)
            files_to_scan = list(changed_files)
            if format.lower() == "console":
                console.print(
                    f"[dim]Scanning {len(files_to_scan)} files changed from {git_diff}[/dim]"
                )
        except ImportError:
            logger.warning("Git integration not available, scanning all files")
        except Exception as e:
            logger.warning(f"Failed to get git diff: {e}, scanning all files")

    # Perform scan
    if use_optimized:
        # Use new optimized scanner with cache and files_to_scan support
        try:
            from owasp_agentic_scanner.scanner import OptimizedScanner

            scanner = OptimizedScanner(selected_rules, max_workers=workers)
            if format.lower() == "console":
                with console.status("[bold green]Scanning..."):
                    findings = scanner.scan(
                        scan_path, parallel=parallel, files_to_scan=files_to_scan, cache=cache
                    )
            else:
                findings = scanner.scan(
                    scan_path, parallel=parallel, files_to_scan=files_to_scan, cache=cache
                )
        except ImportError:
            logger.warning("Optimized scanner not available, using standard scanner")
            use_optimized = False
        except TypeError as e:
            # Scanner doesn't support new parameters - fall back
            logger.warning(f"Scanner doesn't support cache/files_to_scan: {e}")
            if format.lower() == "console":
                with console.status("[bold green]Scanning..."):
                    findings = scanner.scan(scan_path, parallel=parallel)
            else:
                findings = scanner.scan(scan_path, parallel=parallel)
            # Manual filtering if needed
            if git_diff and files_to_scan:
                files_to_scan_strs = {str(p) for p in files_to_scan}
                findings = [f for f in findings if str(f.file_path) in files_to_scan_strs]

    # The OptimizedScanner does not apply inline noqa suppression itself, so
    # filter its findings here to match the legacy scan_codebase() path.
    # When use_optimized is False (ImportError fallback), scan_codebase()
    # already filters, so we skip it here to avoid double work.
    if use_optimized:
        findings = filter_suppressed(findings)

    if not use_optimized:
        # Use original scanner
        if format.lower() == "console":
            with console.status("[bold green]Scanning..."):
                findings = scan_codebase(
                    scan_path, selected_rules, parallel=parallel, max_workers=workers
                )
        else:
            findings = scan_codebase(
                scan_path, selected_rules, parallel=parallel, max_workers=workers
            )

        # Manual filtering for old scanner
        if git_diff and files_to_scan:
            files_to_scan_strs = {str(p) for p in files_to_scan}
            findings = [f for f in findings if str(f.file_path) in files_to_scan_strs]

    # Apply baseline filtering if specified
    baseline = None
    if baseline_file:
        try:
            from owasp_agentic_scanner.baseline import Baseline

            baseline_path = Path(baseline_file)
            baseline = Baseline(baseline_path)
            if baseline_path.exists():
                baseline.load(baseline_path)
                new_findings, baselined_findings = baseline.filter_new_findings(findings)
                findings = new_findings
                if format.lower() == "console" and len(baselined_findings) > 0:
                    console.print(
                        f"[dim]Filtered {len(baselined_findings)} baselined findings[/dim]"
                    )
        except ImportError:
            logger.warning("Baseline module not available")
        except Exception as e:
            logger.warning(f"Failed to load baseline: {e}")

    # Create baseline if requested
    if create_baseline:
        try:
            from owasp_agentic_scanner.baseline import Baseline

            new_baseline_path = Path(create_baseline)
            new_baseline = Baseline()
            new_baseline.save(new_baseline_path, findings)
            if format.lower() == "console":
                console.print(
                    f"[green]Baseline created: {create_baseline} ({len(findings)} findings)[/green]"
                )
        except ImportError:
            logger.warning("Baseline module not available")
        except Exception as e:
            logger.error(f"Failed to create baseline: {e}")

    # Save cache if enabled
    if use_cache and cache:
        try:
            cache.save()
            if format.lower() == "console":
                console.print("[dim]Cache saved[/dim]")
        except Exception as e:
            logger.warning(f"Failed to save cache: {e}")

    # Filter by minimum severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    min_sev_level = severity_order.get(min_severity.lower(), 4)
    findings = [f for f in findings if severity_order.get(f.severity.value, 4) <= min_sev_level]

    # Output results
    if format.lower() == "json":
        json_reporter = JsonReporter()
        if output:
            json_reporter.report_to_file(findings, str(scan_path), output)
            console.print(f"[green]Report written to: {output}[/green]")
        else:
            print(json_reporter.report(findings, str(scan_path)))
    elif format.lower() == "sarif":
        sarif_reporter = SarifReporter()
        if output:
            sarif_reporter.report_to_file(findings, str(scan_path), output)
            console.print(f"[green]SARIF report written to: {output}[/green]")
        else:
            print(sarif_reporter.report(findings, str(scan_path)))
    else:
        console_reporter = ConsoleReporter()
        console_reporter.report(findings, str(scan_path))

        if verbose and findings:
            console.print("[bold]Detailed Findings:[/bold]")
            console.print()
            for finding in findings:
                console_reporter.print_finding_details(finding)
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


@app.command()
def version() -> None:
    """Show scanner version."""
    console.print(f"OWASP Agentic AI Scanner v{__version__}")


def main() -> None:
    """Entry point."""
    app()


if __name__ == "__main__":
    main()
