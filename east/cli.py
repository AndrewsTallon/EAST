"""CLI interface for EAST tool using Click and Rich."""

import logging
import os
import sys
import time
import asyncio
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from east import __version__
from east.config import EASTConfig
from east.report import EASTReportGenerator
from east.scan_engine import ScanEngine
from east.tests.base import TestResult
from east.utils.validators import validate_domain, sanitize_domain
from east.utils.http import log_call_summary

console = Console()

# Registry of available test runners
TEST_REGISTRY = {}


def _register_tests():
    """Lazily import and register all available test runners."""
    global TEST_REGISTRY
    if TEST_REGISTRY:
        return

    from east.tests.ssl_test import SSLLabsTestRunner
    from east.tests.observatory_test import MozillaObservatoryTestRunner
    from east.tests.dns_test import DNSTestRunner
    from east.tests.email_test import EmailAuthTestRunner
    from east.tests.blacklist_test import BlacklistTestRunner
    from east.tests.subdomain_test import SubdomainTestRunner
    from east.tests.headers_test import SecurityHeadersTestRunner
    from east.tests.performance_test import PerformanceTestRunner
    from east.tests.cookies_test import CookiesTestRunner
    from east.tests.open_ports_test import OpenPortsTestRunner
    from east.tests.screenshot_test import ScreenshotTestRunner

    TEST_REGISTRY = {
        "ssl_labs": SSLLabsTestRunner,
        "mozilla_observatory": MozillaObservatoryTestRunner,
        "dns_lookup": DNSTestRunner,
        "spf": EmailAuthTestRunner,
        "dkim": EmailAuthTestRunner,
        "dmarc": EmailAuthTestRunner,
        "email_auth": EmailAuthTestRunner,
        "blacklist": BlacklistTestRunner,
        "subdomains": SubdomainTestRunner,
        "security_headers": SecurityHeadersTestRunner,
        "performance": PerformanceTestRunner,
        "cookies": CookiesTestRunner,
        "open_ports": OpenPortsTestRunner,
        "screenshots": ScreenshotTestRunner,
    }


def _setup_logging(verbose: bool):
    """Configure logging based on verbosity."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _resolve_output_path(output: str, config: EASTConfig) -> str:
    """Resolve the output file path from template or explicit path."""
    if output:
        return output

    template = config.output.filename_template
    client_slug = config.client_info.name.replace(" ", "_")
    date_str = datetime.now().strftime("%Y-%m-%d")
    return template.format(client=client_slug, date=date_str).replace("{client}", client_slug).replace("{date}", date_str)


def _get_tests_to_run(config: EASTConfig, test_filter: list[str] | None = None) -> list[str]:
    """Determine which tests to run based on config and filters."""
    _register_tests()

    # Deduplicate: spf/dkim/dmarc all map to EmailAuthTestRunner
    email_tests = {"spf", "dkim", "dmarc"}

    if test_filter:
        tests = []
        seen_email = False
        for t in test_filter:
            if t in email_tests:
                if not seen_email:
                    tests.append("email_auth")
                    seen_email = True
            elif t in TEST_REGISTRY:
                tests.append(t)
        return tests

    tests = []
    seen_email = False
    for test_name in config.tests.enabled:
        if test_name in config.tests.disabled:
            continue
        if test_name in email_tests:
            if not seen_email:
                tests.append("email_auth")
                seen_email = True
        elif test_name in TEST_REGISTRY:
            tests.append(test_name)

    return tests


def _print_banner():
    """Print the EAST banner."""
    banner = Text()
    banner.append("EAST", style="bold cyan")
    banner.append(" - External Attack Surface Test\n", style="bold white")
    banner.append(f"Version {__version__}", style="dim")
    console.print(Panel(banner, border_style="cyan", padding=(1, 2)))


def _print_results_summary(all_results: dict[str, list[TestResult]]):
    """Print a summary table of results."""
    table = Table(title="Scan Results Summary", border_style="cyan")
    table.add_column("Domain", style="bold")
    table.add_column("Test", style="white")
    table.add_column("Grade", justify="center")
    table.add_column("Score", justify="center")
    table.add_column("Status", justify="center")

    for domain, results in all_results.items():
        for i, result in enumerate(results):
            domain_col = domain if i == 0 else ""
            grade = result.grade or "-"
            score = f"{result.score}/{result.max_score}" if result.score is not None else "-"

            if result.success:
                status = "[green]PASS[/green]"
            elif result.error:
                status = "[red]ERROR[/red]"
            else:
                status = "[yellow]WARN[/yellow]"

            # Color the grade
            if grade.startswith("A"):
                grade_styled = f"[green]{grade}[/green]"
            elif grade.startswith("B"):
                grade_styled = f"[yellow]{grade}[/yellow]"
            elif grade in ("-", "N/A", ""):
                grade_styled = "[dim]-[/dim]"
            else:
                grade_styled = f"[red]{grade}[/red]"

            test_display = result.test_name.replace("_", " ").title()
            table.add_row(domain_col, test_display, grade_styled, score, status)

    console.print()
    console.print(table)


def _run_scan(config: EASTConfig, test_filter: list[str] | None, output: str, verbose: bool):
    """Execute the scan and generate report."""
    _print_banner()

    if not config.domains:
        console.print("[red]Error:[/red] No domains specified. Use --domain or a config file.")
        sys.exit(1)

    # Validate domains
    valid_domains = []
    for domain in config.domains:
        domain = sanitize_domain(domain)
        if validate_domain(domain):
            valid_domains.append(domain)
        else:
            console.print(f"[yellow]Warning:[/yellow] Invalid domain skipped: {domain}")

    if not valid_domains:
        console.print("[red]Error:[/red] No valid domains to scan.")
        sys.exit(1)

    config.domains = valid_domains

    # Determine tests
    tests_to_run = _get_tests_to_run(config, test_filter)
    if not tests_to_run:
        console.print("[red]Error:[/red] No valid tests to run.")
        sys.exit(1)

    console.print(f"\n[bold]Domains:[/bold] {', '.join(valid_domains)}")
    console.print(f"[bold]Tests:[/bold] {', '.join(tests_to_run)}")
    console.print(f"[bold]Output:[/bold] {output}\n")

    _register_tests()

    # Validate SSL Labs email requirement before starting any scans
    if "ssl_labs" in tests_to_run and not config.ssllabs_email:
        from east.tests.ssl_test import REGISTRATION_HELP
        console.print(
            f"[red]Error:[/red] SSL Labs API v4 requires a registered email address.\n"
            f"{REGISTRATION_HELP}"
        )
        sys.exit(1)

    console.print("[dim]Running tests in asynchronous mode with safe per-service rate limits...[/dim]")
    engine = ScanEngine(TEST_REGISTRY)
    all_results = asyncio.run(
        engine.run(
            config,
            tests_to_run,
            on_log=lambda msg: logging.getLogger("east.scan").info(msg),
        )
    )

    # Log HTTP call summary (visible at INFO level when --verbose)
    log_call_summary()

    # Print summary
    _print_results_summary(all_results)

    # Generate report
    console.print(f"\n[bold]Generating report...[/bold]")
    report = EASTReportGenerator(config)
    for domain, results in all_results.items():
        report.add_results(domain, results)

    report.generate(output)
    console.print(f"[green]Report saved to:[/green] {output}")

    # Count findings
    critical = sum(
        1 for results in all_results.values()
        for r in results for rec in r.recommendations
        if rec.get("severity") == "critical"
    )
    warnings = sum(
        1 for results in all_results.values()
        for r in results for rec in r.recommendations
        if rec.get("severity") == "warning"
    )

    if critical:
        console.print(f"\n[red bold]{critical} critical finding(s)[/red bold] require attention.")
    if warnings:
        console.print(f"[yellow]{warnings} warning(s)[/yellow] were identified.")

    console.print(f"\n[dim]Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]")


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """EAST - External Attack Surface Test Automation Tool."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command()
@click.option("--domain", "-d", multiple=True, help="Domain(s) to scan")
@click.option("--domains", help="Comma-separated list of domains")
@click.option("--config", "-c", "config_path", help="Path to YAML configuration file")
@click.option("--output", "-o", default="", help="Output report path (.docx)")
@click.option("--tests", "-t", help="Comma-separated list of tests to run")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--client", help="Client name for the report")
@click.option(
    "--ssllabs-email",
    default="",
    envvar="SSLLABS_EMAIL",
    help="Registered email for SSL Labs API v4 (required for ssl_labs test).",
)
@click.option(
    "--ssllabs-usecache/--fresh",
    default=True,
    help="Use cached SSL Labs results (default) or force a fresh scan.",
)
def scan(domain, domains, config_path, output, tests, verbose, client,
         ssllabs_email, ssllabs_usecache):
    """Run an External Attack Surface Test scan."""
    _setup_logging(verbose)

    # Load configuration
    if config_path:
        try:
            config = EASTConfig.from_yaml(config_path)
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] Config file not found: {config_path}")
            sys.exit(1)
    else:
        config = EASTConfig.default()

    # Override domains from CLI
    cli_domains = list(domain)
    if domains:
        cli_domains.extend(d.strip() for d in domains.split(",") if d.strip())
    if cli_domains:
        config.domains = cli_domains

    # Override client name
    if client:
        config.client_info.name = client

    # SSL Labs v4 options — CLI flags take precedence over config
    if ssllabs_email:
        config.ssllabs_email = ssllabs_email
    if not ssllabs_usecache:
        config.ssllabs_usecache = False

    # Parse test filter
    test_filter = None
    if tests:
        test_filter = [t.strip() for t in tests.split(",") if t.strip()]

    # Resolve output path
    output = _resolve_output_path(output, config)

    _run_scan(config, test_filter, output, verbose)


@cli.command()
def list_tests():
    """List all available tests."""
    _register_tests()

    table = Table(title="Available Tests", border_style="cyan")
    table.add_column("Test Name", style="bold")
    table.add_column("Description")

    test_descriptions = {
        "ssl_labs": "SSL/TLS certificate and configuration analysis via SSL Labs API v4 (requires --ssllabs-email)",
        "mozilla_observatory": "HTTP security headers assessment via Mozilla Observatory",
        "dns_lookup": "DNS record lookup (A, AAAA, MX, NS, CNAME, TXT) and DNSSEC validation",
        "email_auth": "Email authentication checks (SPF, DKIM, DMARC)",
        "blacklist": "Domain/IP blacklist checking across major DNSBL providers",
        "subdomains": "Subdomain enumeration via Certificate Transparency logs",
        "security_headers": "Detailed HTTP security headers analysis",
        "performance": "Web performance metrics via local Lighthouse or PageSpeed API",
        "cookies": "Cookie security analysis (Secure, HttpOnly, SameSite)",
        "open_ports": "Open ports discovery using nmap (top 100 TCP)",
        "screenshots": "Full-page screenshot capture via Playwright",
    }

    for name, desc in test_descriptions.items():
        table.add_row(name, desc)

    console.print(table)


@cli.command()
def version():
    """Show version information."""
    console.print(f"EAST v{__version__}")


if __name__ == "__main__":
    cli()
