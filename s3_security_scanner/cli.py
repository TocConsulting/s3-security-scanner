#!/usr/bin/env python3
"""Command-line interface for S3 Security Scanner - Clean Command Groups Architecture."""

import json
import logging
import os
import sys
import traceback
from datetime import datetime

import boto3
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .scanner import S3SecurityScanner
from . import __version__

# Configure logging format
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.WARNING  # Default to WARNING to keep output clean
)

# Import discovery module if available
try:
    from .discovery import BucketDiscoveryEngine
    DISCOVERY_AVAILABLE = True
except ImportError:
    DISCOVERY_AVAILABLE = False

console = Console()

# ASCII Art Banner
BANNER = """
[bold red]    _____ ____    _____                      _ _
   / ____|___ \\  / ____|                    (_) |
  | (___   __) || (___   ___  ___ _   _ _ __ _| |_ _   _
   \\___ \\ |__ <  \\___ \\ / _ \\/ __| | | | '__| | __| | | |
   ____) |___) | ____) |  __/ (__| |_| | |  | | |_| |_| |
  |_____/|____/ |_____/ \\___|\\___|\\__,_|_|  |_|\\__|\\__, |
                                                    __/ |
   [bold white]Scanner[/bold white]                                   |___/ [/bold red]
"""

BANNER_SIMPLE = """[bold red]╔══════════════════════════════════════════════════════════╗
║  S3 Security Scanner - AWS S3 Security Analysis Tool     ║
╚══════════════════════════════════════════════════════════╝[/bold red]"""


def print_banner(simple: bool = False):
    """Print the ASCII art banner."""
    if simple:
        console.print(BANNER_SIMPLE)
    else:
        console.print(BANNER)
        console.print(f"[dim]  Version {__version__} | https://github.com/TocConsulting/s3-security-scanner[/dim]\n")

# =====================================================================================
# SHARED OPTIONS (used across commands)
# =====================================================================================


def shared_aws_options(f):
    """AWS connection options shared across commands."""
    f = click.option(
        "-r", "--region",
        default="us-east-1",
        help="AWS region (default: us-east-1)"
    )(f)
    f = click.option(
        "-p", "--profile",
        help="AWS profile name"
    )(f)
    return f


def shared_output_options(f):
    """Output options shared across commands."""
    f = click.option(
        "-o", "--output-dir",
        default="./output",
        help="Directory for output files (default: ./output)"
    )(f)
    f = click.option(
        "-f", "--output-format",
        type=click.Choice(
            ["json", "csv", "html", "all"], case_sensitive=False
        ),
        default="all",
        help="Report format (default: all)"
    )(f)
    return f


def shared_performance_options(f):
    """Performance and logging options shared across commands."""
    f = click.option(
        "-w", "--max-workers",
        default=5,
        type=int,
        help="Worker threads for parallel processing (default: 5)"
    )(f)
    f = click.option(
        "-q", "--quiet",
        is_flag=True,
        help="Suppress console output except errors"
    )(f)
    f = click.option(
        "-d", "--debug",
        is_flag=True,
        help="Enable debug logging"
    )(f)
    return f


def shared_options(f):
    """Apply all shared options to a command."""
    f = shared_aws_options(f)
    f = shared_output_options(f)
    f = shared_performance_options(f)
    return f


# =====================================================================================
# MAIN CLI GROUP
# =====================================================================================


class CustomGroup(click.Group):
    """Custom Click group with banner display."""

    def format_help(self, ctx, formatter):
        """Write the help into the formatter with banner."""
        print_banner()
        super().format_help(ctx, formatter)


@click.group(cls=CustomGroup, context_settings=dict(help_option_names=['-h', '--help']))
@click.version_option(version=__version__, prog_name="S3 Security Scanner")
def cli():
    """
    Comprehensive AWS S3 security scanner for vulnerability detection,
    compliance auditing, and bucket discovery.

    \b
    COMMANDS
    ════════════════════════════════════════════════════════════════
      security    Scan your S3 buckets for 40+ security checks
                  Frameworks: CIS, PCI-DSS, HIPAA, SOC2, GDPR, ISO27001
    \b
      discover    Find unknown/forgotten S3 buckets
                  No AWS credentials required for basic discovery
    \b
      dns         Detect DNS subdomain takeover vulnerabilities
                  Scans Route53 and validates CNAME records

    \b
    QUICK START
    ════════════════════════════════════════════════════════════════
      Scan all buckets:     s3-security-scanner security
      Use AWS profile:      s3-security-scanner security -p prod
      Discover buckets:     s3-security-scanner discover --target acme
      Check DNS takeover:   s3-security-scanner dns --domain example.com

    \b
    MORE INFO
    ════════════════════════════════════════════════════════════════
      Run COMMAND --help for detailed options (e.g. security --help)
      Docs: https://github.com/TocConsulting/s3-security-scanner
    """
    pass


# =====================================================================================
# DISCOVERY COMMAND
# =====================================================================================


@cli.command()
@click.option(
    "--target",
    required=True,
    help="Target name for discovery (company/domain name)"
)
@click.option(
    "--level",
    type=click.Choice(["basic", "medium", "advanced"], case_sensitive=False),
    default="basic",
    help="Discovery intensity: basic(~200,5s) | medium(~1k,40s) | advanced(~9k,9min)"
)
@click.option(
    "--methods",
    default="dns,permutations",
    help="Validation methods: dns(fast) | http(accurate) | permutations(generates)"
)
@click.option(
    "--only",
    is_flag=True,
    help="Only discover buckets, don't scan them for security issues"
)
@click.option(
    "--wordlist",
    help="Custom wordlist file for additional bucket names"
)
@click.option(
    "--stealth/--no-stealth",
    default=True,
    help="Use stealth mode for discovery (default: enabled)"
)
@shared_options
def discover(target, level, methods, only, wordlist, stealth, region, profile, output_dir, output_format, max_workers, quiet, debug):
    """
    Find unknown S3 buckets for a target organization.

    \b
    EXAMPLES:
      s3-security-scanner discover --target "acme"                    # Basic: ~200 names, 5s
      s3-security-scanner discover --target "startup" --level medium # ~1,000 names, 40s
      s3-security-scanner discover --target "corp" --level advanced  # ~9,000 names, 9min

      s3-security-scanner discover --target "test" --methods dns     # Fast but less accurate
      s3-security-scanner discover --target "test" --only            # No security scan
    """
    if not DISCOVERY_AVAILABLE:
        console.print("[red] Discovery module not available. Please install discovery dependencies.[/red]")
        sys.exit(1)

    try:
        # Check for AWS credentials for auto-detection FIRST
        aws_credentials_available = False
        try:
            session = boto3.Session(profile_name=profile)
            credentials = session.get_credentials()
            if credentials and credentials.access_key:
                aws_credentials_available = True
        except Exception:
            aws_credentials_available = False

        # Auto-enable discover-only if no AWS credentials
        if not aws_credentials_available and not only:
            only = True
            credential_warning = True
        else:
            credential_warning = False

        if not quiet:
            print_banner(simple=True)
            console.print(f"[bold cyan]Starting S3 bucket discovery for target:[/bold cyan] [white]{target}[/white]")
            console.print(f"[dim]Methods: {methods} | Level: {level} | Stealth: {stealth}[/dim]")

            # Show credential warning BEFORE expected performance
            if credential_warning:
                console.print("[yellow]No AWS credentials detected. Running in discovery-only mode.[/yellow]")
                console.print("[dim]Tip: Use --only flag to explicitly enable this mode.[/dim]")

            # Show expected performance (updated with actual counts)
            level_info = {
                "basic": ("~200", "~5 seconds"),
                "medium": ("~1,000", "~40 seconds"),
                "advanced": ("~9,000", "~9 minutes")
            }
            candidates, time_est = level_info.get(
                level, ("unknown", "unknown")
            )
            console.print(f"[dim]Expected: {candidates} candidates, {time_est} duration[/dim]\n")

        # Parse discovery methods
        method_list = [method.strip() for method in methods.split(',')]

        # Initialize discovery engine
        discovery_engine = BucketDiscoveryEngine(
            use_dns='dns' in method_list,
            use_http='http' in method_list,
            max_workers=max_workers,
            stealth_mode=stealth,
            quiet_mode=quiet
        )

        # Configure logging based on quiet/debug mode
        if debug:
            logging.getLogger().setLevel(logging.DEBUG)
        elif quiet:
            logging.getLogger().setLevel(logging.ERROR)
        else:
            # Suppress INFO logs during discovery to keep output clean
            logging.getLogger().setLevel(logging.WARNING)

        # Critical: Suppress DNS error logging during discovery to prevent output pollution
        dns_logger = logging.getLogger('s3_security_scanner.discovery.dns_validator')
        dns_logger.setLevel(logging.CRITICAL)

        # Also suppress dnspython internal logging
        logging.getLogger('dns').setLevel(logging.CRITICAL)
        logging.getLogger('dns.resolver').setLevel(logging.CRITICAL)

        # Perform discovery
        discovered_buckets = discovery_engine.discover(
            target=target,
            wordlist_path=wordlist,
            methods=method_list,
            permutation_level=level
        )

        # Save discovery results
        discovery_report = os.path.join(
            output_dir,
            f"s3_discovery_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        os.makedirs(output_dir, exist_ok=True)
        with open(discovery_report, 'w') as f:
            discovery_results = {
                'target': target,
                'methods': method_list,
                'level': level,
                'stealth_mode': stealth,
                'discovered_buckets': [bucket.to_dict() for bucket in discovered_buckets],
                'statistics': discovery_engine.get_statistics(),
                'timestamp': datetime.now().isoformat()
            }
            json.dump(discovery_results, f, indent=2, default=str)

        # Calculate buckets found (needed for logic below)
        existing_buckets = [b for b in discovered_buckets if b.exists]
        public_buckets = [b for b in existing_buckets if b.is_public]

        if not quiet:
            console.print(f"\n[green]Discovery report saved to: {discovery_report}[/green]")

            # Print discovery summary
            console.print("\n[bold green]Discovery Results:[/bold green]")
            console.print(f"  • Total candidates: {discovery_engine.stats['total_candidates']}")
            console.print(f"  • Buckets found: {len(existing_buckets)}")
            console.print(f"  • Public buckets: {len(public_buckets)}")
            console.print(f"  • Discovery rate: {discovery_engine.stats['total_candidates']/(discovery_engine.stats['end_time'] - discovery_engine.stats['start_time']).total_seconds():.1f} candidates/sec")

            # Show discovered bucket names
            if existing_buckets:
                console.print(
                    "\n[bold cyan]Discovered Buckets:[/bold cyan]"
                )
                for bucket in existing_buckets:
                    region_info = (
                        f" ({bucket.region})" if bucket.region else ""
                    )
                    public_marker = " [red]PUBLIC[/red]" if bucket.is_public else ""
                    console.print(f"  ✓ {bucket.name}{region_info}{public_marker}")

        # If discover-only mode, exit here
        if only:
            if existing_buckets:
                console.print(f"\n[bold green]Discovery completed! Found {len(existing_buckets)} bucket(s).[/bold green]")
                if credential_warning:
                    console.print("[dim]Configure AWS credentials to perform security analysis.[/dim]")
                else:
                    console.print("[dim]Remove --only flag to perform security analysis.[/dim]")
            else:
                console.print("\n[bold green]Discovery completed! No buckets found with current patterns.[/bold green]")
                console.print("[dim]Try --level medium or --level advanced for more coverage.[/dim]")
            return

        # Continue with security scanning if buckets found and credentials available
        if existing_buckets and aws_credentials_available:
            if not quiet:
                console.print(f"\n[bold yellow]Continuing with security analysis of {len(existing_buckets)} discovered buckets...[/bold yellow]\n")

            # Initialize scanner for security analysis
            scanner = S3SecurityScanner(
                region=region,
                profile=profile,
                output_dir=output_dir,
                max_workers=max_workers,
            )

            # Suppress scanner logs during discovery mode
            # Only show CRITICAL errors to keep output clean
            logging.getLogger('s3_security_scanner.scanner').setLevel(logging.CRITICAL)
            logging.getLogger('s3_security_scanner').setLevel(logging.CRITICAL)
            logging.getLogger('botocore').setLevel(logging.CRITICAL)
            logging.getLogger('boto3').setLevel(logging.CRITICAL)
            logging.getLogger().setLevel(logging.CRITICAL)  # Root logger

            # Convert discovered buckets to scanner format
            buckets_to_scan = [{"Name": b.name} for b in existing_buckets]

            # Perform security scan
            results = scanner.scan_all_buckets(buckets_to_scan)

            if results:
                # Generate reports
                report_files = scanner.generate_reports(results, output_format)

                if not quiet:
                    scanner.print_summary(results)
                    console.print(
                        "\n[bold green]Reports Generated:[/bold green]"
                    )
                    for report_type, file_path in report_files.items():
                        console.print(
                            f"  • {report_type.upper()}: {file_path}"
                        )

                console.print("\n[bold green] Discovery and security scan completed successfully![/bold green]")
            else:
                console.print("[red] No security scan results generated[/red]")
        else:
            if not aws_credentials_available:
                console.print("\n[yellow] No AWS credentials available for security scanning.[/yellow]")
            else:
                console.print("\n[yellow] No buckets discovered for security scanning.[/yellow]")

    except KeyboardInterrupt:
        console.print("\n[yellow] Discovery interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red] Error: {str(e)}[/red]")
        if debug:
            console.print(f"[red]{traceback.format_exc()}[/red]")
        sys.exit(1)


# =====================================================================================
# SECURITY COMMAND
# =====================================================================================

@cli.command()
@click.option(
    "--bucket",
    multiple=True,
    help="Specific bucket(s) to scan (can be used multiple times)"
)
@click.option(
    "--exclude-bucket",
    multiple=True,
    help="Bucket(s) to exclude from scanning (can be used multiple times)"
)
@click.option(
    "--compliance-only",
    is_flag=True,
    help="Generate compliance report only"
)
@click.option(
    "--no-object-scan",
    is_flag=True,
    help="Skip object analysis for faster results"
)
@shared_options
def security(bucket, exclude_bucket, compliance_only, no_object_scan, region, profile, output_dir, output_format, max_workers, quiet, debug):
    """
    Scan your S3 buckets for security vulnerabilities and compliance issues.

    \b
    EXAMPLES:
      s3-security-scanner security                                    # Scan all buckets
      s3-security-scanner security --profile prod --region us-west-2 # Specific profile/region
      s3-security-scanner security --bucket bucket1 --bucket bucket2 # Specific buckets
      s3-security-scanner security --compliance-only                 # Just compliance report
      s3-security-scanner security --no-object-scan                  # Fast scan
    """
    # Configure logging based on debug/quiet mode
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('s3_security_scanner').setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)

    if not quiet:
        print_banner(simple=True)
        console.print("[bold cyan]Starting S3 security analysis...[/bold cyan]\n")

    try:
        # Initialize scanner
        scanner = S3SecurityScanner(
            region=region,
            profile=profile,
            output_dir=output_dir,
            max_workers=max_workers,
        )

        # Configure object-level scanning option
        scanner.skip_object_scan = no_object_scan

        # Get buckets to scan
        if bucket:
            # Scan specific buckets
            buckets_to_scan = [{"Name": b} for b in bucket]

            # Apply exclusions even for specific buckets
            if exclude_bucket:
                original_count = len(buckets_to_scan)
                buckets_to_scan = [
                    b for b in buckets_to_scan
                    if b["Name"] not in exclude_bucket
                ]
                if not quiet:
                    excluded_count = original_count - len(buckets_to_scan)
                    if excluded_count > 0:
                        console.print(f"[yellow]Excluded {excluded_count} bucket(s) from specified buckets[/yellow]")

            if not quiet:
                console.print(f"[cyan]Scanning {len(buckets_to_scan)} specified bucket(s)[/cyan]")
        else:
            # Get all buckets
            all_buckets = scanner.get_all_buckets()

            # Apply exclusions
            if exclude_bucket:
                buckets_to_scan = [
                    b for b in all_buckets
                    if b["Name"] not in exclude_bucket
                ]
                if not quiet:
                    excluded_count = len(all_buckets) - len(buckets_to_scan)
                    console.print(f"[yellow]Excluded {excluded_count} bucket(s) from scan[/yellow]")
            else:
                buckets_to_scan = all_buckets

        if not buckets_to_scan:
            console.print("[red] No buckets found to scan[/red]")
            sys.exit(1)

        # Perform scan
        if not quiet:
            console.print(f"[green]Scanning {len(buckets_to_scan)} bucket(s)...[/green]\n")

        results = scanner.scan_all_buckets(buckets_to_scan)

        if not results:
            console.print("[red] No results generated[/red]")
            sys.exit(1)

        # Generate reports
        report_files = scanner.generate_reports(results, output_format)

        if not quiet:
            # Print summary to console
            scanner.print_summary(results)

            # Print report file locations
            console.print("\n[bold green]Reports Generated:[/bold green]")
            for report_type, file_path in report_files.items():
                console.print(f"  • {report_type.upper()}: {file_path}")

            # Show compliance summary if requested
            if compliance_only or "compliance" in report_files:
                _print_compliance_summary(results)

        console.print("\n[bold green] Security scan completed successfully![/bold green]")
        console.print(f"[dim]Reports saved to: {output_dir}[/dim]")

    except KeyboardInterrupt:
        console.print("\n[yellow] Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red] Error: {str(e)}[/red]")
        if debug:
            console.print(f"[red]{traceback.format_exc()}[/red]")
        sys.exit(1)


# =====================================================================================
# DNS COMMAND
# =====================================================================================

@cli.command()
@click.option(
    "--domain",
    multiple=True,
    required=True,
    help="Domain(s) to check for takeover vulnerabilities (can be used multiple times)"
)
@click.option(
    "--skip-subdomain-enum",
    is_flag=True,
    help="Skip subdomain enumeration"
)
@shared_options
def dns(domain, skip_subdomain_enum, region, profile, output_dir, output_format, max_workers, quiet, debug):
    """
    Check domains for DNS takeover vulnerabilities.

    \b
    EXAMPLES:
      s3-security-scanner dns --domain example.com
      s3-security-scanner dns --domain site1.com --domain site2.com
      s3-security-scanner dns --domain example.com --skip-subdomain-enum
    """
    # Configure logging based on debug/quiet mode
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('s3_security_scanner').setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.ERROR)

    if not quiet:
        print_banner(simple=True)
        console.print(f"[bold cyan]Scanning {len(domain)} domain(s) for DNS takeover vulnerabilities[/bold cyan]\n")

    try:
        # Initialize scanner
        scanner = S3SecurityScanner(
            region=region,
            profile=profile,
            output_dir=output_dir,
            max_workers=max_workers,
        )

        # Perform comprehensive DNS takeover scan
        takeover_results = scanner.scan_subdomain_takeover(
            list(domain),
            check_subdomains=not skip_subdomain_enum,
        )

        # Export results
        takeover_report = os.path.join(
            output_dir,
            f"dns_takeover_{region}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        os.makedirs(output_dir, exist_ok=True)
        with open(takeover_report, "w") as f:
            json.dump(takeover_results, f, indent=2, default=str)

        if not quiet:
            console.print(f"\n[green]DNS takeover report saved to: {takeover_report}[/green]")

        console.print("\n[bold green] DNS takeover scan completed![/bold green]")

    except KeyboardInterrupt:
        console.print("\n[yellow] Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red] Error: {str(e)}[/red]")
        if debug:
            console.print(f"[red]{traceback.format_exc()}[/red]")
        sys.exit(1)


# =====================================================================================
# UTILITY FUNCTIONS
# =====================================================================================

def _print_compliance_summary(results):
    """Print a formatted compliance summary table to the console."""
    console.print("\n[bold cyan]Compliance Summary:[/bold cyan]")

    # Calculate compliance statistics
    frameworks = [
        "CIS", "AWS-FSBP", "PCI-DSS", "HIPAA", "SOC2",
        "ISO27001", "ISO27017", "ISO27018", "GDPR"
    ]
    compliance_stats = {}

    for framework in frameworks:
        total_passed = 0
        total_applicable = 0
        compliant_buckets = 0

        for r in results:
            framework_status = r.get("compliance_status", {}).get(framework, {})
            if framework_status:
                passed = framework_status.get("passed_controls", 0)
                applicable = framework_status.get("applicable_controls", 0)
                total_passed += passed
                total_applicable += applicable

                if framework_status.get("is_compliant", False):
                    compliant_buckets += 1

        percentage = (total_passed / total_applicable * 100) if total_applicable > 0 else 0
        compliance_stats[framework] = {
            "compliant": compliant_buckets,
            "total": len(results),
            "percentage": percentage,
        }

    # Create compliance table
    table = Table(title="Compliance Framework Summary")
    table.add_column("Framework", style="cyan", no_wrap=True, width=12)
    table.add_column("Compliant Buckets", justify="center", width=12)
    table.add_column("Total Buckets", justify="center", width=12)
    table.add_column("Compliance %", justify="center", width=12)
    table.add_column("Status", justify="center")

    for framework, stats in compliance_stats.items():
        percentage = stats["percentage"]

        if percentage >= 90:
            status = "[green]+ Excellent[/green]"
        elif percentage >= 75:
            status = "[yellow]~ Good[/yellow]"
        elif percentage >= 50:
            status = "[orange]! Needs Work[/orange]"
        else:
            status = "[red]- Poor[/red]"

        table.add_row(
            framework,
            str(stats["compliant"]),
            str(stats["total"]),
            f"{percentage:.1f}%",
            status,
        )

    console.print(table)


# For backward compatibility with entry point
main = cli


if __name__ == "__main__":
    cli()
