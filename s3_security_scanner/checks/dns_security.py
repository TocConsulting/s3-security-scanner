"""DNS security checks for S3 subdomain takeover vulnerabilities."""

import logging
import re
import socket
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

import boto3
import dns.resolver
import dns.exception
import requests
from botocore.exceptions import ClientError, NoCredentialsError
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from ..analyzers.dns_analyzer import DNSAnalyzer


class DNSSecurityChecker:
    """Handles DNS-related security checks for S3 buckets."""

    # Regex patterns for matching S3 website endpoints in DNS takeover analysis
    S3_WEBSITE_PATTERNS = [
        re.compile(
            r"([a-z0-9.-]+)\.s3-website[.-]([a-z0-9-]+)\.amazonaws\.com"
        ),
        re.compile(r"([a-z0-9.-]+)\.s3-website\.([a-z0-9-]+)\.amazonaws\.com"),
        re.compile(r"s3-website[.-]([a-z0-9-]+)\.amazonaws\.com"),
    ]

    # Regex patterns for matching legacy S3 direct endpoints
    S3_LEGACY_PATTERNS = [
        re.compile(r"([a-z0-9.-]+)\.s3\.amazonaws\.com"),
        re.compile(r"([a-z0-9.-]+)\.s3-([a-z0-9-]+)\.amazonaws\.com"),
        re.compile(r"s3\.amazonaws\.com/([a-z0-9.-]+)"),
    ]

    def __init__(
        self, session_factory, s3_client, route53_client, region: str, logger
    ):
        """Initialize DNS Security Checker.

        Args:
            session_factory: Callable that returns a boto3 session,
                           or a boto3.Session directly for backwards compatibility
            s3_client: S3 client
            route53_client: Route53 client
            region: AWS region
            logger: Logger instance
        """
        self.session_factory = session_factory
        self.s3_client = s3_client
        self.route53_client = route53_client
        self.region = region
        self.logger = logger
        self.console = Console()

    def _get_session(self):
        """Get a boto3 session, handling both factory and direct session."""
        if self.session_factory is None:
            return boto3.Session()
        elif callable(self.session_factory):
            return self.session_factory()
        else:
            # Backwards compatibility: direct session passed
            return self.session_factory

    def discover_route53_records(self) -> List[Dict[str, Any]]:
        """Discover Route53 DNS records pointing to S3 endpoints in owned hosted zones.

        Only scans hosted zones owned by the current AWS account. Does not scan
        external DNS providers or zones owned by other accounts.

        Returns:
            List of DNS records with S3 endpoint information
        """
        s3_records = []

        try:
            # Get all hosted zones
            paginator = self.route53_client.get_paginator("list_hosted_zones")

            for page in paginator.paginate():
                for zone in page["HostedZones"]:
                    zone_id = zone["Id"]
                    zone_name = zone["Name"].rstrip(".")

                    self.logger.debug(
                        f"Scanning Route53 hosted zone: {zone_name}"
                    )

                    # Get records for this zone
                    try:
                        records_paginator = self.route53_client.get_paginator(
                            "list_resource_record_sets"
                        )

                        for records_page in records_paginator.paginate(
                            HostedZoneId=zone_id
                        ):
                            for record in records_page["ResourceRecordSets"]:
                                # Check for S3 endpoints in CNAME and ALIAS records
                                s3_endpoint = (
                                    self._extract_s3_endpoint_from_record(
                                        record
                                    )
                                )
                                if s3_endpoint:
                                    s3_records.append(
                                        {
                                            "zone_name": zone_name,
                                            "zone_id": zone_id,
                                            "record_name": record[
                                                "Name"
                                            ].rstrip("."),
                                            "record_type": record["Type"],
                                            "s3_endpoint": s3_endpoint,
                                            "ttl": record.get("TTL", "N/A"),
                                            "record": record,
                                        }
                                    )

                    except Exception as e:
                        self.logger.error(
                            f"Error scanning records in zone {zone_name}: {e}"
                        )

        except Exception as e:
            self.logger.error(f"Error accessing Route53: {e}")

        self.logger.info(
            f"Found {len(s3_records)} Route53 records pointing to S3 endpoints"
        )
        return s3_records

    def _extract_s3_endpoint_from_record(
        self, record: Dict[str, Any]
    ) -> Optional[str]:
        """Extract S3 endpoint from a Route53 record.

        Args:
            record: Route53 resource record set

        Returns:
            S3 endpoint URL if found, None otherwise
        """
        if record["Type"] == "CNAME":
            # CNAME records
            if "ResourceRecords" in record:
                for rr in record["ResourceRecords"]:
                    value = rr["Value"].rstrip(".")
                    if self._is_s3_endpoint(value):
                        return value

        elif record["Type"] == "A" and "AliasTarget" in record:
            # ALIAS records
            dns_name = record["AliasTarget"]["DNSName"].rstrip(".")
            if self._is_s3_endpoint(dns_name):
                return dns_name

        return None

    def _is_s3_endpoint(self, endpoint: str) -> bool:
        """Check if an endpoint is an S3 endpoint.

        Args:
            endpoint: DNS endpoint to check

        Returns:
            True if it's an S3 endpoint, False otherwise
        """
        s3_patterns = [
            r"\.s3-website[.-]",
            r"\.s3-website\..*\.amazonaws\.com$",
            r"\.s3\.amazonaws\.com$",
            r"\.s3[.-].*\.amazonaws\.com$",
        ]

        endpoint_lower = endpoint.lower()
        return any(
            re.search(pattern, endpoint_lower) for pattern in s3_patterns
        )

    def extract_bucket_info_from_endpoint(
        self, endpoint: str
    ) -> Dict[str, Optional[str]]:
        """Extract bucket name and region from S3 endpoint.

        Args:
            endpoint: S3 endpoint URL

        Returns:
            Dictionary with bucket_name and region
        """
        # Use shared utility function
        from ..bucket_utils import extract_bucket_info_from_endpoint

        return extract_bucket_info_from_endpoint(endpoint)

    def check_bucket_ownership_in_region(
        self, bucket_name: str, region: str
    ) -> Dict[str, Any]:
        """Check if a bucket exists and who owns it in a specific region.

        Args:
            bucket_name: Name of the bucket to check
            region: AWS region to check in

        Returns:
            Dictionary with bucket status information
        """
        try:
            # Create region-specific S3 client
            if self.s3_client is None:
                # No S3 client available - use HTTP check
                return self._check_bucket_exists_http(bucket_name, region)

            if region != self.region:
                session = self._get_session()
                region_s3_client = session.client(
                    "s3", region_name=region
                )
            else:
                region_s3_client = self.s3_client

            # First check if bucket exists
            region_s3_client.head_bucket(Bucket=bucket_name)

            # If head_bucket succeeds, try get bucket ACL to verify ownership
            try:
                region_s3_client.get_bucket_acl(Bucket=bucket_name)
                # If get_bucket_acl succeeds, we own the bucket
                return {
                    "exists": True,
                    "owned_by_us": True,
                    "error": None,
                    "region": region,
                }
            except ClientError as acl_error:
                acl_error_code = acl_error.response["Error"]["Code"]
                if acl_error_code == "403":
                    # Bucket exists but we can't access ACL - likely not owned by us
                    return {
                        "exists": True,
                        "owned_by_us": False,
                        "error": "AccessDenied on ACL",
                        "region": region,
                    }
                else:
                    # Other ACL error
                    return {
                        "exists": True,
                        "owned_by_us": False,
                        "error": f"ACL Error: {str(acl_error)}",
                        "region": region,
                    }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "404":
                return {
                    "exists": False,
                    "owned_by_us": False,
                    "error": "NoSuchBucket",
                    "region": region,
                }
            elif error_code == "403":
                return {
                    "exists": True,
                    "owned_by_us": False,
                    "error": "AccessDenied",
                    "region": region,
                }
            else:
                return {
                    "exists": "unknown",
                    "owned_by_us": False,
                    "error": str(e),
                    "region": region,
                }

        except NoCredentialsError:
            # No AWS credentials - fall back to HTTP-based check
            return self._check_bucket_exists_http(bucket_name, region)

    def _check_bucket_exists_http(
        self, bucket_name: str, region: str
    ) -> Dict[str, Any]:
        """Check if a bucket exists using HTTP requests (no AWS credentials needed).

        Args:
            bucket_name: Name of the bucket to check
            region: AWS region

        Returns:
            Dictionary with bucket status information
        """
        # Try different S3 URL patterns
        urls = [
            f"https://{bucket_name}.s3.amazonaws.com/",
            f"https://{bucket_name}.s3.{region}.amazonaws.com/",
        ]

        for url in urls:
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)

                if response.status_code == 200:
                    # Bucket exists and is public
                    return {
                        "exists": True,
                        "owned_by_us": False,  # Can't determine ownership without creds
                        "error": None,
                        "region": region,
                        "is_public": True,
                        "check_method": "http",
                    }
                elif response.status_code == 403:
                    # Bucket exists but is private
                    return {
                        "exists": True,
                        "owned_by_us": False,  # Can't determine ownership without creds
                        "error": "AccessDenied (no credentials)",
                        "region": region,
                        "is_public": False,
                        "check_method": "http",
                    }
                elif response.status_code == 404:
                    # Bucket doesn't exist - VULNERABLE!
                    return {
                        "exists": False,
                        "owned_by_us": False,
                        "error": "NoSuchBucket",
                        "region": region,
                        "check_method": "http",
                    }

            except requests.exceptions.RequestException:
                continue

        # If all URLs failed, assume bucket doesn't exist
        return {
            "exists": False,
            "owned_by_us": False,
            "error": "Could not verify bucket existence",
            "region": region,
            "check_method": "http",
        }

    def analyze_route53_takeover_risks(self) -> List[Dict[str, Any]]:
        """Analyze Route53 records for subdomain takeover vulnerabilities.

        Returns:
            List of vulnerability findings
        """
        vulnerabilities = []

        # Discover Route53 records pointing to S3
        s3_records = self.discover_route53_records()

        for record in s3_records:
            self.logger.debug(
                f"Analyzing record: {record['record_name']} -> {record['s3_endpoint']}"
            )

            # Extract bucket info
            bucket_info = self.extract_bucket_info_from_endpoint(
                record["s3_endpoint"]
            )

            if bucket_info["bucket_name"]:
                # Check bucket ownership
                bucket_status = self.check_bucket_ownership_in_region(
                    bucket_info["bucket_name"],
                    bucket_info["region"] or "us-east-1",
                )

                # Determine vulnerability status
                if not bucket_status["exists"]:
                    vulnerabilities.append(
                        {
                            "source": "route53",
                            "domain": record["record_name"],
                            "zone_name": record["zone_name"],
                            "vulnerability": "subdomain_takeover",
                            "severity": "CRITICAL",
                            "s3_endpoint": record["s3_endpoint"],
                            "bucket_name": bucket_info["bucket_name"],
                            "region": bucket_info["region"],
                            "status": "VULNERABLE",
                            "risk": "DNS record points to non-existent S3 bucket. Attacker can claim this bucket.",
                            "recommendation": "Either create the bucket or update DNS records",
                            "exploit_difficulty": "Trivial",
                            "impact": "Complete control over subdomain data",
                        }
                    )

                elif not bucket_status["owned_by_us"]:
                    vulnerabilities.append(
                        {
                            "source": "route53",
                            "domain": record["record_name"],
                            "zone_name": record["zone_name"],
                            "vulnerability": "subdomain_takeover",
                            "severity": "CRITICAL",
                            "s3_endpoint": record["s3_endpoint"],
                            "bucket_name": bucket_info["bucket_name"],
                            "region": bucket_info["region"],
                            "status": "POTENTIALLY_COMPROMISED",
                            "risk": "DNS record points to S3 bucket owned by another account",
                            "recommendation": "Immediately update DNS records - subdomain may be compromised",
                            "exploit_difficulty": "Already exploited",
                            "impact": "Subdomain content controlled by unknown party",
                        }
                    )
                else:
                    self.logger.debug(
                        f"Record {record['record_name']} is safe - we own the bucket"
                    )

        return vulnerabilities

    # Legacy Subdomain Takeover Detection Methods (for manual domain checking)
    def check_cname_record(self, domain: str) -> List[str]:
        """Get CNAME records for a domain.

        Args:
            domain: Domain to check

        Returns:
            List of CNAME targets
        """
        cname_targets = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            answers = resolver.resolve(domain, "CNAME")
            for rdata in answers:
                cname_targets.append(str(rdata.target).rstrip("."))
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.exception.Timeout,
        ):
            pass
        except Exception as e:
            self.logger.debug(f"Error resolving CNAME for {domain}: {e}")

        return cname_targets

    def check_domain_for_takeover(
        self, domain: str
    ) -> Optional[Dict[str, Any]]:
        """Check if a domain is vulnerable to subdomain takeover.

        Args:
            domain: Domain to check

        Returns:
            Vulnerability details if found, None otherwise
        """
        # Get CNAME records
        cname_targets = self.check_cname_record(domain)

        for target in cname_targets:
            # Check if target points to S3
            is_s3_endpoint = any(
                pattern.search(target.lower())
                for pattern in self.S3_WEBSITE_PATTERNS
                + self.S3_LEGACY_PATTERNS
            )

            if is_s3_endpoint:
                # Extract bucket info
                bucket_info = self.extract_bucket_info_from_endpoint(target)

                if bucket_info["bucket_name"]:
                    # Check bucket status
                    bucket_status = self.check_bucket_ownership_in_region(
                        bucket_info["bucket_name"],
                        bucket_info["region"] or "us-east-1",
                    )
                    bucket_name = bucket_info["bucket_name"]

                    if not bucket_status["exists"]:
                        return {
                            "domain": domain,
                            "vulnerability": "subdomain_takeover",
                            "severity": "CRITICAL",
                            "cname_target": target,
                            "bucket_name": bucket_name,
                            "status": "VULNERABLE",
                            "risk": "Subdomain points to non-existent S3 bucket. Attacker can claim this bucket.",
                            "recommendation": "Either create the bucket or update DNS records",
                            "exploit_difficulty": "Trivial",
                            "impact": "Complete control over subdomain data",
                        }
                    elif not bucket_status["owned_by_us"]:
                        return {
                            "domain": domain,
                            "vulnerability": "subdomain_takeover",
                            "severity": "CRITICAL",
                            "cname_target": target,
                            "bucket_name": bucket_name,
                            "status": "POTENTIALLY_COMPROMISED",
                            "risk": "Subdomain points to S3 bucket owned by another account",
                            "recommendation": "Immediately update DNS records - subdomain may be compromised",
                            "exploit_difficulty": "Already exploited",
                            "impact": "Subdomain content controlled by unknown party",
                        }

        return None

    def enumerate_subdomains(
        self, domain: str, wordlist: Optional[List[str]] = None
    ) -> List[str]:
        """Attempt to discover subdomains by testing common prefixes.

        This method doesn't enumerate existing subdomains but rather tests
        a predefined wordlist of common subdomain prefixes to find resolvable ones.

        Args:
            domain: Base domain to test subdomains for
            wordlist: List of subdomain prefixes to try (defaults to common prefixes)

        Returns:
            List of resolvable subdomains found
        """
        if wordlist is None:
            # Load subdomain wordlist from external file
            try:
                subdomain_wordlist_path = Path(__file__).parent.parent / "discovery" / "subdomain_wordlist.txt"
                if subdomain_wordlist_path.exists():
                    with open(subdomain_wordlist_path, 'r') as f:
                        wordlist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        self.logger.debug(f"Loaded {len(wordlist)} subdomains from wordlist file")
                else:
                    # Fallback to builtin list if file not found
                    wordlist = [
                        "www", "app", "api", "blog", "dev", "staging", "stage", "test", "uat",
                        "prod", "production", "cdn", "assets", "static", "media", "img", "images",
                        "docs", "documentation", "help", "support", "admin", "portal", "dashboard",
                        "console", "manage", "manager", "files", "download", "downloads", "data",
                        "backup", "archive", "legacy", "old", "new", "beta", "alpha", "v1", "v2",
                        "mobile", "m", "mail", "email", "ftp", "sftp", "vpn", "remote", "secure",
                        "partner", "partners", "vendor", "vendors", "client", "clients", "customer",
                        "customers", "user", "users", "member", "members", "demo", "sandbox",
                        "training", "learn", "education", "academy"
                    ]
            except Exception as e:
                self.logger.warning(f"Failed to load subdomain wordlist: {e}, using builtin")
                wordlist = ["www", "api", "app", "dev", "staging", "test", "prod", "admin", "portal"]

        discovered_subdomains = []

        for prefix in wordlist:
            subdomain = f"{prefix}.{domain}"
            try:
                # Use socket with timeout instead of signal-based timeout
                # This is thread-safe and cross-platform compatible
                original_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(3.0)  # 3 second timeout
                try:
                    socket.gethostbyname(subdomain)
                    discovered_subdomains.append(subdomain)
                    self.logger.debug(f"Found subdomain: {subdomain}")
                finally:
                    socket.setdefaulttimeout(original_timeout)
            except socket.gaierror:
                # Subdomain doesn't exist
                pass
            except socket.timeout:
                # DNS resolution timeout
                self.logger.debug(f"DNS timeout for {subdomain}")
                pass
            except Exception as e:
                self.logger.debug(f"Error checking {subdomain}: {e}")

        return discovered_subdomains

    def scan_domain_for_takeover(
        self,
        domain: str,
        check_subdomains: bool = True,
        subdomain_wordlist: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Scan a domain and its subdomains for S3 subdomain takeover vulnerabilities.

        Args:
            domain: Domain to scan
            check_subdomains: Whether to enumerate and check subdomains
            subdomain_wordlist: Custom wordlist for subdomain enumeration

        Returns:
            List of vulnerability findings
        """
        vulnerabilities = []
        domains_to_check = [domain]

        # Enumerate subdomains if requested
        if check_subdomains:
            self.logger.info(f"Enumerating subdomains for {domain}...")
            subdomains = self.enumerate_subdomains(domain, subdomain_wordlist)
            domains_to_check.extend(subdomains)
            self.logger.info(f"Found {len(subdomains)} subdomains")

        # Check each domain
        for check_domain in domains_to_check:
            self.logger.debug(
                f"Checking {check_domain} for subdomain takeover..."
            )

            vulnerability = self.check_domain_for_takeover(check_domain)
            if vulnerability:
                vulnerabilities.append(vulnerability)
                self.logger.warning(
                    f"VULNERABILITY FOUND: {check_domain} is vulnerable to subdomain takeover!"
                )

        return vulnerabilities

    def _get_s3_website_endpoint(self, bucket_name: str, region: str) -> str:
        """Get the correct S3 website endpoint format for a given region."""
        # Special cases for specific regions
        if region == "us-east-1":
            return f"{bucket_name}.s3-website-us-east-1.amazonaws.com"
        elif region.startswith("us-") or region.startswith("ca-"):
            return f"{bucket_name}.s3-website-{region}.amazonaws.com"
        else:
            # For most other regions, use the dot format
            return f"{bucket_name}.s3-website.{region}.amazonaws.com"

    def check_bucket_website_config(self, bucket_name: str) -> Dict[str, Any]:
        """Check if a bucket has website hosting enabled and get its configuration.

        Args:
            bucket_name: Name of the bucket

        Returns:
            Website configuration details
        """
        try:
            response = self.s3_client.get_bucket_website(Bucket=bucket_name)
            return {
                "website_enabled": True,
                "index_document": response.get("IndexDocument", {}).get(
                    "Suffix"
                ),
                "error_document": response.get("ErrorDocument", {}).get("Key"),
                "endpoint": self._get_s3_website_endpoint(
                    bucket_name, self.s3_client.meta.region_name
                ),
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchWebsiteConfiguration":
                return {"website_enabled": False, "endpoint": None}
            else:
                return {"website_enabled": "unknown", "error": str(e)}

    def scan_subdomain_takeover(
        self,
        domains: Optional[List[str]] = None,
        check_subdomains: bool = True,
        subdomain_wordlist: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Scan for S3 subdomain takeover vulnerabilities.

        This method performs two types of scans:
        1. Route53 Discovery: Automatically finds DNS records pointing to S3 in your account
        2. Manual Domain Scan: Checks specific domains provided via --check-domain

        Args:
            domains: List of domains to scan manually (optional)
            check_subdomains: Whether to enumerate and check subdomains for manual domains
            subdomain_wordlist: Custom wordlist for subdomain enumeration

        Returns:
            Dictionary containing scan results
        """
        all_vulnerabilities = []
        route53_vulnerabilities = []
        manual_vulnerabilities = []
        cname_vulnerabilities = []

        # Temporarily disable console logging to avoid mixing with progress output
        logger = logging.getLogger("s3_security_scanner")
        original_level = logger.level
        console_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]
        for handler in console_handlers:
            handler.setLevel(logging.CRITICAL + 1)  # Effectively disable

        try:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=self.console,
            ) as progress:

                # Step 1: Route53 Auto-Discovery
                route53_task = progress.add_task(
                    "[cyan]Scanning Route53 hosted zones...", total=1
                )

                try:
                    # Get Route53 records for both takeover and CNAME analysis
                    route53_records = self.discover_route53_records()

                    # Analyze for subdomain takeover
                    route53_vulnerabilities = self.analyze_route53_takeover_risks()

                    # Analyze for CNAME information disclosure
                    dns_analyzer = DNSAnalyzer(self.logger)
                    cname_vulnerabilities = (
                        dns_analyzer.analyze_cname_information_disclosure(
                            route53_records
                        )
                    )

                    if route53_vulnerabilities:
                        all_vulnerabilities.extend(route53_vulnerabilities)

                    if cname_vulnerabilities:
                        all_vulnerabilities.extend(cname_vulnerabilities)

                    progress.update(
                        route53_task,
                        advance=1,
                        description="[green]Route53 scan completed",
                    )

                except Exception as e:
                    progress.update(
                        route53_task,
                        advance=1,
                        description=f"[yellow]Route53 scan failed: {e}",
                    )

                # Step 2: Manual Domain Scanning (if domains provided)
                if domains:
                    manual_task = progress.add_task(
                        f"[cyan]Scanning {len(domains)} manual domains...",
                        total=len(domains),
                    )

                    for domain in domains:
                        progress.update(
                            manual_task,
                            description=f"[cyan]Scanning {domain}...",
                        )

                        try:
                            vulnerabilities = self.scan_domain_for_takeover(
                                domain,
                                check_subdomains=check_subdomains,
                                subdomain_wordlist=subdomain_wordlist,
                            )

                            # Mark these as manual discoveries
                            for vuln in vulnerabilities:
                                vuln["source"] = "manual"

                            if vulnerabilities:
                                manual_vulnerabilities.extend(vulnerabilities)
                                all_vulnerabilities.extend(vulnerabilities)

                        except Exception as e:
                            self.logger.debug(f"Error scanning domain {domain}: {e}")

                        progress.update(manual_task, advance=1)

                    progress.update(
                        manual_task,
                        description="[green]Manual domain scan completed",
                    )

        finally:
            # Re-enable console logging
            for handler in console_handlers:
                handler.setLevel(logging.INFO)

        # Generate comprehensive summary
        summary = {
            "scan_type": "dns_takeover",
            "route53_vulnerabilities_found": len(route53_vulnerabilities),
            "manual_vulnerabilities_found": len(manual_vulnerabilities),
            "cname_vulnerabilities_found": len(cname_vulnerabilities),
            "total_vulnerabilities_found": len(all_vulnerabilities),
            "manual_domains_scanned": len(domains) if domains else 0,
            "vulnerabilities": all_vulnerabilities,
            "critical_count": sum(
                1
                for v in all_vulnerabilities
                if v.get("severity") == "CRITICAL"
            ),
            "high_count": sum(
                1 for v in all_vulnerabilities if v.get("severity") == "HIGH"
            ),
            "medium_count": sum(
                1 for v in all_vulnerabilities if v.get("severity") == "MEDIUM"
            ),
            "low_count": sum(
                1 for v in all_vulnerabilities if v.get("severity") == "LOW"
            ),
            "scan_time": datetime.now().isoformat(),
            "region": self.region,
        }

        # Print summary
        self._print_dns_takeover_summary(summary)

        return summary

    def _print_dns_takeover_summary(self, summary: Dict[str, Any]):
        """Print DNS takeover scan summary."""
        table = Table(title="DNS Takeover Vulnerability Scan Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row(
            "Route53 Vulnerabilities",
            str(summary["route53_vulnerabilities_found"]),
        )
        table.add_row(
            "Manual Domain Vulnerabilities",
            str(summary["manual_vulnerabilities_found"]),
        )
        table.add_row(
            "CNAME Information Disclosure",
            str(summary["cname_vulnerabilities_found"]),
        )
        table.add_row(
            "Total Vulnerabilities",
            f"[red]{summary['total_vulnerabilities_found']}[/red]",
        )
        table.add_row(
            "Critical Issues", f"[red]{summary['critical_count']}[/red]"
        )
        table.add_row(
            "High Severity Issues", f"[red]{summary['high_count']}[/red]"
        )
        table.add_row(
            "Medium Severity Issues",
            f"[yellow]{summary['medium_count']}[/yellow]",
        )
        table.add_row(
            "Low Severity Issues", f"[green]{summary['low_count']}[/green]"
        )

        self.console.print(table)

        # Show vulnerability details
        if summary["vulnerabilities"]:
            vuln_table = Table(title="DNS Takeover Vulnerabilities")
            vuln_table.add_column("Source", style="blue")
            vuln_table.add_column("Domain", style="cyan")
            vuln_table.add_column("Bucket Name", style="yellow")
            vuln_table.add_column("Region", style="green")
            vuln_table.add_column("Severity", style="red")
            vuln_table.add_column("Risk", style="white")

            for vuln in summary["vulnerabilities"]:
                severity = vuln.get("severity", "UNKNOWN")
                risk_text = vuln.get(
                    "risk", vuln.get("disclosed_information", ["Unknown risk"])
                )

                # Format risk text (truncate if too long)
                if isinstance(risk_text, list):
                    risk_display = "; ".join(risk_text)
                else:
                    risk_display = str(risk_text)

                risk_display = (
                    risk_display[:50] + "..."
                    if len(risk_display) > 50
                    else risk_display
                )

                # Color code severity
                if severity == "CRITICAL":
                    severity_display = f"[red]{severity}[/red]"
                elif severity == "HIGH":
                    severity_display = f"[red]{severity}[/red]"
                elif severity == "MEDIUM":
                    severity_display = f"[yellow]{severity}[/yellow]"
                elif severity == "LOW":
                    severity_display = f"[green]{severity}[/green]"
                else:
                    severity_display = severity

                vuln_table.add_row(
                    vuln.get("source", "unknown").upper(),
                    vuln.get("domain", "N/A"),
                    vuln.get("bucket_name", "N/A"),
                    vuln.get("region", "N/A"),
                    severity_display,
                    risk_display,
                )

            self.console.print(vuln_table)
