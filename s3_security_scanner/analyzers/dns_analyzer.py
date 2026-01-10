"""DNS-specific analysis for S3 security scanning."""

from typing import Dict, List, Any
from .pattern_analyzer import PatternAnalyzer


class DNSAnalyzer:
    """Analyzes DNS-related security aspects for S3 buckets."""

    def __init__(self, logger):
        """Initialize DNS analyzer.

        Args:
            logger: Logger instance
        """
        self.logger = logger
        self.pattern_analyzer = PatternAnalyzer()

    def analyze_cname_information_disclosure(
        self, route53_records: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Analyze CNAME records for information disclosure vulnerabilities.

        Args:
            route53_records: List of Route53 records pointing to S3 endpoints

        Returns:
            List of CNAME vulnerability findings
        """
        vulnerabilities = []

        for record in route53_records:
            # Only analyze CNAME records (not ALIAS records)
            if record["record_type"] != "CNAME":
                continue

            # Extract bucket information from the S3 endpoint
            bucket_info = self._extract_bucket_info_from_endpoint(
                record["s3_endpoint"]
            )
            if not bucket_info["bucket_name"]:
                continue

            bucket_name = bucket_info["bucket_name"]

            # Analyze bucket naming patterns
            patterns = self.pattern_analyzer.extract_bucket_naming_patterns(
                bucket_name
            )

            # Assess information disclosure risk
            risk_assessment = (
                self.pattern_analyzer.assess_information_disclosure_risk(
                    bucket_name, patterns
                )
            )

            # Check for bucket enumeration risks
            enumeration_risks = (
                self.pattern_analyzer.check_bucket_enumeration_risk(
                    bucket_name, patterns
                )
            )

            # Create vulnerability record if risk is found
            if risk_assessment["risk_level"] != "NONE":
                vulnerability = {
                    "source": "cname_analysis",
                    "domain": record["record_name"],
                    "zone_name": record["zone_name"],
                    "vulnerability": "information_disclosure",
                    "severity": risk_assessment["severity"],
                    "s3_endpoint": record["s3_endpoint"],
                    "bucket_name": bucket_name,
                    "region": bucket_info["region"],
                    "disclosed_information": risk_assessment["disclosed_info"],
                    "enumeration_risks": enumeration_risks,
                    "risk_level": risk_assessment["risk_level"],
                    "recommendation": risk_assessment["recommendation"],
                    "patterns_found": patterns,
                }
                vulnerabilities.append(vulnerability)

        return vulnerabilities

    def _extract_bucket_info_from_endpoint(
        self, endpoint: str
    ) -> Dict[str, str]:
        """Extract bucket information from S3 endpoint.

        Args:
            endpoint: S3 endpoint URL

        Returns:
            Dictionary with bucket information
        """
        # Use shared utility function to avoid circular imports
        from ..bucket_utils import extract_bucket_info_from_endpoint

        return extract_bucket_info_from_endpoint(endpoint)
