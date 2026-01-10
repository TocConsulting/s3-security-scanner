#!/usr/bin/env python3
"""S3 Security Scanner with multi-threading, compliance mapping,
and object-level checks."""

import csv
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List, Optional, Any

import boto3
from botocore.exceptions import NoCredentialsError
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .compliance import ComplianceChecker
from .html_reporter import HTMLReporter
from .utils import setup_logging, calculate_security_score

from .checks.access_control import AccessControlChecker
from .checks.encryption import EncryptionChecker
from .checks.logging_monitoring import LoggingMonitoringChecker
from .checks.versioning_lifecycle import VersioningLifecycleChecker
from .checks.object_security import ObjectSecurityChecker
from .checks.dns_security import DNSSecurityChecker
from .checks.soc2_monitoring import SOC2MonitoringChecker
from .checks.iso_compliance import ISOComplianceChecker
from .checks.gdpr_compliance import GDPRComplianceChecker
from .checks.cloudtrail_logging import CloudTrailDataEventsChecker
from .checks.account_security import AccountSecurityChecker
from .checks.threat_detection import ThreatDetectionChecker


class S3SecurityScanner:
    """S3 Security Scanner driving all security checks."""

    def __init__(
        self,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        output_dir: str = "./output",
        max_workers: int = 10,
    ):
        """Initialize the S3 Security Scanner.

        Args:
            region: AWS region for API calls (default: us-east-1)
            profile: AWS profile name to use (default: None)
            output_dir: Directory for reports and logs (default: ./output)
            max_workers: Maximum parallel threads for scanning (default: 10)
        """
        self.region = region
        self.profile = profile
        self.output_dir = output_dir
        self.max_workers = max_workers
        self.console = Console()
        self.skip_object_scan = False  # Configuration flag for object scanning
        self._regional_clients = {}  # Cache for regional clients

        os.makedirs(output_dir, exist_ok=True)
        self.logger = setup_logging(output_dir)

        # Setup AWS session configuration
        try:
            # Store config instead of session for thread-local usage
            self.aws_profile = profile
            self.aws_region = region
            self._thread_local = threading.local()
            
            # Initialize clients for main thread
            session = self._get_thread_session()
            self.s3_client = session.client("s3")
            self.route53_client = session.client("route53")
            self.account_id = self._get_account_id()
        except NoCredentialsError:
            self.logger.error(
                "No AWS credentials found. Please configure your credentials."
            )
            raise

        # Initialize compliance checker and HTML reporter
        self.compliance_checker = ComplianceChecker()
        self.html_reporter = HTMLReporter()

        # Initialize modular checkers with session factory for thread safety
        self.access_control_checker = AccessControlChecker(self._get_thread_session)
        self.encryption_checker = EncryptionChecker(self._get_thread_session)
        self.logging_monitoring_checker = LoggingMonitoringChecker(
            self._get_thread_session
        )
        self.versioning_lifecycle_checker = VersioningLifecycleChecker(
            self._get_thread_session
        )
        self.object_security_checker = ObjectSecurityChecker(self._get_thread_session)
        self.dns_security_checker = DNSSecurityChecker(
            self._get_thread_session,
            self.s3_client,
            self.route53_client,
            self.region,
            self.logger,
        )
        self.soc2_monitoring_checker = SOC2MonitoringChecker(
            self._get_thread_session, self.region
        )
        self.iso_compliance_checker = ISOComplianceChecker(self._get_thread_session)
        self.gdpr_compliance_checker = GDPRComplianceChecker(self._get_thread_session)
        self.cloudtrail_checker = CloudTrailDataEventsChecker(self._get_thread_session)
        self.account_security_checker = AccountSecurityChecker(self._get_thread_session)
        self.threat_detection_checker = ThreatDetectionChecker(self._get_thread_session)

    def _get_account_id(self) -> str:
        """Get the AWS account ID."""
        try:
            session = self._get_thread_session()
            sts_client = session.client("sts")
            return sts_client.get_caller_identity()["Account"]
        except Exception as e:
            self.logger.debug(f"Could not determine AWS account ID: {e}")
            return "unknown"

    def _get_thread_session(self):
        """Get or create a session for the current thread."""
        if not hasattr(self._thread_local, 'session'):
            self._thread_local.session = (
                boto3.Session(profile_name=self.aws_profile, region_name=self.aws_region)
                if self.aws_profile
                else boto3.Session(region_name=self.aws_region)
            )
        return self._thread_local.session

    def _create_regional_client(self, region: str):
        """Create a region-specific S3 client for optimal performance.

        Uses caching to avoid creating multiple clients for the same region.

        Args:
            region: AWS region for the client

        Returns:
            Configured S3 client for the specified region
        """
        if region not in self._regional_clients:
            session = self._get_thread_session()
            self._regional_clients[region] = session.client(
                "s3", region_name=region
            )
        return self._regional_clients[region]

    def get_all_buckets(self) -> List[Dict[str, Any]]:
        """Retrieve all S3 buckets accessible to the current AWS account.

        Returns:
            List of bucket dictionaries with name and creation date.
        """
        try:
            response = self.s3_client.list_buckets()
            buckets = response.get("Buckets", [])
            self.logger.info(
                f"Found {len(buckets)} S3 buckets in account {self.account_id}"
            )
            return buckets
        except Exception as e:
            self.logger.error(f"Error retrieving S3 buckets: {e}")
            return []

    def get_bucket_region(self, bucket_name: str) -> Optional[str]:
        """Determine the AWS region where a bucket is located.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            AWS region name, or 'us-east-1' if LocationConstraint is None.
            Returns None if bucket doesn't exist.
        """
        try:
            location = self.s3_client.get_bucket_location(Bucket=bucket_name)
            region = location.get("LocationConstraint")
            # AWS API returns None for us-east-1 for buckets created without explicitly specifying a region (legacy behavior)
            return "us-east-1" if region is None else region
        except self.s3_client.exceptions.NoSuchBucket:
            self.logger.error(f"Bucket {bucket_name} does not exist")
            return None
        except Exception as e:
            self.logger.error(
                f"Error getting region for bucket {bucket_name}: {e}"
            )
            # Return a default region for other errors to prevent downstream issues
            return self.region or "us-east-1"

    def check_public_access_block(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if public access block is enabled for a bucket."""
        return self.access_control_checker.check_public_access_block(
            bucket_name, client
        )

    def check_bucket_policy(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check if bucket policy has any public access."""
        return self.access_control_checker.check_bucket_policy(
            bucket_name, client
        )

    def check_bucket_acl(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check if bucket ACL has any public access grants."""
        return self.access_control_checker.check_bucket_acl(
            bucket_name, client
        )

    def check_encryption(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check if default encryption is enabled for the bucket."""
        return self.encryption_checker.check_encryption(bucket_name, client)

    def check_versioning(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check if versioning is enabled for the bucket."""
        return self.versioning_lifecycle_checker.check_versioning(
            bucket_name, client
        )

    def check_logging(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check if logging is enabled for the bucket."""
        return self.logging_monitoring_checker.check_logging(
            bucket_name, client
        )

    def check_lifecycle_rules(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if lifecycle rules are configured for the bucket."""
        return self.versioning_lifecycle_checker.check_lifecycle_rules(
            bucket_name, client
        )

    def check_object_lock(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check object lock configuration."""
        return self.versioning_lifecycle_checker.check_object_lock(
            bucket_name, client
        )

    def check_cors(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check for overly permissive CORS configuration."""
        return self.object_security_checker.check_cors(bucket_name, client)

    def check_object_level_security(
        self, bucket_name: str, client, sample_size: int = 100
    ) -> Dict[str, Any]:
        """Check object-level security by sampling objects."""
        if self.skip_object_scan:
            return {
                "total_objects_scanned": 0,
                "public_objects": [],
                "public_object_count": 0,
                "sensitive_objects": [],
                "sensitive_object_count": 0,
                "skipped": True,
            }
        return self.object_security_checker.check_object_level_security(
            bucket_name, client, sample_size
        )

    def check_wildcard_principal(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if bucket policy allows wildcard (*) principal access."""
        return self.access_control_checker.check_wildcard_principal(
            bucket_name, client
        )

    def check_event_notifications(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if bucket has event notifications configured."""
        return self.access_control_checker.check_event_notifications(
            bucket_name, client
        )

    def check_replication(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check if bucket has replication configured."""
        return self.access_control_checker.check_replication(
            bucket_name, client
        )

    def check_transfer_acceleration(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if S3 Transfer Acceleration is enabled."""
        return self.access_control_checker.check_transfer_acceleration(
            bucket_name, client
        )

    def check_cross_account_access(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if bucket policy allows cross-account access."""
        return self.access_control_checker.check_cross_account_access(
            bucket_name, client
        )

    def check_mfa_requirement(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if bucket policy requires MFA for access."""
        return self.access_control_checker.check_mfa_requirement(
            bucket_name, client
        )

    def check_data_classification_tagging(
        self, bucket_name: str, client, sample_size: int = 50
    ) -> Dict[str, Any]:
        """Data classification analysis using object tagging."""
        return self.object_security_checker.check_data_classification_tagging(
            bucket_name, client, sample_size
        )

    def check_kms_key_management(
        self,
        bucket_name: str,
        client,
        encryption_config: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Check KMS key management for bucket encryption."""
        return self.soc2_monitoring_checker.check_kms_key_management(
            bucket_name, client, encryption_config
        )

    def check_cloudwatch_monitoring(
        self, bucket_name: str, bucket_region: str
    ) -> Dict[str, Any]:
        """Check CloudWatch monitoring configuration."""
        return self.soc2_monitoring_checker.check_cloudwatch_monitoring(
            bucket_name, bucket_region
        )

    def check_storage_lens_configuration(self) -> Dict[str, Any]:
        """Check S3 Storage Lens configuration."""
        return self.soc2_monitoring_checker.check_storage_lens_configuration(
            self.account_id
        )

    def scan_bucket(
        self,
        bucket: Dict[str, Any],
        progress: Optional[Progress] = None,
        task_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Perform a comprehensive security scan of a bucket."""
        bucket_name = bucket.get("Name")
        self.logger.info(f"Scanning bucket: {bucket_name}")

        # Get bucket region and create regional client
        bucket_region = self.get_bucket_region(bucket_name)
        if not bucket_region:
            return self._error_result(
                bucket,
                f"Bucket '{bucket_name}' does not exist or is not accessible",
            )

        client = self._create_regional_client(bucket_region)

        checks = {
            "public_access_block": self.check_public_access_block(
                bucket_name, client
            ),
            "bucket_policy": self.check_bucket_policy(bucket_name, client),
            "bucket_acl": self.check_bucket_acl(bucket_name, client),
            "encryption": self.check_encryption(bucket_name, client),
            "versioning": self.check_versioning(bucket_name, client),
            "logging": self.check_logging(bucket_name, client),
            "lifecycle_rules": self.check_lifecycle_rules(bucket_name, client),
            "object_lock": self.check_object_lock(bucket_name, client),
            "cors": self.check_cors(bucket_name, client),
            "object_level_security": self.check_object_level_security(
                bucket_name, client
            ),
            "wildcard_principal": self.check_wildcard_principal(
                bucket_name, client
            ),
            "event_notifications": self.check_event_notifications(
                bucket_name, client
            ),
            "replication": self.check_replication(bucket_name, client),
            # SOC 2 checks
            "transfer_acceleration": self.check_transfer_acceleration(
                bucket_name, client
            ),
            "cross_account_access": self.check_cross_account_access(
                bucket_name, client
            ),
            "mfa_requirement": self.check_mfa_requirement(bucket_name, client),
            "data_classification": self.check_data_classification_tagging(
                bucket_name, client
            ),
            "cloudwatch_monitoring": self.check_cloudwatch_monitoring(
                bucket_name, bucket_region
            ),
        }

        # Add KMS management check (pass encryption config to avoid duplicate API calls)
        checks["kms_key_management"] = self.check_kms_key_management(
            bucket_name, client, checks["encryption"]
        )

        # ISO compliance checks
        # ISO 27001 Controls
        checks["iso27001_access_control"] = (
            self.access_control_checker.check_iso27001_access_control(
                bucket_name, client
            )
        )
        checks["iso27001_access_rights"] = (
            self.iso_compliance_checker.check_iso27001_access_rights(checks)
        )
        checks["iso27001_cloud_service_security"] = (
            self.iso_compliance_checker.check_iso27001_cloud_service_security(
                checks
            )
        )
        checks["iso27001_cryptography"] = (
            self.iso_compliance_checker.check_iso27001_cryptography(
                bucket_name, client
            )
        )
        checks["iso27001_backup"] = (
            self.iso_compliance_checker.check_iso27001_backup(checks)
        )
        checks["iso27001_logging"] = (
            self.iso_compliance_checker.check_iso27001_logging(checks)
        )
        checks["iso27001_info_transfer"] = (
            self.iso_compliance_checker.check_iso27001_info_transfer(checks)
        )

        # ISO 27017 Controls
        checks["iso27017_access_restriction"] = (
            self.iso_compliance_checker.check_iso27017_access_restriction(
                checks
            )
        )
        checks["iso27017_shared_responsibility"] = (
            self.iso_compliance_checker.check_iso27017_shared_responsibility(
                checks
            )
        )
        checks["iso27017_data_location"] = (
            self.iso_compliance_checker.check_iso27017_data_location(
                bucket_name, client
            )
        )
        checks["iso27017_monitoring"] = (
            self.iso_compliance_checker.check_iso27017_monitoring(checks)
        )
        checks["iso27017_cloud_logging"] = (
            self.iso_compliance_checker.check_iso27017_cloud_logging(checks)
        )
        checks["iso27017_data_deletion"] = (
            self.iso_compliance_checker.check_iso27017_data_deletion(checks)
        )
        checks["iso27017_data_isolation"] = (
            self.iso_compliance_checker.check_iso27017_data_isolation(checks)
        )

        # ISO 27018 Controls
        checks["iso27018_purpose_limitation"] = (
            self.iso_compliance_checker.check_iso27018_purpose_limitation(
                bucket_name, client
            )
        )
        checks["iso27018_data_minimization"] = (
            self.iso_compliance_checker.check_iso27018_data_minimization(
                checks
            )
        )
        checks["iso27018_retention_deletion"] = (
            self.iso_compliance_checker.check_iso27018_retention_deletion(
                checks
            )
        )
        checks["iso27018_accountability"] = (
            self.iso_compliance_checker.check_iso27018_accountability(checks)
        )

        # GDPR compliance checks
        gdpr_checks = (
            self.gdpr_compliance_checker.check_gdpr_compliance_features(
                bucket_name, bucket_region
            )
        )
        checks.update(gdpr_checks)

        # AWS FSBP additional checks
        checks["access_points"] = (
            self.access_control_checker.check_access_points(
                bucket_name, client
            )
        )
        checks["multi_region_access_points"] = (
            self.access_control_checker.check_multi_region_access_points(
                bucket_name, client
            )
        )

        # CloudTrail data events compliance checks
        checks["cloudtrail_s3_22"] = (
            self.cloudtrail_checker.check_cis_s3_22_compliance(
                bucket_name, bucket_region
            )
        )
        checks["cloudtrail_s3_23"] = (
            self.cloudtrail_checker.check_cis_s3_23_compliance(
                bucket_name, bucket_region
            )
        )

        # New Prowler-aligned checks
        checks["shadow_resource_vulnerability"] = (
            self.access_control_checker.check_shadow_resource_vulnerability(
                bucket_name, self.account_id, bucket_region
            )
        )
        checks["cloudtrail_bucket_logging"] = (
            self.logging_monitoring_checker.check_cloudtrail_bucket_logging(
                bucket_name, client
            )
        )

        # A bucket is truly public only if:
        # 1. It has a public bucket policy, OR
        # 2. It has a public bucket ACL, OR
        # 3. It has public objects (and PAB doesn't block them)
        # Note: Having PAB disabled alone does NOT make a bucket public
        has_public_policy = checks["bucket_policy"].get("is_public", False)
        has_public_acl = checks["bucket_acl"].get("has_public_access", False)
        has_public_objects = (
            checks.get("object_level_security", {}).get("public_object_count", 0) > 0
        )
        pab_blocks_public = checks["public_access_block"]["is_properly_configured"]

        # Bucket is public if it has public policy/ACL/objects AND PAB doesn't block
        is_public = (
            (has_public_policy and not pab_blocks_public)
            or (has_public_acl and not pab_blocks_public)
            or (has_public_objects and not pab_blocks_public)
        )

        # Add is_public to checks so compliance checker can use it
        checks["is_public"] = is_public

        # Analyze security issues
        issues = self._analyze_issues(checks, is_public)

        # Calculate security score
        security_score = calculate_security_score(checks)

        # Check compliance
        compliance_status = self.compliance_checker.check_bucket_compliance(
            checks
        )

        # Prepare result
        result = {
            "bucket_name": bucket_name,
            "region": bucket_region,
            "creation_date": bucket.get("CreationDate"),
            **checks,
            "is_public": is_public,
            "issues": issues,
            "issue_count": len(issues),
            "has_high_severity": any(
                issue["severity"] == "HIGH" for issue in issues
            ),
            "has_medium_severity": any(
                issue["severity"] == "MEDIUM" for issue in issues
            ),
            "security_score": security_score,
            "compliance_status": compliance_status,
        }

        if progress and task_id is not None:
            progress.update(task_id, advance=1)

        return result

    def _analyze_issues(
        self, checks: Dict[str, Any], is_public: bool
    ) -> List[Dict[str, Any]]:
        """Analyze security checks and generate issues list."""
        issues = []

        # Public access issues
        if is_public:
            issues.append(
                {
                    "severity": "HIGH",
                    "issue_type": "public_access",
                    "description": "Bucket may be publicly accessible",
                    "recommendation": (
                        "Enable bucket public access block settings and "
                        "review bucket policy and ACLs"
                    ),
                }
            )

        # SSL enforcement
        if not checks["bucket_policy"].get("ssl_enforced", False):
            issues.append(
                {
                    "severity": "MEDIUM",
                    "issue_type": "ssl_not_enforced",
                    "description": "SSL/TLS not enforced for bucket access",
                    "recommendation": (
                        "Add bucket policy to deny non-SSL requests"
                    ),
                }
            )

        # Encryption
        if not checks["encryption"].get("is_enabled", False):
            issues.append(
                {
                    "severity": "MEDIUM",
                    "issue_type": "missing_encryption",
                    "description": "Default encryption not enabled",
                    "recommendation": (
                        "Enable default encryption with SSE-S3 or SSE-KMS"
                    ),
                }
            )

        # MFA Delete
        if not checks["versioning"].get("mfa_delete_enabled", False):
            issues.append(
                {
                    "severity": "LOW",
                    "issue_type": "mfa_delete_disabled",
                    "description": "MFA delete not enabled",
                    "recommendation": (
                        "Enable MFA delete for additional protection "
                        "against accidental deletion"
                    ),
                }
            )

        # Versioning
        if not checks["versioning"].get("is_enabled", False):
            issues.append(
                {
                    "severity": "LOW",
                    "issue_type": "missing_versioning",
                    "description": "Bucket versioning not enabled",
                    "recommendation": (
                        "Enable versioning to protect against accidental "
                        "deletion and ransomware"
                    ),
                }
            )

        # Logging
        if not checks["logging"].get("is_enabled", False):
            issues.append(
                {
                    "severity": "LOW",
                    "issue_type": "missing_logging",
                    "description": "Server access logging not enabled",
                    "recommendation": (
                        "Enable server access logging to track access to "
                        "bucket objects"
                    ),
                }
            )

        # Object Lock
        if not checks["object_lock"].get("is_enabled", False):
            issues.append(
                {
                    "severity": "INFO",
                    "issue_type": "object_lock_disabled",
                    "description": "Object lock not configured",
                    "recommendation": (
                        "Consider enabling object lock for compliance "
                        "requirements"
                    ),
                }
            )

        # CORS
        if checks["cors"].get("is_risky", False):
            issues.append(
                {
                    "severity": "MEDIUM",
                    "issue_type": "risky_cors",
                    "description": "Overly permissive CORS configuration",
                    "recommendation": (
                        "Review and restrict CORS allowed origins"
                    ),
                }
            )

        # Object-level issues
        obj_security = checks.get("object_level_security", {})
        if obj_security.get("public_object_count", 0) > 0:
            issues.append(
                {
                    "severity": "HIGH",
                    "issue_type": "public_objects",
                    "description": (
                        f"Found {obj_security['public_object_count']} "
                        "publicly accessible objects"
                    ),
                    "recommendation": "Review and restrict object ACLs",
                }
            )

        if obj_security.get("sensitive_object_count", 0) > 0:
            issues.append(
                {
                    "severity": "HIGH",
                    "issue_type": "sensitive_data",
                    "description": (
                        f"Found {obj_security['sensitive_object_count']} "
                        "potentially sensitive objects"
                    ),
                    "recommendation": (
                        "Review object names and consider encryption or "
                        "access restrictions"
                    ),
                }
            )

        # Lifecycle rules
        if not checks["lifecycle_rules"].get("has_lifecycle_rules", False):
            issues.append(
                {
                    "severity": "INFO",
                    "issue_type": "missing_lifecycle_rules",
                    "description": "No lifecycle rules configured",
                    "recommendation": (
                        "Consider setting up lifecycle rules for cost "
                        "optimization and data management"
                    ),
                }
            )

        # Wildcard principal in bucket policy (CIS S3.2)
        if checks["wildcard_principal"].get("has_wildcard_principal", False):
            issues.append(
                {
                    "severity": "HIGH",
                    "issue_type": "wildcard_principal",
                    "description": "Bucket policy allows wildcard (*) principal access",
                    "recommendation": (
                        "Review and restrict bucket policy to specific principals only"
                    ),
                }
            )

        # Event notifications (CIS S3.11)
        if not checks["event_notifications"].get("has_notifications", False):
            issues.append(
                {
                    "severity": "LOW",
                    "issue_type": "missing_event_notifications",
                    "description": "No event notifications configured",
                    "recommendation": (
                        "Consider enabling event notifications for security monitoring"
                    ),
                }
            )

        # Replication (CIS S3.13)
        if not checks["replication"].get("has_replication", False):
            issues.append(
                {
                    "severity": "MEDIUM",
                    "issue_type": "missing_replication",
                    "description": "No cross-region replication configured",
                    "recommendation": (
                        "Consider enabling replication for disaster recovery and compliance"
                    ),
                }
            )

        # SOC 2 checks
        # Transfer Acceleration
        if not checks["transfer_acceleration"].get("is_enabled", False):
            issues.append(
                {
                    "severity": "LOW",
                    "issue_type": "transfer_acceleration_disabled",
                    "description": "S3 Transfer Acceleration not enabled",
                    "recommendation": (
                        "Consider enabling Transfer Acceleration for improved performance"
                    ),
                }
            )

        # Cross-account access
        if checks["cross_account_access"].get(
            "has_cross_account_access", False
        ):
            issues.append(
                {
                    "severity": "MEDIUM",
                    "issue_type": "cross_account_access",
                    "description": "Bucket policy allows cross-account access",
                    "recommendation": (
                        "Review cross-account access permissions and ensure they are necessary"
                    ),
                }
            )

        # MFA requirement
        if not checks["mfa_requirement"].get("mfa_required", False):
            issues.append(
                {
                    "severity": "MEDIUM",
                    "issue_type": "mfa_not_required",
                    "description": "Bucket policy does not require MFA for sensitive operations",
                    "recommendation": (
                        "Consider requiring MFA for bucket access in security-sensitive environments"
                    ),
                }
            )

        # Data classification
        data_classification = checks["data_classification"]
        if not data_classification.get("has_proper_classification", False):
            issues.append(
                {
                    "severity": "LOW",
                    "issue_type": "poor_data_classification",
                    "description": f"Data classification coverage: {data_classification.get('classification_coverage_percent', 0)}%",
                    "recommendation": (
                        "Improve data classification tagging for better governance and compliance"
                    ),
                }
            )

        # KMS key management
        kms_analysis = checks["kms_key_management"]
        if kms_analysis.get("kms_managed", False):
            if kms_analysis.get("rotation_compliance_percent", 0) < 100:
                issues.append(
                    {
                        "severity": "MEDIUM",
                        "issue_type": "kms_rotation_disabled",
                        "description": "Some KMS keys do not have automatic rotation enabled",
                        "recommendation": (
                            "Enable automatic key rotation for all customer-managed KMS keys"
                        ),
                    }
                )

        # CloudWatch monitoring
        monitoring = checks["cloudwatch_monitoring"]
        if not monitoring.get("monitoring_enabled", False):
            issues.append(
                {
                    "severity": "LOW",
                    "issue_type": "cloudwatch_monitoring_disabled",
                    "description": "CloudWatch monitoring not properly configured",
                    "recommendation": (
                        "Enable CloudWatch metrics and alarms for proactive monitoring"
                    ),
                }
            )
        elif (
            monitoring.get("monitoring_compliance", {}).get(
                "monitoring_score", 0
            )
            < 70
        ):
            issues.append(
                {
                    "severity": "LOW",
                    "issue_type": "incomplete_monitoring",
                    "description": "CloudWatch monitoring configuration is incomplete",
                    "recommendation": (
                        "Configure comprehensive monitoring including alarms for error rates"
                    ),
                }
            )

        # ISO compliance issues
        # ISO 27001 - Access Control
        iso_access_control = checks.get("iso27001_access_control", {})
        if not iso_access_control.get("is_compliant", True):
            issues.append(
                {
                    "severity": (
                        "HIGH"
                        if iso_access_control.get("privilege_score", 100) < 60
                        else "MEDIUM"
                    ),
                    "issue_type": "iso27001_access_control",
                    "description": f"ISO 27001 Access Control non-compliant (Score: {iso_access_control.get('privilege_score', 0)})",
                    "recommendation": "Review and implement least privilege access controls",
                }
            )

        # ISO 27001 - Cloud Service Security
        iso_cloud_security = checks.get("iso27001_cloud_service_security", {})
        if not iso_cloud_security.get("is_compliant", True):
            issues.append(
                {
                    "severity": "MEDIUM",
                    "issue_type": "iso27001_cloud_security",
                    "description": f"ISO 27001 Cloud Service Security gaps detected (Score: {iso_cloud_security.get('security_score', 0)}%)",
                    "recommendation": "Implement missing cloud security controls",
                }
            )

        # ISO 27001 - Cryptography
        iso_crypto = checks.get("iso27001_cryptography", {})
        if not iso_crypto.get("is_compliant", True):
            issues.append(
                {
                    "severity": "HIGH",
                    "issue_type": "iso27001_cryptography",
                    "description": "ISO 27001 Cryptography requirements not met",
                    "recommendation": "Enable encryption at rest and enforce SSL/TLS",
                }
            )

        # ISO 27017 - Data Location
        iso_data_location = checks.get("iso27017_data_location", {})
        if not iso_data_location.get("is_compliant", True):
            issues.append(
                {
                    "severity": "MEDIUM",
                    "issue_type": "iso27017_data_location",
                    "description": "ISO 27017 Data Location compliance issues",
                    "recommendation": "Review data residency and cross-region replication settings",
                }
            )

        # ISO 27017 - Data Isolation
        iso_data_isolation = checks.get("iso27017_data_isolation", {})
        if not iso_data_isolation.get("is_compliant", True):
            issues.append(
                {
                    "severity": "HIGH",
                    "issue_type": "iso27017_data_isolation",
                    "description": f"ISO 27017 Data Isolation compromised (Score: {iso_data_isolation.get('isolation_score', 0)})",
                    "recommendation": "Remove cross-account access and public grants",
                }
            )

        # ISO 27017 - Data Deletion (using existing key)
        iso_data_deletion = checks.get("iso27017_data_deletion", {})
        if not iso_data_deletion.get("is_compliant", True):
            issues.append(
                {
                    "severity": "LOW",
                    "issue_type": "iso27017_data_deletion",
                    "description": "ISO 27017 Data Deletion controls incomplete",
                    "recommendation": "Configure lifecycle rules, versioning, and object lock",
                }
            )

        # ISO 27018 - Purpose Limitation
        iso_purpose = checks.get("iso27018_purpose_limitation", {})
        if not iso_purpose.get("is_compliant", True):
            issues.append(
                {
                    "severity": "MEDIUM",
                    "issue_type": "iso27018_purpose_limitation",
                    "description": "ISO 27018 Purpose Limitation requirements not met",
                    "recommendation": "Define and tag specific data processing purposes",
                }
            )

        return issues

    def _error_result(
        self, bucket: Dict[str, Any], error_message: str
    ) -> Dict[str, Any]:
        """Generate an error result for a bucket."""
        return {
            "bucket_name": bucket.get("Name"),
            "creation_date": bucket.get("CreationDate"),
            "error": error_message,
            "scan_error": True,  # Flag to identify error results
            "issues": [
                {
                    "severity": "ERROR",
                    "issue_type": "scan_error",
                    "description": f"Error scanning bucket: {error_message}",
                    "recommendation": "Check permissions and try again",
                }
            ],
            "issue_count": 1,
            "has_high_severity": False,
            "has_medium_severity": False,
            "security_score": None,  # Use None instead of 0 to indicate error
            "compliance_status": {},
        }

    def scan_account_security(self) -> Dict[str, Any]:
        """Scan account-level security settings."""
        return {
            'account_public_access_block':
                self.account_security_checker.check_account_public_access_block(),
            'guardduty_s3_protection':
                self.threat_detection_checker.check_guardduty_s3_protection(),
            'macie_s3_discovery':
                self.threat_detection_checker.check_macie_s3_discovery()
        }

    def scan_all_buckets(
        self, buckets: Optional[List[Dict[str, Any]]] = None
    ) -> List[Dict[str, Any]]:
        """Scan all S3 buckets using parallel processing."""
        if buckets is None:
            buckets = self.get_all_buckets()

        if not buckets:
            self.logger.info("No S3 buckets found or unable to list buckets")
            return []

        # Check account-level security settings first
        account_security = self.scan_account_security()
        if not account_security['account_public_access_block']['is_properly_configured']:
            self.logger.warning(
                f"Account {self.account_id} missing account-level public access block"
            )
        if not account_security['guardduty_s3_protection'].get('has_s3_protection', False):
            self.logger.warning(
                "GuardDuty S3 protection is not enabled for threat detection"
            )
        if not account_security['macie_s3_discovery'].get('has_s3_discovery', False):
            self.logger.warning(
                "Macie S3 discovery is not enabled for sensitive data detection"
            )

        results = []

        # Use rich progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Scanning {len(buckets)} buckets...", total=len(buckets)
            )

            # Use ThreadPoolExecutor for parallel scanning
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all bucket scans
                future_to_bucket = {
                    executor.submit(
                        self.scan_bucket, bucket, progress, task
                    ): bucket
                    for bucket in buckets
                }

                # Process completed scans
                for future in as_completed(future_to_bucket):
                    bucket = future_to_bucket[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        self.logger.error(
                            f"Error scanning bucket {bucket.get('Name')}: {e}"
                        )
                        results.append(self._error_result(bucket, str(e)))

        # Sort results by security score
        results.sort(
            key=lambda x: (
                x.get("security_score", 0),
                x.get("bucket_name", ""),
            )
        )

        return results

    def generate_reports(
        self, results: List[Dict[str, Any]], output_format: str = "all"
    ) -> Dict[str, str]:
        """Generate report formats based on output_format parameter."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        reports = {}

        # Always generate compliance report for internal use
        compliance_file = os.path.join(
            self.output_dir, f"s3_compliance_{self.region}_{timestamp}.json"
        )
        self._export_compliance_report(results, compliance_file)

        # Generate reports based on format selection
        if output_format in ("json", "all"):
            json_file = os.path.join(
                self.output_dir, f"s3_scan_{self.region}_{timestamp}.json"
            )
            self._export_json(results, json_file)
            reports["json"] = json_file

        if output_format in ("csv", "all"):
            csv_file = os.path.join(
                self.output_dir, f"s3_scan_{self.region}_{timestamp}.csv"
            )
            self._export_csv(results, csv_file)
            reports["csv"] = csv_file

        if output_format in ("html", "all"):
            html_file = os.path.join(
                self.output_dir, f"s3_scan_{self.region}_{timestamp}.html"
            )
            self._export_html(results, html_file)
            reports["html"] = html_file

        # Always include compliance report in output
        reports["compliance"] = compliance_file

        return reports

    def _export_json(self, results: List[Dict[str, Any]], filename: str):
        """Export results to JSON."""
        summary = self._generate_summary(results)

        with open(filename, "w") as f:
            json.dump(
                {"summary": summary, "results": results},
                f,
                indent=2,
                default=str,
            )

        self.logger.info(f"Exported JSON report to {filename}")

    def _export_csv(self, results: List[Dict[str, Any]], filename: str):
        """Export results to CSV."""

        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)

            # Header
            writer.writerow(
                [
                    "Bucket Name",
                    "Region",
                    "Creation Date",
                    "Security Score",
                    "Is Public",
                    "Public Access Block",
                    "SSL Enforced",
                    "Default Encryption",
                    "Versioning",
                    "MFA Delete",
                    "Logging",
                    "Object Lock",
                    "Has Lifecycle Rules",
                    "Public Objects",
                    "Sensitive Objects",
                    "High Severity Issues",
                    "Medium Severity Issues",
                    "CIS Compliant",
                    "AWS-FSBP Compliant",
                    "PCI-DSS Compliant",
                    "HIPAA Compliant",
                    "SOC2 Compliant",
                    "ISO27001 Compliant",
                    "ISO27017 Compliant",
                    "ISO27018 Compliant",
                    "GDPR Compliant",
                    "Issues",
                ]
            )

            # Data
            for result in results:
                compliance = result.get("compliance_status", {})
                obj_security = result.get("object_level_security", {})

                writer.writerow(
                    [
                        result.get("bucket_name", ""),
                        result.get("region", ""),
                        result.get("creation_date", ""),
                        result.get("security_score", 0),
                        "Yes" if result.get("is_public", False) else "No",
                        (
                            "Yes"
                            if result.get("public_access_block", {}).get(
                                "is_properly_configured", False
                            )
                            else "No"
                        ),
                        (
                            "Yes"
                            if result.get("bucket_policy", {}).get(
                                "ssl_enforced", False
                            )
                            else "No"
                        ),
                        (
                            "Yes"
                            if result.get("encryption", {}).get(
                                "is_enabled", False
                            )
                            else "No"
                        ),
                        (
                            "Yes"
                            if result.get("versioning", {}).get(
                                "is_enabled", False
                            )
                            else "No"
                        ),
                        (
                            "Yes"
                            if result.get("versioning", {}).get(
                                "mfa_delete_enabled", False
                            )
                            else "No"
                        ),
                        (
                            "Yes"
                            if result.get("logging", {}).get(
                                "is_enabled", False
                            )
                            else "No"
                        ),
                        (
                            "Yes"
                            if result.get("object_lock", {}).get(
                                "is_enabled", False
                            )
                            else "No"
                        ),
                        (
                            "Yes"
                            if result.get("lifecycle_rules", {}).get(
                                "has_lifecycle_rules", False
                            )
                            else "No"
                        ),
                        obj_security.get("public_object_count", 0),
                        obj_security.get("sensitive_object_count", 0),
                        sum(
                            1
                            for i in result.get("issues", [])
                            if i["severity"] == "HIGH"
                        ),
                        sum(
                            1
                            for i in result.get("issues", [])
                            if i["severity"] == "MEDIUM"
                        ),
                        compliance.get("CIS", {}).get(
                            "compliance_percentage", 0
                        ),
                        compliance.get("AWS-FSBP", {}).get(
                            "compliance_percentage", 0
                        ),
                        compliance.get("PCI-DSS", {}).get(
                            "compliance_percentage", 0
                        ),
                        compliance.get("HIPAA", {}).get(
                            "compliance_percentage", 0
                        ),
                        compliance.get("SOC2", {}).get(
                            "compliance_percentage", 0
                        ),
                        compliance.get("ISO27001", {}).get(
                            "compliance_percentage", 0
                        ),
                        compliance.get("ISO27017", {}).get(
                            "compliance_percentage", 0
                        ),
                        compliance.get("ISO27018", {}).get(
                            "compliance_percentage", 0
                        ),
                        compliance.get("GDPR", {}).get(
                            "compliance_percentage", 0
                        ),
                        "; ".join(
                            [
                                i["description"]
                                for i in result.get("issues", [])
                            ]
                        ),
                    ]
                )

        self.logger.info(f"Exported CSV report to {filename}")

    def _export_compliance_report(
        self, results: List[Dict[str, Any]], filename: str
    ):
        """Export compliance report."""
        compliance_summary = {
            "scan_time": datetime.now().isoformat(),
            "total_buckets": len(results),
            "compliance_frameworks": {},
        }

        for framework in [
            "CIS",
            "AWS-FSBP",
            "PCI-DSS",
            "HIPAA",
            "SOC2",
            "ISO27001",
            "ISO27017",
            "ISO27018",
            "GDPR",
        ]:
            compliant_buckets = sum(
                1
                for r in results
                if r.get("compliance_status", {})
                .get(framework, {})
                .get("is_compliant", False)
            )
            
            # Calculate actual compliance percentage across all controls
            total_passed = 0
            total_applicable = 0
            
            for r in results:
                framework_status = r.get("compliance_status", {}).get(framework, {})
                if framework_status:
                    passed = framework_status.get("passed_controls", 0)
                    applicable = framework_status.get("applicable_controls", 0)
                    total_passed += passed
                    total_applicable += applicable
            
            actual_compliance_percentage = (
                round(total_passed / total_applicable * 100, 2)
                if total_applicable > 0
                else 0
            )

            compliance_summary["compliance_frameworks"][framework] = {
                "compliant_buckets": compliant_buckets,
                "non_compliant_buckets": len(results) - compliant_buckets,
                "compliance_percentage": actual_compliance_percentage,
            }

        with open(filename, "w") as f:
            json.dump(
                {
                    "summary": compliance_summary,
                    "detailed_results": [
                        {
                            "bucket_name": r["bucket_name"],
                            "compliance_status": r.get(
                                "compliance_status", {}
                            ),
                        }
                        for r in results
                    ],
                },
                f,
                indent=2,
                default=str,
            )

        self.logger.info(f"Exported compliance report to {filename}")

    def _export_html(self, results: List[Dict[str, Any]], filename: str):
        """Export results to HTML."""
        summary = self._generate_summary(results)

        try:
            self.html_reporter.generate_report(results, summary, filename)
            self.logger.info(f"Exported HTML report to {filename}")
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {e}")
            # Don't fail the entire scan if HTML generation fails

    def _generate_summary(
        self, results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate scan summary statistics."""
        if not results:
            return {}

        public_buckets = sum(1 for r in results if r.get("is_public", False))
        high_severity_buckets = sum(
            1 for r in results if r.get("has_high_severity", False)
        )
        medium_severity_buckets = sum(
            1 for r in results if r.get("has_medium_severity", False)
        )

        # Filter out error results for statistics calculation
        valid_results = [r for r in results if not r.get("scan_error", False)]

        if valid_results:
            avg_security_score = sum(
                r.get("security_score", 0) for r in valid_results
            ) / len(valid_results)
        else:
            avg_security_score = 0

        # Object-level statistics
        total_public_objects = sum(
            r.get("object_level_security", {}).get("public_object_count", 0)
            for r in results
        )
        total_sensitive_objects = sum(
            r.get("object_level_security", {}).get("sensitive_object_count", 0)
            for r in results
        )

        return {
            "scan_time": datetime.now().isoformat(),
            "region": self.region,
            "account_id": self.account_id,
            "total_buckets": len(valid_results),
            "error_buckets": len(results) - len(valid_results),
            "public_buckets": public_buckets,
            "high_severity_buckets": high_severity_buckets,
            "medium_severity_buckets": medium_severity_buckets,
            "average_security_score": round(avg_security_score, 2),
            "total_public_objects": total_public_objects,
            "total_sensitive_objects": total_sensitive_objects,
        }

    def print_summary(self, results: List[Dict[str, Any]]):
        """Print a rich summary to console."""
        if not results:
            self.console.print("[yellow]No buckets were scanned.[/yellow]")
            return

        summary = self._generate_summary(results)

        # Create summary table
        table = Table(title=f"S3 Security Scan Summary - {self.region}")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Account ID", summary["account_id"])
        table.add_row("Total Buckets", str(summary["total_buckets"]))
        if summary["error_buckets"] > 0:
            table.add_row(
                "Error Buckets", f"[red]{summary['error_buckets']}[/red]"
            )
        table.add_row(
            "Average Security Score",
            f"{summary['average_security_score']}/100",
        )
        table.add_row(
            "Public Buckets", f"[red]{summary['public_buckets']}[/red]"
        )
        table.add_row(
            "High Severity Issues",
            f"[red]{summary['high_severity_buckets']}[/red]",
        )
        table.add_row(
            "Medium Severity Issues",
            f"[yellow]{summary['medium_severity_buckets']}[/yellow]",
        )
        table.add_row(
            "Public Objects Found",
            f"[red]{summary['total_public_objects']}[/red]",
        )
        table.add_row(
            "Sensitive Objects Found",
            f"[red]{summary['total_sensitive_objects']}[/red]",
        )

        self.console.print(table)

        # Show worst buckets (exclude error results)
        valid_results = [r for r in results if not r.get("scan_error", False)]
        if valid_results:
            worst_buckets = sorted(
                valid_results, key=lambda x: x.get("security_score", 100)
            )[:5]

            worst_table = Table(title="Lowest Scoring Buckets")
            worst_table.add_column("Bucket", style="cyan")
            worst_table.add_column("Score", style="white")
            worst_table.add_column("Issues", style="yellow")

            for bucket in worst_buckets:
                issues = bucket.get("issue_count", 0)
                score = bucket.get("security_score", 0)

                score_style = (
                    "red"
                    if score < 50
                    else "yellow" if score < 80 else "green"
                )
                worst_table.add_row(
                    bucket["bucket_name"],
                    f"[{score_style}]{score}/100[/{score_style}]",
                    str(issues),
                )

            self.console.print(worst_table)

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
        return self.dns_security_checker.scan_subdomain_takeover(
            domains, check_subdomains, subdomain_wordlist
        )
