"""ISO 27001/27017/27018 Compliance Checks for S3 Buckets."""

import json
from typing import Dict, Any

import boto3
from botocore.exceptions import ClientError


class ISOComplianceChecker:
    """Checks for ISO 27001, 27017, and 27018 compliance requirements."""

    def __init__(self, session=None):
        """Initialize ISO compliance checker."""
        self.session = session

    def check_iso27001_cloud_service_security(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27001 - 5.23 Information Security for Cloud Services."""
        try:
            # Meta-analysis of existing security checks for cloud service compliance
            security_controls = {
                "encryption_at_rest": bucket_checks.get("encryption", {}).get(
                    "is_enabled", False
                ),
                "encryption_in_transit": bucket_checks.get(
                    "bucket_policy", {}
                ).get("ssl_enforced", False),
                "access_controls": not bucket_checks.get("is_public", True),
                "public_access_blocked": bucket_checks.get(
                    "public_access_block", {}
                ).get("is_properly_configured", False),
                "versioning_enabled": bucket_checks.get("versioning", {}).get(
                    "is_enabled", False
                ),
                "logging_enabled": bucket_checks.get("logging", {}).get(
                    "is_enabled", False
                ),
                "mfa_delete": bucket_checks.get("versioning", {}).get(
                    "mfa_delete_enabled", False
                ),
                "object_lock": bucket_checks.get("object_lock", {}).get(
                    "is_enabled", False
                ),
            }

            # Calculate cloud service security score
            total_controls = len(security_controls)
            enabled_controls = sum(
                1 for enabled in security_controls.values() if enabled
            )
            security_score = (enabled_controls / total_controls) * 100

            # Identify missing controls
            missing_controls = [
                control
                for control, enabled in security_controls.items()
                if not enabled
            ]

            # Determine compliance level
            if security_score >= 90:
                compliance_level = "EXCELLENT"
            elif security_score >= 75:
                compliance_level = "GOOD"
            elif security_score >= 60:
                compliance_level = "ACCEPTABLE"
            else:
                compliance_level = "NON_COMPLIANT"

            return {
                "iso_control": "27001-5.23",
                "control_name": "Information Security for Cloud Services",
                "is_compliant": security_score >= 75,
                "compliance_level": compliance_level,
                "security_score": round(security_score, 1),
                "enabled_controls": enabled_controls,
                "total_controls": total_controls,
                "missing_controls": missing_controls,
                "security_controls": security_controls,
                "recommendations": self._get_cloud_security_recommendations(
                    missing_controls
                ),
            }

        except Exception as e:
            return {
                "iso_control": "27001-5.23",
                "control_name": "Information Security for Cloud Services",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27001_cryptography(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check ISO 27001 - 8.24 Use of Cryptography."""
        try:
            # Check encryption at rest
            try:
                encryption_response = client.get_bucket_encryption(
                    Bucket=bucket_name
                )
                encryption_config = encryption_response.get(
                    "ServerSideEncryptionConfiguration", {}
                )
                encryption_at_rest = True
                encryption_details = self._analyze_encryption_config(
                    encryption_config
                )
            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "ServerSideEncryptionConfigurationNotFoundError"
                ):
                    encryption_at_rest = False
                    encryption_details = {
                        "algorithm": "None",
                        "kms_managed": False,
                    }
                else:
                    raise e

            # Check encryption in transit (SSL enforcement)
            try:
                policy_response = client.get_bucket_policy(Bucket=bucket_name)
                policy_str = policy_response.get("Policy", "")
                ssl_enforced = (
                    self._check_ssl_enforcement(policy_str)
                    if policy_str
                    else False
                )
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    ssl_enforced = False
                else:
                    raise e

            # Calculate cryptography compliance score
            crypto_score = 0
            crypto_issues = []

            if encryption_at_rest:
                crypto_score += 50
                if encryption_details.get("kms_managed", False):
                    crypto_score += 20  # Bonus for KMS
            else:
                crypto_issues.append("No encryption at rest configured")

            if ssl_enforced:
                crypto_score += 30
            else:
                crypto_issues.append("SSL/TLS enforcement not configured")

            # Determine compliance
            is_compliant = crypto_score >= 80
            compliance_level = (
                "EXCELLENT"
                if crypto_score >= 90
                else (
                    "GOOD"
                    if crypto_score >= 80
                    else (
                        "ACCEPTABLE" if crypto_score >= 60 else "NON_COMPLIANT"
                    )
                )
            )

            return {
                "iso_control": "27001-8.24",
                "control_name": "Use of Cryptography",
                "is_compliant": is_compliant,
                "compliance_level": compliance_level,
                "crypto_score": crypto_score,
                "encryption_at_rest": encryption_at_rest,
                "encryption_in_transit": ssl_enforced,
                "encryption_details": encryption_details,
                "crypto_issues": crypto_issues,
                "recommendations": self._get_crypto_recommendations(
                    crypto_issues
                ),
            }

        except Exception as e:
            return {
                "iso_control": "27001-8.24",
                "control_name": "Use of Cryptography",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27017_data_location(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check ISO 27017 - CLD.8.1.4 Data Location."""
        try:
            # Get bucket region
            bucket_location = client.get_bucket_location(Bucket=bucket_name)
            bucket_region = (
                bucket_location.get("LocationConstraint") or "us-east-1"
            )

            # Check cross-region replication
            try:
                replication_response = client.get_bucket_replication(
                    Bucket=bucket_name
                )
                replication_config = replication_response.get(
                    "ReplicationConfiguration", {}
                )
                replication_rules = replication_config.get("Rules", [])
                has_replication = len(replication_rules) > 0

                # Analyze replication destinations
                replication_regions = []
                for rule in replication_rules:
                    dest_bucket = rule.get("Destination", {}).get("Bucket", "")
                    if dest_bucket:
                        # Extract region from destination bucket ARN or assume same region
                        replication_regions.append("cross-region-detected")

            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "ReplicationConfigurationNotFoundError"
                ):
                    has_replication = False
                    replication_regions = []
                else:
                    raise e

            # Data location compliance analysis
            data_locations = [bucket_region] + replication_regions
            location_control_score = 100
            location_issues = []

            # Check for data sovereignty compliance (basic validation)
            if has_replication:
                location_issues.append(
                    "Cross-region replication may affect data sovereignty"
                )
                location_control_score -= 20

            # Compliance assessment
            is_compliant = location_control_score >= 80
            compliance_level = (
                "EXCELLENT"
                if location_control_score >= 95
                else ("GOOD" if location_control_score >= 80 else "ACCEPTABLE")
            )

            return {
                "iso_control": "27017-CLD.8.1.4",
                "control_name": "Data Location",
                "is_compliant": is_compliant,
                "compliance_level": compliance_level,
                "location_control_score": location_control_score,
                "primary_region": bucket_region,
                "has_cross_region_replication": has_replication,
                "replication_regions": replication_regions,
                "total_data_locations": len(data_locations),
                "location_issues": location_issues,
                "data_residency_controlled": not has_replication,
            }

        except Exception as e:
            return {
                "iso_control": "27017-CLD.8.1.4",
                "control_name": "Data Location",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27017_tenant_isolation(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check ISO 27017 - CLD.9.1.2 Tenant Isolation."""
        try:
            # Get current account ID
            if self.session:
                sts_client = self.session.client("sts")
            else:
                sts_client = boto3.client("sts")
            current_account = sts_client.get_caller_identity()["Account"]

            # Check bucket policy for cross-account access
            try:
                policy_response = client.get_bucket_policy(Bucket=bucket_name)
                policy_str = policy_response.get("Policy", "")
                cross_account_access = (
                    self._analyze_cross_account_policy(
                        policy_str, current_account
                    )
                    if policy_str
                    else {}
                )
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                    cross_account_access = {
                        "has_cross_account": False,
                        "external_accounts": [],
                    }
                else:
                    raise e

            # Check bucket ACL for external access
            acl_response = client.get_bucket_acl(Bucket=bucket_name)
            grants = acl_response.get("Grants", [])
            external_acl_grants = []

            for grant in grants:
                grantee = grant.get("Grantee", {})
                if grantee.get("Type") == "Group":
                    uri = grantee.get("URI", "")
                    if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                        external_acl_grants.append(grant)

            # Tenant isolation analysis
            isolation_score = 100
            isolation_issues = []

            if cross_account_access.get("has_cross_account", False):
                isolation_issues.append(
                    f"Cross-account access to {len(cross_account_access.get('external_accounts', []))} external accounts"
                )
                isolation_score -= 30

            if external_acl_grants:
                isolation_issues.append(
                    f"Public ACL grants detected: {len(external_acl_grants)}"
                )
                isolation_score -= 40

            # Compliance assessment
            is_compliant = isolation_score >= 80
            compliance_level = (
                "EXCELLENT"
                if isolation_score >= 95
                else (
                    "GOOD"
                    if isolation_score >= 80
                    else (
                        "ACCEPTABLE"
                        if isolation_score >= 60
                        else "NON_COMPLIANT"
                    )
                )
            )

            return {
                "iso_control": "27017-CLD.9.1.2",
                "control_name": "Tenant Isolation",
                "is_compliant": is_compliant,
                "compliance_level": compliance_level,
                "isolation_score": isolation_score,
                "current_account": current_account,
                "has_cross_account_access": cross_account_access.get(
                    "has_cross_account", False
                ),
                "external_accounts": cross_account_access.get(
                    "external_accounts", []
                ),
                "external_acl_grants": len(external_acl_grants),
                "isolation_issues": isolation_issues,
                "tenant_isolation_effective": len(isolation_issues) == 0,
            }

        except Exception as e:
            return {
                "iso_control": "27017-CLD.9.1.2",
                "control_name": "Tenant Isolation",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27017_service_termination(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check ISO 27017 - CLD.13.1.1 Service Termination."""
        try:
            # Check lifecycle configuration for data deletion
            try:
                lifecycle_response = client.get_bucket_lifecycle_configuration(
                    Bucket=bucket_name
                )
                lifecycle_rules = lifecycle_response.get("Rules", [])
                has_deletion_rules = any(
                    rule.get("Status") == "Enabled"
                    and (
                        rule.get("Expiration")
                        or rule.get("NoncurrentVersionExpiration")
                    )
                    for rule in lifecycle_rules
                )
                deletion_rules_count = sum(
                    1
                    for rule in lifecycle_rules
                    if rule.get("Status") == "Enabled"
                    and (
                        rule.get("Expiration")
                        or rule.get("NoncurrentVersionExpiration")
                    )
                )
            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "NoSuchLifecycleConfiguration"
                ):
                    has_deletion_rules = False
                    deletion_rules_count = 0
                    lifecycle_rules = []
                else:
                    raise e

            # Check object lock for retention management
            try:
                object_lock_response = client.get_object_lock_configuration(
                    Bucket=bucket_name
                )
                object_lock_config = object_lock_response.get(
                    "ObjectLockConfiguration", {}
                )
                object_lock_enabled = (
                    object_lock_config.get("ObjectLockEnabled") == "Enabled"
                )
                retention_config = object_lock_config.get("Rule", {}).get(
                    "DefaultRetention", {}
                )
            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "ObjectLockConfigurationNotFoundError"
                ):
                    object_lock_enabled = False
                    retention_config = {}
                else:
                    raise e

            # Check versioning for data recovery
            versioning_response = client.get_bucket_versioning(
                Bucket=bucket_name
            )
            versioning_enabled = versioning_response.get("Status") == "Enabled"
            mfa_delete_enabled = (
                versioning_response.get("MfaDelete") == "Enabled"
            )

            # Service termination compliance analysis
            termination_score = 100
            termination_issues = []

            if not has_deletion_rules:
                termination_issues.append(
                    "No lifecycle rules for data deletion configured"
                )
                termination_score -= 30

            if not versioning_enabled:
                termination_issues.append(
                    "Versioning not enabled for data recovery"
                )
                termination_score -= 25

            if not object_lock_enabled:
                termination_issues.append(
                    "Object lock not configured for retention management"
                )
                termination_score -= 20

            if versioning_enabled and not mfa_delete_enabled:
                termination_issues.append(
                    "MFA delete not enabled for additional protection"
                )
                termination_score -= 15

            # Compliance assessment
            is_compliant = (
                termination_score >= 70
            )  # Lower threshold for this control
            compliance_level = (
                "EXCELLENT"
                if termination_score >= 90
                else (
                    "GOOD"
                    if termination_score >= 70
                    else (
                        "ACCEPTABLE"
                        if termination_score >= 50
                        else "NON_COMPLIANT"
                    )
                )
            )

            return {
                "iso_control": "27017-CLD.13.1.1",
                "control_name": "Cloud Service Termination",
                "is_compliant": is_compliant,
                "compliance_level": compliance_level,
                "termination_score": max(0, termination_score),
                "has_deletion_rules": has_deletion_rules,
                "deletion_rules_count": deletion_rules_count,
                "object_lock_enabled": object_lock_enabled,
                "versioning_enabled": versioning_enabled,
                "mfa_delete_enabled": mfa_delete_enabled,
                "termination_issues": termination_issues,
                "data_deletion_controlled": has_deletion_rules,
                "retention_managed": object_lock_enabled,
                "lifecycle_rules": lifecycle_rules,
                "retention_config": retention_config,
            }

        except Exception as e:
            return {
                "iso_control": "27017-CLD.13.1.1",
                "control_name": "Cloud Service Termination",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27018_consent_choice(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check ISO 27018 - PII.1.1 Consent and Choice."""
        try:
            # Check bucket tagging for consent-related metadata
            try:
                tagging_response = client.get_bucket_tagging(
                    Bucket=bucket_name
                )
                tags = tagging_response.get("TagSet", [])
                tag_dict = {tag["Key"].lower(): tag["Value"] for tag in tags}
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchTagSet":
                    tags = []
                    tag_dict = {}
                else:
                    raise e

            # Analyze consent-related tags
            consent_indicators = [
                "consent",
                "data-consent",
                "pii-consent",
                "privacy-consent",
                "data-processing-consent",
                "user-consent",
                "consent-status",
            ]

            purpose_indicators = [
                "purpose",
                "data-purpose",
                "processing-purpose",
                "usage-purpose",
                "data-use",
                "pii-purpose",
            ]

            legal_basis_indicators = [
                "legal-basis",
                "lawful-basis",
                "processing-basis",
                "consent-basis",
                "gdpr-basis",
                "data-protection-basis",
            ]

            # Check for consent metadata
            consent_tags = [
                key
                for key in tag_dict.keys()
                if any(indicator in key for indicator in consent_indicators)
            ]
            purpose_tags = [
                key
                for key in tag_dict.keys()
                if any(indicator in key for indicator in purpose_indicators)
            ]
            legal_basis_tags = [
                key
                for key in tag_dict.keys()
                if any(
                    indicator in key for indicator in legal_basis_indicators
                )
            ]

            # Calculate consent compliance score
            consent_score = 0
            consent_issues = []

            if consent_tags:
                consent_score += 40
            else:
                consent_issues.append("No consent metadata tags found")

            if purpose_tags:
                consent_score += 30
            else:
                consent_issues.append("No data processing purpose tags found")

            if legal_basis_tags:
                consent_score += 30
            else:
                consent_issues.append("No legal basis tags found")

            # Check for data subject rights tags
            rights_indicators = [
                "data-subject-rights",
                "user-rights",
                "privacy-rights",
                "access-rights",
            ]
            rights_tags = [
                key
                for key in tag_dict.keys()
                if any(indicator in key for indicator in rights_indicators)
            ]

            if rights_tags:
                consent_score += 10

            # Compliance assessment
            is_compliant = consent_score >= 70
            compliance_level = (
                "EXCELLENT"
                if consent_score >= 90
                else (
                    "GOOD"
                    if consent_score >= 70
                    else (
                        "ACCEPTABLE"
                        if consent_score >= 50
                        else "NON_COMPLIANT"
                    )
                )
            )

            return {
                "iso_control": "27018-PII.1.1",
                "control_name": "Consent and Choice",
                "is_compliant": is_compliant,
                "compliance_level": compliance_level,
                "consent_score": consent_score,
                "consent_metadata_present": len(consent_tags) > 0,
                "purpose_metadata_present": len(purpose_tags) > 0,
                "legal_basis_metadata_present": len(legal_basis_tags) > 0,
                "consent_tags": consent_tags,
                "purpose_tags": purpose_tags,
                "legal_basis_tags": legal_basis_tags,
                "rights_tags": rights_tags,
                "consent_issues": consent_issues,
                "total_relevant_tags": len(consent_tags)
                + len(purpose_tags)
                + len(legal_basis_tags),
                "all_tags": tag_dict,
            }

        except Exception as e:
            return {
                "iso_control": "27018-PII.1.1",
                "control_name": "Consent and Choice",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27018_purpose_limitation(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check ISO 27018 - PII.1.2 Purpose Limitation."""
        try:
            # Get bucket tags for purpose validation
            try:
                tagging_response = client.get_bucket_tagging(
                    Bucket=bucket_name
                )
                tags = tagging_response.get("TagSet", [])
                tag_dict = {tag["Key"].lower(): tag["Value"] for tag in tags}
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchTagSet":
                    tags = []
                    tag_dict = {}
                else:
                    raise e

            # Define valid data processing purposes
            valid_purposes = [
                "analytics",
                "backup",
                "archival",
                "compliance",
                "audit",
                "marketing",
                "customer-service",
                "product-development",
                "security",
                "fraud-prevention",
                "legal-compliance",
                "operational",
                "technical-support",
                "research",
            ]

            # Analyze purpose limitation compliance
            purpose_tags = {}
            for key, value in tag_dict.items():
                if "purpose" in key:
                    purpose_tags[key] = value

            # Check for specific purpose declarations
            declared_purposes = []
            for purpose_tag, purpose_value in purpose_tags.items():
                purpose_lower = purpose_value.lower()
                for valid_purpose in valid_purposes:
                    if valid_purpose in purpose_lower:
                        declared_purposes.append(valid_purpose)

            # Remove duplicates
            declared_purposes = list(set(declared_purposes))

            # Calculate purpose limitation score
            purpose_score = 0
            purpose_issues = []

            if purpose_tags:
                purpose_score += 50
            else:
                purpose_issues.append("No data processing purpose tags found")

            if declared_purposes:
                purpose_score += 30
                if (
                    len(declared_purposes) <= 3
                ):  # Principle of minimal purposes
                    purpose_score += 20
                else:
                    purpose_issues.append(
                        "Too many declared purposes may violate minimization principle"
                    )
            else:
                purpose_issues.append("No recognized valid purposes declared")

            # Check for purpose-specific access controls
            access_control_tags = [
                key
                for key in tag_dict.keys()
                if "access" in key or "permission" in key
            ]
            if access_control_tags:
                purpose_score += 10

            # Compliance assessment
            is_compliant = purpose_score >= 70
            compliance_level = (
                "EXCELLENT"
                if purpose_score >= 90
                else (
                    "GOOD"
                    if purpose_score >= 70
                    else (
                        "ACCEPTABLE"
                        if purpose_score >= 50
                        else "NON_COMPLIANT"
                    )
                )
            )

            return {
                "iso_control": "27018-PII.1.2",
                "control_name": "Purpose Limitation",
                "is_compliant": is_compliant,
                "compliance_level": compliance_level,
                "purpose_score": purpose_score,
                "purpose_tags_present": len(purpose_tags) > 0,
                "declared_purposes": declared_purposes,
                "purpose_count": len(declared_purposes),
                "purpose_minimization_compliant": len(declared_purposes) <= 3,
                "purpose_tags": purpose_tags,
                "access_control_tags": access_control_tags,
                "purpose_issues": purpose_issues,
                "valid_purposes_detected": len(declared_purposes) > 0,
            }

        except Exception as e:
            return {
                "iso_control": "27018-PII.1.2",
                "control_name": "Purpose Limitation",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    # Helper methods
    def _analyze_encryption_config(
        self, encryption_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze encryption configuration details."""
        rules = encryption_config.get("Rules", [])
        if not rules:
            return {"algorithm": "None", "kms_managed": False}

        rule = rules[0]  # Analyze first rule
        sse_config = rule.get("ApplyServerSideEncryptionByDefault", {})
        algorithm = sse_config.get("SSEAlgorithm", "None")
        kms_key_id = sse_config.get("KMSMasterKeyID")

        return {
            "algorithm": algorithm,
            "kms_managed": algorithm == "aws:kms",
            "kms_key_id": kms_key_id,
            "bucket_key_enabled": rule.get("BucketKeyEnabled", False),
        }

    def _check_ssl_enforcement(self, policy_str: str) -> bool:
        """Check if bucket policy enforces SSL."""
        try:
            policy = json.loads(policy_str)
            for statement in policy.get("Statement", []):
                if statement.get("Effect") == "Deny":
                    condition = statement.get("Condition", {})
                    bool_condition = condition.get("Bool", {})
                    if bool_condition.get("aws:SecureTransport") == "false":
                        return True
            return False
        except Exception:
            return False

    def _analyze_cross_account_policy(
        self, policy_str: str, current_account: str
    ) -> Dict[str, Any]:
        """Analyze bucket policy for cross-account access."""
        try:
            policy = json.loads(policy_str)
            external_accounts = []

            for statement in policy.get("Statement", []):
                if statement.get("Effect") == "Allow":
                    principal = statement.get("Principal", {})
                    if isinstance(principal, dict) and "AWS" in principal:
                        aws_principals = principal["AWS"]
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]

                        for aws_principal in aws_principals:
                            if "arn:aws:iam::" in aws_principal:
                                account_id = aws_principal.split(":")[4]
                                if (
                                    account_id != current_account
                                    and account_id not in external_accounts
                                ):
                                    external_accounts.append(account_id)

            return {
                "has_cross_account": len(external_accounts) > 0,
                "external_accounts": external_accounts,
            }
        except Exception:
            return {"has_cross_account": False, "external_accounts": []}

    def _get_cloud_security_recommendations(
        self, missing_controls: list
    ) -> list:
        """Get recommendations for cloud security improvements."""
        recommendations = []
        for control in missing_controls:
            if control == "encryption_at_rest":
                recommendations.append(
                    "Enable default bucket encryption with SSE-S3 or SSE-KMS"
                )
            elif control == "encryption_in_transit":
                recommendations.append(
                    "Add bucket policy to enforce SSL/HTTPS connections"
                )
            elif control == "access_controls":
                recommendations.append(
                    "Enable S3 Block Public Access settings"
                )
            elif control == "versioning_enabled":
                recommendations.append(
                    "Enable bucket versioning for data protection"
                )
            elif control == "logging_enabled":
                recommendations.append("Enable S3 server access logging")
            elif control == "mfa_delete":
                recommendations.append(
                    "Enable MFA Delete for versioned buckets"
                )
            elif control == "object_lock":
                recommendations.append(
                    "Consider enabling S3 Object Lock for compliance requirements"
                )
        return recommendations

    def _get_crypto_recommendations(self, crypto_issues: list) -> list:
        """Get recommendations for cryptography improvements."""
        recommendations = []
        for issue in crypto_issues:
            if "encryption at rest" in issue:
                recommendations.append(
                    "Configure server-side encryption: aws s3api put-bucket-encryption"
                )
            elif "SSL/TLS enforcement" in issue:
                recommendations.append(
                    "Add bucket policy with aws:SecureTransport condition"
                )
        return recommendations

    # Additional ISO 27001 Controls
    def check_iso27001_access_control(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27001 - 5.15 Access Control Management."""
        try:
            # Use the existing comprehensive access control analysis
            # This leverages the existing iso27001_access_control function
            # which provides comprehensive privilege analysis
            return bucket_checks.get(
                "iso27001_access_control",
                {
                    "iso_control": "27001-5.15",
                    "control_name": "Access Control Management",
                    "is_compliant": False,
                    "compliance_level": "ERROR",
                    "error": "Access control check not available",
                },
            )
        except Exception as e:
            return {
                "iso_control": "27001-5.15",
                "control_name": "Access Control Management",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27001_access_rights(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27001 - 5.18 Access Rights Management."""
        try:
            # Analyze permission governance
            public_access_blocked = bucket_checks.get(
                "public_access_block", {}
            ).get("is_properly_configured", False)
            bucket_policy_safe = not bucket_checks.get(
                "bucket_policy", {}
            ).get("is_public", True)
            acl_safe = not bucket_checks.get("bucket_acl", {}).get(
                "has_public_access", True
            )

            # Score based on access right controls
            score = 0
            if public_access_blocked:
                score += 40
            if bucket_policy_safe:
                score += 30
            if acl_safe:
                score += 30

            return {
                "iso_control": "27001-5.18",
                "control_name": "Access Rights Management",
                "is_compliant": score >= 80,
                "compliance_level": (
                    "EXCELLENT"
                    if score >= 90
                    else (
                        "GOOD"
                        if score >= 80
                        else "ACCEPTABLE" if score >= 60 else "NON_COMPLIANT"
                    )
                ),
                "score": score,
                "public_access_controls": {
                    "public_access_block": public_access_blocked,
                    "safe_bucket_policy": bucket_policy_safe,
                    "safe_acl": acl_safe,
                },
            }
        except Exception as e:
            return {
                "iso_control": "27001-5.18",
                "control_name": "Access Rights Management",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27001_backup(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27001 - 12.3 Information Backup."""
        try:
            versioning_enabled = bucket_checks.get("versioning", {}).get(
                "is_enabled", False
            )
            replication_enabled = bucket_checks.get("replication", {}).get(
                "has_replication", False
            )

            # Backup score calculation
            score = 0
            backup_features = []

            if versioning_enabled:
                score += 60
                backup_features.append("versioning")
            if replication_enabled:
                score += 40
                backup_features.append("replication")

            return {
                "iso_control": "27001-12.3",
                "control_name": "Information Backup",
                "is_compliant": score >= 60,
                "compliance_level": (
                    "EXCELLENT"
                    if score >= 90
                    else "GOOD" if score >= 60 else "NON_COMPLIANT"
                ),
                "score": score,
                "backup_features": backup_features,
                "versioning_enabled": versioning_enabled,
                "replication_enabled": replication_enabled,
            }
        except Exception as e:
            return {
                "iso_control": "27001-12.3",
                "control_name": "Information Backup",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27001_logging(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27001 - 12.4 Logging and Monitoring."""
        try:
            access_logging = bucket_checks.get("logging", {}).get(
                "is_enabled", False
            )

            # Note: CloudTrail logging would require additional API calls
            # For now, focus on S3 access logging
            score = 0
            if access_logging:
                score = 80  # Good coverage with access logging

            return {
                "iso_control": "27001-12.4",
                "control_name": "Logging and Monitoring",
                "is_compliant": score >= 70,
                "compliance_level": (
                    "GOOD"
                    if score >= 80
                    else "ACCEPTABLE" if score >= 70 else "NON_COMPLIANT"
                ),
                "score": score,
                "access_logging_enabled": access_logging,
                "note": "CloudTrail logging recommended for comprehensive audit trail",
            }
        except Exception as e:
            return {
                "iso_control": "27001-12.4",
                "control_name": "Logging and Monitoring",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27001_info_transfer(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27001 - 13.2 Information Transfer."""
        try:
            ssl_enforced = bucket_checks.get("bucket_policy", {}).get(
                "ssl_enforced", False
            )

            return {
                "iso_control": "27001-13.2",
                "control_name": "Information Transfer",
                "is_compliant": ssl_enforced,
                "compliance_level": (
                    "EXCELLENT" if ssl_enforced else "NON_COMPLIANT"
                ),
                "ssl_enforced": ssl_enforced,
                "secure_transfer_required": ssl_enforced,
            }
        except Exception as e:
            return {
                "iso_control": "27001-13.2",
                "control_name": "Information Transfer",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    # Additional ISO 27017 Controls
    def check_iso27017_access_restriction(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27017 - CLD.6.3.1 Restriction of Access Rights."""
        try:
            # Cloud-specific access management
            public_access_blocked = bucket_checks.get(
                "public_access_block", {}
            ).get("is_properly_configured", False)
            no_public_policy = not bucket_checks.get("bucket_policy", {}).get(
                "is_public", True
            )
            no_public_acl = not bucket_checks.get("bucket_acl", {}).get(
                "has_public_access", True
            )

            # Cloud access restriction score
            score = 0
            if public_access_blocked:
                score += 50
            if no_public_policy:
                score += 25
            if no_public_acl:
                score += 25

            return {
                "iso_control": "27017-CLD.6.3.1",
                "control_name": "Restriction of Access Rights",
                "is_compliant": score >= 75,
                "compliance_level": (
                    "EXCELLENT"
                    if score >= 90
                    else "GOOD" if score >= 75 else "NON_COMPLIANT"
                ),
                "score": score,
                "cloud_access_controls": {
                    "public_access_block": public_access_blocked,
                    "no_public_policy": no_public_policy,
                    "no_public_acl": no_public_acl,
                },
            }
        except Exception as e:
            return {
                "iso_control": "27017-CLD.6.3.1",
                "control_name": "Restriction of Access Rights",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27017_shared_responsibility(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27017 - CLD.7.1.1 Cloud Service Responsibilities."""
        try:
            # Customer responsibility areas in shared model
            encryption_enabled = bucket_checks.get("encryption", {}).get(
                "is_enabled", False
            )
            versioning_enabled = bucket_checks.get("versioning", {}).get(
                "is_enabled", False
            )
            logging_enabled = bucket_checks.get("logging", {}).get(
                "is_enabled", False
            )
            backup_configured = bucket_checks.get("replication", {}).get(
                "has_replication", False
            )

            # Shared responsibility score
            customer_controls = [
                encryption_enabled,
                versioning_enabled,
                logging_enabled,
                backup_configured,
            ]
            score = (sum(customer_controls) / len(customer_controls)) * 100

            return {
                "iso_control": "27017-CLD.7.1.1",
                "control_name": "Cloud Service Responsibilities",
                "is_compliant": score >= 75,
                "compliance_level": (
                    "EXCELLENT"
                    if score >= 90
                    else "GOOD" if score >= 75 else "NON_COMPLIANT"
                ),
                "score": score,
                "customer_responsibilities": {
                    "encryption": encryption_enabled,
                    "versioning": versioning_enabled,
                    "logging": logging_enabled,
                    "backup": backup_configured,
                },
            }
        except Exception as e:
            return {
                "iso_control": "27017-CLD.7.1.1",
                "control_name": "Cloud Service Responsibilities",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27017_monitoring(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27017 - CLD.12.1.5 Monitoring Activities."""
        try:
            access_logging = bucket_checks.get("logging", {}).get(
                "is_enabled", False
            )
            notifications_configured = bucket_checks.get(
                "event_notifications", {}
            ).get("has_notifications", False)

            # Monitoring score
            score = 0
            if access_logging:
                score += 60
            if notifications_configured:
                score += 40

            return {
                "iso_control": "27017-CLD.12.1.5",
                "control_name": "Monitoring Activities",
                "is_compliant": score >= 60,
                "compliance_level": (
                    "EXCELLENT"
                    if score >= 90
                    else "GOOD" if score >= 60 else "NON_COMPLIANT"
                ),
                "score": score,
                "monitoring_features": {
                    "access_logging": access_logging,
                    "event_notifications": notifications_configured,
                },
            }
        except Exception as e:
            return {
                "iso_control": "27017-CLD.12.1.5",
                "control_name": "Monitoring Activities",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27017_cloud_logging(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27017 - CLD.12.4.1 Logging Cloud Services."""
        try:
            access_logging = bucket_checks.get("logging", {}).get(
                "is_enabled", False
            )

            # Note: CloudTrail would provide additional cloud service logging
            return {
                "iso_control": "27017-CLD.12.4.1",
                "control_name": "Logging Cloud Services",
                "is_compliant": access_logging,
                "compliance_level": (
                    "GOOD" if access_logging else "NON_COMPLIANT"
                ),
                "access_logging_enabled": access_logging,
                "note": "CloudTrail integration recommended for comprehensive cloud service logging",
            }
        except Exception as e:
            return {
                "iso_control": "27017-CLD.12.4.1",
                "control_name": "Logging Cloud Services",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27017_data_deletion(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27017 - CLD.13.1.1 Information Deletion."""
        try:
            lifecycle_configured = bucket_checks.get(
                "lifecycle_rules", {}
            ).get("has_lifecycle_rules", False)
            versioning_enabled = bucket_checks.get("versioning", {}).get(
                "is_enabled", False
            )

            # Data deletion capabilities
            score = 0
            if lifecycle_configured:
                score += 70
            if versioning_enabled:
                score += 30  # Allows for controlled deletion

            return {
                "iso_control": "27017-CLD.13.1.1",
                "control_name": "Information Deletion",
                "is_compliant": score >= 70,
                "compliance_level": (
                    "EXCELLENT"
                    if score >= 90
                    else "GOOD" if score >= 70 else "NON_COMPLIANT"
                ),
                "score": score,
                "deletion_controls": {
                    "lifecycle_rules": lifecycle_configured,
                    "versioning": versioning_enabled,
                },
            }
        except Exception as e:
            return {
                "iso_control": "27017-CLD.13.1.1",
                "control_name": "Information Deletion",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27017_data_isolation(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27017 - CLD.13.1.2 Information Isolation."""
        try:
            # Tenant isolation through access controls
            public_access_blocked = bucket_checks.get(
                "public_access_block", {}
            ).get("is_properly_configured", False)
            no_cross_account = not bucket_checks.get(
                "cross_account_access", {}
            ).get("has_cross_account_access", True)
            policy_secure = not bucket_checks.get("bucket_policy", {}).get(
                "is_public", True
            )

            # Isolation score
            isolation_controls = [
                public_access_blocked,
                no_cross_account,
                policy_secure,
            ]
            score = (sum(isolation_controls) / len(isolation_controls)) * 100

            return {
                "iso_control": "27017-CLD.13.1.2",
                "control_name": "Information Isolation",
                "is_compliant": score >= 80,
                "compliance_level": (
                    "EXCELLENT"
                    if score >= 90
                    else "GOOD" if score >= 80 else "NON_COMPLIANT"
                ),
                "score": score,
                "isolation_controls": {
                    "public_access_blocked": public_access_blocked,
                    "no_cross_account_access": no_cross_account,
                    "secure_policy": policy_secure,
                },
            }
        except Exception as e:
            return {
                "iso_control": "27017-CLD.13.1.2",
                "control_name": "Information Isolation",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    # Additional ISO 27018 Controls
    def check_iso27018_data_minimization(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27018 - 6.4.1 Data Minimization."""
        try:
            lifecycle_configured = bucket_checks.get(
                "lifecycle_rules", {}
            ).get("has_lifecycle_rules", False)

            # Data minimization score
            score = 0
            if lifecycle_configured:
                score = 85  # Good data minimization through lifecycle

            return {
                "iso_control": "27018-6.4.1",
                "control_name": "Data Minimization",
                "is_compliant": score >= 70,
                "compliance_level": (
                    "EXCELLENT"
                    if score >= 85
                    else "GOOD" if score >= 70 else "NON_COMPLIANT"
                ),
                "score": score,
                "lifecycle_configured": lifecycle_configured,
                "data_minimization_features": {
                    "lifecycle_rules": lifecycle_configured
                },
            }
        except Exception as e:
            return {
                "iso_control": "27018-6.4.1",
                "control_name": "Data Minimization",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27018_retention_deletion(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27018 - 6.5.1 Use, Retention and Deletion."""
        try:
            lifecycle_configured = bucket_checks.get(
                "lifecycle_rules", {}
            ).get("has_lifecycle_rules", False)
            versioning_enabled = bucket_checks.get("versioning", {}).get(
                "is_enabled", False
            )

            # Retention management score
            score = 0
            if lifecycle_configured:
                score += 70
            if versioning_enabled:
                score += 30

            return {
                "iso_control": "27018-6.5.1",
                "control_name": "Use, Retention and Deletion",
                "is_compliant": score >= 70,
                "compliance_level": (
                    "EXCELLENT"
                    if score >= 90
                    else "GOOD" if score >= 70 else "NON_COMPLIANT"
                ),
                "score": score,
                "retention_features": {
                    "lifecycle_rules": lifecycle_configured,
                    "versioning": versioning_enabled,
                },
            }
        except Exception as e:
            return {
                "iso_control": "27018-6.5.1",
                "control_name": "Use, Retention and Deletion",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }

    def check_iso27018_accountability(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check ISO 27018 - 8.2.1 Accountability Policy."""
        try:
            access_logging = bucket_checks.get("logging", {}).get(
                "is_enabled", False
            )

            # Accountability score
            score = 0
            if access_logging:
                score = 75  # Good accountability through logging

            return {
                "iso_control": "27018-8.2.1",
                "control_name": "Accountability Policy",
                "is_compliant": score >= 70,
                "compliance_level": (
                    "GOOD"
                    if score >= 75
                    else "ACCEPTABLE" if score >= 70 else "NON_COMPLIANT"
                ),
                "score": score,
                "accountability_features": {"access_logging": access_logging},
                "note": "Enhanced accountability through comprehensive audit logging",
            }
        except Exception as e:
            return {
                "iso_control": "27018-8.2.1",
                "control_name": "Accountability Policy",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "error": str(e),
            }
