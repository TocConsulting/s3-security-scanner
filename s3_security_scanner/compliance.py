"""Compliance checking module for S3 Security Scanner."""

from typing import Dict, Any, List


class ComplianceChecker:
    """Check S3 bucket compliance against various security frameworks."""

    def __init__(self):
        """Initialize compliance checker with framework definitions."""
        self.frameworks = self._define_frameworks()

    def _define_frameworks(self) -> Dict[str, Dict[str, Any]]:
        """Define compliance framework requirements."""
        return {
            "CIS": {
                "name": "CIS AWS Foundations Benchmark v3.0.0",
                "controls": {
                    "S3.1": {
                        "description": (
                            "S3 buckets should have block public access "
                            "settings enabled"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "public_access_block", {}
                        ).get("is_properly_configured", False),
                    },
                    "S3.5": {
                        "description": (
                            "S3 buckets should require requests to use SSL"
                        ),
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("bucket_policy", {}).get(
                            "ssl_enforced", False
                        ),
                    },
                    "S3.8": {
                        "description": "S3 buckets should block public access",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("is_public", True),
                    },
                    "S3.20": {
                        "description": (
                            "S3 buckets should have MFA delete enabled"
                        ),
                        "severity": "MEDIUM",
                        "check": lambda r: r["versioning"].get(
                            "mfa_delete_enabled", False
                        ),
                    },
                    "S3.22": {
                        "description": (
                            "S3 buckets should have object-level logging "
                            "for write events"
                        ),
                        "severity": "LOW",
                        "check": lambda r: r.get("cloudtrail_s3_22", {}).get(
                            "is_compliant", False
                        ),  # CloudTrail data events for write operations
                    },
                    "S3.23": {
                        "description": (
                            "S3 buckets should have object-level logging "
                            "for read events"
                        ),
                        "severity": "LOW",
                        "check": lambda r: r.get("cloudtrail_s3_23", {}).get(
                            "is_compliant", False
                        ),  # CloudTrail data events for read operations
                    },
                },
            },
            "PCI-DSS": {
                "name": "PCI DSS v4.0 (AWS Config Rules)",
                "controls": {
                    "S3.1": {
                        "description": "S3 buckets should prohibit public access",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("is_public", True),
                    },
                    "S3.5": {
                        "description": "S3 buckets should require requests to use SSL",
                        "severity": "HIGH",
                        "check": lambda r: r.get("bucket_policy", {}).get(
                            "ssl_enforced", False
                        ),
                    },
                    "S3.8": {
                        "description": "S3 buckets should prohibit public read access",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("is_public", True)
                        and r.get("public_access_block", {}).get(
                            "is_properly_configured", False
                        ),
                    },
                    "S3.9": {
                        "description": "S3 buckets should have access logging configured",
                        "severity": "HIGH",
                        "check": lambda r: r.get("logging", {}).get(
                            "is_enabled", False
                        ),
                    },
                    "S3.15": {
                        "description": "S3 buckets should have object lock enabled",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("object_lock", {}).get(
                            "is_enabled", False
                        ),
                    },
                    "S3.17": {
                        "description": "S3 buckets should have server-side encryption enabled",
                        "severity": "HIGH",
                        "check": lambda r: r.get("encryption", {}).get(
                            "is_enabled", False
                        ),
                    },
                    "S3.19": {
                        "description": "S3 buckets should prohibit public write access",
                        "severity": "HIGH",
                        "check": lambda r: not r.get("bucket_acl", {}).get(
                            "has_public_write", False
                        ),
                    },
                    "S3.22": {
                        "description": "S3 bucket level public access should be prohibited",
                        "severity": "HIGH",
                        "check": lambda r: r["public_access_block"][
                            "is_properly_configured"
                        ],
                    },
                    "S3.23": {
                        "description": "S3 buckets should have versioning enabled",
                        "severity": "MEDIUM",
                        "check": lambda r: r["versioning"]["is_enabled"],
                    },
                    "S3.24": {
                        "description": "S3 buckets should have cross-region replication enabled",
                        "severity": "LOW",
                        "check": lambda r: r["replication"].get(
                            "has_replication", False
                        ),
                    },
                },
            },
            "HIPAA": {
                "name": "HIPAA Security Rule (AWS Config Rules)",
                "controls": {
                    "s3-bucket-server-side-encryption-enabled": {
                        "description": (
                            "S3 buckets should have server-side encryption enabled "
                            "(HIPAA §164.312(a)(2)(iv) - Encryption and decryption)"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: r.get("encryption", {}).get(
                            "is_enabled", False
                        ),
                    },
                    "s3-bucket-ssl-requests-only": {
                        "description": (
                            "S3 buckets should require requests to use SSL "
                            "(HIPAA §164.312(e)(1) - Transmission security)"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: r.get("bucket_policy", {}).get(
                            "ssl_enforced", False
                        ),
                    },
                    "s3-bucket-logging-enabled": {
                        "description": (
                            "S3 buckets should have access logging configured "
                            "(HIPAA §164.312(b) - Audit controls)"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: r.get("logging", {}).get(
                            "is_enabled", False
                        ),
                    },
                    "s3-bucket-public-read-prohibited": {
                        "description": (
                            "S3 buckets should prohibit public read access "
                            "(HIPAA §164.312(a)(1) - Access control)"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: not r.get("is_public", True),
                    },
                    "s3-bucket-public-write-prohibited": {
                        "description": (
                            "S3 buckets should prohibit public write access "
                            "(HIPAA §164.312(a)(1) - Access control)"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: not r.get("bucket_acl", {}).get(
                            "has_public_write", False
                        ),
                    },
                    "s3-bucket-versioning-enabled": {
                        "description": (
                            "S3 buckets should have versioning enabled "
                            "(HIPAA §164.308(a)(7)(ii)(A) - Data backup plan)"
                        ),
                        "severity": "MEDIUM",
                        "check": lambda r: r["versioning"]["is_enabled"],
                    },
                    "s3-bucket-default-lock-enabled": {
                        "description": (
                            "S3 buckets should have object lock enabled "
                            "(HIPAA §164.308(a)(1)(ii)(D) - Assigned security responsibility)"
                        ),
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("object_lock", {}).get(
                            "is_enabled", False
                        ),
                    },
                },
            },
            "SOC2": {
                "name": "SOC 2 Type II - AWS S3 Controls Supporting Trust Service Criteria",
                "controls": {
                    # SECURITY (CC) - Mandatory
                    "SOC2-CC-ENCRYPTION-REST": {
                        "description": (
                            "S3 buckets must have server-side encryption enabled "
                            "(TSC CC6.6 - Data Encryption)"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: r.get("encryption", {}).get(
                            "is_enabled", False
                        ),
                    },
                    "SOC2-CC-ENCRYPTION-TRANSIT": {
                        "description": (
                            "S3 buckets must enforce SSL/TLS for data in transit "
                            "(TSC CC6.6 - Data Encryption)"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: r["bucket_policy"].get(
                            "ssl_enforced", False
                        ),
                    },
                    "SOC2-CC-ACCESS-CONTROL": {
                        "description": (
                            "S3 buckets must have proper access controls and block public access "
                            "(TSC CC6.1 - Logical Access)"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "public_access_block", {}
                        ).get("is_properly_configured", False)
                        and not r.get("is_public", True),
                    },
                    "SOC2-CC-MFA-REQUIREMENTS": {
                        "description": (
                            "S3 buckets should require MFA for sensitive operations "
                            "(TSC CC6.2 - User Authentication)"
                        ),
                        "severity": "MEDIUM",
                        "check": lambda r: r["mfa_requirement"].get(
                            "mfa_required", False
                        ),
                    },
                    "SOC2-CC-AUDIT-LOGGING": {
                        "description": (
                            "S3 buckets must have access logging enabled for security monitoring "
                            "(TSC CC7.2 - Security Events)"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: r.get("logging", {}).get(
                            "is_enabled", False
                        ),
                    },
                    "SOC2-CC-KEY-MANAGEMENT": {
                        "description": (
                            "S3 encryption keys must follow proper management practices "
                            "(TSC CC6.8 - Encryption Key Management)"
                        ),
                        "severity": "MEDIUM",
                        "check": lambda r: r["kms_key_management"].get(
                            "kms_managed", False
                        ),
                    },
                    # AVAILABILITY (A) - Optional but Common
                    "SOC2-A-BACKUP-RECOVERY": {
                        "description": (
                            "S3 buckets should have versioning enabled for data recovery "
                            "(TSC A1.2 - Backup Infrastructure)"
                        ),
                        "severity": "MEDIUM",
                        "check": lambda r: r["versioning"]["is_enabled"],
                    },
                    "SOC2-A-REPLICATION": {
                        "description": (
                            "S3 buckets should have cross-region replication for disaster recovery "
                            "(TSC A1.2 - Recovery Infrastructure)"
                        ),
                        "severity": "LOW",
                        "check": lambda r: r["replication"].get(
                            "has_replication", False
                        ),
                    },
                    "SOC2-A-MONITORING": {
                        "description": (
                            "S3 buckets should have CloudWatch monitoring configured "
                            "(TSC A1.3 - System Monitoring)"
                        ),
                        "severity": "MEDIUM",
                        "check": lambda r: r["cloudwatch_monitoring"].get(
                            "monitoring_enabled", False
                        ),
                    },
                    # CONFIDENTIALITY (C) - Optional
                    "SOC2-C-DATA-PROTECTION": {
                        "description": (
                            "S3 buckets containing confidential data must prevent unauthorized access "
                            "(TSC CC6.7 - Data Transmission)"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: not r["cross_account_access"].get(
                            "has_cross_account_access", False
                        )
                        and r["encryption"]["is_enabled"],
                    },
                    # PROCESSING INTEGRITY (PI) - Optional
                    "SOC2-PI-DATA-INTEGRITY": {
                        "description": (
                            "S3 buckets should have object lock enabled to protect data integrity "
                            "(TSC CC8.1 - Data Integrity)"
                        ),
                        "severity": "LOW",
                        "check": lambda r: r.get("object_lock", {}).get(
                            "is_enabled", False
                        ),
                    },
                    # PRIVACY (P) - Optional
                    "SOC2-P-DATA-GOVERNANCE": {
                        "description": (
                            "S3 buckets should implement data governance through Storage Lens "
                            "(TSC P2.1 - Data Management)"
                        ),
                        "severity": "LOW",
                        "check": lambda r: r.get(
                            "storage_lens_config", {}
                        ).get("storage_lens_enabled", False),
                    },
                },
            },
            "ISO27001": {
                "name": "ISO 27001:2022 - Information Security Management Systems",
                "controls": {
                    # Access Control (Chapter 5)
                    "5.15": {
                        "description": "Access control management - S3 bucket policies and IAM integration",
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "iso27001_access_control", {}
                        ).get("is_compliant", False),
                    },
                    "5.18": {
                        "description": "Access rights management - S3 permission governance",
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "iso27001_access_rights", {}
                        ).get("is_compliant", False),
                    },
                    "5.23": {
                        "description": "Information security for use of cloud services - S3 security configuration",
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "iso27001_cloud_service_security", {}
                        ).get("is_compliant", False),
                    },
                    # Cryptographic Controls (Chapter 8)
                    "8.24": {
                        "description": "Use of cryptography - S3 encryption at rest and in transit",
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "iso27001_cryptography", {}
                        ).get("is_compliant", False),
                    },
                    # Operations Security (Chapter 12)
                    "12.3": {
                        "description": "Information backup - S3 versioning and replication",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("iso27001_backup", {}).get(
                            "is_compliant", False
                        ),
                    },
                    "12.4": {
                        "description": "Logging and monitoring - S3 access logging and CloudTrail",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("iso27001_logging", {}).get(
                            "is_compliant", False
                        ),
                    },
                    # Communications Security (Chapter 13)
                    "13.2": {
                        "description": "Information transfer - S3 secure data transmission",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get(
                            "iso27001_info_transfer", {}
                        ).get("is_compliant", False),
                    },
                },
            },
            "ISO27017": {
                "name": "ISO 27017:2015 - Cloud Security Guidelines",
                "controls": {
                    "CLD.6.3.1": {
                        "description": "Restriction of access rights - Cloud-specific S3 access management",
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "iso27017_access_restriction", {}
                        ).get("is_compliant", False),
                    },
                    "CLD.7.1.1": {
                        "description": "Cloud service responsibilities - S3 shared responsibility model compliance",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get(
                            "iso27017_shared_responsibility", {}
                        ).get("is_compliant", False),
                    },
                    "CLD.8.1.4": {
                        "description": "Data and information location - S3 data residency and region controls",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get(
                            "iso27017_data_location", {}
                        ).get("is_compliant", False),
                    },
                    "CLD.12.1.5": {
                        "description": "Monitoring activities - S3 security monitoring and alerting",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get(
                            "iso27017_monitoring", {}
                        ).get("is_compliant", False),
                    },
                    "CLD.12.4.1": {
                        "description": "Logging cloud services - S3 comprehensive audit logging",
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "iso27017_cloud_logging", {}
                        ).get("is_compliant", False),
                    },
                    "CLD.13.1.1": {
                        "description": "Information deletion - S3 secure data deletion and lifecycle",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get(
                            "iso27017_data_deletion", {}
                        ).get("is_compliant", False),
                    },
                    "CLD.13.1.2": {
                        "description": "Information isolation - S3 tenant and data isolation",
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "iso27017_data_isolation", {}
                        ).get("is_compliant", False),
                    },
                },
            },
            "ISO27018": {
                "name": "ISO 27018:2019 - PII Protection in Public Clouds",
                "controls": {
                    "6.2.1": {
                        "description": "Purpose limitation and use limitation - S3 purpose-bound access controls",
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "iso27018_purpose_limitation", {}
                        ).get("is_compliant", False),
                    },
                    "6.4.1": {
                        "description": "Data minimization - S3 storage optimization and data reduction",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get(
                            "iso27018_data_minimization", {}
                        ).get("is_compliant", False),
                    },
                    "6.5.1": {
                        "description": "Use, retention and deletion - S3 lifecycle and retention management",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get(
                            "iso27018_retention_deletion", {}
                        ).get("is_compliant", False),
                    },
                    "8.2.1": {
                        "description": "Accountability policy - S3 data protection accountability measures",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get(
                            "iso27018_accountability", {}
                        ).get("is_compliant", False),
                    },
                },
            },
            "AWS-FSBP": {
                "name": "AWS Foundational Security Best Practices",
                "controls": {
                    "S3.1": {
                        "description": (
                            "S3 general purpose buckets should have block public "
                            "access settings enabled"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "public_access_block", {}
                        ).get("is_properly_configured", False),
                    },
                    "S3.2": {
                        "description": (
                            "S3 general purpose buckets should block public read access"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: not r.get("is_public", True)
                        and not r.get("bucket_acl", {}).get(
                            "has_public_access", False
                        ),
                    },
                    "S3.3": {
                        "description": (
                            "S3 general purpose buckets should block public write access"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: not r.get("bucket_acl", {}).get(
                            "has_public_write", False
                        ),
                    },
                    "S3.5": {
                        "description": (
                            "S3 general purpose buckets should require requests to use SSL"
                        ),
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("bucket_policy", {}).get(
                            "ssl_enforced", False
                        ),
                    },
                    "S3.6": {
                        "description": (
                            "S3 general purpose bucket policies should restrict access "
                            "to other AWS accounts"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: not r["cross_account_access"].get(
                            "has_cross_account_access", False
                        ),
                    },
                    "S3.8": {
                        "description": (
                            "S3 general purpose buckets should block public access"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: not r.get("is_public", True),
                    },
                    "S3.9": {
                        "description": (
                            "S3 general purpose buckets should have server access "
                            "logging enabled"
                        ),
                        "severity": "LOW",
                        "check": lambda r: r.get("logging", {}).get(
                            "is_enabled", False
                        ),
                    },
                    "S3.12": {
                        "description": (
                            "ACLs should not be used to manage user access to S3 "
                            "general purpose buckets"
                        ),
                        "severity": "MEDIUM",
                        "check": lambda r: not r["bucket_acl"].get(
                            "has_acl_grants", False
                        ),
                    },
                    "S3.13": {
                        "description": (
                            "S3 general purpose buckets should have Lifecycle configurations"
                        ),
                        "severity": "LOW",
                        "check": lambda r: r["lifecycle_rules"].get(
                            "has_lifecycle_rules", False
                        ),
                    },
                    "S3.19": {
                        "description": (
                            "S3 access points should have block public access settings enabled"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: r.get("access_points", {}).get(
                            "all_have_public_access_blocked", True
                        ),
                    },
                    "S3.24": {
                        "description": (
                            "S3 Multi-Region Access Points should have block public "
                            "access settings enabled"
                        ),
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "multi_region_access_points", {}
                        ).get("all_have_public_access_blocked", True),
                    },
                },
            },
            "GDPR": {
                "name": "General Data Protection Regulation (EU) 2016/679",
                "controls": {
                    # Article 32 - Security of Processing
                    "G1": {
                        "description": "S3 buckets must have server-side encryption enabled to protect personal data at rest (Article 32(1)(a) - Pseudonymisation and encryption)",
                        "severity": "HIGH",
                        "check": lambda r: r.get("encryption", {}).get(
                            "is_enabled", False
                        ),
                    },
                    "G2": {
                        "description": "S3 buckets must enforce SSL/TLS for all data transfers to protect personal data in transit (Article 32(1)(a) - Pseudonymisation and encryption)",
                        "severity": "HIGH",
                        "check": lambda r: r["bucket_policy"].get(
                            "ssl_enforced", False
                        ),
                    },
                    "G3": {
                        "description": "S3 buckets using KMS encryption must have proper key management practices (Article 32(1)(a) - Security of processing)",
                        "severity": "HIGH",
                        "check": lambda r: r.get("kms_key_management", {}).get(
                            "kms_managed", False
                        ),
                    },
                    "G4": {
                        "description": "S3 buckets must have proper access controls to ensure only authorized access to personal data (Article 32(1)(b) - Confidentiality, integrity, availability)",
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "public_access_block", {}
                        ).get("is_properly_configured", False)
                        and not r.get("is_public", True),
                    },
                    "G5": {
                        "description": "S3 buckets containing personal data must have Block Public Access enabled (Article 32(1)(b) - Confidentiality of processing systems)",
                        "severity": "HIGH",
                        "check": lambda r: r["public_access_block"][
                            "is_properly_configured"
                        ],
                    },
                    "G6": {
                        "description": "S3 buckets must have versioning enabled to prevent accidental data loss (Article 32(1)(c) - Ability to restore availability and access)",
                        "severity": "MEDIUM",
                        "check": lambda r: r["versioning"]["is_enabled"],
                    },
                    "G7": {
                        "description": "S3 buckets with personal data must require MFA for object deletion operations (Article 32(1)(c) - Ability to restore availability and access)",
                        "severity": "MEDIUM",
                        "check": lambda r: r["versioning"].get(
                            "mfa_delete_enabled", False
                        ),
                    },
                    # Article 25 - Data Protection by Design and by Default
                    "G9": {
                        "description": "S3 buckets must have lifecycle policies to automatically delete personal data when no longer needed (Article 25(2) - Data protection by default)",
                        "severity": "MEDIUM",
                        "check": lambda r: r["lifecycle_rules"].get(
                            "has_lifecycle_rules", False
                        ),
                    },
                    "G10": {
                        "description": "S3 bucket policies must restrict access based on specific purposes for processing personal data (Article 5(1)(b) - Purpose limitation)",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get(
                            "gdpr_purpose_limitation", {}
                        ).get("purpose_restricted", False),
                    },
                    # Article 30 - Records of Processing Activities
                    "G11": {
                        "description": "S3 buckets must have server access logging enabled for audit trail of personal data access (Article 30(1) - Records of processing activities)",
                        "severity": "HIGH",
                        "check": lambda r: r.get("logging", {}).get(
                            "is_enabled", False
                        ),
                    },
                    "G12": {
                        "description": "S3 buckets must be monitored via AWS CloudTrail for comprehensive audit logging (Article 30(1) - Records of processing activities)",
                        "severity": "HIGH",
                        "check": lambda r: r.get("cloudtrail_logging", {}).get(
                            "is_enabled", False
                        ),
                    },
                    # Article 33 - Notification of Data Breach
                    "G13": {
                        "description": "S3 buckets must have event notifications configured to detect potential data breaches (Article 33(1) - Notification of personal data breach)",
                        "severity": "MEDIUM",
                        "check": lambda r: r["event_notifications"][
                            "has_notifications"
                        ],
                    },
                    # Article 17 - Right to Erasure (Right to be Forgotten)
                    "G15": {
                        "description": "S3 buckets must have Object Lock properly configured to support legal holds and retention (Article 17(1) - Right to erasure)",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("object_lock", {}).get(
                            "is_enabled", False
                        ),
                    },
                    "G16": {
                        "description": "S3 buckets with cross-region replication must ensure GDPR compliance in all regions (Article 17(1) - Right to erasure across all systems)",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get(
                            "gdpr_replication_compliance", {}
                        ).get("all_regions_compliant", False),
                    },
                    # Article 44-49 - International Data Transfers
                    "G18": {
                        "description": "S3 buckets must be in appropriate regions to comply with data residency requirements (Article 44 - General principle for transfers)",
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "gdpr_data_residency", {}
                        ).get("compliant_region", False),
                    },
                    "G19": {
                        "description": "S3 buckets should not replicate personal data to non-adequate countries without proper safeguards (Article 45 - Transfers on basis of adequacy decision)",
                        "severity": "HIGH",
                        "check": lambda r: r.get(
                            "gdpr_international_transfers", {}
                        ).get("compliant_transfers", False),
                    },
                    # Additional Technical Safeguards
                    "G21": {
                        "description": "S3 Transfer Acceleration should be properly configured with security considerations (Article 32(1) - Appropriate technical measures)",
                        "severity": "LOW",
                        "check": lambda r: r.get(
                            "transfer_acceleration", {}
                        ).get("is_properly_configured", True),
                    },
                    "G22": {
                        "description": "S3 CORS configuration must not expose personal data to unauthorized domains (Article 32(1)(b) - Confidentiality of processing systems)",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("cors", {}).get(
                            "is_risky", True
                        )
                        is False,
                    },
                    "G23": {
                        "description": "S3 static website hosting must have proper security controls if serving personal data (Article 32(1) - Appropriate technical measures)",
                        "severity": "MEDIUM",
                        "check": lambda r: r.get("website_hosting", {}).get(
                            "is_secure", True
                        ),
                    },
                    "G24": {
                        "description": "S3 Inventory should be configured to track personal data storage and management (Article 30(1) - Records of processing activities)",
                        "severity": "LOW",
                        "check": lambda r: r.get("inventory_config", {}).get(
                            "has_inventory", False
                        ),
                    },
                    "G25": {
                        "description": "S3 Analytics configuration should not expose personal data insights inappropriately (Article 32(1) - Appropriate technical measures)",
                        "severity": "LOW",
                        "check": lambda r: r.get("analytics_config", {}).get(
                            "is_secure", True
                        ),
                    },
                },
            },
        }

    def check_bucket_compliance(
        self, bucket_checks: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """Check bucket against all compliance frameworks."""
        compliance_results = {}

        for framework_name, framework in self.frameworks.items():
            results = self._check_framework_compliance(
                bucket_checks, framework
            )
            compliance_results[framework_name] = results

        return compliance_results

    def _check_framework_compliance(
        self, bucket_checks: Dict[str, Any], framework: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check bucket against a specific compliance framework."""
        controls = framework["controls"]
        passed_controls = []
        failed_controls = []

        for control_id, control in controls.items():
            try:
                check_func = control["check"]
                # Evaluate control against bucket configuration
                if check_func(bucket_checks):
                    passed_controls.append(
                        {
                            "id": control_id,
                            "description": control["description"],
                            "severity": control["severity"],
                        }
                    )
                else:
                    failed_controls.append(
                        {
                            "id": control_id,
                            "description": control["description"],
                            "severity": control["severity"],
                        }
                    )
            except Exception as e:
                # If check fails, mark as failed
                failed_controls.append(
                    {
                        "id": control_id,
                        "description": control["description"],
                        "severity": control["severity"],
                        "error": str(e),
                    }
                )

        total_applicable = len(passed_controls) + len(failed_controls)
        compliance_percentage = (
            (len(passed_controls) / total_applicable * 100)
            if total_applicable > 0
            else 0
        )

        return {
            "framework_name": framework["name"],
            "total_controls": len(controls),
            "applicable_controls": total_applicable,
            "passed_controls": len(passed_controls),
            "failed_controls": len(failed_controls),
            "not_applicable_controls": 0,
            "compliance_percentage": round(compliance_percentage, 2),
            "is_compliant": len(failed_controls) == 0,
            "passed": passed_controls,
            "failed": failed_controls,
            "not_applicable": [],
        }

    def get_remediation_steps(
        self, framework: str, control_id: str
    ) -> List[str]:
        """Get remediation steps for a failed control."""
        remediation_map = {
            "CIS": {
                "S3.1": [
                    "Enable S3 Block Public Access at the bucket level:",
                    "aws s3api put-public-access-block --bucket "
                    "BUCKET_NAME \\\\",
                    "  --public-access-block-configuration \\",
                    "  'BlockPublicAcls=true,IgnorePublicAcls=true,"
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                ],
                "S3.5": [
                    "Add a bucket policy to enforce SSL:",
                    "Create a policy that denies all requests where "
                    "aws:SecureTransport is false",
                ],
                "S3.8": [
                    "Remove public access permissions from bucket ACL "
                    "and policy",
                    "Enable S3 Block Public Access settings",
                ],
                "S3.20": [
                    "Enable MFA delete on the bucket:",
                    "aws s3api put-bucket-versioning --bucket BUCKET_NAME \\",
                    "  --versioning-configuration "
                    "Status=Enabled,MFADelete=Enabled \\\\",
                    "  --mfa 'DEVICE_ARN MFA_CODE'",
                ],
                "S3.9": [
                    "Enable server access logging:",
                    "aws s3api put-bucket-logging --bucket BUCKET_NAME \\",
                    "  --bucket-logging-status \\",
                    "  'LoggingEnabled={TargetBucket=LOG_BUCKET,"
                    "TargetPrefix=logs/}'",
                ],
                "S3.17": [
                    "Enable default encryption:",
                    "aws s3api put-bucket-encryption --bucket BUCKET_NAME \\",
                    "  --server-side-encryption-configuration \\",
                    '  \'{"Rules": [{"ApplyServerSideEncryptionByDefault": '
                    '{"SSEAlgorithm": "AES256"}}]}\'',
                ],
                "S3.2": [
                    "Review and update bucket policy to remove wildcard principals:",
                    'Replace "Principal": "*" with specific ARNs',
                    'Use "Principal": {"AWS": "arn:aws:iam::ACCOUNT:user/USER"} instead',
                    "Consider using IAM policies for access control",
                ],
                "S3.6": [
                    "Configure lifecycle rules for cost optimization:",
                    "aws s3api put-bucket-lifecycle-configuration --bucket BUCKET_NAME \\",
                    "  --lifecycle-configuration file://lifecycle.json",
                    "Example: transition to IA after 30 days, Glacier after 90 days",
                ],
                "S3.11": [
                    "Enable event notifications:",
                    "aws s3api put-bucket-notification-configuration --bucket BUCKET_NAME \\",
                    "  --notification-configuration file://notification.json",
                    "Configure SNS, SQS, or Lambda targets for events",
                ],
                "S3.13": [
                    "Enable cross-region replication:",
                    "aws s3api put-bucket-replication --bucket BUCKET_NAME \\",
                    "  --replication-configuration file://replication.json",
                    "Requires versioning enabled and IAM role configured",
                ],
            },
            "PCI-DSS": {
                "S3.1": [
                    "Enable S3 Block Public Access settings on the bucket",
                    "Review and remove public access permissions",
                ],
                "S3.5": [
                    "Enforce SSL/TLS for all connections",
                    "Add bucket policy to deny non-HTTPS requests",
                ],
                "S3.8": [
                    "Enable all S3 Block Public Access settings",
                    "Remove public read permissions from bucket ACLs and policies",
                ],
                "S3.9": [
                    "Enable S3 server access logging",
                    "Configure a target bucket for access logs",
                ],
                "S3.15": [
                    "Enable S3 Object Lock in Governance or Compliance mode",
                    "Set appropriate retention periods for audit trails",
                ],
                "S3.17": [
                    "Enable encryption at rest using SSE-S3 or SSE-KMS",
                    "Consider using customer-managed KMS keys for sensitive data",
                ],
                "S3.19": [
                    "Remove public write permissions from bucket ACLs",
                    "Update bucket policy to deny public write access",
                ],
                "S3.22": [
                    "Enable all four S3 Block Public Access settings",
                    "Apply at both bucket and account level",
                ],
                "S3.23": [
                    "Enable versioning on the S3 bucket",
                    "Consider implementing lifecycle policies for version management",
                ],
                "S3.24": [
                    "Configure cross-region replication to a bucket in another region",
                    "Ensure proper IAM roles for replication",
                ],
            },
            "HIPAA": {
                "s3-bucket-server-side-encryption-enabled": [
                    "Enable encryption for all buckets containing PHI:",
                    "aws s3api put-bucket-encryption --bucket BUCKET_NAME \\",
                    "  --server-side-encryption-configuration \\",
                    '  \'{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "KEY_ID"}}]}\'',
                    "Use SSE-KMS with customer-managed keys for enhanced control",
                ],
                "s3-bucket-ssl-requests-only": [
                    "Enforce HTTPS for all bucket access:",
                    "Add bucket policy to deny non-SSL requests:",
                    "aws s3api put-bucket-policy --bucket BUCKET_NAME \\",
                    '  --policy \'{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::BUCKET_NAME/*","arn:aws:s3:::BUCKET_NAME"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}\'',
                ],
                "s3-bucket-logging-enabled": [
                    "Enable comprehensive logging:",
                    "aws s3api put-bucket-logging --bucket BUCKET_NAME \\",
                    "  --bucket-logging-status 'LoggingEnabled={TargetBucket=LOG_BUCKET,TargetPrefix=access-logs/}'",
                    "Enable CloudTrail for API calls",
                    "Configure CloudWatch alarms for suspicious activity",
                ],
                "s3-bucket-public-read-prohibited": [
                    "Remove public read access:",
                    "aws s3api put-public-access-block --bucket BUCKET_NAME \\",
                    "  --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                    "Review and remove public read permissions from bucket policy",
                ],
                "s3-bucket-public-write-prohibited": [
                    "Remove public write access:",
                    "aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private",
                    "Review bucket policy for public write statements",
                    "Enable Block Public Access settings",
                ],
                "s3-bucket-versioning-enabled": [
                    "Enable versioning for data recovery:",
                    "aws s3api put-bucket-versioning --bucket BUCKET_NAME \\",
                    "  --versioning-configuration Status=Enabled",
                    "Implement regular backup procedures",
                    "Consider cross-region replication for critical PHI",
                ],
                "s3-bucket-default-lock-enabled": [
                    "Enable Object Lock for audit trail protection:",
                    "aws s3api put-object-lock-configuration --bucket BUCKET_NAME \\",
                    "  --object-lock-configuration 'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=GOVERNANCE,Years=1}}'",
                    "Note: Object Lock requires versioning and must be enabled at bucket creation",
                    "Consider using Compliance mode for stricter retention requirements",
                ],
            },
            "SOC2": {
                "SOC2-CC-ENCRYPTION-REST": [
                    "Enable S3 server-side encryption:",
                    "aws s3api put-bucket-encryption --bucket BUCKET_NAME \\",
                    '  --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}\'',
                    "For enhanced security, use SSE-KMS:",
                    "aws s3api put-bucket-encryption --bucket BUCKET_NAME \\",
                    '  --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"KEY_ID"}}]}\'',
                ],
                "SOC2-CC-ENCRYPTION-TRANSIT": [
                    "Add bucket policy to enforce SSL:",
                    "aws s3api put-bucket-policy --bucket BUCKET_NAME \\",
                    '  --policy \'{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::BUCKET_NAME/*","arn:aws:s3:::BUCKET_NAME"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}\'',
                ],
                "SOC2-CC-ACCESS-CONTROL": [
                    "Enable S3 Block Public Access settings:",
                    "aws s3api put-public-access-block --bucket BUCKET_NAME \\",
                    "  --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                    "Review and remove any public access permissions",
                ],
                "SOC2-CC-MFA-REQUIREMENTS": [
                    "Implement MFA requirements in bucket policy:",
                    "Add conditions to require MFA for sensitive operations:",
                    '"Condition": {',
                    '  "Bool": {"aws:MultiFactorAuthPresent": "true"},',
                    '  "NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}',
                    "}",
                ],
                "SOC2-CC-AUDIT-LOGGING": [
                    "Enable S3 server access logging:",
                    "aws s3api put-bucket-logging --bucket BUCKET_NAME \\",
                    "  --bucket-logging-status 'LoggingEnabled={TargetBucket=LOG_BUCKET,TargetPrefix=access-logs/}'",
                    "Enable CloudTrail for API calls and consider CloudWatch integration",
                ],
                "SOC2-CC-KEY-MANAGEMENT": [
                    "Implement proper KMS key management:",
                    "1. Enable key rotation for customer-managed keys:",
                    "aws kms enable-key-rotation --key-id KEY_ID",
                    "2. Review and update key policies for least privilege",
                    "3. Implement regular key policy audits",
                ],
                "SOC2-A-BACKUP-RECOVERY": [
                    "Enable S3 bucket versioning:",
                    "aws s3api put-bucket-versioning --bucket BUCKET_NAME \\",
                    "  --versioning-configuration Status=Enabled",
                    "Consider implementing lifecycle policies for version management",
                ],
                "SOC2-A-REPLICATION": [
                    "Configure cross-region replication:",
                    "aws s3api put-bucket-replication --bucket BUCKET_NAME \\",
                    "  --replication-configuration file://replication-config.json",
                    "Note: Requires versioning enabled and proper IAM role",
                ],
                "SOC2-A-MONITORING": [
                    "Enable CloudWatch monitoring for S3:",
                    "1. Enable S3 request metrics:",
                    "aws s3api put-bucket-metrics-configuration --bucket BUCKET_NAME \\",
                    "  --id EntireBucket --metrics-configuration Id=EntireBucket",
                    "2. Create CloudWatch alarms for critical metrics",
                    "3. Monitor storage usage and request patterns",
                ],
                "SOC2-C-DATA-PROTECTION": [
                    "Ensure data protection and access controls:",
                    "1. Review and restrict cross-account access in bucket policy",
                    "2. Verify encryption is enabled for confidential data",
                    "3. Add conditions to cross-account statements for trusted accounts only",
                    "4. Consider using AWS Organizations for account management",
                ],
                "SOC2-PI-DATA-INTEGRITY": [
                    "Enable S3 Object Lock for data integrity:",
                    "aws s3api put-object-lock-configuration --bucket BUCKET_NAME \\",
                    "  --object-lock-configuration 'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=GOVERNANCE,Years=1}}'",
                    "Note: Object Lock requires versioning and must be enabled at bucket creation",
                ],
                "SOC2-P-DATA-GOVERNANCE": [
                    "Configure S3 Storage Lens:",
                    "1. Enable the default Storage Lens configuration:",
                    "aws s3control put-storage-lens-configuration \\",
                    "  --config-id default-account-dashboard \\",
                    "  --storage-lens-configuration file://storage-lens-config.json",
                    "2. Enable advanced metrics and recommendations",
                    "3. Set up data export to S3 for analysis",
                ],
            },
            "AWS-FSBP": {
                "S3.1": [
                    "Enable S3 Block Public Access at the bucket level:",
                    "aws s3api put-public-access-block --bucket BUCKET_NAME \\",
                    "  --public-access-block-configuration \\",
                    "  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                ],
                "S3.2": [
                    "Block public read access by ensuring:",
                    "1. Enable Block Public Access settings",
                    "2. Review and remove public read permissions from ACLs:",
                    "aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private",
                    "3. Remove public read statements from bucket policy",
                ],
                "S3.3": [
                    "Block public write access:",
                    "1. Enable Block Public Access settings",
                    "2. Review ACL grants for WRITE permissions:",
                    "aws s3api get-bucket-acl --bucket BUCKET_NAME",
                    "3. Remove any public write grants:",
                    "aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private",
                    "4. Review bucket policy for public write statements",
                ],
                "S3.5": [
                    "Enforce SSL/TLS for all requests:",
                    "Add a bucket policy to deny non-HTTPS requests:",
                    "{",
                    '  "Version": "2012-10-17",',
                    '  "Statement": [{',
                    '    "Effect": "Deny",',
                    '    "Principal": "*",',
                    '    "Action": "s3:*",',
                    '    "Resource": ["arn:aws:s3:::BUCKET_NAME/*", "arn:aws:s3:::BUCKET_NAME"],',
                    '    "Condition": {"Bool": {"aws:SecureTransport": "false"}}',
                    "  }]",
                    "}",
                ],
                "S3.6": [
                    "Restrict cross-account access:",
                    "1. Review bucket policy for cross-account principals",
                    "2. Add conditions to limit access:",
                    "aws s3api get-bucket-policy --bucket BUCKET_NAME",
                    "3. Use aws:SourceAccount condition for trusted accounts:",
                    '"Condition": {"StringEquals": {"aws:SourceAccount": "TRUSTED_ACCOUNT_ID"}}',
                    "4. Consider using AWS Organizations for account management",
                ],
                "S3.8": [
                    "Comprehensively block all public access:",
                    "1. Enable all Block Public Access settings",
                    "2. Remove public ACL grants",
                    "3. Remove public bucket policy statements",
                    "4. Verify no public access through all methods:",
                    "aws s3api get-bucket-acl --bucket BUCKET_NAME",
                    "aws s3api get-bucket-policy --bucket BUCKET_NAME",
                ],
                "S3.9": [
                    "Enable server access logging:",
                    "aws s3api put-bucket-logging --bucket BUCKET_NAME \\",
                    "  --bucket-logging-status \\",
                    "  'LoggingEnabled={TargetBucket=LOG_BUCKET,TargetPrefix=access-logs/}'",
                    "Note: Ensure the target bucket exists and has appropriate permissions",
                ],
                "S3.12": [
                    "Minimize ACL usage and prefer bucket policies:",
                    "1. Review current ACL grants:",
                    "aws s3api get-bucket-acl --bucket BUCKET_NAME",
                    "2. Migrate ACL permissions to bucket policy",
                    "3. Set bucket to private ACL:",
                    "aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private",
                    "4. Use bucket policies for access management instead",
                ],
                "S3.13": [
                    "Configure lifecycle rules for cost optimization:",
                    "aws s3api put-bucket-lifecycle-configuration --bucket BUCKET_NAME \\",
                    "  --lifecycle-configuration file://lifecycle.json",
                    "Example lifecycle.json:",
                    "{",
                    '  "Rules": [{',
                    '    "ID": "CostOptimization",',
                    '    "Status": "Enabled",',
                    '    "Transitions": [',
                    '      {"Days": 30, "StorageClass": "STANDARD_IA"},',
                    '      {"Days": 90, "StorageClass": "GLACIER"}',
                    "    ]",
                    "  }]",
                    "}",
                ],
                "S3.19": [
                    "Enable Block Public Access for S3 Access Points:",
                    "1. List existing access points:",
                    "aws s3control list-access-points --account-id ACCOUNT_ID",
                    "2. Configure public access block for each access point:",
                    "aws s3control put-access-point-public-access-block \\",
                    "  --account-id ACCOUNT_ID --name ACCESS_POINT_NAME \\",
                    "  --public-access-block-configuration \\",
                    "  'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                ],
                "S3.24": [
                    "Configure Multi-Region Access Points with public access blocking:",
                    "1. List Multi-Region Access Points:",
                    "aws s3control list-multi-region-access-points --account-id ACCOUNT_ID",
                    "2. Create MRAP with public access blocked:",
                    "aws s3control create-multi-region-access-point \\",
                    "  --account-id ACCOUNT_ID \\",
                    "  --details file://mrap-config.json",
                    "3. Ensure PublicAccessBlock is configured in the MRAP policy",
                    "Note: MRAP creation requires multiple regions and proper IAM permissions",
                ],
            },
            "ISO27001": {
                "5.15": [
                    "Implement comprehensive access control management:",
                    "1. Enable S3 Block Public Access settings:",
                    "aws s3api put-public-access-block --bucket BUCKET_NAME \\",
                    "  --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                    "2. Review and restrict bucket policy principals:",
                    "Replace wildcard principals with specific ARNs",
                    "3. Remove public ACL grants:",
                    "aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private",
                    "4. Implement MFA requirements for sensitive operations",
                ],
                "5.18": [
                    "Implement proper access rights management:",
                    "1. Enable S3 Block Public Access settings:",
                    "aws s3api put-public-access-block --bucket BUCKET_NAME \\",
                    "  --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                    "2. Review bucket policy for least privilege:",
                    "Update bucket policy to use specific principals instead of wildcards",
                    "3. Set bucket ACL to private:",
                    "aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private",
                    "4. Audit IAM roles and users with S3 access",
                ],
                "5.23": [
                    "Ensure information security for cloud services:",
                    "1. Enable encryption at rest:",
                    "aws s3api put-bucket-encryption --bucket BUCKET_NAME \\",
                    '  --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}\'',
                    "2. Enable SSL/TLS enforcement:",
                    "aws s3api put-bucket-policy --bucket BUCKET_NAME \\",
                    '  --policy \'{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::BUCKET_NAME/*","arn:aws:s3:::BUCKET_NAME"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}\'',
                    "3. Enable versioning:",
                    "aws s3api put-bucket-versioning --bucket BUCKET_NAME --versioning-configuration Status=Enabled",
                    "4. Enable server access logging:",
                    "aws s3api put-bucket-logging --bucket BUCKET_NAME \\",
                    "  --bucket-logging-status 'LoggingEnabled={TargetBucket=LOG_BUCKET,TargetPrefix=access-logs/}'",
                ],
                "8.24": [
                    "Implement proper use of cryptography:",
                    "1. Enable server-side encryption:",
                    "aws s3api put-bucket-encryption --bucket BUCKET_NAME \\",
                    '  --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}\'',
                    "2. For enhanced security, use SSE-KMS:",
                    "aws s3api put-bucket-encryption --bucket BUCKET_NAME \\",
                    '  --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"KEY_ID"}}]}\'',
                    "3. Enforce SSL/TLS in transit:",
                    "Add bucket policy to deny non-HTTPS requests",
                    "4. Enable bucket key for KMS cost optimization:",
                    "aws s3api put-bucket-encryption --bucket BUCKET_NAME \\",
                    '  --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"KEY_ID"},"BucketKeyEnabled":true}]}\'',
                ],
                "12.3": [
                    "Implement information backup strategies:",
                    "1. Enable bucket versioning:",
                    "aws s3api put-bucket-versioning --bucket BUCKET_NAME --versioning-configuration Status=Enabled",
                    "2. Configure cross-region replication:",
                    "aws s3api put-bucket-replication --bucket BUCKET_NAME \\",
                    "  --replication-configuration file://replication-config.json",
                    "3. Enable MFA Delete for additional protection:",
                    "aws s3api put-bucket-versioning --bucket BUCKET_NAME \\",
                    "  --versioning-configuration Status=Enabled,MFADelete=Enabled \\",
                    "  --mfa 'DEVICE_ARN MFA_CODE'",
                    "Note: MFA Delete requires root account or IAM user with appropriate permissions",
                ],
                "12.4": [
                    "Implement logging and monitoring:",
                    "1. Enable S3 server access logging:",
                    "aws s3api put-bucket-logging --bucket BUCKET_NAME \\",
                    "  --bucket-logging-status 'LoggingEnabled={TargetBucket=LOG_BUCKET,TargetPrefix=access-logs/}'",
                    "2. Enable CloudTrail for API logging:",
                    "aws cloudtrail create-trail --name s3-audit-trail \\",
                    "  --s3-bucket-name TRAIL_BUCKET",
                    "3. Configure S3 request metrics:",
                    "aws s3api put-bucket-metrics-configuration --bucket BUCKET_NAME \\",
                    "  --id EntireBucket --metrics-configuration Id=EntireBucket",
                    "4. Set up CloudWatch alarms for monitoring",
                ],
                "13.2": [
                    "Ensure secure information transfer:",
                    "1. Enforce SSL/TLS for all requests:",
                    "aws s3api put-bucket-policy --bucket BUCKET_NAME \\",
                    '  --policy \'{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::BUCKET_NAME/*","arn:aws:s3:::BUCKET_NAME"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}\'',
                    "2. Verify bucket policy denies HTTP requests:",
                    "aws s3api get-bucket-policy --bucket BUCKET_NAME",
                    "3. Test SSL enforcement:",
                    "curl -I http://BUCKET_NAME.s3.amazonaws.com/ (should return 403)",
                ],
            },
            "ISO27017": {
                "CLD.6.3.1": [
                    "Implement restriction of access rights (cloud-specific):",
                    "1. Enable S3 Block Public Access settings:",
                    "aws s3api put-public-access-block --bucket BUCKET_NAME \\",
                    "  --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                    "2. Review and restrict bucket policy:",
                    "Remove or restrict wildcard principals",
                    "3. Set bucket ACL to private:",
                    "aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private",
                    "4. Implement cloud-specific access controls using IAM conditions",
                ],
                "CLD.7.1.1": [
                    "Ensure cloud service responsibilities are met:",
                    "1. Customer responsibility - Enable encryption:",
                    "aws s3api put-bucket-encryption --bucket BUCKET_NAME \\",
                    '  --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}\'',
                    "2. Customer responsibility - Enable versioning:",
                    "aws s3api put-bucket-versioning --bucket BUCKET_NAME --versioning-configuration Status=Enabled",
                    "3. Customer responsibility - Enable logging:",
                    "aws s3api put-bucket-logging --bucket BUCKET_NAME \\",
                    "  --bucket-logging-status 'LoggingEnabled={TargetBucket=LOG_BUCKET,TargetPrefix=access-logs/}'",
                    "4. Customer responsibility - Configure backup/replication:",
                    "aws s3api put-bucket-replication --bucket BUCKET_NAME \\",
                    "  --replication-configuration file://replication-config.json",
                ],
                "CLD.8.1.4": [
                    "Manage data and information location:",
                    "1. Verify bucket region:",
                    "aws s3api get-bucket-location --bucket BUCKET_NAME",
                    "2. Configure cross-region replication with region restrictions:",
                    "aws s3api put-bucket-replication --bucket BUCKET_NAME \\",
                    "  --replication-configuration file://replication-config.json",
                    "3. Review replication destination regions for compliance",
                    "4. Document data residency requirements and verify compliance",
                ],
                "CLD.12.1.5": [
                    "Implement monitoring activities:",
                    "1. Enable S3 server access logging:",
                    "aws s3api put-bucket-logging --bucket BUCKET_NAME \\",
                    "  --bucket-logging-status 'LoggingEnabled={TargetBucket=LOG_BUCKET,TargetPrefix=access-logs/}'",
                    "2. Configure S3 event notifications:",
                    "aws s3api put-bucket-notification-configuration --bucket BUCKET_NAME \\",
                    "  --notification-configuration file://notification-config.json",
                    "3. Set up CloudWatch monitoring:",
                    "aws s3api put-bucket-metrics-configuration --bucket BUCKET_NAME \\",
                    "  --id EntireBucket --metrics-configuration Id=EntireBucket",
                    "4. Configure alerts for security events",
                ],
                "CLD.12.4.1": [
                    "Implement logging for cloud services:",
                    "1. Enable S3 server access logging:",
                    "aws s3api put-bucket-logging --bucket BUCKET_NAME \\",
                    "  --bucket-logging-status 'LoggingEnabled={TargetBucket=LOG_BUCKET,TargetPrefix=access-logs/}'",
                    "2. Enable CloudTrail for comprehensive API logging:",
                    "aws cloudtrail create-trail --name s3-audit-trail \\",
                    "  --s3-bucket-name TRAIL_BUCKET",
                    "3. Consider VPC Flow Logs for network-level logging",
                    "4. Implement log analysis and alerting",
                ],
                "CLD.13.1.1": [
                    "Implement secure information deletion:",
                    "1. Configure bucket lifecycle policies:",
                    "aws s3api put-bucket-lifecycle-configuration --bucket BUCKET_NAME \\",
                    "  --lifecycle-configuration file://lifecycle-config.json",
                    "2. Enable versioning for controlled deletion:",
                    "aws s3api put-bucket-versioning --bucket BUCKET_NAME --versioning-configuration Status=Enabled",
                    "3. Consider S3 Object Lock for compliance requirements:",
                    "aws s3api put-object-lock-configuration --bucket BUCKET_NAME \\",
                    "  --object-lock-configuration 'ObjectLockEnabled=Enabled'",
                    "4. Implement secure deletion procedures for sensitive data",
                ],
                "CLD.13.1.2": [
                    "Implement information isolation:",
                    "1. Enable S3 Block Public Access settings:",
                    "aws s3api put-public-access-block --bucket BUCKET_NAME \\",
                    "  --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                    "2. Review and restrict cross-account access:",
                    "Remove or restrict cross-account principals in bucket policy",
                    "3. Implement tenant isolation through bucket policies:",
                    "Use conditions to restrict access based on requester account",
                    "4. Set bucket ACL to private:",
                    "aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private",
                ],
            },
            "ISO27018": {
                "6.2.1": [
                    "Implement purpose limitation and use limitation:",
                    "1. Add purpose tags to S3 buckets:",
                    "aws s3api put-bucket-tagging --bucket BUCKET_NAME \\",
                    '  --tagging \'TagSet=[{"Key":"DataPurpose","Value":"Marketing"},{"Key":"ProcessingBasis","Value":"Consent"}]\'',
                    "2. Configure bucket policy with purpose-based conditions:",
                    "Add conditions to restrict access based on intended use",
                    "3. Document data processing purposes and update policies accordingly",
                    "4. Regular review of access patterns against stated purposes",
                ],
                "6.4.1": [
                    "Implement data minimization:",
                    "1. Configure lifecycle policies to reduce storage:",
                    "aws s3api put-bucket-lifecycle-configuration --bucket BUCKET_NAME \\",
                    "  --lifecycle-configuration file://lifecycle-config.json",
                    "2. Example lifecycle rule for data minimization:",
                    "Transition to IA after 30 days, delete after 365 days",
                    "3. Enable Storage Class Analysis:",
                    "aws s3api put-bucket-analytics-configuration --bucket BUCKET_NAME \\",
                    "  --id DataMinimization --analytics-configuration file://analytics-config.json",
                    "4. Regular review of stored data for necessity",
                ],
                "6.5.1": [
                    "Implement proper use, retention and deletion:",
                    "1. Configure comprehensive lifecycle policies:",
                    "aws s3api put-bucket-lifecycle-configuration --bucket BUCKET_NAME \\",
                    "  --lifecycle-configuration file://lifecycle-config.json",
                    "2. Enable versioning for controlled retention:",
                    "aws s3api put-bucket-versioning --bucket BUCKET_NAME --versioning-configuration Status=Enabled",
                    "3. Set up automated deletion based on retention requirements:",
                    "Configure expiration actions in lifecycle rules",
                    "4. Document retention periods and legal requirements",
                ],
                "8.2.1": [
                    "Implement accountability policy:",
                    "1. Enable comprehensive S3 access logging:",
                    "aws s3api put-bucket-logging --bucket BUCKET_NAME \\",
                    "  --bucket-logging-status 'LoggingEnabled={TargetBucket=LOG_BUCKET,TargetPrefix=access-logs/}'",
                    "2. Add accountability tags to buckets:",
                    "aws s3api put-bucket-tagging --bucket BUCKET_NAME \\",
                    '  --tagging \'TagSet=[{"Key":"DataController","Value":"CompanyName"},{"Key":"ContactDPO","Value":"dpo@company.com"}]\'',
                    "3. Enable CloudTrail for API call accountability:",
                    "aws cloudtrail create-trail --name s3-accountability-trail \\",
                    "  --s3-bucket-name TRAIL_BUCKET",
                    "4. Implement regular audit reports and accountability measures",
                ],
            },
            "GDPR": {
                "G1": [
                    "Enable server-side encryption for personal data protection:",
                    "aws s3api put-bucket-encryption --bucket BUCKET_NAME \\",
                    '  --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}\'',
                    "For enhanced protection, use SSE-KMS:",
                    "aws s3api put-bucket-encryption --bucket BUCKET_NAME \\",
                    '  --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"KEY_ID"}}]}\'',
                ],
                "G2": [
                    "Enforce SSL/TLS for all data transfers (GDPR Article 32):",
                    "aws s3api put-bucket-policy --bucket BUCKET_NAME \\",
                    '  --policy \'{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::BUCKET_NAME/*","arn:aws:s3:::BUCKET_NAME"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}\'',
                ],
                "G3": [
                    "Implement proper KMS key management:",
                    "1. Enable key rotation:",
                    "aws kms enable-key-rotation --key-id KEY_ID",
                    "2. Review key policies for least privilege access",
                    "3. Implement key usage monitoring and auditing",
                ],
                "G4": [
                    "Implement proper access controls for personal data:",
                    "aws s3api put-public-access-block --bucket BUCKET_NAME \\",
                    "  --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                    "Review and remove any public access permissions from bucket policy",
                ],
                "G5": [
                    "Enable Block Public Access settings:",
                    "aws s3api put-public-access-block --bucket BUCKET_NAME \\",
                    "  --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'",
                ],
                "G6": [
                    "Enable versioning for data loss prevention:",
                    "aws s3api put-bucket-versioning --bucket BUCKET_NAME \\",
                    "  --versioning-configuration Status=Enabled",
                ],
                "G7": [
                    "Enable MFA Delete for enhanced protection:",
                    "aws s3api put-bucket-versioning --bucket BUCKET_NAME \\",
                    "  --versioning-configuration Status=Enabled,MFADelete=Enabled \\",
                    "  --mfa 'DEVICE_ARN MFA_CODE'",
                    "Note: Requires root credentials or IAM user with appropriate permissions",
                ],
                "G9": [
                    "Configure lifecycle policies for data minimization:",
                    "aws s3api put-bucket-lifecycle-configuration --bucket BUCKET_NAME \\",
                    "  --lifecycle-configuration file://gdpr-lifecycle.json",
                    "Example: Delete personal data after retention period expires",
                ],
                "G10": [
                    "Implement purpose limitation in bucket policies:",
                    "Add conditions to bucket policy to restrict access based on processing purpose",
                    "Use resource tags to categorize data by purpose",
                    "Document processing purposes and update policies accordingly",
                ],
                "G11": [
                    "Enable comprehensive audit logging:",
                    "aws s3api put-bucket-logging --bucket BUCKET_NAME \\",
                    "  --bucket-logging-status 'LoggingEnabled={TargetBucket=LOG_BUCKET,TargetPrefix=gdpr-access-logs/}'",
                ],
                "G12": [
                    "Enable CloudTrail for comprehensive audit trail:",
                    "aws cloudtrail create-trail --name gdpr-s3-trail \\",
                    "  --s3-bucket-name TRAIL_BUCKET",
                    "Enable data events for S3 object-level operations",
                ],
                "G13": [
                    "Configure event notifications for breach detection:",
                    "aws s3api put-bucket-notification-configuration --bucket BUCKET_NAME \\",
                    "  --notification-configuration file://gdpr-notifications.json",
                    "Configure SNS/SQS/Lambda for security event monitoring",
                ],
                "G15": [
                    "Enable Object Lock for legal holds and retention:",
                    "aws s3api put-object-lock-configuration --bucket BUCKET_NAME \\",
                    "  --object-lock-configuration 'ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=GOVERNANCE,Years=1}}'",
                    "Note: Must be enabled at bucket creation",
                ],
                "G16": [
                    "Ensure GDPR compliance across replication regions:",
                    "Review replication destination regions for adequacy decisions",
                    "Implement appropriate safeguards for international transfers",
                    "Document compliance measures for each replication target",
                ],
                "G18": [
                    "Verify bucket region compliance with data residency:",
                    "aws s3api get-bucket-location --bucket BUCKET_NAME",
                    "Move bucket to compliant region if necessary",
                    "Document data residency requirements and compliance",
                ],
                "G19": [
                    "Review and restrict international data transfers:",
                    "aws s3api get-bucket-replication --bucket BUCKET_NAME",
                    "Ensure replication targets are in adequate countries or have proper safeguards",
                    "Implement appropriate transfer mechanisms (BCRs, SCCs, etc.)",
                ],
                "G21": [
                    "Configure Transfer Acceleration securely:",
                    "aws s3api put-bucket-accelerate-configuration --bucket BUCKET_NAME \\",
                    "  --accelerate-configuration Status=Enabled",
                    "Ensure SSL/TLS enforcement remains in effect",
                ],
                "G22": [
                    "Review and secure CORS configuration:",
                    "aws s3api get-bucket-cors --bucket BUCKET_NAME",
                    "Remove or restrict overly permissive CORS rules",
                    "Ensure only authorized domains can access personal data",
                ],
                "G23": [
                    "Secure static website hosting configuration:",
                    "Review website hosting configuration for security risks",
                    "Implement appropriate access controls for personal data",
                    "Consider disabling website hosting for buckets with personal data",
                ],
                "G24": [
                    "Configure S3 Inventory for data governance:",
                    "aws s3api put-bucket-inventory-configuration --bucket BUCKET_NAME \\",
                    "  --id GDPRInventory --inventory-configuration file://inventory-config.json",
                    "Track personal data storage and management",
                ],
                "G25": [
                    "Secure analytics configuration:",
                    "Review analytics configurations for personal data exposure",
                    "Implement appropriate access controls for analytics data",
                    "Consider data anonymization for analytics purposes",
                ],
            },
        }

        return remediation_map.get(framework, {}).get(
            control_id, ["No specific remediation steps available"]
        )
