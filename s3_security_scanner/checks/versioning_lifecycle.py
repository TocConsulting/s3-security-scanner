"""Versioning and Lifecycle Checks for S3 Buckets."""

from typing import Dict, Any
from botocore.exceptions import ClientError
from .base import BaseChecker


class VersioningLifecycleChecker(BaseChecker):
    """Checks for S3 bucket versioning and lifecycle configurations."""

    def check_versioning(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check if versioning is enabled for the bucket."""
        try:
            response = client.get_bucket_versioning(Bucket=bucket_name)
            status = response.get("Status", "Disabled")
            mfa_delete = response.get("MFADelete", "Disabled")

            return {
                "is_enabled": status == "Enabled",
                "status": status,
                "mfa_delete_enabled": mfa_delete == "Enabled",
            }

        except Exception as e:
            return {
                "is_enabled": False,
                "status": "Error",
                "mfa_delete_enabled": False,
                "error": str(e),
            }

    def check_lifecycle_rules(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if lifecycle rules are configured for the bucket."""
        try:
            response = client.get_bucket_lifecycle_configuration(
                Bucket=bucket_name
            )
            rules = response.get("Rules", [])
            enabled_rules = [
                rule for rule in rules if rule.get("Status") == "Enabled"
            ]

            return {
                "has_lifecycle_rules": len(enabled_rules) > 0,
                "rule_count": len(enabled_rules),
                "rules": enabled_rules,
            }

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
                return {
                    "has_lifecycle_rules": False,
                    "rule_count": 0,
                    "rules": [],
                }
            else:
                return {
                    "has_lifecycle_rules": False,
                    "rule_count": 0,
                    "rules": [],
                    "error": str(e),
                }

    def check_object_lock(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check object lock configuration."""
        try:
            response = client.get_object_lock_configuration(Bucket=bucket_name)
            return {
                "is_enabled": True,
                "mode": response["ObjectLockConfiguration"][
                    "ObjectLockEnabled"
                ],
                "rule": response["ObjectLockConfiguration"].get("Rule"),
            }
        except ClientError as e:
            if (
                e.response["Error"]["Code"]
                == "ObjectLockConfigurationNotFoundError"
            ):
                return {"is_enabled": False}
            else:
                return {"is_enabled": False, "error": str(e)}
