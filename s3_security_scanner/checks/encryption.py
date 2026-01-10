"""Encryption and Data Protection Checks for S3 Buckets."""

from typing import Dict, Any
from botocore.exceptions import ClientError
from .base import BaseChecker


class EncryptionChecker(BaseChecker):
    """Checks for S3 bucket encryption and data protection configurations."""

    def check_encryption(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check if default encryption is enabled for the bucket."""
        try:
            response = client.get_bucket_encryption(Bucket=bucket_name)
            rules = response.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )

            if not rules:
                return {
                    "is_enabled": False,
                    "details": "No encryption rules found",
                }

            encryption_details = rules[0].get(
                "ApplyServerSideEncryptionByDefault", {}
            )
            algorithm = encryption_details.get("SSEAlgorithm")

            return {
                "is_enabled": True,
                "algorithm": algorithm,
                "kms_master_key_id": encryption_details.get("KMSMasterKeyID"),
            }

        except ClientError as e:
            if (
                e.response["Error"]["Code"]
                == "ServerSideEncryptionConfigurationNotFoundError"
            ):
                return {
                    "is_enabled": False,
                    "details": "Default encryption not configured",
                }
            else:
                return self.handle_client_error(e)
        except Exception as e:
            return {
                "is_enabled": False,
                "details": f"Unexpected error: {str(e)}",
            }
