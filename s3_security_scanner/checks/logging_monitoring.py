"""Logging and Monitoring Checks for S3 Buckets."""

from typing import Dict, Any


class LoggingMonitoringChecker:
    """Checks for S3 bucket logging and monitoring configurations."""

    def __init__(self, session=None):
        """Initialize the logging monitoring checker.

        Args:
            session: Boto3 session for AWS API calls
        """
        self.session = session

    def check_logging(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check if logging is enabled for the bucket."""
        try:
            response = client.get_bucket_logging(Bucket=bucket_name)
            logging_config = response.get("LoggingEnabled", None)

            if logging_config:
                return {
                    "is_enabled": True,
                    "target_bucket": logging_config.get("TargetBucket"),
                    "target_prefix": logging_config.get("TargetPrefix"),
                }
            else:
                return {"is_enabled": False, "details": "Logging not enabled"}

        except Exception as e:
            return {"is_enabled": False, "details": f"Error: {str(e)}"}

    def check_cloudtrail_bucket_logging(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if a CloudTrail logging bucket has its own access logging.

        CloudTrail buckets should have server access logging enabled
        for security and compliance.

        Args:
            bucket_name: Name of the bucket
            client: S3 client

        Returns:
            Dict with CloudTrail bucket logging status
        """
        # First check if this is a CloudTrail bucket
        is_cloudtrail_bucket = False

        # Common CloudTrail bucket naming patterns
        cloudtrail_patterns = [
            'cloudtrail', 'cloud-trail', 'aws-cloudtrail',
            'audit', 'logs', 'logging'
        ]

        for pattern in cloudtrail_patterns:
            if pattern in bucket_name.lower():
                is_cloudtrail_bucket = True
                break

        # Also check bucket policy for CloudTrail service principal
        try:
            policy_response = client.get_bucket_policy(Bucket=bucket_name)
            if 'cloudtrail.amazonaws.com' in policy_response.get('Policy', ''):
                is_cloudtrail_bucket = True
        except Exception:
            pass

        # If not a CloudTrail bucket, return N/A
        if not is_cloudtrail_bucket:
            return {
                'is_cloudtrail_bucket': False,
                'logging_enabled': None,
                'applicable': False
            }

        # Check logging for CloudTrail bucket
        logging_status = self.check_logging(bucket_name, client)

        return {
            'is_cloudtrail_bucket': True,
            'logging_enabled': logging_status.get('is_enabled', False),
            'logging_target': logging_status.get('target_bucket'),
            'applicable': True,
            'recommendation': (
                "CloudTrail buckets must have server access logging enabled "
                "for audit trail integrity" if not logging_status.get('is_enabled')
                else "CloudTrail bucket logging is properly configured"
            )
        }
