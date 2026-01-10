"""SOC 2 Monitoring and Compliance Checks for S3 Buckets."""

import json
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List
from botocore.exceptions import ClientError
import boto3


class SOC2MonitoringChecker:
    """Checks for SOC 2 monitoring, key management, and governance configurations."""

    def __init__(self, session_factory, region: str):
        """Initialize SOC 2 monitoring checker."""
        self.session_factory = session_factory
        self.region = region
        # Don't create clients in __init__ as they may be called from different threads

    def check_kms_key_management(
        self,
        bucket_name: str,
        s3_client,
        encryption_config: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Check KMS key management for bucket encryption."""
        try:
            # If no encryption config provided, get it
            if not encryption_config:
                try:
                    response = s3_client.get_bucket_encryption(
                        Bucket=bucket_name
                    )
                    encryption_config = response.get(
                        "ServerSideEncryptionConfiguration", {}
                    )
                except ClientError:
                    return {
                        "kms_managed": False,
                        "key_analysis": {},
                        "error": "No encryption configuration found",
                    }

            # Extract KMS key information
            rules = encryption_config.get("Rules", [])
            if not rules:
                return {
                    "kms_managed": False,
                    "key_analysis": {},
                    "note": "No encryption rules configured",
                }

            kms_analysis = {
                "kms_managed": False,
                "keys_analyzed": [],
                "total_keys": 0,
                "aws_managed_keys": 0,
                "customer_managed_keys": 0,
                "keys_with_rotation": 0,
                "keys_with_proper_policies": 0,
            }

            for rule in rules:
                sse_config = rule.get("ApplyServerSideEncryptionByDefault", {})
                sse_algorithm = sse_config.get("SSEAlgorithm", "")

                if sse_algorithm == "aws:kms":
                    kms_analysis["kms_managed"] = True
                    kms_key_id = sse_config.get("KMSMasterKeyID")

                    if kms_key_id:
                        key_details = self._analyze_kms_key(kms_key_id)
                        kms_analysis["keys_analyzed"].append(key_details)
                        kms_analysis["total_keys"] += 1

                        if key_details.get("key_manager") == "AWS":
                            kms_analysis["aws_managed_keys"] += 1
                        elif key_details.get("key_manager") == "CUSTOMER":
                            kms_analysis["customer_managed_keys"] += 1

                        if key_details.get("rotation_enabled"):
                            kms_analysis["keys_with_rotation"] += 1

                        if key_details.get("policy_compliant"):
                            kms_analysis["keys_with_proper_policies"] += 1

            # Calculate compliance metrics
            if kms_analysis["total_keys"] > 0:
                kms_analysis["rotation_compliance_percent"] = (
                    kms_analysis["keys_with_rotation"]
                    / kms_analysis["total_keys"]
                    * 100
                )
                kms_analysis["policy_compliance_percent"] = (
                    kms_analysis["keys_with_proper_policies"]
                    / kms_analysis["total_keys"]
                    * 100
                )
            else:
                kms_analysis["rotation_compliance_percent"] = 0
                kms_analysis["policy_compliance_percent"] = 0

            return kms_analysis

        except Exception as e:
            return {"kms_managed": False, "key_analysis": {}, "error": str(e)}

    def _analyze_kms_key(self, key_id: str) -> Dict[str, Any]:
        """Analyze a specific KMS key for SOC 2 compliance."""
        try:
            # Create KMS client for current thread
            session = self.session_factory() if callable(self.session_factory) else self.session_factory
            kms_client = session.client('kms', region_name=self.region)
            
            # Get key metadata
            key_response = kms_client.describe_key(KeyId=key_id)
            key_metadata = key_response["KeyMetadata"]

            # Check rotation status
            try:
                rotation_response = kms_client.get_key_rotation_status(
                    KeyId=key_id
                )
                rotation_enabled = rotation_response["KeyRotationEnabled"]
            except ClientError as e:
                if (
                    e.response["Error"]["Code"]
                    == "UnsupportedOperationException"
                ):
                    # Asymmetric keys don't support automatic rotation
                    rotation_enabled = False
                else:
                    rotation_enabled = False

            # Get key policy
            try:
                policy_response = kms_client.get_key_policy(
                    KeyId=key_id, PolicyName="default"
                )
                key_policy = json.loads(policy_response["Policy"])
                policy_compliant = self._analyze_key_policy(key_policy)
            except ClientError:
                key_policy = {}
                policy_compliant = False

            return {
                "key_id": key_metadata["KeyId"],
                "key_arn": key_metadata["Arn"],
                "key_manager": key_metadata.get("KeyManager", "UNKNOWN"),
                "key_usage": key_metadata.get("KeyUsage", "UNKNOWN"),
                "key_spec": key_metadata.get("KeySpec", "UNKNOWN"),
                "creation_date": key_metadata.get("CreationDate"),
                "enabled": key_metadata.get("Enabled", False),
                "rotation_enabled": rotation_enabled,
                "policy_compliant": policy_compliant,
                "cross_account_access": self._check_cross_account_key_access(
                    key_policy
                ),
            }

        except ClientError as e:
            return {
                "key_id": key_id,
                "error": str(e),
                "rotation_enabled": False,
                "policy_compliant": False,
            }

    def _analyze_key_policy(self, key_policy: Dict[str, Any]) -> bool:
        """Analyze KMS key policy for SOC 2 compliance."""
        if not key_policy:
            return False

        try:
            # Get current account for comparison
            session = self.session_factory() if callable(self.session_factory) else self.session_factory
            sts_client = session.client("sts")
            current_account = sts_client.get_caller_identity()["Account"]

            statements = key_policy.get("Statement", [])

            for statement in statements:
                # Check for overly permissive policies
                if statement.get("Effect") == "Allow":
                    principal = statement.get("Principal", {})

                    # Flag wildcard principals as non-compliant
                    if principal == "*":
                        return False

                    # Check for cross-account access without proper conditions
                    if isinstance(principal, dict) and "AWS" in principal:
                        aws_principals = principal["AWS"]
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]

                        for aws_principal in aws_principals:
                            if "arn:aws:iam::" in aws_principal:
                                account_id = aws_principal.split(":")[4]
                                if account_id != current_account:
                                    # Cross-account access should have conditions
                                    if not statement.get("Condition"):
                                        return False

            return True

        except Exception:
            return False

    def _check_cross_account_key_access(
        self, key_policy: Dict[str, Any]
    ) -> List[str]:
        """Check for cross-account access in KMS key policy."""
        cross_account_principals = []

        if not key_policy:
            return cross_account_principals

        try:
            session = self.session_factory() if callable(self.session_factory) else self.session_factory
            sts_client = session.client("sts")
            current_account = sts_client.get_caller_identity()["Account"]

            statements = key_policy.get("Statement", [])

            for statement in statements:
                if statement.get("Effect") == "Allow":
                    principal = statement.get("Principal", {})

                    if isinstance(principal, dict) and "AWS" in principal:
                        aws_principals = principal["AWS"]
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]

                        for aws_principal in aws_principals:
                            if "arn:aws:iam::" in aws_principal:
                                account_id = aws_principal.split(":")[4]
                                if account_id != current_account:
                                    cross_account_principals.append(
                                        aws_principal
                                    )

        except Exception:
            pass

        return cross_account_principals

    def check_cloudwatch_monitoring(
        self, bucket_name: str, bucket_region: str
    ) -> Dict[str, Any]:
        """Check CloudWatch monitoring configuration for the bucket."""
        try:
            # Create CloudWatch client for bucket region
            session = self.session_factory() if callable(self.session_factory) else self.session_factory
            cw_client = session.client(
                "cloudwatch", region_name=bucket_region
            )

            # Check for S3 metrics
            metrics = self._get_s3_bucket_metrics(bucket_name, cw_client)

            # Check for CloudWatch alarms
            alarms = self._get_s3_cloudwatch_alarms(bucket_name, cw_client)

            # Check recent metric activity (last 7 days)
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=7)

            recent_activity = self._check_recent_metric_activity(
                bucket_name, cw_client, start_time, end_time
            )

            return {
                "monitoring_enabled": len(metrics) > 0,
                "available_metrics": metrics,
                "metric_count": len(metrics),
                "cloudwatch_alarms": alarms,
                "alarm_count": len(alarms),
                "recent_activity": recent_activity,
                "monitoring_compliance": {
                    "has_storage_metrics": any(
                        "BucketSizeBytes" in m["MetricName"] for m in metrics
                    ),
                    "has_request_metrics": any(
                        "GetRequests" in m["MetricName"]
                        or "PutRequests" in m["MetricName"]
                        for m in metrics
                    ),
                    "has_error_alarms": any(
                        "4xx" in a["MetricName"] or "5xx" in a["MetricName"]
                        for a in alarms
                    ),
                    "monitoring_score": self._calculate_monitoring_score(
                        metrics, alarms
                    ),
                },
            }

        except Exception as e:
            return {
                "monitoring_enabled": False,
                "available_metrics": [],
                "metric_count": 0,
                "cloudwatch_alarms": [],
                "alarm_count": 0,
                "recent_activity": {},
                "monitoring_compliance": {},
                "error": str(e),
            }

    def _get_s3_bucket_metrics(
        self, bucket_name: str, cw_client
    ) -> List[Dict[str, Any]]:
        """Get available S3 metrics for the bucket."""
        try:
            response = cw_client.list_metrics(
                Namespace="AWS/S3",
                Dimensions=[{"Name": "BucketName", "Value": bucket_name}],
            )
            return response.get("Metrics", [])
        except ClientError:
            return []

    def _get_s3_cloudwatch_alarms(
        self, bucket_name: str, cw_client
    ) -> List[Dict[str, Any]]:
        """Get CloudWatch alarms related to the S3 bucket."""
        try:
            paginator = cw_client.get_paginator("describe_alarms")
            s3_alarms = []

            for page in paginator.paginate():
                for alarm in page["MetricAlarms"]:
                    if alarm["Namespace"] == "AWS/S3":
                        for dimension in alarm["Dimensions"]:
                            if (
                                dimension["Name"] == "BucketName"
                                and dimension["Value"] == bucket_name
                            ):
                                s3_alarms.append(alarm)
                                break

            return s3_alarms
        except ClientError:
            return []

    def _check_recent_metric_activity(
        self,
        bucket_name: str,
        cw_client,
        start_time: datetime,
        end_time: datetime,
    ) -> Dict[str, Any]:
        """Check for recent metric activity to validate monitoring."""
        try:
            # Check BucketSizeBytes metric
            size_response = cw_client.get_metric_statistics(
                Namespace="AWS/S3",
                MetricName="BucketSizeBytes",
                Dimensions=[
                    {"Name": "BucketName", "Value": bucket_name},
                    {"Name": "StorageType", "Value": "StandardStorage"},
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,  # Daily
                Statistics=["Average"],
            )

            return {
                "has_recent_storage_data": len(
                    size_response.get("Datapoints", [])
                )
                > 0,
                "latest_storage_datapoints": len(
                    size_response.get("Datapoints", [])
                ),
                "monitoring_active": len(size_response.get("Datapoints", []))
                > 0,
            }
        except ClientError:
            return {
                "has_recent_storage_data": False,
                "latest_storage_datapoints": 0,
                "monitoring_active": False,
            }

    def _calculate_monitoring_score(
        self, metrics: List[Dict], alarms: List[Dict]
    ) -> int:
        """Calculate a monitoring compliance score (0-100)."""
        score = 0

        # Base score for having any metrics
        if metrics:
            score += 30

        # Points for specific metric types
        metric_names = [m["MetricName"] for m in metrics]
        if any("BucketSizeBytes" in name for name in metric_names):
            score += 20
        if any("NumberOfObjects" in name for name in metric_names):
            score += 10
        if any("Request" in name for name in metric_names):
            score += 20

        # Points for having alarms
        if alarms:
            score += 20

        return min(score, 100)

    def check_storage_lens_configuration(
        self, account_id: str
    ) -> Dict[str, Any]:
        """Check S3 Storage Lens config for governance and monitoring."""
        try:
            # Create S3 Control client for current thread
            session = self.session_factory() if callable(self.session_factory) else self.session_factory
            s3control_client = session.client('s3control', region_name=self.region)
            
            # List all Storage Lens configurations
            configs_response = (
                s3control_client.list_storage_lens_configurations(
                    AccountId=account_id
                )
            )
            configurations = configs_response.get(
                "StorageLensConfigurationList", []
            )

            if not configurations:
                return {
                    "storage_lens_enabled": False,
                    "configuration_count": 0,
                    "default_config_analysis": {},
                    "error": "No Storage Lens configurations found",
                }

            # Analyze default configuration
            default_config = None
            for config in configurations:
                if config["Id"] == "default-account-dashboard":
                    default_config = config
                    break

            if default_config:
                detailed_config = self._get_detailed_storage_lens_config(
                    account_id, default_config["Id"]
                )
            else:
                detailed_config = {}

            return {
                "storage_lens_enabled": len(configurations) > 0,
                "configuration_count": len(configurations),
                "configurations": configurations,
                "default_config_analysis": detailed_config,
                "governance_compliance": self._analyze_storage_lens_governance(
                    detailed_config
                ),
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "AccessDeniedException":
                return {
                    "storage_lens_enabled": False,
                    "configuration_count": 0,
                    "default_config_analysis": {},
                    "error": "Access denied - insufficient permissions for Storage Lens",
                }
            else:
                return {
                    "storage_lens_enabled": False,
                    "configuration_count": 0,
                    "default_config_analysis": {},
                    "error": str(e),
                }

    def _get_detailed_storage_lens_config(
        self, account_id: str, config_id: str
    ) -> Dict[str, Any]:
        """Get detailed Storage Lens configuration."""
        try:
            # Create S3 Control client for current thread
            session = self.session_factory() if callable(self.session_factory) else self.session_factory
            s3control_client = session.client('s3control', region_name=self.region)
            
            response = s3control_client.get_storage_lens_configuration(
                ConfigId=config_id, AccountId=account_id
            )
            return response.get("StorageLensConfiguration", {})
        except ClientError:
            return {}

    def _analyze_storage_lens_governance(
        self, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze Storage Lens configuration for governance compliance."""
        if not config:
            return {
                "governance_score": 0,
                "enabled": False,
                "data_export_enabled": False,
                "advanced_metrics_enabled": False,
                "cloudwatch_enabled": False,
            }

        analysis = {
            "enabled": config.get("IsEnabled", False),
            "data_export_enabled": False,
            "advanced_metrics_enabled": False,
            "cloudwatch_enabled": False,
            "organization_scope": False,
            "governance_score": 0,
        }

        # Check data export configuration
        data_export = config.get("DataExport", {})
        if data_export:
            analysis["data_export_enabled"] = True
            analysis["governance_score"] += 25

            # Check CloudWatch metrics publishing
            cloudwatch_metrics = data_export.get("CloudWatchMetrics", {})
            if cloudwatch_metrics.get("IsEnabled", False):
                analysis["cloudwatch_enabled"] = True
                analysis["governance_score"] += 25

        # Check advanced metrics
        account_level = config.get("AccountLevel", {})
        if account_level:
            # Cost optimization metrics
            cost_metrics = account_level.get(
                "AdvancedCostOptimizationMetrics", {}
            )
            if cost_metrics.get("IsEnabled", False):
                analysis["advanced_metrics_enabled"] = True
                analysis["governance_score"] += 25

            # Data protection metrics
            data_protection = account_level.get(
                "AdvancedDataProtectionMetrics", {}
            )
            if data_protection.get("IsEnabled", False):
                analysis["governance_score"] += 25

        # Check organization scope
        if config.get("AwsOrg"):
            analysis["organization_scope"] = True

        return analysis
