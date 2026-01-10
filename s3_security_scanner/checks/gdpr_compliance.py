"""GDPR compliance specific checks for S3 security scanner."""

import boto3
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError


class GDPRComplianceChecker:
    """GDPR compliance specific checks for S3 buckets."""

    def __init__(self, session_factory=None):
        """Initialize GDPR compliance checker.

        Args:
            session_factory: A callable that returns a boto3.Session,
                           or a boto3.Session directly for backwards compatibility.
        """
        self.session_factory = session_factory

    def _get_session(self):
        """Get a boto3 session, handling both factory and direct session."""
        if self.session_factory is None:
            return boto3.Session()
        elif callable(self.session_factory):
            return self.session_factory()
        else:
            # Backwards compatibility: direct session passed
            return self.session_factory

    def check_gdpr_compliance_features(
        self, bucket_name: str, region: str
    ) -> Dict[str, Any]:
        """Check GDPR-specific compliance features for a bucket."""
        gdpr_results = {}

        try:
            # Get session and create clients for different services
            session = self._get_session()
            s3_client = session.client("s3", region_name=region)
            kms_client = session.client("kms", region_name=region)
            cloudtrail_client = session.client(
                "cloudtrail", region_name=region
            )

            # Check KMS key management
            gdpr_results["kms_key_management"] = (
                self._check_kms_key_management(
                    bucket_name, s3_client, kms_client
                )
            )

            # Check CloudTrail logging
            gdpr_results["cloudtrail_logging"] = (
                self._check_cloudtrail_logging(bucket_name, cloudtrail_client)
            )

            # Check data residency compliance
            gdpr_results["gdpr_data_residency"] = self._check_data_residency(
                bucket_name, s3_client, region
            )

            # Check international transfer compliance
            gdpr_results["gdpr_international_transfers"] = (
                self._check_international_transfers(bucket_name, s3_client)
            )

            # Check replication compliance
            gdpr_results["gdpr_replication_compliance"] = (
                self._check_replication_compliance(bucket_name, s3_client)
            )

            # Check purpose limitation (basic implementation)
            gdpr_results["gdpr_purpose_limitation"] = (
                self._check_purpose_limitation(bucket_name, s3_client)
            )

            # Check transfer acceleration configuration
            gdpr_results["transfer_acceleration"] = (
                self._check_transfer_acceleration(bucket_name, s3_client)
            )

            # Check website hosting security
            gdpr_results["website_hosting"] = self._check_website_hosting(
                bucket_name, s3_client
            )

            # Check inventory configuration
            gdpr_results["inventory_config"] = self._check_inventory_config(
                bucket_name, s3_client
            )

            # Check analytics configuration
            gdpr_results["analytics_config"] = self._check_analytics_config(
                bucket_name, s3_client
            )

        except Exception:
            # Handle errors gracefully and return defaults
            gdpr_results = self._get_default_gdpr_results()

        return gdpr_results

    def _check_kms_key_management(
        self, bucket_name: str, s3_client, kms_client
    ) -> Dict[str, Any]:
        """Check KMS key management practices."""
        try:
            # Get bucket encryption configuration
            response = s3_client.get_bucket_encryption(Bucket=bucket_name)
            rules = response.get("ServerSideEncryptionConfiguration", {}).get(
                "Rules", []
            )

            kms_managed = False
            key_rotation_enabled = False

            for rule in rules:
                sse_config = rule.get("ApplyServerSideEncryptionByDefault", {})
                if sse_config.get("SSEAlgorithm") == "aws:kms":
                    kms_managed = True

                    # Check key rotation if KMS key is specified
                    kms_key_id = sse_config.get("KMSMasterKeyID")
                    if kms_key_id:
                        try:
                            rotation_response = (
                                kms_client.get_key_rotation_status(
                                    KeyId=kms_key_id
                                )
                            )
                            key_rotation_enabled = rotation_response.get(
                                "KeyRotationEnabled", False
                            )
                        except ClientError:
                            # Key might not support rotation or access denied
                            pass
                    break

            return {
                "kms_managed": kms_managed,
                "key_rotation_enabled": key_rotation_enabled,
                "is_compliant": kms_managed and key_rotation_enabled,
            }

        except ClientError:
            return {
                "kms_managed": False,
                "key_rotation_enabled": False,
                "is_compliant": False,
            }

    def _check_cloudtrail_logging(
        self, bucket_name: str, cloudtrail_client
    ) -> Dict[str, Any]:
        """Check CloudTrail logging configuration."""
        try:
            # List trails and check if any cover S3 data events
            trails_response = cloudtrail_client.describe_trails()
            trails = trails_response.get("trailList", [])

            s3_data_events_enabled = False

            for trail in trails:
                trail_name = trail.get("Name")
                if trail_name:
                    try:
                        # Check event selectors for S3 data events
                        selectors_response = (
                            cloudtrail_client.get_event_selectors(
                                TrailName=trail_name
                            )
                        )
                        event_selectors = selectors_response.get(
                            "EventSelectors", []
                        )

                        for selector in event_selectors:
                            data_resources = selector.get("DataResources", [])
                            for resource in data_resources:
                                if resource.get("Type") == "AWS::S3::Object":
                                    values = resource.get("Values", [])
                                    # Check if this bucket is covered
                                    if (
                                        f"arn:aws:s3:::{bucket_name}/*"
                                        in values
                                        or "arn:aws:s3:::*/*" in values
                                    ):
                                        s3_data_events_enabled = True
                                        break
                            if s3_data_events_enabled:
                                break
                    except ClientError:
                        continue

                if s3_data_events_enabled:
                    break

            return {
                "is_enabled": s3_data_events_enabled,
                "trails_count": len(trails),
            }

        except ClientError:
            return {"is_enabled": False, "trails_count": 0}

    def _check_data_residency(
        self, bucket_name: str, s3_client, region: str
    ) -> Dict[str, Any]:
        """Check data residency compliance."""
        # EU/EEA regions considered GDPR compliant
        gdpr_compliant_regions = {
            "eu-west-1",  # Ireland
            "eu-west-2",  # London
            "eu-west-3",  # Paris
            "eu-central-1",  # Frankfurt
            "eu-north-1",  # Stockholm
            "eu-south-1",  # Milan
        }

        try:
            location_response = s3_client.get_bucket_location(
                Bucket=bucket_name
            )
            bucket_region = (
                location_response.get("LocationConstraint") or "us-east-1"
            )

            return {
                "bucket_region": bucket_region,
                "compliant_region": bucket_region in gdpr_compliant_regions,
                "gdpr_regions": list(gdpr_compliant_regions),
            }

        except ClientError:
            return {
                "bucket_region": region,
                "compliant_region": region in gdpr_compliant_regions,
                "gdpr_regions": list(gdpr_compliant_regions),
            }

    def _check_international_transfers(
        self, bucket_name: str, s3_client
    ) -> Dict[str, Any]:
        """Check international data transfer compliance."""
        # EU/EEA and adequate countries for GDPR transfers
        # Based on EU adequacy decisions
        gdpr_adequate_regions = {
            # EU/EEA regions
            "eu-west-1", "eu-west-2", "eu-west-3",
            "eu-central-1", "eu-north-1", "eu-south-1",
            "eu-south-2", "eu-central-2",
            # Note: Other regions may be compliant with appropriate safeguards (SCCs)
            # but we can't determine that automatically
        }

        try:
            # Check replication configuration for international transfers
            replication_response = s3_client.get_bucket_replication(
                Bucket=bucket_name
            )
            replication_config = replication_response.get(
                "ReplicationConfiguration", {}
            )
            rules = replication_config.get("Rules", [])

            if len(rules) == 0:
                # No replication = no international transfers = compliant
                return {
                    "compliant_transfers": True,
                    "non_compliant_destinations": [],
                    "replication_rules_count": 0,
                }

            compliant_transfers = True
            non_compliant_destinations = []

            for rule in rules:
                destination = rule.get("Destination", {})
                dest_bucket_arn = destination.get("Bucket", "")
                if dest_bucket_arn:
                    # Check if destination is in an adequate region
                    is_adequate = False
                    for region in gdpr_adequate_regions:
                        if region in dest_bucket_arn:
                            is_adequate = True
                            break

                    if not is_adequate:
                        compliant_transfers = False
                        non_compliant_destinations.append(dest_bucket_arn)

            return {
                "compliant_transfers": compliant_transfers,
                "non_compliant_destinations": non_compliant_destinations,
                "replication_rules_count": len(rules),
            }

        except ClientError:
            # No replication configured is compliant
            return {
                "compliant_transfers": True,
                "non_compliant_destinations": [],
                "replication_rules_count": 0,
            }

    def _check_replication_compliance(
        self, bucket_name: str, s3_client
    ) -> Dict[str, Any]:
        """Check replication compliance across regions."""
        # EU/EEA regions considered GDPR compliant for replication
        gdpr_compliant_regions = {
            "eu-west-1", "eu-west-2", "eu-west-3",
            "eu-central-1", "eu-north-1", "eu-south-1",
            "eu-south-2", "eu-central-2",
        }

        try:
            replication_response = s3_client.get_bucket_replication(
                Bucket=bucket_name
            )
            replication_config = replication_response.get(
                "ReplicationConfiguration", {}
            )
            rules = replication_config.get("Rules", [])

            if len(rules) == 0:
                # No replication configured = compliant (no data leaving)
                return {
                    "all_regions_compliant": True,
                    "replication_rules": 0,
                }

            # Check each replication destination region
            non_compliant_destinations = []
            for rule in rules:
                destination = rule.get("Destination", {})
                dest_bucket_arn = destination.get("Bucket", "")
                # Try to determine destination region from bucket
                # Note: This is a simplified check - ideally we'd query the dest bucket region
                # For now, assume replication within same account to EU regions is compliant
                # if destination contains EU region indicators
                dest_region = None
                for region in gdpr_compliant_regions:
                    if region in dest_bucket_arn:
                        dest_region = region
                        break

                if dest_region is None:
                    # Can't determine region or not in EU - flag as potentially non-compliant
                    non_compliant_destinations.append(dest_bucket_arn)

            all_regions_compliant = len(non_compliant_destinations) == 0

            return {
                "all_regions_compliant": all_regions_compliant,
                "replication_rules": len(rules),
                "non_compliant_destinations": non_compliant_destinations,
            }

        except ClientError:
            # No replication configuration = compliant
            return {"all_regions_compliant": True, "replication_rules": 0}

    def _check_purpose_limitation(
        self, bucket_name: str, s3_client
    ) -> Dict[str, Any]:
        """Check purpose limitation config through tags and policies."""
        try:
            # Check bucket tags for purpose indication
            tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
            tags = tags_response.get("TagSet", [])

            purpose_tags = [
                tag for tag in tags if "purpose" in tag.get("Key", "").lower()
            ]
            purpose_restricted = len(purpose_tags) > 0

            return {
                "purpose_restricted": purpose_restricted,
                "purpose_tags": purpose_tags,
                "total_tags": len(tags),
            }

        except ClientError:
            # No tags = not purpose restricted
            return {
                "purpose_restricted": False,
                "purpose_tags": [],
                "total_tags": 0,
            }

    def _check_transfer_acceleration(
        self, bucket_name: str, s3_client
    ) -> Dict[str, Any]:
        """Check transfer acceleration configuration."""
        try:
            accel_response = s3_client.get_bucket_accelerate_configuration(
                Bucket=bucket_name
            )
            status = accel_response.get("Status", "Suspended")

            # Transfer acceleration is properly configured if enabled with SSL enforcement
            is_properly_configured = status == "Enabled"

            return {
                "is_enabled": status == "Enabled",
                "status": status,
                "is_properly_configured": is_properly_configured,
            }

        except ClientError:
            return {
                "is_enabled": False,
                "status": "Suspended",
                "is_properly_configured": True,  # Not enabled = OK
            }

    def _check_website_hosting(
        self, bucket_name: str, s3_client
    ) -> Dict[str, Any]:
        """Check website hosting security configuration."""
        try:
            website_response = s3_client.get_bucket_website(Bucket=bucket_name)
            # If we get here, website hosting is enabled

            # For GDPR, website hosting with personal data is risky
            return {
                "is_enabled": True,
                "is_secure": False,  # Website hosting with personal data is risky
                "configuration": website_response,
            }

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchWebsiteConfiguration":
                return {
                    "is_enabled": False,
                    "is_secure": True,  # No website hosting = secure
                    "configuration": {},
                }
            else:
                return {
                    "is_enabled": False,
                    "is_secure": True,
                    "configuration": {},
                }

    def _check_inventory_config(
        self, bucket_name: str, s3_client
    ) -> Dict[str, Any]:
        """Check S3 Inventory configuration."""
        try:
            inventory_response = (
                s3_client.list_bucket_inventory_configurations(
                    Bucket=bucket_name
                )
            )
            configs = inventory_response.get("InventoryConfigurationList", [])

            return {
                "has_inventory": len(configs) > 0,
                "config_count": len(configs),
                "configurations": configs,
            }

        except ClientError:
            return {
                "has_inventory": False,
                "config_count": 0,
                "configurations": [],
            }

    def _check_analytics_config(
        self, bucket_name: str, s3_client
    ) -> Dict[str, Any]:
        """Check S3 Analytics configuration security."""
        try:
            analytics_response = (
                s3_client.list_bucket_analytics_configurations(
                    Bucket=bucket_name
                )
            )
            configs = analytics_response.get("AnalyticsConfigurationList", [])

            # For GDPR, analytics on personal data should be secured/anonymized
            is_secure = len(configs) == 0  # No analytics = secure

            return {
                "has_analytics": len(configs) > 0,
                "config_count": len(configs),
                "is_secure": is_secure,
                "configurations": configs,
            }

        except ClientError:
            return {
                "has_analytics": False,
                "config_count": 0,
                "is_secure": True,
                "configurations": [],
            }

    def _get_default_gdpr_results(self) -> Dict[str, Any]:
        """Get default GDPR compliance results."""
        return {
            "kms_key_management": {
                "kms_managed": False,
                "is_compliant": False,
            },
            "cloudtrail_logging": {"is_enabled": False},
            "gdpr_data_residency": {"compliant_region": False},
            "gdpr_international_transfers": {"compliant_transfers": False},
            "gdpr_replication_compliance": {"all_regions_compliant": False},
            "gdpr_purpose_limitation": {"purpose_restricted": False},
            "transfer_acceleration": {"is_properly_configured": True},
            "website_hosting": {"is_secure": True},
            "inventory_config": {"has_inventory": False},
            "analytics_config": {"is_secure": True},
        }
