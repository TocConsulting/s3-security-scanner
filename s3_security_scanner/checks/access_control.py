"""Access Control Security Checks for S3 Buckets."""

import json
from typing import Dict, Any
import boto3
from botocore.exceptions import ClientError


class AccessControlChecker:
    """Checks for S3 bucket access control configurations."""

    def __init__(self, session_factory=None):
        """Initialize with optional session factory for thread safety."""
        self.session_factory = session_factory

    def check_public_access_block(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if public access block is enabled for a bucket."""
        try:
            response = client.get_public_access_block(Bucket=bucket_name)
            config = response.get("PublicAccessBlockConfiguration", {})

            all_enabled = all(
                [
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ]
            )

            return {"is_properly_configured": all_enabled, "details": config}
        except ClientError as e:
            if (
                e.response["Error"]["Code"]
                == "NoSuchPublicAccessBlockConfiguration"
            ):
                return {
                    "is_properly_configured": False,
                    "details": "No public access block configuration found",
                }
            else:
                return {
                    "is_properly_configured": False,
                    "details": f"Error: {str(e)}",
                }

    def check_bucket_policy(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check if bucket policy has any public access."""
        try:
            policy_response = client.get_bucket_policy(Bucket=bucket_name)
            policy_str = policy_response.get("Policy", "")

            if not policy_str:
                return {
                    "has_policy": False,
                    "is_public": False,
                    "policy": None,
                    "ssl_enforced": False,
                }

            policy = json.loads(policy_str)
            is_public = False
            ssl_enforced = False

            for statement in policy.get("Statement", []):
                principal = statement.get("Principal", {})
                effect = statement.get("Effect", "")

                # Check for public access
                if effect == "Allow" and (
                    principal == "*"
                    or principal == {"AWS": "*"}
                    or (
                        isinstance(principal, dict)
                        and principal.get("AWS", "") == "*"
                    )
                ):
                    is_public = True

                # Check for SSL enforcement
                conditions = statement.get("Condition", {})
                if (
                    "Bool" in conditions
                    and "aws:SecureTransport" in conditions["Bool"]
                ):
                    if (
                        conditions["Bool"]["aws:SecureTransport"] == "false"
                        and effect == "Deny"
                    ):
                        ssl_enforced = True

            return {
                "has_policy": True,
                "is_public": is_public,
                "policy": policy,
                "ssl_enforced": ssl_enforced,
            }

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return {
                    "has_policy": False,
                    "is_public": False,
                    "policy": None,
                    "ssl_enforced": False,
                }
            else:
                return {
                    "has_policy": False,
                    "is_public": False,
                    "policy": None,
                    "ssl_enforced": False,
                    "error": str(e),
                }

    def check_bucket_acl(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check if bucket ACL has any public access grants."""
        try:
            acl_response = client.get_bucket_acl(Bucket=bucket_name)
            grants = acl_response.get("Grants", [])

            public_access = False
            public_write = False
            public_grants = []
            has_acl_grants = len(grants) > 1  # More than just the owner grant

            for grant in grants:
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                permission = grant.get("Permission", "")

                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    public_access = True
                    public_grants.append(
                        {
                            "permission": permission,
                            "grantee": grantee,
                        }
                    )

                    # Check for public write permissions
                    if permission in ["WRITE", "WRITE_ACP", "FULL_CONTROL"]:
                        public_write = True

            return {
                "has_public_access": public_access,
                "has_public_write": public_write,
                "has_acl_grants": has_acl_grants,
                "public_grants": public_grants,
            }

        except Exception as e:
            return {
                "has_public_access": False,
                "has_public_write": False,
                "has_acl_grants": False,
                "public_grants": [],
                "error": str(e),
            }

    def check_wildcard_principal(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if bucket policy allows wildcard (*) principal access."""
        try:
            policy_response = client.get_bucket_policy(Bucket=bucket_name)
            policy_str = policy_response.get("Policy", "")

            if not policy_str:
                return {
                    "has_wildcard_principal": False,
                    "wildcard_statements": [],
                }

            policy = json.loads(policy_str)
            has_wildcard = False
            wildcard_statements = []

            for statement in policy.get("Statement", []):
                principal = statement.get("Principal", {})
                effect = statement.get("Effect", "")

                # Check for wildcard principal in Allow statements
                if effect == "Allow" and (
                    principal == "*"
                    or principal == {"AWS": "*"}
                    or (
                        isinstance(principal, dict)
                        and principal.get("AWS", "") == "*"
                    )
                ):
                    has_wildcard = True
                    wildcard_statements.append(
                        {
                            "effect": effect,
                            "principal": principal,
                            "action": statement.get("Action", []),
                            "resource": statement.get("Resource", []),
                        }
                    )

            return {
                "has_wildcard_principal": has_wildcard,
                "wildcard_statements": wildcard_statements,
            }

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return {
                    "has_wildcard_principal": False,
                    "wildcard_statements": [],
                }
            else:
                return {
                    "has_wildcard_principal": False,
                    "wildcard_statements": [],
                    "error": str(e),
                }

    def check_event_notifications(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if bucket has event notifications configured."""
        try:
            response = client.get_bucket_notification_configuration(
                Bucket=bucket_name
            )

            # Check for any type of notification configuration
            has_notifications = bool(
                response.get("TopicConfigurations", [])
                or response.get("QueueConfigurations", [])
                or response.get("LambdaConfigurations", [])
                or response.get("EventBridgeConfiguration", {})
            )

            notification_count = (
                len(response.get("TopicConfigurations", []))
                + len(response.get("QueueConfigurations", []))
                + len(response.get("LambdaConfigurations", []))
            )

            if response.get("EventBridgeConfiguration", {}):
                notification_count += 1

            return {
                "has_notifications": has_notifications,
                "notification_count": notification_count,
                "sns_topics": len(response.get("TopicConfigurations", [])),
                "sqs_queues": len(response.get("QueueConfigurations", [])),
                "lambda_functions": len(
                    response.get("LambdaConfigurations", [])
                ),
                "eventbridge_enabled": bool(
                    response.get("EventBridgeConfiguration", {})
                ),
            }

        except ClientError:
            # No notification configuration is not an error, just means none configured
            return {
                "has_notifications": False,
                "notification_count": 0,
                "sns_topics": 0,
                "sqs_queues": 0,
                "lambda_functions": 0,
                "eventbridge_enabled": False,
            }

    def check_replication(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check if bucket has replication configured."""
        try:
            response = client.get_bucket_replication(Bucket=bucket_name)

            replication_config = response.get("ReplicationConfiguration", {})
            rules = replication_config.get("Rules", [])

            # Count enabled rules
            enabled_rules = [
                rule for rule in rules if rule.get("Status") == "Enabled"
            ]

            return {
                "has_replication": len(rules) > 0,
                "replication_rule_count": len(rules),
                "enabled_rule_count": len(enabled_rules),
                "replication_role": replication_config.get("Role", ""),
                "rules": rules,
            }

        except ClientError as e:
            if (
                e.response["Error"]["Code"]
                == "ReplicationConfigurationNotFoundError"
            ):
                return {
                    "has_replication": False,
                    "replication_rule_count": 0,
                    "enabled_rule_count": 0,
                    "replication_role": "",
                    "rules": [],
                }
            else:
                return {
                    "has_replication": False,
                    "replication_rule_count": 0,
                    "enabled_rule_count": 0,
                    "replication_role": "",
                    "rules": [],
                    "error": str(e),
                }

    def check_transfer_acceleration(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if S3 Transfer Acceleration is enabled for the bucket."""
        try:
            response = client.get_bucket_accelerate_configuration(
                Bucket=bucket_name
            )

            status = response.get("Status", "Suspended")
            is_enabled = status == "Enabled"

            return {"is_enabled": is_enabled, "status": status}

        except ClientError:
            # Transfer acceleration not configured returns empty response, not error
            return {"is_enabled": False, "status": "Suspended"}

    def check_cross_account_access(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if bucket policy allows cross-account access."""
        try:
            policy_response = client.get_bucket_policy(Bucket=bucket_name)
            policy_str = policy_response.get("Policy", "")

            if not policy_str:
                return {
                    "has_cross_account_access": False,
                    "cross_account_principals": [],
                }

            # Get current account ID for comparison
            if self.session_factory:
                session = self.session_factory() if callable(self.session_factory) else self.session_factory
                sts_client = session.client("sts")
            else:
                sts_client = boto3.client("sts")
            current_account = sts_client.get_caller_identity()["Account"]

            policy = json.loads(policy_str)
            cross_account_principals = []

            for statement in policy.get("Statement", []):
                principal = statement.get("Principal", {})
                effect = statement.get("Effect", "")

                if effect == "Allow":
                    # Check for AWS principals
                    if isinstance(principal, dict) and "AWS" in principal:
                        aws_principals = principal["AWS"]
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]

                        for aws_principal in aws_principals:
                            # Extract account ID from ARN
                            if "arn:aws:iam::" in aws_principal:
                                account_id = aws_principal.split(":")[4]
                                if (
                                    account_id != current_account
                                    and account_id != ""
                                ):
                                    cross_account_principals.append(
                                        {
                                            "principal": aws_principal,
                                            "account_id": account_id,
                                            "action": statement.get(
                                                "Action", []
                                            ),
                                        }
                                    )

            return {
                "has_cross_account_access": len(cross_account_principals) > 0,
                "cross_account_principals": cross_account_principals,
                "current_account": current_account,
            }

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return {
                    "has_cross_account_access": False,
                    "cross_account_principals": [],
                }
            else:
                return {
                    "has_cross_account_access": False,
                    "cross_account_principals": [],
                    "error": str(e),
                }

    def check_mfa_requirement(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check if bucket policy requires MFA for access."""
        try:
            policy_response = client.get_bucket_policy(Bucket=bucket_name)
            policy_str = policy_response.get("Policy", "")

            if not policy_str:
                return {"mfa_required": False, "mfa_statements": []}

            policy = json.loads(policy_str)
            mfa_statements = []

            for statement in policy.get("Statement", []):
                condition = statement.get("Condition", {})

                # Check for MFA conditions
                mfa_conditions = []

                # Check Bool conditions for MFA
                bool_conditions = condition.get("Bool", {})
                if "aws:MultiFactorAuthPresent" in bool_conditions:
                    if bool_conditions["aws:MultiFactorAuthPresent"] in [
                        "true",
                        True,
                    ]:
                        mfa_conditions.append("aws:MultiFactorAuthPresent")

                # Check NumericLessThan for MFA age
                numeric_conditions = condition.get("NumericLessThan", {})
                if "aws:MultiFactorAuthAge" in numeric_conditions:
                    mfa_conditions.append("aws:MultiFactorAuthAge")

                if mfa_conditions:
                    mfa_statements.append(
                        {
                            "effect": statement.get("Effect", ""),
                            "conditions": mfa_conditions,
                            "actions": statement.get("Action", []),
                            "mfa_age_limit": numeric_conditions.get(
                                "aws:MultiFactorAuthAge"
                            ),
                        }
                    )

            return {
                "mfa_required": len(mfa_statements) > 0,
                "mfa_statements": mfa_statements,
                "mfa_statement_count": len(mfa_statements),
            }

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                return {"mfa_required": False, "mfa_statements": []}
            else:
                return {
                    "mfa_required": False,
                    "mfa_statements": [],
                    "error": str(e),
                }

    def check_iso27001_access_control(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check ISO 27001 - 5.15 Access Control compliance."""
        try:
            # Get all access control configurations
            public_access_block = self.check_public_access_block(
                bucket_name, client
            )
            bucket_policy = self.check_bucket_policy(bucket_name, client)
            bucket_acl = self.check_bucket_acl(bucket_name, client)
            wildcard_principal = self.check_wildcard_principal(
                bucket_name, client
            )
            cross_account = self.check_cross_account_access(
                bucket_name, client
            )
            mfa_requirement = self.check_mfa_requirement(bucket_name, client)

            # Analyze least privilege compliance
            privilege_issues = []
            privilege_score = 100

            # Check for overly permissive configurations
            if not public_access_block["is_properly_configured"]:
                privilege_issues.append(
                    "Public access block not properly configured"
                )
                privilege_score -= 20

            if bucket_policy["is_public"]:
                privilege_issues.append("Bucket policy allows public access")
                privilege_score -= 25

            if bucket_acl["has_public_access"]:
                privilege_issues.append("Bucket ACL grants public access")
                privilege_score -= 25

            if wildcard_principal["has_wildcard_principal"]:
                privilege_issues.append(
                    "Bucket policy uses wildcard principals"
                )
                privilege_score -= 15

            if cross_account["has_cross_account_access"]:
                privilege_issues.append(
                    "Cross-account access detected without proper controls"
                )
                privilege_score -= 10

            if not mfa_requirement["mfa_required"] and (
                bucket_policy["has_policy"]
                or len(cross_account.get("cross_account_principals", [])) > 0
            ):
                privilege_issues.append(
                    "No MFA requirement for sensitive operations"
                )
                privilege_score -= 5

            # Determine compliance level
            if privilege_score >= 95:
                compliance_level = "EXCELLENT"
            elif privilege_score >= 80:
                compliance_level = "GOOD"
            elif privilege_score >= 60:
                compliance_level = "ACCEPTABLE"
            else:
                compliance_level = "NON_COMPLIANT"

            return {
                "iso_control": "27001-5.15",
                "control_name": "Access Control",
                "is_compliant": privilege_score >= 80,
                "compliance_level": compliance_level,
                "privilege_score": max(0, privilege_score),
                "privilege_issues": privilege_issues,
                "least_privilege_enforced": len(privilege_issues) == 0,
                "access_control_summary": {
                    "public_access_blocked": public_access_block[
                        "is_properly_configured"
                    ],
                    "no_public_policy": not bucket_policy["is_public"],
                    "no_public_acl": not bucket_acl["has_public_access"],
                    "no_wildcard_principals": not wildcard_principal[
                        "has_wildcard_principal"
                    ],
                    "controlled_cross_account": not cross_account[
                        "has_cross_account_access"
                    ]
                    or mfa_requirement["mfa_required"],
                    "mfa_enforced": mfa_requirement["mfa_required"],
                },
                "remediation_priority": (
                    "HIGH"
                    if privilege_score < 60
                    else ("MEDIUM" if privilege_score < 80 else "LOW")
                ),
                "detailed_findings": {
                    "public_access_block": public_access_block,
                    "bucket_policy": bucket_policy,
                    "bucket_acl": bucket_acl,
                    "wildcard_principal": wildcard_principal,
                    "cross_account_access": cross_account,
                    "mfa_requirement": mfa_requirement,
                },
            }

        except Exception as e:
            return {
                "iso_control": "27001-5.15",
                "control_name": "Access Control",
                "is_compliant": False,
                "compliance_level": "ERROR",
                "privilege_score": 0,
                "privilege_issues": [f"Error during analysis: {str(e)}"],
                "error": str(e),
            }

    def check_access_points(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check S3 access points configuration for public access blocking."""
        try:
            # Get the account ID for access point operations
            # Always use session-based clients for consistency
            if self.session_factory:
                session = self.session_factory() if callable(self.session_factory) else self.session_factory
                sts_client = session.client("sts")
                # Get bucket region for proper S3 Control client configuration
                bucket_region = client.get_bucket_location(
                    Bucket=bucket_name
                ).get("LocationConstraint")
                region = bucket_region if bucket_region else "us-east-1"
                session = self.session_factory() if callable(self.session_factory) else self.session_factory
                s3control = session.client(
                    "s3control", region_name=region
                )
            else:
                sts_client = boto3.client("sts")
                # Get bucket region for proper S3 Control client configuration
                bucket_region = client.get_bucket_location(
                    Bucket=bucket_name
                ).get("LocationConstraint")
                region = bucket_region if bucket_region else "us-east-1"
                s3control = boto3.client("s3control", region_name=region)
            account_id = sts_client.get_caller_identity()["Account"]

            # List access points for this bucket
            access_points = []
            all_have_public_access_blocked = True

            try:
                # Note: list_access_points does not support Bucket parameter
                # It lists all access points for the account, we need to filter later
                response = s3control.list_access_points(AccountId=account_id)
                access_points_list = response.get("AccessPointList", [])
                # Filter access points for this specific bucket
                access_points_list = [
                    ap
                    for ap in access_points_list
                    if ap.get("Bucket") == bucket_name
                ]

                for ap in access_points_list:
                    ap_name = ap.get("Name", "")
                    # Get access point configuration
                    try:
                        ap_config = s3control.get_access_point(
                            AccountId=account_id, Name=ap_name
                        )

                        public_access_block = ap_config.get(
                            "PublicAccessBlockConfiguration", {}
                        )
                        has_block_settings = (
                            public_access_block.get("BlockPublicAcls", False)
                            and public_access_block.get(
                                "IgnorePublicAcls", False
                            )
                            and public_access_block.get(
                                "BlockPublicPolicy", False
                            )
                            and public_access_block.get(
                                "RestrictPublicBuckets", False
                            )
                        )

                        if not has_block_settings:
                            all_have_public_access_blocked = False

                        access_points.append(
                            {
                                "name": ap_name,
                                "arn": ap.get("AccessPointArn", ""),
                                "has_public_access_blocked": (
                                    has_block_settings
                                ),
                                "public_access_block_config": public_access_block,
                            }
                        )

                    except Exception as ap_error:
                        access_points.append(
                            {
                                "name": ap_name,
                                "arn": ap.get("AccessPointArn", ""),
                                "has_public_access_blocked": False,
                                "error": str(ap_error),
                            }
                        )
                        all_have_public_access_blocked = False

            except Exception:
                # If we can't list access points, assume compliant (no access points)
                pass

            return {
                "access_points": access_points,
                "access_point_count": len(access_points),
                "all_have_public_access_blocked": all_have_public_access_blocked,
            }

        except Exception as e:
            return {
                "access_points": [],
                "access_point_count": 0,
                "all_have_public_access_blocked": True,  # Default to compliant if can't check
                "error": str(e),
            }

    def check_multi_region_access_points(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Check S3 Multi-Region Access Points configuration for public access blocking."""
        try:
            # Get the account ID for MRAP operations
            if self.session_factory:
                session = self.session_factory() if callable(self.session_factory) else self.session_factory
                sts_client = session.client("sts")
                s3control = session.client("s3control")
            else:
                sts_client = boto3.client("sts")
                s3control = boto3.client("s3control")
            account_id = sts_client.get_caller_identity()["Account"]

            # List Multi-Region Access Points
            mraps = []
            all_have_public_access_blocked = True

            try:
                response = s3control.list_multi_region_access_points(
                    AccountId=account_id
                )
                mrap_list = response.get("AccessPoints", [])

                for mrap in mrap_list:
                    mrap_name = mrap.get("Name", "")

                    # Check if this MRAP is associated with our bucket
                    regions = mrap.get("Regions", [])
                    bucket_associated = any(
                        region.get("Bucket", "") == bucket_name
                        for region in regions
                    )

                    if bucket_associated:
                        # Get MRAP configuration
                        try:
                            mrap_config = (
                                s3control.get_multi_region_access_point(
                                    AccountId=account_id, Name=mrap_name
                                )
                            )

                            public_access_block = mrap_config.get(
                                "AccessPoint", {}
                            ).get("PublicAccessBlock", {})
                            has_block_settings = (
                                public_access_block.get(
                                    "BlockPublicAcls", False
                                )
                                and public_access_block.get(
                                    "IgnorePublicAcls", False
                                )
                                and public_access_block.get(
                                    "BlockPublicPolicy", False
                                )
                                and public_access_block.get(
                                    "RestrictPublicBuckets", False
                                )
                            )

                            if not has_block_settings:
                                all_have_public_access_blocked = False

                            mraps.append(
                                {
                                    "name": mrap_name,
                                    "arn": mrap.get("Arn", ""),
                                    "has_public_access_blocked": has_block_settings,
                                    "public_access_block_config": public_access_block,
                                    "regions": regions,
                                }
                            )

                        except Exception as mrap_error:
                            mraps.append(
                                {
                                    "name": mrap_name,
                                    "arn": mrap.get("Arn", ""),
                                    "has_public_access_blocked": False,
                                    "error": str(mrap_error),
                                }
                            )
                            all_have_public_access_blocked = False

            except Exception:
                # If we can't list MRAPs, assume compliant (no MRAPs)
                pass

            return {
                "multi_region_access_points": mraps,
                "mrap_count": len(mraps),
                "all_have_public_access_blocked": all_have_public_access_blocked,
            }

        except Exception as e:
            return {
                "multi_region_access_points": [],
                "mrap_count": 0,
                "all_have_public_access_blocked": True,  # Default to compliant if can't check
                "error": str(e),
            }

    def check_shadow_resource_vulnerability(
        self, bucket_name: str, account_id: str, region: str
    ) -> Dict[str, Any]:
        """Check if bucket name follows predictable AWS service pattern.

        Shadow resources are S3 buckets with predictable names that AWS
        services try to create automatically. If an attacker creates these
        buckets first,
        they can potentially intercept data meant for the legitimate service.

        Args:
            bucket_name: Name of the bucket to check
            account_id: AWS account ID
            region: AWS region

        Returns:
            Dict with vulnerability assessment
        """

        # Predictable patterns used by AWS services
        # These can be exploited if created by attackers
        vulnerable_patterns = {
            'Glue': [
                f'aws-glue-assets-{account_id}-{region}',
                f'aws-glue-{account_id}-{region}'
            ],
            'SageMaker': [
                f'sagemaker-{region}-{account_id}',
                f'sagemaker-studio-{account_id}-{region}'
            ],
            'EMR': [
                f'aws-emr-studio-{account_id}-{region}',
                f'aws-emr-resources-{account_id}-{region}'
            ],
            'CodeStar': [
                f'aws-codestar-{region}-{account_id}',
                f'aws-codestar-{region}-{account_id}-'
            ],
            'CloudFormation': [
                f'cf-templates-{account_id}-{region}',
            ],
            'ElasticBeanstalk': [
                f'elasticbeanstalk-{region}-{account_id}',
            ],
            'DataBrew': [
                f'aws-databrew-{region}-{account_id}'
            ],
            'Amplify': [
                f'amplify-{account_id}-{region}'
            ]
        }

        vulnerabilities = []
        is_vulnerable = False
        affected_services = []

        # Check if bucket name matches any vulnerable pattern
        for service, patterns in vulnerable_patterns.items():
            for pattern in patterns:
                # Check exact match
                if bucket_name == pattern:
                    is_vulnerable = True
                    affected_services.append(service)
                    vulnerabilities.append({
                        'type': 'exact_match',
                        'service': service,
                        'pattern': pattern,
                        'risk': 'HIGH',
                        'description': f'Bucket name exactly matches {service} service pattern'
                    })
                # Check prefix match for patterns with suffix
                elif pattern.endswith('-') and bucket_name.startswith(pattern):
                    is_vulnerable = True
                    affected_services.append(service)
                    vulnerabilities.append({
                        'type': 'prefix_match',
                        'service': service,
                        'pattern': pattern,
                        'risk': 'MEDIUM',
                        'description': f'Bucket name matches {service} service prefix pattern'
                    })

        # Additional checks for generic AWS patterns
        aws_reserved_prefixes = [
            'aws-', 'amazon-', 'aws.', 'amazon.'
        ]

        for prefix in aws_reserved_prefixes:
            if bucket_name.startswith(prefix) and not is_vulnerable:
                vulnerabilities.append({
                    'type': 'reserved_prefix',
                    'prefix': prefix,
                    'risk': 'LOW',
                    'description': 'Bucket uses AWS reserved prefix (potential confusion)'
                })

        # Check if bucket exists but we don't own it (shadow resource)
        shadow_resource_detected = False
        if is_vulnerable and self.session_factory:
            try:
                # Try to get bucket location (will fail if we don't own it)
                session = self.session_factory() if callable(self.session_factory) else self.session_factory
                s3_client = session.client('s3')
                s3_client.get_bucket_location(
                    Bucket=bucket_name
                )
                # We own it, so it's our legitimate service bucket
                shadow_resource_detected = False
            except ClientError as e:
                if e.response['Error']['Code'] == 'AccessDenied':
                    # Bucket exists but we don't own it - SHADOW RESOURCE!
                    shadow_resource_detected = True
                elif e.response['Error']['Code'] == 'NoSuchBucket':
                    # Bucket doesn't exist - we should create it to prevent attacks
                    shadow_resource_detected = False

        return {
            'is_vulnerable': is_vulnerable,
            'shadow_resource_detected': shadow_resource_detected,
            'affected_services': list(set(affected_services)),
            'vulnerabilities': vulnerabilities,
            'recommendation': self._get_shadow_resource_recommendation(
                is_vulnerable, shadow_resource_detected, affected_services
            )
        }

    def _get_shadow_resource_recommendation(
        self, is_vulnerable: bool, shadow_detected: bool, services: list
    ) -> str:
        """Generate recommendation for shadow resource findings."""
        if shadow_detected:
            return (
                f"CRITICAL: Shadow resource detected! Bucket name matches {', '.join(services)} "
                f"service pattern but is owned by another account. This could lead to data "
                f"exfiltration. Contact AWS Support immediately and avoid using affected services."
            )
        elif is_vulnerable:
            return (
                f"WARNING: Bucket name matches predictable {', '.join(services)} service patterns. "
                f"Consider creating this bucket proactively to prevent shadow resource attacks, "
                f"or use a different naming convention."
            )
        else:
            return "Bucket name does not match known vulnerable patterns."
