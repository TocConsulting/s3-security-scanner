"""Object-Level Security Checks for S3 Buckets."""

import re
import time
from typing import Dict, Any
from botocore.exceptions import ClientError


class ObjectSecurityChecker:
    """Checks for S3 object-level security configurations."""

    def __init__(self, session=None):
        """Initialize the object security checker.

        Args:
            session: Boto3 session for AWS API calls
        """
        self.session = session

    # Regex patterns for identifying sensitive data in S3 object names
    SENSITIVE_PATTERNS = {
        "ssn": re.compile(r"\d{3}-\d{2}-\d{4}"),
        "credit_card": re.compile(r"\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}"),
        "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "private_key": re.compile(
            r".*\.(pem|key|pfx|p12|ppk)$", re.IGNORECASE
        ),
        "password_file": re.compile(
            r".*(password|passwd|pwd|secret|credential).*", re.IGNORECASE
        ),
        "database_backup": re.compile(
            r".*\.(sql|dump|bak|backup)$", re.IGNORECASE
        ),
    }

    # SOC 2 data classification patterns
    SOC2_DATA_CLASSIFICATION = {
        "public": ["public", "marketing", "general", "website"],
        "internal": ["internal", "company", "employee", "staff"],
        "confidential": [
            "confidential",
            "private",
            "restricted",
            "proprietary",
        ],
        "sensitive": [
            "sensitive",
            "pii",
            "personal",
            "ssn",
            "medical",
            "financial",
        ],
        "regulatory": ["sox", "pci", "hipaa", "gdpr", "ccpa", "compliance"],
        "financial": ["financial", "billing", "invoice", "payment", "revenue"],
        "personal": ["personal", "pii", "customer", "user", "profile"],
        "medical": ["medical", "health", "patient", "phi", "hipaa"],
        "legal": ["legal", "contract", "agreement", "litigation", "discovery"],
    }

    def check_cors(self, bucket_name: str, client) -> Dict[str, Any]:
        """Check for overly permissive CORS configuration."""
        try:
            response = client.get_bucket_cors(Bucket=bucket_name)
            risky_cors = False
            risky_rules = []

            for rule in response.get("CORSRules", []):
                if "*" in rule.get("AllowedOrigins", []):
                    risky_cors = True
                    risky_rules.append(rule)

            return {
                "has_cors": True,
                "is_risky": risky_cors,
                "risky_rules": risky_rules,
            }
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchCORSConfiguration":
                return {"has_cors": False, "is_risky": False}
            else:
                return {"has_cors": False, "is_risky": False, "error": str(e)}

    def check_object_level_security(
        self, bucket_name: str, client, sample_size: int = 100
    ) -> Dict[str, Any]:
        """Check object-level security by sampling objects."""
        try:
            # List objects (sample)
            paginator = client.get_paginator("list_objects_v2")
            page_iterator = paginator.paginate(
                Bucket=bucket_name,
                PaginationConfig={"MaxItems": sample_size, "PageSize": 100},
            )

            public_objects = []
            sensitive_objects = []
            total_objects = 0

            for page in page_iterator:
                for obj in page.get("Contents", []):
                    total_objects += 1
                    key = obj["Key"]

                    # Check for sensitive data patterns (case-insensitive)
                    key_lower = key.lower()
                    for (
                        pattern_name,
                        pattern,
                    ) in self.SENSITIVE_PATTERNS.items():
                        if pattern.search(key_lower):
                            sensitive_objects.append(
                                {
                                    "key": key,
                                    "pattern": pattern_name,
                                    "size": obj["Size"],
                                }
                            )

                    # Check object ACL with improved rate limiting and sampling
                    # Use more conservative approach for ACL checks due to API limits
                    acl_check_count = len(
                        [
                            obj
                            for obj in public_objects + sensitive_objects
                            if obj.get("acl_checked", False)
                        ]
                    )

                    if (
                        acl_check_count < 3
                    ):  # Reduced from 5 to 3 for better rate limiting
                        try:
                            time.sleep(
                                0.1
                            )  # Small delay to avoid rate limiting

                            acl_response = client.get_object_acl(
                                Bucket=bucket_name, Key=key
                            )

                            for grant in acl_response.get("Grants", []):
                                grantee = grant.get("Grantee", {})
                                uri = grantee.get("URI", "")

                                if (
                                    "AllUsers" in uri
                                    or "AuthenticatedUsers" in uri
                                ):
                                    public_objects.append(
                                        {
                                            "key": key,
                                            "permission": grant.get(
                                                "Permission"
                                            ),
                                            "size": obj["Size"],
                                            "acl_checked": True,
                                        }
                                    )
                                    break  # Found public access, no need to check other grants

                        except ClientError as e:
                            error_code = e.response.get("Error", {}).get(
                                "Code", ""
                            )
                            if error_code == "Throttling":
                                # Stop ACL checks if we hit rate limits
                                break
                            # Continue for other errors (AccessDenied, etc.)

            return {
                "total_objects_scanned": total_objects,
                "public_objects": public_objects,
                "public_object_count": len(public_objects),
                "sensitive_objects": sensitive_objects,
                "sensitive_object_count": len(sensitive_objects),
            }

        except Exception as e:
            return {
                "total_objects_scanned": 0,
                "public_objects": [],
                "public_object_count": 0,
                "sensitive_objects": [],
                "sensitive_object_count": 0,
                "error": str(e),
            }

    def check_data_classification_tagging(
        self, bucket_name: str, client, sample_size: int = 50
    ) -> Dict[str, Any]:
        """Enhanced data classification analysis using object tagging and naming patterns."""
        try:
            # Get bucket tagging for overall classification
            bucket_classification = self._get_bucket_classification_tags(
                bucket_name, client
            )

            # Sample objects for individual classification analysis
            paginator = client.get_paginator("list_objects_v2")
            page_iterator = paginator.paginate(
                Bucket=bucket_name,
                PaginationConfig={"MaxItems": sample_size, "PageSize": 100},
            )

            classified_objects = []
            classification_summary = {
                "public": 0,
                "internal": 0,
                "confidential": 0,
                "sensitive": 0,
                "regulatory": 0,
                "financial": 0,
                "personal": 0,
                "medical": 0,
                "legal": 0,
                "unclassified": 0,
            }

            total_objects = 0

            for page in page_iterator:
                for obj in page.get("Contents", []):
                    total_objects += 1
                    key = obj["Key"]

                    # Get object classification from tags and naming patterns
                    object_classification = self._classify_object(
                        bucket_name, key, client
                    )

                    if object_classification["classification"]:
                        classification_summary[
                            object_classification["classification"]
                        ] += 1
                        classified_objects.append(
                            {
                                "key": key,
                                "classification": object_classification[
                                    "classification"
                                ],
                                "confidence": object_classification[
                                    "confidence"
                                ],
                                "reasons": object_classification["reasons"],
                            }
                        )
                    else:
                        classification_summary["unclassified"] += 1

            # Calculate classification coverage
            classified_count = (
                total_objects - classification_summary["unclassified"]
            )
            classification_coverage = (
                (classified_count / total_objects * 100)
                if total_objects > 0
                else 0
            )

            # Identify most sensitive classification
            sensitive_levels = [
                "medical",
                "financial",
                "personal",
                "regulatory",
                "sensitive",
                "confidential",
            ]
            highest_sensitivity = "public"
            for level in sensitive_levels:
                if classification_summary[level] > 0:
                    highest_sensitivity = level
                    break

            return {
                "bucket_classification": bucket_classification,
                "total_objects_analyzed": total_objects,
                "classification_coverage_percent": round(
                    classification_coverage, 1
                ),
                "classification_summary": classification_summary,
                "highest_sensitivity_level": highest_sensitivity,
                "classified_objects_sample": classified_objects[
                    :10
                ],  # Return first 10 for review
                "has_proper_classification": classification_coverage
                > 50,  # SOC 2 expectation
                "classification_gaps": classification_summary["unclassified"],
            }

        except Exception as e:
            return {
                "bucket_classification": {},
                "total_objects_analyzed": 0,
                "classification_coverage_percent": 0,
                "classification_summary": {},
                "highest_sensitivity_level": "unknown",
                "classified_objects_sample": [],
                "has_proper_classification": False,
                "classification_gaps": 0,
                "error": str(e),
            }

    def _get_bucket_classification_tags(
        self, bucket_name: str, client
    ) -> Dict[str, Any]:
        """Get bucket-level classification from tags."""
        try:
            response = client.get_bucket_tagging(Bucket=bucket_name)
            tags = response.get("TagSet", [])

            classification_tags = {}
            for tag in tags:
                key = tag["Key"].lower()

                # Look for classification-related tags
                if any(
                    cls_key in key
                    for cls_key in [
                        "classification",
                        "data-class",
                        "sensitivity",
                        "privacy",
                    ]
                ):
                    classification_tags[tag["Key"]] = tag["Value"]

                # Check for SOC 2 related tags
                if any(
                    soc_key in key
                    for soc_key in ["soc2", "compliance", "audit", "control"]
                ):
                    classification_tags[tag["Key"]] = tag["Value"]

            return classification_tags

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchTagSet":
                return {}
            return {"error": str(e)}

    def _classify_object(
        self, bucket_name: str, object_key: str, client
    ) -> Dict[str, Any]:
        """Classify an individual object based on tags and naming patterns."""
        classification = None
        confidence = 0
        reasons = []

        # Try to get object tags first
        try:
            response = client.get_object_tagging(
                Bucket=bucket_name, Key=object_key
            )
            tags = response.get("TagSet", [])

            for tag in tags:
                key = tag["Key"].lower()
                value = tag["Value"].lower()

                # Direct classification tag
                if "classification" in key or "data-class" in key:
                    classification = value
                    confidence = 90
                    reasons.append(
                        f"Direct classification tag: {tag['Key']}={tag['Value']}"
                    )
                    break
        except ClientError:
            # Object tagging not available, continue with naming analysis
            pass

        # If no direct classification found, analyze naming patterns
        if not classification:
            object_key_lower = object_key.lower()

            # Check each classification pattern
            for class_name, patterns in self.SOC2_DATA_CLASSIFICATION.items():
                for pattern in patterns:
                    if pattern in object_key_lower:
                        classification = class_name
                        confidence = 70  # Lower confidence for naming patterns
                        reasons.append(
                            f"Naming pattern match: '{pattern}' in object key"
                        )
                        break
                if classification:
                    break

        return {
            "classification": classification,
            "confidence": confidence,
            "reasons": reasons,
        }
