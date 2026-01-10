"""Utility functions for S3 Security Scanner."""

import logging
import os
from datetime import datetime
from typing import Dict, Any


def setup_logging(output_dir: str) -> logging.Logger:
    """Setup logging configuration."""
    logger = logging.getLogger("s3_security_scanner")
    logger.setLevel(logging.INFO)

    # Prevent propagation to root logger to avoid duplicate messages
    logger.propagate = False

    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # File handler
    log_file = os.path.join(
        output_dir, f's3_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    )
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    return logger


def calculate_security_score(checks: Dict[str, Any]) -> int:
    """Calculate a security score for the bucket (0-100)."""
    score = 100

    # Helper function to safely get check results with proper defaults
    def get_check_result(
        check_name: str, key: str, default_value: bool = False
    ):
        """Safely get check result, handling missing or error cases."""
        check = checks.get(check_name, {})
        if isinstance(check, dict) and "error" not in check:
            return check.get(key, default_value)
        return default_value  # If check failed, assume safe default

    # Public access is the most critical - only penalize if explicitly public
    public_access_block = checks.get("public_access_block", {})
    if (
        isinstance(public_access_block, dict)
        and "error" not in public_access_block
    ):
        if not public_access_block.get(
            "is_properly_configured", True
        ):  # Default to True (safe)
            score -= 20

    bucket_policy = checks.get("bucket_policy", {})
    if isinstance(bucket_policy, dict) and "error" not in bucket_policy:
        if bucket_policy.get("is_public", False):  # Default to False (safe)
            score -= 20

    bucket_acl = checks.get("bucket_acl", {})
    if isinstance(bucket_acl, dict) and "error" not in bucket_acl:
        if bucket_acl.get(
            "has_public_access", False
        ):  # Default to False (safe)
            score -= 20

    # SSL enforcement is important
    if not get_check_result("bucket_policy", "ssl_enforced", False):
        score -= 15

    # Encryption is very important
    if not get_check_result("encryption", "is_enabled", False):
        score -= 20

    # Versioning is important
    if not get_check_result("versioning", "is_enabled", False):
        score -= 10

    # MFA delete is good practice
    if not get_check_result("versioning", "mfa_delete_enabled", False):
        score -= 5

    # Logging is good practice
    if not get_check_result("logging", "is_enabled", False):
        score -= 5

    # Object-level issues are critical
    obj_security = checks.get("object_level_security", {})
    if isinstance(obj_security, dict) and "error" not in obj_security:
        if obj_security.get("public_object_count", 0) > 0:
            score -= 15

        if obj_security.get("sensitive_object_count", 0) > 0:
            score -= 10

    # CORS risks
    if get_check_result("cors", "is_risky", False):
        score -= 5

    # Object lock is nice to have
    if not get_check_result("object_lock", "is_enabled", False):
        score -= 3

    # Lifecycle rules are nice to have
    if not get_check_result("lifecycle_rules", "has_lifecycle_rules", False):
        score -= 2

    # Ensure score doesn't go below 0
    return max(0, score)


def format_bytes(bytes_count: int) -> str:
    size = float(bytes_count)  # Use local variable to avoid modifying input
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def get_severity_color(severity: str) -> str:
    colors = {
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "cyan",
        "ERROR": "magenta",
    }
    return colors.get(severity, "white")
