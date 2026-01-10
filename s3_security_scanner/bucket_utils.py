"""Shared utility functions for S3 bucket operations."""

import re
from typing import Dict, Optional


def extract_bucket_info_from_endpoint(
    endpoint: str,
) -> Dict[str, Optional[str]]:
    """Extract bucket name and region from S3 endpoint.

    Args:
        endpoint: S3 endpoint URL

    Returns:
        Dictionary with bucket_name and region
    """
    endpoint_lower = endpoint.lower()

    # S3 website endpoint patterns
    website_patterns = [
        re.compile(
            r"^([a-z0-9.-]+)\.s3-website[.-]([a-z0-9-]+)\.amazonaws\.com$"
        ),
        re.compile(
            r"^([a-z0-9.-]+)\.s3-website\.([a-z0-9-]+)\.amazonaws\.com$"
        ),
    ]

    for pattern in website_patterns:
        match = pattern.match(endpoint_lower)
        if match:
            return {"bucket_name": match.group(1), "region": match.group(2)}

    # S3 direct endpoint patterns
    direct_patterns = [
        re.compile(r"^([a-z0-9.-]+)\.s3\.amazonaws\.com$"),
        re.compile(r"^([a-z0-9.-]+)\.s3[.-]([a-z0-9-]+)\.amazonaws\.com$"),
    ]

    for pattern in direct_patterns:
        match = pattern.match(endpoint_lower)
        if match:
            bucket_name = match.group(1)
            region = match.group(2) if match.lastindex >= 2 else "us-east-1"
            return {"bucket_name": bucket_name, "region": region}

    return {"bucket_name": None, "region": None}
