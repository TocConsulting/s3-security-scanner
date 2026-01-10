"""
DNS-Based Bucket Validator - Stealth enumeration inspired by s3enum

This module implements the genius DNS-based bucket detection technique from s3enum.
DNS queries are much less likely to trigger security alerts than HTTP requests.
"""

import logging
import time
import threading
import queue
from typing import Dict, Optional, List
import dns.resolver
import dns.exception


logger = logging.getLogger(__name__)


class DNSBucketValidator:
    """
    DNS-based S3 bucket validator with resolver recycling to prevent file descriptor leaks

    Key insight from s3enum:
    - Non-existent buckets resolve to: s3-1-w.amazonaws.com
    - Existing buckets resolve to: s3-<region>-w.amazonaws.com

    Production optimization:
    - Uses resolver pool to prevent FD exhaustion
    - Explicit resource cleanup and recycling
    - Optimized dnspython configuration
    """

    # S3 DNS suffixes
    S3_GLOBAL_SUFFIX = "s3.amazonaws.com"
    S3_NONEXISTENT_CNAME = "s3-1-w.amazonaws.com."

    # Regional endpoints for detection
    S3_REGIONAL_PATTERNS = [
        "s3-{region}-w.amazonaws.com",
        "s3.{region}.amazonaws.com",
        "s3-website-{region}.amazonaws.com"
    ]

    def __init__(self,
                 timeout: float = 2.0,
                 retries: int = 2,
                 nameservers: Optional[List[str]] = None,
                 resolver_pool_size: int = 3):
        """
        Initialize DNS validator with resolver recycling

        Args:
            timeout: DNS query timeout in seconds
            retries: Number of retry attempts
            nameservers: Custom DNS servers (for anonymity)
            resolver_pool_size: Number of resolvers to pool for reuse
        """
        self.timeout = timeout
        self.retries = retries
        self.nameservers = nameservers
        self.resolver_pool_size = resolver_pool_size

        # Resolver pool for resource recycling
        self._resolver_pool = queue.Queue(maxsize=resolver_pool_size)
        self._pool_lock = threading.Lock()
        self._created_resolvers = 0

        # Shared cache for all resolvers
        self._shared_cache = dns.resolver.LRUCache(max_size=2000)

        # Results cache with thread-safe access
        self._cache = {}
        self._cache_ttl = 300  # 5 minutes
        self._cache_lock = threading.Lock()

        # Initialize resolver pool
        self._initialize_pool()

    def _initialize_pool(self):
        """Initialize the resolver pool with optimally configured resolvers"""
        for _ in range(self.resolver_pool_size):
            resolver = self._create_optimized_resolver()
            self._resolver_pool.put(resolver)
            self._created_resolvers += 1

    def _create_optimized_resolver(self) -> dns.resolver.Resolver:
        """Create an optimally configured resolver to prevent FD leaks"""
        resolver = dns.resolver.Resolver()

        # Critical production settings to prevent FD exhaustion
        resolver.timeout = self.timeout          # Socket timeout
        resolver.lifetime = self.timeout * 2     # Total query timeout
        resolver.cache = self._shared_cache      # Share cache to reduce memory
        resolver.retry_servfail = False          # Don't retry server failures
        resolver.search = []                     # Disable search domains
        resolver.ndots = 1                      # Reduce query complexity

        # Force UDP only to reduce TCP fallback sockets
        resolver.use_edns(-1)                   # Disable EDNS to prevent TCP fallback
        resolver.edns = -1

        if self.nameservers:
            resolver.nameservers = self.nameservers

        return resolver

    def _get_resolver(self) -> dns.resolver.Resolver:
        """Get a resolver from the pool (blocking if none available)"""
        try:
            # Try to get existing resolver from pool
            return self._resolver_pool.get_nowait()
        except queue.Empty:
            # If pool is empty and we haven't reached max, create new one
            with self._pool_lock:
                if self._created_resolvers < self.resolver_pool_size:
                    resolver = self._create_optimized_resolver()
                    self._created_resolvers += 1
                    return resolver

            # Wait for resolver to become available
            return self._resolver_pool.get()

    def _return_resolver(self, resolver: dns.resolver.Resolver):
        """Return resolver to pool for reuse"""
        try:
            self._resolver_pool.put_nowait(resolver)
        except queue.Full:
            # Pool is full, resolver will be garbage collected
            pass

    def validate(self, bucket_name: str) -> Optional[Dict]:
        """
        Validate bucket existence using DNS with concurrency control

        Args:
            bucket_name: Name of the bucket to validate

        Returns:
            Dictionary with validation results or None
        """
        # Check cache first (thread-safe)
        with self._cache_lock:
            if bucket_name in self._cache:
                cached_time, cached_result = self._cache[bucket_name]
                if time.time() - cached_time < self._cache_ttl:
                    logger.debug(f"DNS cache hit for {bucket_name}")
                    return cached_result

        # Get resolver from pool
        resolver = self._get_resolver()

        try:
            # Perform DNS validation with pooled resolver
            result = self._dns_check(bucket_name, resolver)

            # Cache the result (thread-safe)
            with self._cache_lock:
                self._cache[bucket_name] = (time.time(), result)

            return result
        finally:
            # Always return resolver to pool
            self._return_resolver(resolver)

    def _dns_check(self, bucket_name: str, resolver: dns.resolver.Resolver) -> Optional[Dict]:
        """
        Perform DNS-based bucket existence check with provided resolver

        Args:
            bucket_name: Name of bucket to check
            resolver: Pre-configured resolver from pool

        Returns:
            Dictionary with:
            - exists: True if bucket exists
            - region: Detected AWS region (if possible)
            - cname: The CNAME record found
            - confidence: Confidence level (0-1)
        """
        # Construct S3 bucket domain
        bucket_domain = f"{bucket_name}.{self.S3_GLOBAL_SUFFIX}"

        # Try multiple times with exponential backoff
        delay = 0.1
        for attempt in range(self.retries):
            try:
                # Query CNAME record
                answers = resolver.resolve(bucket_domain, 'CNAME')

                if answers:
                    cname = str(answers[0])
                    # Removed debug logging to keep discovery output clean

                    # Check if it's the non-existent bucket CNAME
                    if cname == self.S3_NONEXISTENT_CNAME:
                        return {
                            'exists': False,
                            'cname': cname,
                            'confidence': 0.9  # High confidence it doesn't exist
                        }

                    # Check if CNAME points to actual S3 infrastructure
                    if any(pattern in cname for pattern in ['s3-', 's3.']) and 'amazonaws.com' in cname:
                        # Real S3 infrastructure CNAME - bucket exists
                        region = self._extract_region_from_cname(cname)
                        return {
                            'exists': True,
                            'region': region,
                            'cname': cname,
                            'confidence': 0.8  # Good confidence from DNS
                        }
                    else:
                        # CNAME points elsewhere, not S3 - bucket doesn't exist
                        return {
                            'exists': False,
                            'cname': cname,
                            'confidence': 0.7  # Medium confidence it doesn't exist
                        }

            except dns.resolver.NXDOMAIN:
                # Domain doesn't exist - definitive answer
                return {
                    'exists': False,
                    'error': 'NXDOMAIN',
                    'confidence': 0.9
                }

            except dns.resolver.NoAnswer:
                # No CNAME record - try A record as fallback
                try:
                    resolver.resolve(bucket_domain, 'A')
                    return {
                        'exists': True,
                        'confidence': 0.6  # Lower confidence without CNAME
                    }
                except Exception:
                    pass

            except dns.exception.Timeout:
                # DNS timeout - retry with backoff
                if attempt < self.retries - 1:
                    time.sleep(delay)
                    delay *= 2  # Exponential backoff

            except OSError as e:
                if "Too many open files" in str(e):
                    # File descriptor exhaustion - this should now be rare with resolver pooling
                    raise e
                else:
                    # Other OS errors - don't log during discovery to keep output clean
                    break
            except Exception:
                # DNS errors are expected during discovery - don't pollute output
                break

        # If we get here, we couldn't determine via DNS
        return None

    def _extract_region_from_cname(self, cname: str) -> Optional[str]:
        """
        Extract AWS region from CNAME record

        Examples:
        - s3-us-west-2-w.amazonaws.com → us-west-2
        - s3.eu-west-1.amazonaws.com → eu-west-1
        """
        # Common region codes
        regions = [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
            'eu-north-1', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2',
            'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'sa-east-1',
            'me-south-1', 'af-south-1', 'ap-east-1'
        ]

        # Check if any region appears in the CNAME
        for region in regions:
            if region in cname:
                return region

        # Special case for us-east-1 (default region)
        if 's3-external-1' in cname or 's3.amazonaws.com' in cname:
            return 'us-east-1'

        return None

    def bulk_validate(self, bucket_names: List[str]) -> Dict[str, Dict]:
        """
        Validate multiple buckets efficiently

        Args:
            bucket_names: List of bucket names to validate

        Returns:
            Dictionary mapping bucket names to validation results
        """
        results = {}

        for bucket_name in bucket_names:
            result = self.validate(bucket_name)
            if result:
                results[bucket_name] = result

            # Small delay to avoid overwhelming DNS
            time.sleep(0.05)

        return results

    def test_dns_servers(self) -> Dict[str, bool]:
        """
        Test connectivity to DNS servers

        Returns:
            Dictionary of DNS server -> reachability status
        """
        test_results = {}

        for nameserver in self.resolver.nameservers:
            try:
                # Try to resolve a known domain
                test_resolver = dns.resolver.Resolver()
                test_resolver.nameservers = [nameserver]
                test_resolver.timeout = 2.0
                test_resolver.resolve('google.com', 'A')
                test_results[nameserver] = True
            except Exception:
                test_results[nameserver] = False

        return test_results
