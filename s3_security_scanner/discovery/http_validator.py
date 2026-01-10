"""
HTTP-Based Bucket Validator - Comprehensive validation inspired by cloud_enum

This module implements sophisticated HTTP-based bucket validation with:
- Multiple URL patterns
- Status code intelligence
- Permission enumeration
- Regional detection
- Stealth features
"""

import logging
import random
import re
import time
from typing import Dict, Optional, List
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


logger = logging.getLogger(__name__)


class HTTPBucketValidator:
    """
    HTTP-based S3 bucket validator with comprehensive features

    Features:
    - Multiple URL patterns (subdomain, path-style, regional)
    - Status code intelligence (200, 403, 404 analysis)
    - Permission enumeration (read, write, list)
    - Regional detection and validation
    - User-agent rotation for stealth
    - Rate limiting and backoff
    """

    # URL patterns for different S3 access styles
    URL_PATTERNS = [
        "https://{bucket}.s3.amazonaws.com/",           # Virtual-hosted style
        "https://s3.amazonaws.com/{bucket}/",           # Path-style
        "http://{bucket}.s3.amazonaws.com/",            # HTTP virtual-hosted
        "http://s3.amazonaws.com/{bucket}/",            # HTTP path-style
        "https://{bucket}.s3-{region}.amazonaws.com/",  # Regional virtual-hosted
        "https://s3-{region}.amazonaws.com/{bucket}/",  # Regional path-style
    ]

    # AWS regions for regional testing
    AWS_REGIONS = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
        'ap-south-1', 'ap-northeast-1', 'ap-northeast-2',
        'ap-southeast-1', 'ap-southeast-2', 'ca-central-1'
    ]

    # User agents for rotation
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'curl/7.68.0',
        'wget/1.20.3 (linux-gnu)'
    ]

    def __init__(self,
                 timeout: float = 5.0,
                 retries: int = 3,
                 rate_limit_delay: float = 0.1,
                 user_agent_rotation: bool = True,
                 verify_ssl: bool = True):
        """
        Initialize HTTP validator

        Args:
            timeout: Request timeout in seconds
            retries: Number of retry attempts
            rate_limit_delay: Base delay between requests
            user_agent_rotation: Enable user-agent rotation
            verify_ssl: Verify SSL certificates
        """
        self.timeout = timeout
        self.retries = retries
        self.rate_limit_delay = rate_limit_delay
        self.user_agent_rotation = user_agent_rotation
        self.verify_ssl = verify_ssl

        # Configure session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Rate limiting state
        self._last_request_time = 0
        self._rate_limit_detected = False

    def validate(self, bucket_name: str) -> Optional[Dict]:
        """
        Validate bucket existence using HTTP

        Args:
            bucket_name: Name of the bucket to validate

        Returns:
            Dictionary with validation results or None
        """
        # Apply rate limiting
        self._apply_rate_limit()

        # Test primary patterns first
        for pattern in self.URL_PATTERNS[:4]:  # Start with basic patterns
            try:
                # Skip regional patterns for now
                if '{region}' in pattern:
                    continue

                url = pattern.format(bucket=bucket_name)
                response = self._make_request(url)

                if response:
                    result = self._analyze_response(bucket_name, url, response)
                    if result and result.get('exists'):
                        # Found the bucket, try to get more info
                        return self._enrich_result(bucket_name, result)

            except Exception as e:
                logger.debug(f"HTTP error for {bucket_name}: {e}")

        # If not found with basic patterns, try regional
        return self._try_regional_patterns(bucket_name)

    def _make_request(self, url: str) -> Optional[requests.Response]:
        """
        Make HTTP request with stealth features

        Args:
            url: URL to request

        Returns:
            Response object or None
        """
        headers = {}

        # Rotate user agent if enabled
        if self.user_agent_rotation:
            headers['User-Agent'] = random.choice(self.USER_AGENTS)

        # Add common headers to look legitimate
        headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        try:
            response = self.session.head(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )

            # Check for rate limiting
            if response.status_code == 429 or 'SlowDown' in response.text:
                self._rate_limit_detected = True
                logger.warning(f"Rate limit detected for {url}")
                time.sleep(self.rate_limit_delay * 10)  # Back off more

            return response

        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed for {url}: {e}")
            return None

    def _analyze_response(self,
                          bucket_name: str,
                          url: str,
                          response: requests.Response) -> Optional[Dict]:
        """
        Analyze HTTP response to determine bucket status

        Args:
            bucket_name: Name of the bucket
            url: URL that was requested
            response: HTTP response object

        Returns:
            Dictionary with analysis results
        """
        result = {
            'exists': False,
            'is_public': False,
            'status_code': response.status_code,
            'url': url,
            'headers': dict(response.headers),
            'confidence': 0.0
        }

        # Analyze status code
        if response.status_code == 200:
            # Public bucket - jackpot!
            result.update({
                'exists': True,
                'is_public': True,
                'confidence': 1.0,
                'access_level': 'public'
            })
            logger.info(f"PUBLIC bucket found: {bucket_name}")

        elif response.status_code == 403:
            # Protected bucket - exists but requires auth
            result.update({
                'exists': True,
                'is_public': False,
                'confidence': 0.9,
                'access_level': 'protected'
            })
            logger.info(f"PROTECTED bucket found: {bucket_name}")

        elif response.status_code == 404:
            # Bucket doesn't exist
            result.update({
                'exists': False,
                'confidence': 0.8
            })

        elif response.status_code in [301, 302, 307, 308]:
            # Redirect - bucket might exist in different region
            location = response.headers.get('Location', '')
            if 's3' in location:
                result.update({
                    'exists': True,
                    'confidence': 0.7,
                    'redirect_location': location
                })
                # Try to extract region from redirect
                region = self._extract_region_from_url(location)
                if region:
                    result['region'] = region

        # Check for S3-specific headers
        s3_headers = ['x-amz-bucket-region', 'x-amz-request-id', 'x-amz-id-2']
        if any(header in response.headers for header in s3_headers):
            result['confidence'] = min(result['confidence'] + 0.2, 1.0)

            # Extract region from headers if present
            if 'x-amz-bucket-region' in response.headers:
                result['region'] = response.headers['x-amz-bucket-region']

        return result if result['exists'] or result['confidence'] > 0.5 else None

    def _try_regional_patterns(self, bucket_name: str) -> Optional[Dict]:
        """
        Try regional URL patterns for bucket detection

        Args:
            bucket_name: Name of the bucket to validate

        Returns:
            Dictionary with validation results or None
        """
        # Try a few common regions first
        priority_regions = ['us-east-1', 'us-west-2', 'eu-west-1']

        for region in priority_regions:
            for pattern in self.URL_PATTERNS:
                if '{region}' not in pattern:
                    continue

                try:
                    url = pattern.format(bucket=bucket_name, region=region)
                    response = self._make_request(url)

                    if response:
                        result = self._analyze_response(bucket_name, url, response)
                        if result and result.get('exists'):
                            result['region'] = region
                            return result

                except Exception as e:
                    logger.debug(f"Regional test failed for {bucket_name} in {region}: {e}")

        return None

    def _enrich_result(self, bucket_name: str, result: Dict) -> Dict:
        """
        Enrich result with additional information

        Args:
            bucket_name: Name of the bucket
            result: Initial validation result

        Returns:
            Enriched result dictionary
        """
        # If bucket is public, try to get more details
        if result.get('is_public', False):
            # Try to list objects
            permissions = self.test_permissions(bucket_name)
            result['permissions'] = permissions

            # Try to determine region if not already known
            if not result.get('region'):
                region = self.detect_region(bucket_name)
                if region:
                    result['region'] = region

        return result

    def test_permissions(self, bucket_name: str) -> Dict[str, bool]:
        """
        Test various permissions on the bucket

        Args:
            bucket_name: Name of the bucket to test

        Returns:
            Dictionary of permission -> bool mapping
        """
        permissions = {
            'list_objects': False,
            'read_objects': False,
            'write_objects': False,
            'read_acp': False,
            'write_acp': False
        }

        # Test list objects
        try:
            list_url = f"https://{bucket_name}.s3.amazonaws.com/"
            response = self._make_request(list_url)
            if response and response.status_code == 200:
                permissions['list_objects'] = True
        except Exception:
            pass

        # Test read a common object
        try:
            common_files = ['index.html', 'readme.txt', 'robots.txt']
            for filename in common_files:
                obj_url = f"https://{bucket_name}.s3.amazonaws.com/{filename}"
                response = self._make_request(obj_url)
                if response and response.status_code == 200:
                    permissions['read_objects'] = True
                    break
        except Exception:
            pass

        # Test write permissions (careful not to actually write)
        try:
            options_url = f"https://{bucket_name}.s3.amazonaws.com/"
            response = self.session.options(options_url, timeout=self.timeout)
            if response and 'PUT' in response.headers.get('Allow', ''):
                permissions['write_objects'] = True
        except Exception:
            pass

        return permissions

    def detect_region(self, bucket_name: str) -> Optional[str]:
        """
        Detect the region of a bucket

        Args:
            bucket_name: Name of the bucket

        Returns:
            AWS region or None
        """
        # Try to get region from bucket location
        try:
            url = f"https://{bucket_name}.s3.amazonaws.com/?location"
            response = self._make_request(url)
            if response and response.status_code == 200:
                # Parse location from response
                if 'LocationConstraint' in response.text:
                    # Extract region from XML response
                    match = re.search(r'<LocationConstraint>([^<]+)</LocationConstraint>', response.text)
                    if match:
                        return match.group(1)
        except Exception:
            pass

        # Try regional endpoints
        for region in self.AWS_REGIONS:
            try:
                url = f"https://{bucket_name}.s3-{region}.amazonaws.com/"
                response = self._make_request(url)
                if response and response.status_code in [200, 403]:
                    return region
            except Exception:
                continue

        return None

    def _extract_region_from_url(self, url: str) -> Optional[str]:
        """
        Extract AWS region from S3 URL

        Args:
            url: S3 URL

        Returns:
            AWS region or None
        """
        for region in self.AWS_REGIONS:
            if region in url:
                return region
        return None

    def _apply_rate_limit(self):
        """Apply rate limiting to avoid triggering protection"""
        current_time = time.time()

        # Calculate delay based on rate limit detection
        base_delay = self.rate_limit_delay
        if self._rate_limit_detected:
            base_delay *= 10  # Much longer delay if rate limited

        # Add jitter to avoid synchronized requests
        jitter = random.uniform(0.5, 1.5)
        delay = base_delay * jitter

        # Apply delay if needed
        elapsed = current_time - self._last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)

        self._last_request_time = time.time()

    def bulk_validate(self, bucket_names: List[str]) -> Dict[str, Dict]:
        """
        Validate multiple buckets with optimized batching

        Args:
            bucket_names: List of bucket names to validate

        Returns:
            Dictionary mapping bucket names to validation results
        """
        results = {}

        for i, bucket_name in enumerate(bucket_names):
            result = self.validate(bucket_name)
            if result:
                results[bucket_name] = result

            # Progress indicator
            if i % 50 == 0:
                logger.info(f"HTTP validation progress: {i}/{len(bucket_names)}")

        return results
