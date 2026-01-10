"""
Main Bucket Discovery Engine - Orchestrates all discovery methods

Combines DNS-based stealth enumeration with HTTP validation for comprehensive coverage.
"""

import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .dns_validator import DNSBucketValidator
from .http_validator import HTTPBucketValidator
from .permutation_generator import PermutationGenerator
from .wordlist_manager import WordlistManager


logger = logging.getLogger(__name__)


@dataclass
class BucketInfo:
    """Container for discovered bucket information"""
    name: str
    exists: bool = False
    region: Optional[str] = None
    is_public: bool = False
    status_code: Optional[int] = None
    discovery_method: Optional[str] = None
    discovery_time: datetime = field(default_factory=datetime.now)
    confidence: float = 0.0
    error_message: Optional[str] = None
    permissions: Dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'name': self.name,
            'exists': self.exists,
            'region': self.region,
            'is_public': self.is_public,
            'status_code': self.status_code,
            'discovery_method': self.discovery_method,
            'discovery_time': self.discovery_time.isoformat(),
            'confidence': self.confidence,
            'error_message': self.error_message,
            'permissions': self.permissions
        }


class BucketDiscoveryEngine:
    """
    S3 Bucket Discovery Engine

    Combines multiple discovery techniques:
    1. DNS-based enumeration
    2. HTTP-based validation
    3. Advanced permutation generation
    4. Cross-validation for accuracy
    """

    def __init__(self,
                 use_dns: bool = True,
                 use_http: bool = True,
                 max_workers: int = 10,
                 rate_limit_delay: float = 0.1,
                 user_agent_rotation: bool = True,
                 stealth_mode: bool = True,
                 quiet_mode: bool = False):
        """
        Initialize the discovery engine

        Args:
            use_dns: Enable DNS-based discovery
            use_http: Enable HTTP-based validation
            max_workers: Maximum concurrent workers
            rate_limit_delay: Delay between requests
            user_agent_rotation: Rotate user agents for stealth
            stealth_mode: Enable all stealth features
        """
        self.use_dns = use_dns
        self.use_http = use_http
        self.max_workers = max_workers
        self.rate_limit_delay = rate_limit_delay
        self.user_agent_rotation = user_agent_rotation
        self.stealth_mode = stealth_mode
        self.quiet_mode = quiet_mode

        # Initialize validators
        self.dns_validator = DNSBucketValidator() if use_dns else None
        self.http_validator = HTTPBucketValidator(
            user_agent_rotation=user_agent_rotation,
            rate_limit_delay=rate_limit_delay
        ) if use_http else None

        # Initialize generators
        self.permutation_generator = PermutationGenerator()
        self.wordlist_manager = WordlistManager()

        # Statistics
        self.stats = {
            'total_candidates': 0,
            'dns_validated': 0,
            'http_validated': 0,
            'buckets_found': 0,
            'public_buckets': 0,
            'errors': 0,
            'start_time': None,
            'end_time': None
        }

    def discover(self,
                 target: str,
                 wordlist_path: Optional[str] = None,
                 methods: Optional[List[str]] = None,
                 permutation_level: str = 'medium') -> List[BucketInfo]:
        """
        Main discovery method - orchestrates the entire process

        Args:
            target: Target company name, domain, or base name
            wordlist_path: Optional custom wordlist path
            methods: Discovery methods to use ['dns', 'http', 'permutations']
            permutation_level: Level of permutation generation ('basic', 'medium', 'advanced')

        Returns:
            List of discovered BucketInfo objects
        """
        self.stats['start_time'] = datetime.now(timezone.utc)

        if methods is None:
            methods = ['dns', 'http', 'permutations']

        logger.info(f"Starting bucket discovery for target: {target}")
        logger.info(f"Methods: {methods}, Workers: {self.max_workers}, Stealth: {self.stealth_mode}")

        # Phase 1: Generate candidate bucket names
        candidates = self._generate_candidates(target, wordlist_path, methods, permutation_level)
        self.stats['total_candidates'] = len(candidates)
        logger.info(f"Generated {len(candidates)} candidate bucket names")

        # Phase 2: Validate candidates
        discovered_buckets = self._validate_candidates(candidates, methods)

        # Phase 3: Enrich with additional information
        enriched_buckets = self._enrich_bucket_info(discovered_buckets)

        # Phase 4: Sort by confidence and public access
        sorted_buckets = sorted(
            enriched_buckets,
            key=lambda b: (b.is_public, b.confidence),
            reverse=True
        )

        self.stats['end_time'] = datetime.now(timezone.utc)
        self.stats['buckets_found'] = len([b for b in sorted_buckets if b.exists])
        self.stats['public_buckets'] = len([b for b in sorted_buckets if b.is_public])

        self._print_summary()

        return sorted_buckets

    def _generate_candidates(self,
                             target: str,
                             wordlist_path: Optional[str],
                             methods: List[str],
                             permutation_level: str) -> Set[str]:
        """Generate candidate bucket names"""
        candidates = set()

        # Always add the base target
        candidates.add(target.lower())

        if 'permutations' in methods:
            # Generate permutations based on level
            perms = self.permutation_generator.generate(
                target,
                level=permutation_level
            )
            candidates.update(perms)
            logger.info(f"Generated {len(perms)} permutations")

        if wordlist_path:
            # Load custom wordlist
            wordlist = self.wordlist_manager.load_wordlist(wordlist_path)
            # Combine with target
            for word in wordlist:
                candidates.update(
                    self.permutation_generator.combine_with_wordlist(target, [word])
                )

        return candidates

    def _validate_candidates(self,
                             candidates: Set[str],
                             methods: List[str]) -> List[BucketInfo]:
        """Validate candidate bucket names using simple threading"""
        return self._validate_candidates_simple(candidates, methods)

    def _validate_candidates_simple(self,
                                    candidates: Set[str],
                                    methods: List[str]) -> List[BucketInfo]:
        """Simple validation using ThreadPoolExecutor with adaptive worker scaling"""
        discovered_buckets = []
        candidate_count = len(candidates)

        # Simple worker scaling based on candidate count
        if candidate_count <= 500:
            # Basic level: ~100 candidates
            effective_workers = min(self.max_workers, 5)
        elif candidate_count <= 2000:
            # Medium level: ~1,200 candidates
            effective_workers = min(self.max_workers, 3)
        else:
            # Advanced level: ~7,000+ candidates
            effective_workers = min(self.max_workers, 2)

        if not self.quiet_mode:
            logger.info(f"Using {effective_workers} workers for {candidate_count} candidates")

        with ThreadPoolExecutor(max_workers=effective_workers) as executor:
            # Submit validation tasks
            future_to_bucket = {}

            for candidate in candidates:
                future = executor.submit(self._validate_single_bucket, candidate, methods)
                future_to_bucket[future] = candidate

            # Collect results with progress indication
            processed = 0
            total = len(candidates)
            recent_times = []

            for future in as_completed(future_to_bucket):
                processed += 1
                bucket_name = future_to_bucket[future]
                current_time = datetime.now(timezone.utc)

                # Track recent completion times for rolling average
                recent_times.append(current_time)
                if len(recent_times) > 50:
                    recent_times.pop(0)

                # Show progress every 10 buckets or when complete
                if not self.quiet_mode and (processed % 10 == 0 or processed == total):
                    self._show_progress(processed, total, recent_times)

                try:
                    bucket_info = future.result()
                    if bucket_info and (bucket_info.exists or bucket_info.confidence > 0.5):
                        discovered_buckets.append(bucket_info)

                except Exception as e:
                    logger.error(f"Error validating {bucket_name}: {e}")
                    self.stats['errors'] += 1

            # Clear progress line when done
            if not self.quiet_mode:
                self._clear_progress_line()

        return discovered_buckets

    def _show_progress(self, processed: int, total: int, recent_times: list):
        """Show progress with consistent formatting"""
        current_time = datetime.now(timezone.utc)
        elapsed = (current_time - self.stats['start_time']).total_seconds()

        # Calculate rate using rolling average for better ETA
        if len(recent_times) >= 10 and processed >= 20:
            recent_elapsed = (recent_times[-1] - recent_times[0]).total_seconds()
            recent_rate = (len(recent_times) - 1) / recent_elapsed if recent_elapsed > 0 else 0
            eta = (total - processed) / recent_rate if recent_rate > 0 else 0
            display_rate = recent_rate
        else:
            overall_rate = processed / elapsed if elapsed > 0 else 0
            eta = (total - processed) / overall_rate if overall_rate > 0 else 0
            display_rate = overall_rate

        # Check if we're in a proper terminal
        if sys.stdout.isatty():
            print(f"\r⏳ Progress: {processed}/{total} ({processed/total:.1%}) | "
                  f"Rate: {display_rate:.1f}/s | ETA: {eta:.0f}s", end='', flush=True)
        else:
            # Not a TTY, show progress at intervals
            if processed == total or processed % 20 == 0:
                print(f"⏳ Progress: {processed}/{total} ({processed/total:.1%}) | "
                      f"Rate: {display_rate:.1f}/s | ETA: {eta:.0f}s")

    def _clear_progress_line(self):
        """Clear progress line when done"""
        if sys.stdout.isatty():
            print("\r" + " " * 80 + "\r", end='')
        else:
            print()

    def _validate_single_bucket(self,
                                bucket_name: str,
                                methods: List[str]) -> Optional[BucketInfo]:
        """Validate a single bucket using multiple methods"""
        # Apply stealth delay before making network requests
        if self.stealth_mode:
            time.sleep(self.rate_limit_delay * (0.5 + time.time() % 1))

        bucket_info = BucketInfo(name=bucket_name)
        validation_results = []

        # DNS validation (stealth)
        if 'dns' in methods and self.dns_validator:
            dns_result = self.dns_validator.validate(bucket_name)
            if dns_result:
                validation_results.append(('dns', dns_result))
                self.stats['dns_validated'] += 1

        # HTTP validation (comprehensive)
        if 'http' in methods and self.http_validator:
            http_result = self.http_validator.validate(bucket_name)
            if http_result:
                validation_results.append(('http', http_result))
                self.stats['http_validated'] += 1

        # Cross-validation for confidence scoring
        if validation_results:
            bucket_info = self._cross_validate_results(bucket_name, validation_results)

        return bucket_info

    def _cross_validate_results(self,
                                bucket_name: str,
                                validation_results: List[Tuple[str, Dict]]) -> BucketInfo:
        """Cross-validate results from multiple methods for accuracy"""
        bucket_info = BucketInfo(name=bucket_name)

        # Count positive validations
        positive_validations = 0
        methods_used = []

        for method, result in validation_results:
            methods_used.append(method)

            if result.get('exists', False):
                positive_validations += 1

                # Update bucket info with most comprehensive result
                if result.get('status_code'):
                    bucket_info.status_code = result['status_code']
                if result.get('region'):
                    bucket_info.region = result['region']
                if result.get('is_public', False):
                    bucket_info.is_public = True
                if result.get('permissions'):
                    bucket_info.permissions.update(result['permissions'])

        # Calculate confidence based on validation agreement
        total_methods = len(validation_results)
        if total_methods > 0:
            bucket_info.confidence = positive_validations / total_methods
            bucket_info.exists = positive_validations > 0
            bucket_info.discovery_method = '+'.join(methods_used)

        return bucket_info

    def _enrich_bucket_info(self, buckets: List[BucketInfo]) -> List[BucketInfo]:
        """Enrich bucket information with additional details"""
        enriched = []

        for bucket in buckets:
            # Skip if doesn't exist
            if not bucket.exists:
                continue

            # Try to detect region if not already known
            if not bucket.region and self.http_validator:
                region = self.http_validator.detect_region(bucket.name)
                if region:
                    bucket.region = region

            # Test additional permissions if public
            if bucket.is_public and self.http_validator:
                perms = self.http_validator.test_permissions(bucket.name)
                bucket.permissions.update(perms)

            enriched.append(bucket)

        return enriched

    def _print_summary(self):
        """Print discovery summary statistics"""
        # Discovery summary is now disabled to keep output clean
        # Statistics are available via get_statistics() and shown in CLI summary
        return

    def get_statistics(self) -> Dict:
        """Get detailed discovery statistics"""
        return self.stats.copy()
